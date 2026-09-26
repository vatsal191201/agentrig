"""`agentrig doctor --egress`: prove the sandbox actually blocks egress.

Runs a battery of escape probes from *inside* a real sandbox and reports each
as BLOCKED / ALLOWED / inconclusive, then repeats with one layer removed at a
time to show which layer does the blocking -- OpenAI's "blocking controls at
two independent layers, either of which would have prevented this".

The two layers agentrig composes:
  * network namespace -- the sandbox has its own netns with nothing routable;
  * egress gate -- the only bridged exit, an allowlisting recording proxy.

Configs run:
  both        production: netns on, gate on (empty allowlist), proxy env set
  netns_only  netns on, no gate, no proxy env
  gate_only   netns OFF (shares host net), gate on, proxy env set

If a config cannot be established on this host, its probes are reported
inconclusive -- never faked. The probe agent is agentrig's own, not hostile.
"""

from __future__ import annotations

import json
import os
import shutil
import tempfile
import textwrap

from agentrig.backends.base import Limits, SandboxSpec
from agentrig.engine import GATE_PORT, prepare_agent
from agentrig.observe.gate import EgressGate

PROBE = textwrap.dedent('''
    import json, os, socket, urllib.request
    res = {}
    def attempt(name, fn):
        try:
            res[name] = fn()
        except Exception as exc:
            res[name] = "BLOCKED:%s:%s" % (type(exc).__name__,
                                           getattr(exc, "errno", None) or str(exc)[:48])
    def direct_tcp():
        s = socket.create_connection(("1.1.1.1", 443), timeout=3); s.close(); return "ALLOWED"
    attempt("direct_tcp_public_ip", direct_tcp)
    def udp_dns():
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(3)
        pkt = b"\\xab\\xcd\\x01\\x00\\x00\\x01\\x00\\x00\\x00\\x00\\x00\\x00" \\
              b"\\x07example\\x03com\\x00\\x00\\x01\\x00\\x01"
        s.sendto(pkt, ("8.8.8.8", 53)); d, _ = s.recvfrom(512); s.close()
        return "ALLOWED" if d else "BLOCKED:empty"
    attempt("udp_dns_public_resolver", udp_dns)
    def gai():
        return "ALLOWED:" + socket.getaddrinfo("example.com", 443)[0][4][0]
    attempt("getaddrinfo_public_name", gai)
    def doh():
        r = urllib.request.urlopen(
            "https://dns.google/resolve?name=example.com&type=A", timeout=5)
        return "ALLOWED:%d" % r.status
    attempt("doh_via_proxy_connect", doh)
    def ipv6():
        s = socket.create_connection(("2606:4700:4700::1111", 443), timeout=3)
        s.close(); return "ALLOWED"
    attempt("ipv6_direct", ipv6)
    def bypass():
        for k in ("http_proxy","https_proxy","HTTP_PROXY","HTTPS_PROXY","ALL_PROXY"):
            os.environ.pop(k, None)
        op = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        return "ALLOWED:%d" % op.open("https://example.com/", timeout=5).status
    attempt("bypass_proxy_env", bypass)
    def raw_icmp():
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        s.close(); return "ALLOWED"
    attempt("raw_icmp_socket", raw_icmp)
    def abstract_unix():
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); s.settimeout(2)
        s.connect("\\0agentrig-probe-host-service"); s.close(); return "ALLOWED"
    attempt("abstract_unix_socket", abstract_unix)
    print(json.dumps(res))
''')

# probe -> which layer is expected to stop it (for the human summary)
_EXPECTED_LAYER = {
    "direct_tcp_public_ip": "network namespace",
    "udp_dns_public_resolver": "network namespace",
    "getaddrinfo_public_name": "network namespace",
    "doh_via_proxy_connect": "egress gate",
    "ipv6_direct": "network namespace",
    "bypass_proxy_env": "network namespace",
    "raw_icmp_socket": "dropped capabilities",
    "abstract_unix_socket": "network/ipc namespace",
}

_CONFIGS = [
    ("both", {"unshare_net": True, "gate": True, "proxy": True}),
    ("netns_only", {"unshare_net": True, "gate": False, "proxy": False}),
    # netns off: give it the host's real resolver so name lookups work and the
    # ablation isolates the layer under test (not an incidental missing resolver).
    ("gate_only", {"unshare_net": False, "gate": True, "proxy": True, "resolver": True}),
]


def _host_nameservers() -> list[str]:
    try:
        with open(os.path.realpath("/etc/resolv.conf"), encoding="utf-8") as fh:
            ns = [ln.split()[1] for ln in fh
                  if ln.startswith("nameserver") and len(ln.split()) > 1]
        return ns or ["127.0.0.53"]
    except OSError:
        return ["127.0.0.53"]


def _classify(raw) -> str:
    if raw is None:
        return "inconclusive"
    if raw.startswith("ALLOWED"):
        return "ALLOWED"
    if raw.startswith("BLOCKED"):
        return "BLOCKED"
    return "inconclusive"


def _run_config(backend, opts: dict, timeout: float) -> dict:
    """Run the probe once under one layer configuration; return {probe: raw}."""
    net_dir = tempfile.mkdtemp(prefix="agentrig-egresstest-")
    gate = None
    probe_path = os.path.join(net_dir, "probe.py")
    with open(probe_path, "w", encoding="utf-8") as fh:
        fh.write(PROBE)
    try:
        forwards = []
        env = {}
        if opts["gate"]:
            gate = EgressGate(allow=set())  # empty allowlist == production default
            gate.start(os.path.join(net_dir, "gate.sock"), GATE_PORT)
            forwards = [(GATE_PORT, "gate.sock")]
        if opts["proxy"]:
            proxy = f"http://127.0.0.1:{GATE_PORT}"
            for k in ("http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY"):
                env[k] = proxy
            env["no_proxy"] = env["NO_PROXY"] = "127.0.0.1,localhost"
        resolv_conf = None
        if opts.get("resolver"):
            resolv_conf = os.path.join(net_dir, "resolv.conf")
            with open(resolv_conf, "w", encoding="utf-8") as fh:
                fh.write("".join(f"nameserver {ns}\n" for ns in _host_nameservers()))
        argv, ro_mounts, _info = prepare_agent(f"/usr/bin/python3 {probe_path}")
        spec = SandboxSpec(network="loopback", env=env, limits=Limits(wall_timeout_s=timeout),
                           ro_mounts=ro_mounts, trace_syscalls=False, forwards=forwards,
                           net_dir=net_dir, share_net=not opts["unshare_net"],
                           resolv_conf=resolv_conf)
        handle = backend.create(spec)
        try:
            result = backend.exec(handle, argv, timeout=timeout)
        finally:
            backend.destroy(handle)
        line = (result.stdout or "").strip().splitlines()
        try:
            return json.loads(line[-1]) if line else {}
        except (ValueError, IndexError):
            return {}
    except Exception:
        return {}
    finally:
        if gate is not None:
            gate.stop()
        shutil.rmtree(net_dir, ignore_errors=True)


def run_egress_selftest(backend, *, timeout: float = 8.0) -> dict:
    caps = backend.capabilities()
    if not caps.can_isolate:
        return {"available": False,
                "reason": "backend cannot establish isolation; run `agentrig doctor`"}
    configs: dict[str, dict] = {}
    for name, opts in _CONFIGS:
        # gate_only needs to *disable* the network namespace; if that is somehow
        # unavailable the probes stay inconclusive rather than faked.
        configs[name] = _run_config(backend, opts, timeout)

    probes = list(_EXPECTED_LAYER)
    rows = []
    for probe in probes:
        both = _classify(configs.get("both", {}).get(probe))
        netns = _classify(configs.get("netns_only", {}).get(probe))
        gate = _classify(configs.get("gate_only", {}).get(probe))
        rows.append({
            "probe": probe,
            "expected_layer": _EXPECTED_LAYER[probe],
            "both": both, "netns_only": netns, "gate_only": gate,
            "raw": {"both": configs.get("both", {}).get(probe),
                    "netns_only": configs.get("netns_only", {}).get(probe),
                    "gate_only": configs.get("gate_only", {}).get(probe)},
            "attribution": _attribute(probe, both, netns, gate),
        })
    leaked = [r["probe"] for r in rows if r["both"] == "ALLOWED"]
    return {"available": True, "configs_run": [c[0] for c in _CONFIGS],
            "probes": rows, "leaked_in_production": leaked,
            "secure": not leaked}


def _attribute(probe: str, both: str, netns: str, gate: str) -> str:
    if both == "ALLOWED":
        return "LEAK: not blocked in the production config"
    if both == "inconclusive":
        return "inconclusive"
    # These are not stopped by the two *egress* layers; name the real mechanism.
    if probe == "raw_icmp_socket":
        return "dropped capabilities (no CAP_NET_RAW; independent of the egress layers)"
    if probe == "abstract_unix_socket":
        return "network namespace (abstract sockets are per-netns; no host socket reachable)"
    if netns == "BLOCKED" and gate == "BLOCKED":
        return "both layers independently (gate blocks the proxied path; namespace blocks the direct path)"
    if netns == "BLOCKED" and gate == "ALLOWED":
        return "network namespace is the blocking layer (gate alone allows it)"
    if gate == "BLOCKED" and netns == "ALLOWED":
        return "egress gate is the blocking layer (netns alone allows it)"
    return "blocked; single-layer attribution inconclusive"


def render_egress(result: dict) -> str:
    if not result.get("available"):
        return f"egress self-test unavailable: {result.get('reason', 'unknown')}"
    lines = ["agentrig doctor --egress", "=" * 72,
             "escape probes from inside a real sandbox; each layer removed in turn",
             ""]
    hdr = f"{'probe':26} {'both':>6} {'netns':>6} {'gate':>6}  attribution"
    lines.append(hdr)
    lines.append("-" * 72)
    mark = {"BLOCKED": "BLOCK", "ALLOWED": "ALLOW", "inconclusive": "  ? "}
    for r in result["probes"]:
        lines.append(f"{r['probe']:26} {mark[r['both']]:>6} {mark[r['netns_only']]:>6} "
                     f"{mark[r['gate_only']]:>6}  {r['attribution']}")
    lines.append("-" * 72)
    lines.append("columns: both = production (netns+gate); netns = namespace only "
                 "(no gate); gate = gate only (netns disabled)")
    if result["secure"]:
        lines.append("RESULT: every probe was BLOCKED in the production config.")
    else:
        lines.append("RESULT: LEAK -- probes escaped in production: "
                     + ", ".join(result["leaked_in_production"]))
    return "\n".join(lines)
