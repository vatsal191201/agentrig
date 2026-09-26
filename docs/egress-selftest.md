# `agentrig doctor --egress` — egress self-test (real output on the build host)

Escape probes run from *inside* a real sandbox, with each isolation layer
removed in turn to show which layer does the blocking. Reproduce with:

```
$ agentrig doctor --egress
agentrig doctor --egress
========================================================================
escape probes from inside a real sandbox; each layer removed in turn

probe                        both  netns   gate  attribution
------------------------------------------------------------------------
direct_tcp_public_ip        BLOCK  BLOCK  ALLOW  network namespace is the blocking layer (gate alone allows it)
udp_dns_public_resolver     BLOCK  BLOCK  ALLOW  network namespace is the blocking layer (gate alone allows it)
getaddrinfo_public_name     BLOCK  BLOCK  ALLOW  network namespace is the blocking layer (gate alone allows it)
doh_via_proxy_connect       BLOCK  BLOCK  BLOCK  both layers independently (gate blocks the proxied path; namespace blocks the direct path)
ipv6_direct                 BLOCK  BLOCK  ALLOW  network namespace is the blocking layer (gate alone allows it)
bypass_proxy_env            BLOCK  BLOCK  ALLOW  network namespace is the blocking layer (gate alone allows it)
raw_icmp_socket             BLOCK  BLOCK  BLOCK  dropped capabilities (no CAP_NET_RAW; independent of the egress layers)
abstract_unix_socket        BLOCK  BLOCK  BLOCK  network namespace (abstract sockets are per-netns; no host socket reachable)
------------------------------------------------------------------------
columns: both = production (netns+gate); netns = namespace only (no gate); gate = gate only (netns disabled)
RESULT: every probe was BLOCKED in the production config.
$ echo $?
0
```

Reading it: every probe is BLOCKED in the production config (`both`). The
`netns`/`gate` columns remove one layer at a time. Direct/DNS/IPv6/proxy-bypass
egress escapes only once the **network namespace** is disabled (so the namespace
is what stops them); the proxied DNS-over-HTTPS CONNECT is stopped by the **egress
gate** even with the namespace off, and by the namespace when the proxy is removed
— two independent layers, either of which prevents that path. `raw_icmp` is stopped
by dropped capabilities (no `CAP_NET_RAW`), independent of the egress layers.

The `gate_only` column disables the network namespace (`bwrap` without
`--unshare-net`) and gives the sandbox the host resolver, so the ablation
isolates the layer under test. This mode is used **only** by this self-test with
agentrig's own probe — never to run a scenario agent.
