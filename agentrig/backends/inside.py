"""agentrig in-sandbox launcher. Runs INSIDE the sandbox; stdlib only.

This file is bind-mounted read-only at ``/.agentrig/inside.py`` and executed as

    /usr/bin/python3 -I -S /.agentrig/inside.py <config-fd> -- <agent argv...>

It does exactly two things, then gets out of the way:

  1. **Loopback forwards.** The sandbox has its own network namespace with only
     ``lo`` -- nothing outside is routable. For each configured forward it
     listens on ``127.0.0.1:<port>`` and relays every connection, byte for
     byte, to a host-side Unix socket (a fake service or the egress gate).
     All recording happens on the host side, where the agent cannot reach it.
  2. **Secret env.** It reads a small JSON config from an inherited pipe fd
     (so secrets never appear in argv, strace output, or on disk), adds the
     secret env vars to the agent's environment, and runs the agent as its
     child with stdin/stdout/stderr inherited. Its exit code is the agent's.

It must never import agentrig: the sandbox has no access to the host package.
"""

import json
import os
import signal
import socket
import subprocess
import sys
import threading


def _pump(src, dst):
    try:
        while True:
            data = src.recv(65536)
            if not data:
                break
            dst.sendall(data)
    except OSError:
        pass
    finally:
        try:
            dst.shutdown(socket.SHUT_WR)
        except OSError:
            pass


def _relay(client, unix_path):
    upstream = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        upstream.connect(unix_path)
    except OSError:
        client.close()
        return
    back = threading.Thread(target=_pump, args=(upstream, client), daemon=True)
    back.start()
    _pump(client, upstream)
    back.join()
    client.close()
    upstream.close()


def _listen(port, unix_path):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port))
    srv.listen(64)

    def loop():
        while True:
            try:
                conn, _addr = srv.accept()
            except OSError:
                return
            threading.Thread(target=_relay, args=(conn, unix_path),
                             daemon=True).start()

    threading.Thread(target=loop, daemon=True).start()


def main(argv):
    if len(argv) < 4 or argv[2] != "--":
        sys.stderr.write("agentrig-launcher: usage: inside.py FD -- ARGV...\n")
        return 2
    with os.fdopen(int(argv[1]), "rb") as fh:
        cfg = json.loads(fh.read() or b"{}")
    for fwd in cfg.get("forwards", []):
        _listen(int(fwd["port"]), fwd["unix"])
    env = dict(os.environ)
    env.update(cfg.get("env", {}))
    try:
        proc = subprocess.Popen(argv[3:], env=env)
    except OSError as exc:
        sys.stderr.write(f"agentrig-launcher: cannot start agent: {exc}\n")
        return 127

    def forward_signal(signum, _frame):
        try:
            proc.send_signal(signum)
        except OSError:
            pass

    for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(sig, forward_signal)
    rc = proc.wait()
    return rc if rc >= 0 else 128 - rc


if __name__ == "__main__":
    sys.exit(main(sys.argv))
