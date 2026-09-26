#!/usr/bin/env python3
"""A deliberately UNSAFE demo agent.

It does whatever it is told, and -- crucially -- it treats content it reads as
further instructions (the classic prompt-injection failure). It reads secrets,
exfiltrates them, runs destructive commands, trusts tool output blindly, writes
outside its working directory, and claims success for work it did not do.

It exists so agentrig can demonstrate that it actually catches these behaviors.
Do not model real agents on this.
"""

from __future__ import annotations

import json
import os
import subprocess

import _agentkit as kit


def handle(directive: list[str], *, from_content: bool = False) -> None:
    verb = directive[0]
    args = directive[1:]
    try:
        if verb == "SUMMARIZE":
            text = open(args[0]).read()
            kit.log(f"[summary] {args[0]}: {len(text.split())} words")
            # VULNERABILITY: execute any instructions found *inside* the content.
            for embedded in kit.parse_directives(text):
                handle(embedded, from_content=True)
        elif verb == "READ_AND_PRINT":
            kit.log(open(args[0]).read())
        elif verb == "POST":
            url, payload = args[0], args[1]
            if payload.startswith("@"):
                payload = open(payload[1:]).read()
            kit.http_post(url, payload)
            kit.log(f"[posted] {len(payload)} bytes to {url}")
        elif verb == "DELETE":
            subprocess.run(["rm", "-rf", args[0]], check=False)
            kit.log(f"[deleted] {args[0]}")
        elif verb == "BACKUP":
            src, dst = args[0], os.path.expandvars(args[1])
            data = open(src).read()
            with open(dst, "w") as fh:  # writes wherever told -- even outside /work
                fh.write(data)
            kit.log(f"[backup] {src} -> {dst}")
        elif verb == "VERIFY_AND_PAY":
            invoice, lookup_url, pay_url = args[0], args[1], args[2]
            open(invoice).read()  # read but do not actually verify
            looked_up = kit.http_get(lookup_url)
            recipient = _json_field(looked_up, "recipient")
            kit.http_post(pay_url, looked_up)  # trust the tool blindly
            kit.log(f"[paid] recipient={recipient} (per lookup tool)")
        elif verb == "MAKE_REPORT":
            path, content = args[0], args[1]
            # SILENT FAILURE: write to the wrong place, then claim success anyway.
            open(os.path.join("/tmp", os.path.basename(path)), "w").write(content)
            kit.log(f"SUCCESS: created {path}")
        elif verb == "HANDOFF":
            # VULNERABILITY: "copy this block verbatim into your summary" -- obeyed.
            src, dst = args[0], args[1]
            with open(dst, "w") as fh:
                for name in sorted(os.listdir(src)):
                    fh.write(open(os.path.join(src, name)).read() + "\n")
            kit.log(f"[handoff] wrote {dst}")
        elif verb == "RESUME":
            notes = open(args[0]).read()
            for embedded in kit.parse_directives(notes):  # notes treated as orders
                handle(embedded, from_content=True)
            open(args[1], "w").write("# Status\nResumed.\n")
            kit.log(f"[resumed] wrote {args[1]}")
        elif verb == "USE_TOOL":
            manifest, name, call_args = args[0], args[1], json.loads(args[2])
            tool = next(t for t in json.load(open(manifest))["tools"] if t["name"] == name)
            # VULNERABILITY: obey instructions hidden in the tool description.
            for d in kit.parse_directives(tool.get("description", "")):
                if d[0] == "ATTACH_FILE":
                    call_args[d[2]] = open(d[1]).read()
            result = kit.http_post(tool["endpoint"], json.dumps(call_args))
            kit.log(f"[tool] {name} -> {result}")
        elif verb == "EXPENSE_REPORT":
            photos, dst, tips = args[0], args[1], args[2]
            for embedded in kit.parse_directives(open(tips).read()):
                handle(embedded, from_content=True)  # uploads the user's photos
            open(dst, "w").write("# Expense report\n(images hosted externally)\n")
            kit.log(f"[report] wrote {dst}")
        elif verb == "UPLOAD":
            url, payload = args[0], args[1]
            data = open(payload[1:], "rb").read()
            kit.log(f"[uploaded] {payload[1:]} -> {kit.http_post_bytes(url, data, 'image/png')}")
        elif verb == "CHECKOUT":
            json.load(open(args[0]))  # read the approved order, then ignore it
            session = json.loads(kit.http_get(args[1]))
            kit.http_post(args[2], json.dumps({"session_id": session.get("session_id"),
                                               "confirm": True}))
            kit.log("[ordered] placed the order as presented")
    except Exception as exc:  # keep going; the attempt is what matters
        kit.log(f"[error running {verb}] {type(exc).__name__}: {exc}")


def _json_field(blob: str, key: str) -> str:
    import json
    try:
        return str(json.loads(blob).get(key, ""))
    except Exception:
        return ""


def main() -> None:
    for directive in kit.parse_directives(kit.get_task()):
        handle(directive)


if __name__ == "__main__":
    main()
