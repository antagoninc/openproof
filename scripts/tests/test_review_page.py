"""The review page's own approval check (app/approval.js), run in Node.

The page computes the passkey challenge from an approval it has compared with
what it shows. These tests pin its digest to the Rust one (the same vector is
asserted in crates/openproof-witness/src/gate_tests.rs) and check that every
single difference between the approval and the shown change is refused.
"""

import json, os, shutil, subprocess, unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
VECTOR = json.loads((ROOT / "scripts/tests/approval_vector.json").read_text())
DIGEST = "65b0894aab66bc7074fe773218831975386c4b7234177650f492f06529c9218e"
# Inside the vector's validity window.
NOW = VECTOR["not_before"] + 10
SHOWN = {
    "document": "project-status",
    "expected_version": 7,
    "content": "Exact text, café ✓\n",
}

SCRIPT = """
import { checkedDigest, signingBytes, sha256, hex } from %s;
const cases = JSON.parse(process.argv[1]);
const out = [];
for (const c of cases) {
  try {
    const d = await checkedDigest(c.approval, c.shown, c.server, c.now);
    out.push({ ok: true, digest: hex(d), plain: hex(await sha256(signingBytes(c.approval))) });
  } catch (e) {
    out.push({ ok: false, error: e.message });
  }
}
console.log(JSON.stringify(out));
"""


def node():
    found = shutil.which("node")
    if not found and os.environ.get("CI"):
        raise AssertionError("Node is required in CI for the review page tests")
    return found


@unittest.skipUnless(node(), "needs Node")
class ReviewPageTests(unittest.TestCase):
    def run_cases(self, cases):
        module = json.dumps((ROOT / "app/approval.js").as_uri())
        r = subprocess.run(
            [node(), "--input-type=module", "-e", SCRIPT % module, json.dumps(cases)],
            capture_output=True,
            text=True,
            timeout=60,
        )
        self.assertEqual(r.returncode, 0, r.stderr)
        return json.loads(r.stdout)

    def case(self, approval=None, shown=None, server=DIGEST, now=NOW):
        return {
            "approval": VECTOR if approval is None else approval,
            "shown": SHOWN if shown is None else shown,
            "server": server,
            "now": now,
        }

    def test_digest_matches_rust(self):
        [r] = self.run_cases([self.case()])
        self.assertEqual(r, {"ok": True, "digest": DIGEST, "plain": DIGEST})

    def test_every_single_difference_is_refused(self):
        def changed(**fields):
            a = dict(VECTOR)
            a.update(fields)
            return a

        shown_wrong = [
            dict(SHOWN, content=SHOWN["content"] + " "),
            dict(SHOWN, content=SHOWN["content"].replace("é", "e")),
            dict(SHOWN, document="project-statu"),
            dict(SHOWN, expected_version=8),
        ]
        extra = dict(VECTOR, owner="x")
        missing = {k: v for k, v in VECTOR.items() if k != "nonce"}
        approvals_wrong = [
            changed(version="openproof-witness/2"),
            changed(document="other"),
            changed(expected_version=6),
            changed(content_sha256="00" * 32),
            changed(expires_at=VECTOR["not_before"] + 601),
            changed(not_before=VECTOR["expires_at"] + 1),
            changed(nonce="AB" * 32),
            changed(receiver="zz" * 32),
            changed(expected_version="7"),
            changed(expected_version=2**53),
            changed(expected_version=-1),
            extra,
            missing,
        ]
        cases = [self.case(shown=s) for s in shown_wrong]
        cases += [self.case(approval=a) for a in approvals_wrong if a is not None]
        cases.append({"approval": None, "shown": SHOWN, "server": DIGEST, "now": NOW})
        # An approval that starts later, or has already ended, is refused.
        cases.append(self.case(now=VECTOR["not_before"] - 61))
        cases.append(self.case(now=VECTOR["expires_at"] + 1))
        cases.append(self.case(server="00" * 32))
        cases.append(self.case(server=DIGEST.upper()))
        results = self.run_cases(cases)
        self.assertEqual(len(results), len(cases))
        for c, r in zip(cases, results):
            self.assertFalse(r["ok"], c)
            self.assertTrue(r["error"].startswith("The approval"), (c, r))
        # The control: the unchanged case passes in the same run.
        self.assertTrue(self.run_cases([self.case()])[0]["ok"])

    def test_pages_load_no_dashboard_code(self):
        """The trusted pages import only the shared modules."""
        import re

        for page, script in [("review", "review.js"), ("setup", "setup.js")]:
            html = (ROOT / "app" / f"{page}.html").read_text()
            self.assertEqual(
                re.findall(r'<script[^>]*src="([^"]+)"', html), ["/" + script]
            )
            self.assertEqual(
                re.findall(r'<link[^>]*href="([^"]+)"', html), ["/base.css"]
            )
            self.assertNotIn("app.js", html)
            js = (ROOT / "app" / script).read_text()
            imports = set(re.findall(r'from "\./([a-z]+\.js)"', js))
            self.assertLessEqual(imports, {"common.js", "approval.js"})
            self.assertNotIn("innerHTML", js)


if __name__ == "__main__":
    unittest.main()
