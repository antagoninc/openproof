"""The trusted code count and its checks (scripts/tcb_count.py, docs/TCB.md)."""

import sys, tempfile, unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
import tcb_count


class TcbCountTests(unittest.TestCase):
    def test_tree_passes_and_a_lower_budget_fails(self):
        r = tcb_count.report()
        self.assertEqual(tcb_count.problems(r, tcb_count.BUDGET), [])
        found = tcb_count.problems(r, r["total"] - 1)
        self.assertEqual(len(found), 1)
        self.assertIn("over the budget", found[0])

    def test_an_unlisted_file_in_a_trusted_crate_fails(self):
        saved = dict(tcb_count.TRUSTED)
        try:
            del tcb_count.TRUSTED["crates/openproof-receiver/src/files.rs"]
            found = tcb_count.problems(tcb_count.report(), 10**6)
        finally:
            tcb_count.TRUSTED.clear()
            tcb_count.TRUSTED.update(saved)
        # The count then also differs from the totals stated in docs/TCB.md.
        self.assertIn(
            "crates/openproof-receiver/src/files.rs is in a trusted crate but not listed",
            found,
        )
        self.assertTrue(any("docs/TCB.md does not state" in f for f in found), found)

    def test_an_unlisted_file_on_the_review_origin_fails(self):
        saved = dict(tcb_count.TRUSTED)
        try:
            del tcb_count.TRUSTED["app/approval.js"]
            found = tcb_count.problems(tcb_count.report(), 10**6)
        finally:
            tcb_count.TRUSTED.clear()
            tcb_count.TRUSTED.update(saved)
        self.assertIn(
            "the review origin serves or loads app/approval.js, which is not listed",
            found,
        )

    def test_counting_rules(self):
        with tempfile.TemporaryDirectory(dir=ROOT / "outputs") as d:
            rs = Path(d) / "a.rs"
            rs.write_text(
                "fn a() {}\n\n// x\n#[cfg(test)]\nmod tests {\n    fn t() {}\n}\n"
            )
            self.assertEqual(tcb_count.count(str(rs)), 2)
            marked = Path(d) / "b.rs"
            marked.write_text("a\n// TCB:begin\nb\n\nc\n// TCB:end\nd\n")
            self.assertEqual(tcb_count.count(str(marked), regions=True), 2)
            for bad in ["// TCB:begin\nb\n", "b\n// TCB:end\n", "x\n"]:
                marked.write_text(bad)
                with self.assertRaises(ValueError):
                    tcb_count.count(str(marked), regions=True)


if __name__ == "__main__":
    unittest.main()
