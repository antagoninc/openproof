"""The OpenProof approval-outcome example set for TRACE, re-checked from the
committed bytes, plus one failure for each verifier step."""

import copy, json, sys, unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "integrations/trace"))
import openproof_trace as ot

EXAMPLES = ROOT / "integrations/trace/examples"


def load(name):
    return json.loads((EXAMPLES / name).read_text())


class TraceBridge(unittest.TestCase):
    def setUp(self):
        self.expected = load("expected.json")
        self.root = self.expected["openproof_root_public_key"]
        self.store = load("openproof-approvals.json")
        self.record = load("01-approval-executed.json")

    def test_every_committed_case_recomputes(self):
        names = sorted(p.name for p in EXAMPLES.glob("0*.json"))
        self.assertEqual(names, sorted(self.expected["cases"]))
        for name, case in self.expected["cases"].items():
            got = ot.check(load(name), load(case["store"]), self.root)
            self.assertEqual(got, {k: v for k, v in case.items() if k != "store"}, name)
            # Rule 3 of TRACE section 3.1.2: every record verifies on its own.
            self.assertTrue(got["trace_record_verifies"], name)

    def test_each_step_fails_on_its_own_defect(self):
        def verdict(record=None, store=None, root=None):
            return ot.check(
                record or self.record, store or self.store, root or self.root
            )["verdict"]

        record = copy.deepcopy(self.record)
        record["subject"] += "-changed"
        self.assertFalse(
            ot.check(record, self.store, self.root)["trace_record_verifies"]
        )
        entry_id = self.record["references"][0]["id"]
        store = copy.deepcopy(self.store)
        store["entries"][entry_id]["receipt"]["payload"]["document_version"] += 1
        self.assertEqual(verdict(store=store), "execution-contradicted")
        store = copy.deepcopy(self.store)
        store["entries"][entry_id]["checkpoint"] = None
        self.assertEqual(verdict(store=store), "executed-unwitnessed")
        store = copy.deepcopy(self.store)
        store["entries"][entry_id]["request"]["owner_assertion"]["signature"] = store[
            "entries"
        ][entry_id]["request"]["owner_assertion"]["signature"][::-1]
        # The digest covers the assertion, so a changed one contradicts the record.
        self.assertEqual(verdict(store=store), "approval-contradicted")
        self.assertEqual(verdict(root="00" * 32), "trust-unverified")
        record = copy.deepcopy(self.record)
        record["references"] = []
        self.assertEqual(verdict(record=record), "no-approval-reference")

    def test_reference_digest_is_rfc8785_over_the_request(self):
        entry_id = self.record["references"][0]["id"]
        request = self.store["entries"][entry_id]["request"]
        self.assertEqual(
            ot.reference(request, self.store["resolver"]), self.record["references"][0]
        )


if __name__ == "__main__":
    unittest.main()
