"""Regressions for Claude F1/F2/F5; approvals are simulated test responses."""

import contextlib, io, json, sqlite3, subprocess, sys, tempfile, unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
from witness_workflow import Broker, initialize, call, gate_list


class Fixes(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=ROOT / "outputs")
        self.h = Path(self.tmp.name) / "roles"
        initialize(self.h)
        self.b = Broker(self.h)

    def tearDown(self):
        self.tmp.cleanup()

    def approved(self, doc="test", content="hello"):
        p = self.b.propose(doc, 0, content)
        with contextlib.redirect_stdout(io.StringIO()):
            self.b.approve(
                p["proposal_id"], reader=lambda _: "APPROVE " + p["content_sha256"][:12]
            )
        return p["proposal_id"]

    def test_flood_reclaims_only_unsigned_pending(self):
        identity = self.approved()
        first = self.b.propose("pending", 0, "x")["proposal_id"]
        for _ in range(1001):
            self.b.propose("pending", 0, "x")
        listing = gate_list(self.h)
        pending = [p["id"] for p in listing["proposals"]]
        self.assertEqual(len(pending), 1000)
        self.assertNotIn(first, pending)
        self.assertEqual([a["id"] for a in listing["approved"]], [identity])
        self.assertEqual(self.b.commit(identity)["document_version"], 1)

    def test_outage_reports_committed_and_catches_up_without_receive(self):
        a = self.approved("a")
        b = self.approved("b")
        # A witness that cannot use its key is a witness outage.
        key = self.h / "witness/key.secret"
        key.chmod(0o644)
        try:
            r = self.b.commit(a)
        finally:
            key.chmod(0o600)
        self.assertEqual(r["status"], "committed_unwitnessed")
        self.assertEqual(r["execution_status"], "committed")
        self.assertEqual(
            call(["document", self.h / "receiver/state", "a"])["version"], 1
        )
        # Later commits recover all earlier receipts in order.
        self.assertEqual(
            self.b.commit(b)["verification_status"], "local_consistency_verified"
        )
        # Recovering an earlier commit never dispatches it again.
        r = self.b.commit(a)
        self.assertEqual(call(["head", self.h / "receiver/state"])["count"], 2)
        self.assertEqual(r["verification_status"], "local_consistency_verified")
        self.assertFalse(r["independent_operators"])

    def test_lost_receiver_reply_recovers_exact_once(self):
        identity = self.approved()
        real = call

        def lost(args, value=None):
            result = real(args, value)
            if args[0] == "receive":
                raise TimeoutError("lost response after commit")
            return result

        with patch("witness_workflow.call", side_effect=lost):
            r = self.b.commit(identity)
        self.assertEqual(r["verification_status"], "local_consistency_verified")
        self.assertEqual(r["document_version"], 1)

    def test_post_witness_export_failure_is_explicit(self):
        identity = self.approved()
        # The receiver commits, then evidence storage is full.
        call(
            [
                "receive",
                self.h / "receiver/state",
                self.h / "receiver/key.secret",
                self.h / "trust.json",
            ],
            self.b.request(identity),
        )
        filler = [self.h / "evidence" / f"filler-{i}" for i in range(1000)]
        for f in filler:
            f.mkdir()
        r = self.b.commit(identity)
        for f in filler:
            f.rmdir()
        self.assertEqual(r["status"], "witnessed_evidence_failed")
        self.assertEqual(r["execution_status"], "committed")
        self.assertEqual(
            self.b.commit(identity)["verification_status"], "local_consistency_verified"
        )

    def test_real_process_concurrent_commits_and_unicode_archive(self):
        ids = [self.approved(str(i), 'é\\\n"' * 200) for i in range(4)]
        processes = [
            subprocess.Popen(
                [
                    sys.executable,
                    str(ROOT / "scripts/witness_workflow.py"),
                    "commit",
                    str(self.h),
                    i,
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            for i in ids
        ]
        for proc in processes:
            stdout, stderr = proc.communicate(timeout=60)
            self.assertEqual(proc.returncode, 0, stderr)
            r = json.loads(stdout)
            self.assertEqual(r["verification_status"], "local_consistency_verified")
            run = Path(r["evidence_directory"])
            p = json.loads((run / "package.json").read_text())
            self.assertEqual(
                call(["verify", self.h / "trust.json", run / "checkpoint.json"], p)[
                    "status"
                ],
                "receiver_confirmed_and_witnessed",
            )
        self.assertEqual(call(["head", self.h / "receiver/state"])["count"], 4)

    def test_open_owner_review_does_not_block_commit_and_change_is_refused(self):
        prior = self.approved("prior")
        p = self.b.propose("review", 0, "reviewed bytes")

        def reader(_):
            # An already-approved operation can finish while this review is open.
            self.assertEqual(
                self.b.commit(prior)["verification_status"],
                "local_consistency_verified",
            )
            # A change to the stored proposal after review is refused by the gate.
            changed = dict(document="review", expected_version=0, content="changed")
            db = sqlite3.connect(self.h / "authority/gate/gate.db")
            db.execute(
                "UPDATE proposals SET proposal=? WHERE id=?",
                (json.dumps(changed), p["proposal_id"]),
            )
            db.commit()
            db.close()
            return "APPROVE " + p["content_sha256"][:12]

        with contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaisesRegex(RuntimeError, "does not match"):
                self.b.approve(p["proposal_id"], reader=reader)
        with self.assertRaises(FileNotFoundError):
            self.b.commit(p["proposal_id"])
        with self.assertRaises(RuntimeError):
            call(["document", self.h / "receiver/state", "review"])

    def test_failed_admission_is_not_committed(self):
        identity = self.approved()
        other = self.approved()
        self.assertEqual(self.b.commit(identity)["execution_status"], "committed")
        r = self.b.commit(other)
        self.assertEqual(r["status"], "not_committed")
        self.assertEqual(call(["head", self.h / "receiver/state"])["count"], 1)


if __name__ == "__main__":
    unittest.main()
