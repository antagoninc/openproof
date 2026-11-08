import os
import hashlib, json, subprocess, sys, tempfile, time, unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
from witness_workflow import initialize, call, ref
from paged_workflow import enable
from owner_app import Owner
from owner_rotation import prepare, resume
from portable_history import export_history


class Adversarial(unittest.TestCase):
    def test_process_exit_during_handover_preserves_pause_and_can_resume(self):
        with tempfile.TemporaryDirectory(dir=ROOT / "outputs") as d:
            h = Path(d) / "home"
            initialize(h)
            enable(h)
            o = Owner(h)
            p = o.broker.propose("report", 0, "before crash")["proposal_id"]
            r = o.review(p)
            o.approve(p, r["review_token"])
            o.broker.commit(p)
            prepare(h)
            program = """import os,sys
sys.path.insert(0,sys.argv[1]);import owner_rotation
real=owner_rotation.call
def crash(args,value=None):
 result=real(args,value)
 if args[0]=='rotate-state' and 'receiver/state' in str(args):os._exit(73)
 return result
owner_rotation.call=crash
owner_rotation.resume(sys.argv[2])
"""
            child = subprocess.run(
                [sys.executable, "-c", program, str(ROOT / "scripts"), str(h)],
                capture_output=True,
            )
            self.assertEqual(child.returncode, 73, child.stderr)
            self.assertTrue((h / "rotation-pending.json").exists())
            self.assertTrue(resume(h)["completed"])
            self.assertEqual(o.broker.commit(p)["document_version"], 1)

    def test_corrupt_state_does_not_claim_success(self):
        with tempfile.TemporaryDirectory(dir=ROOT / "outputs") as d:
            h = Path(d) / "home"
            initialize(h)
            enable(h)
            o = Owner(h)
            p = o.broker.propose("report", 0, "database corruption fixture")[
                "proposal_id"
            ]
            r = o.review(p)
            o.approve(p, r["review_token"])
            db = h / "receiver/state/state.db"
            db.write_bytes(b"not a database")
            with self.assertRaises(RuntimeError):
                o.broker.commit(p)
            self.assertEqual(call(["head", h / "witness/state"])["count"], 0)

    def test_multi_page_archive_omission_reorder_wrong_pin_and_io_failure(self):
        with tempfile.TemporaryDirectory(dir=ROOT / "outputs") as d:
            h = Path(d) / "home"
            initialize(h)
            enable(h)
            o = Owner(h)
            for i in range(35):
                p = o.broker.propose("report", i, "fixture " + str(i))["proposal_id"]
                r = o.review(p)
                o.approve(p, r["review_token"])
                result = o.broker.commit(p)
                self.assertEqual(
                    result["verification_status"], "local_consistency_verified"
                )
            archive = Path(d) / "archive"
            export_history(h, archive)
            manifest = ref.read(archive / "manifest.json")
            self.assertGreaterEqual(len(manifest["entries"]), 3)
            cmd = [
                os.environ.get(
                    "OPENPROOF_GO_VERIFY",
                    str(ROOT / "outputs/v0.9/openproof-go-verify"),
                ),
                "verify-archive",
                ref.read(h / "root-public.json")["public_key"],
                str(archive / "checkpoint-copy.json"),
                str(archive),
                str(int(time.time())),
            ]
            self.assertEqual(subprocess.run(cmd, capture_output=True).returncode, 0)
            for entries in [
                manifest["entries"][1:],
                list(reversed(manifest["entries"])),
            ]:
                (archive / "manifest.json").write_text(
                    json.dumps(dict(manifest, entries=entries))
                )
                self.assertNotEqual(
                    subprocess.run(cmd, capture_output=True).returncode, 0
                )
            (archive / "manifest.json").write_text(json.dumps(manifest))
            pin = ref.read(archive / "checkpoint-copy.json")
            pin["payload"]["head"] = "00" * 32
            (archive / "checkpoint-copy.json").write_text(json.dumps(pin))
            self.assertNotEqual(subprocess.run(cmd, capture_output=True).returncode, 0)
            # Evidence storage failure follows a durable commit. Retrying recovers it.
            p = o.broker.propose("report", 35, "disk failure fixture")["proposal_id"]
            r = o.review(p)
            o.approve(p, r["review_token"])
            with patch("paged_workflow.save", side_effect=OSError("simulated ENOSPC")):
                result = o.broker.commit(p)
            self.assertEqual(result["execution_status"], "committed")
            self.assertEqual(result["verification_status"], "not_verified")
            self.assertEqual(o.broker.commit(p)["document_version"], 36)
