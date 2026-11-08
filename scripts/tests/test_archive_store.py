import json, os, shutil, sys, tempfile, unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
from witness_workflow import initialize, call, ref
from owner_app import Owner
from paged_workflow import enable
from portable_history import export_history
from archive_store import seal, check


class ArchiveStore(unittest.TestCase):
    def test_seal_tamper_omission_wrong_pin_and_live_state_preserved(self):
        with tempfile.TemporaryDirectory(dir=ROOT / "outputs") as d:
            d = Path(d)
            h = d / "home"
            initialize(h)
            enable(h)
            o = Owner(h)
            for i in range(3):
                p = o.broker.propose("report", i, "Archive fixture " + str(i))[
                    "proposal_id"
                ]
                r = o.review(p)
                o.approve(p, r["review_token"])
                o.broker.commit(p)
            archive = d / "export"
            export_history(h, archive)
            pin = d / "independent-channel-fixture-pin.json"
            shutil.copyfile(archive / "checkpoint-copy.json", pin)
            root = ref.read(h / "root-public.json")["public_key"]
            go = os.environ.get(
                "OPENPROOF_GO_VERIFY", str(ROOT / "outputs/tooling/openproof-go-verify")
            )
            with self.assertRaises(ValueError):
                seal(
                    archive,
                    root,
                    archive / "checkpoint-copy.json",
                    go,
                    d / "bad-internal-pin",
                )
            result = seal(archive, root, pin, go, d / "stored")
            self.assertEqual(
                check(d / "stored", result["seal_sha256"])["status"],
                "matches_separately_pinned_seal",
            )
            self.assertEqual(call(["head", h / "receiver/state"])["count"], 3)
            victim = d / "stored/entry-000000.json"
            victim.chmod(0o600)
            victim.write_text("tampered")
            with self.assertRaises(ValueError):
                check(d / "stored", result["seal_sha256"])
            victim.unlink()
            with self.assertRaises(ValueError):
                check(d / "stored", result["seal_sha256"])
            value = ref.read(pin)
            value["payload"]["head"] = "00" * 32
            pin.write_text(json.dumps(value))
            with self.assertRaises(ValueError):
                seal(archive, root, pin, go, d / "wrong-pin")
            self.assertFalse((d / "wrong-pin").exists())
            self.assertEqual(call(["head", h / "receiver/state"])["count"], 3)
