import hashlib, json, sys, tempfile, unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
from witness_workflow import initialize, Broker, call, save
from witness_pages import consume
from owner_dashboard import render
import release_evidence as release


class Improvements(unittest.TestCase):
    def test_incremental_pages_and_dashboard_stale_state(self):
        with tempfile.TemporaryDirectory(dir=ROOT / "outputs") as d:
            d = Path(d)
            home = d / "home"
            initialize(home)
            b = Broker(home)
            proposal = b.propose("report", 0, "Synthetic public status")
            b.approve(
                proposal["proposal_id"],
                reader=lambda _: "APPROVE " + proposal["content_sha256"][:12],
            )
            result = b.commit(proposal["proposal_id"])
            evidence = Path(result["evidence_directory"])
            root = json.loads((home / "root-public.json").read_text())["public_key"]
            verifier = d / "verifier"
            call(["verifier-init", verifier, root])
            first = consume(
                home / "receiver/state",
                verifier,
                home / "trust-signed.json",
                evidence / "checkpoint.json",
                d / "pages",
            )
            self.assertTrue(first["checkpoint_complete"])
            again = consume(
                home / "receiver/state",
                verifier,
                home / "trust-signed.json",
                evidence / "checkpoint.json",
                d / "refresh",
            )
            self.assertEqual(again["processed"], 1)
            self.assertEqual(render(home, d / "good.html")["Fresh check"], 1)
            package = evidence / "package.json"
            value = json.loads(package.read_text())
            value["requests"][0]["content"] = "<script>bad()</script>"
            package.write_text(json.dumps(value))
            self.assertEqual(render(home, d / "bad.html")["Needs attention"], 1)
            self.assertNotIn("<script>", (d / "bad.html").read_text())

    def test_release_binding_tamper_and_wrong_identity(self):
        with tempfile.TemporaryDirectory(dir=ROOT / "outputs") as d:
            d = Path(d)
            v = d / "validation"
            v.mkdir()
            for name in release.FILES:
                (v / name).write_text("fixture")
            (v / "steps.json").write_text('[{"exit_code":0}]')
            key = d / "key.secret"
            public = call(["keygen", key])["public_key"]
            envelope = d / "signed.json"
            release.sign(v, key, "local-test", envelope)
            source = release.digest(v / "source-manifest.json")
            self.assertEqual(
                release.verify(v, envelope, public, "local-test", source)["status"],
                "local_build_signature_verified",
            )
            for builder, src in [("wrong", source), ("local-test", "00" * 32)]:
                with self.assertRaises(ValueError):
                    release.verify(v, envelope, public, builder, src)
            other = call(["keygen", d / "other.secret"])["public_key"]
            with self.assertRaises(Exception):
                release.verify(v, envelope, other, "local-test", source)
            (v / "openproof").write_text("tampered")
            with self.assertRaises(ValueError):
                release.verify(v, envelope, public, "local-test", source)
            key.chmod(0o644)
            with self.assertRaises(ValueError):
                release.sign(v, key, "local-test", d / "no.json")


if __name__ == "__main__":
    unittest.main()
