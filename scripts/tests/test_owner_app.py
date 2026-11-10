"""The Rust owner app over HTTP, as the browser uses it."""

import os
import hashlib, json, sqlite3, subprocess, sys, tempfile, time, unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
from witness_workflow import initialize, call, ref
from paged_workflow import enable
from portable_history import export_history
from owner_client import OwnerClient


class OwnerAppTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=ROOT / "outputs")
        self.h = Path(self.temp.name) / "home"
        initialize(self.h)
        enable(self.h)
        self.o = OwnerClient(self.h)

    def tearDown(self):
        self.o.close()
        self.temp.cleanup()

    def proposed(self, document="report", version=0):
        return self.o.broker.propose(
            document, version, "<script>untrusted text</script>"
        )["proposal_id"]

    def approved(self, document="report", version=0):
        identity = self.proposed(document, version)
        self.o.approve(identity, self.o.review(identity)["review_token"])
        return identity

    def test_review_binds_all_fields_and_is_one_use(self):
        identity = self.proposed()
        review = self.o.review(identity)
        db = sqlite3.connect(self.h / "authority/gate/gate.db")
        (raw,) = db.execute(
            "SELECT proposal FROM proposals WHERE id=?", (identity,)
        ).fetchone()
        data = json.loads(raw)
        data["document"] = "other"
        db.execute(
            "UPDATE proposals SET proposal=? WHERE id=?", (json.dumps(data), identity)
        )
        db.commit()
        db.close()
        # The gate refuses a stored proposal that no longer matches its id.
        with self.assertRaises(ValueError):
            self.o.approve(identity, review["review_token"])
        # The review token was used up by the refused attempt.
        with self.assertRaisesRegex(ValueError, "no longer valid"):
            self.o.approve(identity, review["review_token"])
        self.assertEqual(call(["head", self.h / "receiver/state"])["count"], 0)

    def test_expired_trust_is_named_and_renewed_from_the_workspace(self):
        from witness_workflow import install_trust

        identity = self.proposed()
        self.assertFalse(self.o.status()["trust"]["expired"])
        # A new trust epoch that expires in two seconds.
        t = ref.read(self.h / "trust.json")
        t["epoch"] += 1
        t["expires_at"] = int(time.time()) + 2
        short = self.h.parent / "short-trust.json"
        short.write_text(json.dumps(t))
        install_trust(self.h, short)
        time.sleep(3)
        status = self.o.status()["trust"]
        self.assertEqual(
            (status["expired"], status["expires_at"]), (True, t["expires_at"])
        )
        # Review and execution say why they are refused.
        for route in ["review", "commit"]:
            code, data = self.o.post(route, {"id": identity})
            self.assertEqual(code, 409)
            self.assertIn("trust configuration expired", data["error"])
        # Renewal is a workspace request; the review origin does not serve it.
        code, _, _ = self.o.request(
            "POST",
            "/api/renew",
            "{}",
            {"Origin": self.o.review_origin, "Content-Type": "application/json"},
            origin=self.o.review_origin,
        )
        self.assertEqual(code, 404)
        code, data = self.o.post("renew", {})
        self.assertEqual((code, data["installed_epoch"]), (200, t["epoch"] + 1))
        self.assertFalse(self.o.status()["trust"]["expired"])
        self.o.approve(identity, self.o.review(identity)["review_token"])
        result = self.o.commit(identity)
        self.assertEqual(result["verification_status"], "local_consistency_verified")

    def test_witness_outage_recovery_and_portable_history(self):
        identity = self.approved()
        key = self.h / "witness/key.secret"
        key.chmod(0o644)
        try:
            first = self.o.commit(identity)
        finally:
            key.chmod(0o600)
        self.assertEqual(first["status"], "committed_unwitnessed")
        recovered = self.o.call("recover", {"id": identity})
        self.assertEqual(recovered["verification_status"], "local_consistency_verified")
        self.assertNotIn("evidence_directory", recovered)
        self.assertEqual(self.o.commit(identity)["document_version"], 1)
        stages = {i["id"]: i["stage"] for i in self.o.status()["items"]}
        self.assertEqual(stages[identity], "Verified locally")
        archive = Path(self.temp.name) / "archive"
        export_history(self.h, archive)
        root = ref.read(self.h / "root-public.json")["public_key"]
        cmd = [
            os.environ.get(
                "OPENPROOF_GO_VERIFY", str(ROOT / "outputs/v0.9/openproof-go-verify")
            ),
            "verify-archive",
            root,
            str(archive / "checkpoint-copy.json"),
            str(archive),
            str(int(time.time())),
        ]
        r = subprocess.run(cmd, capture_output=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        manifest = ref.read(archive / "manifest.json")
        f = archive / manifest["entries"][0]["file"]
        raw = ref.read(f)
        raw["page"]["requests"][0]["content"] = "changed"
        f.write_text(json.dumps(raw))
        manifest["entries"][0]["sha256"] = hashlib.sha256(f.read_bytes()).hexdigest()
        (archive / "manifest.json").write_text(json.dumps(manifest))
        self.assertNotEqual(subprocess.run(cmd, capture_output=True).returncode, 0)

    def test_archive_download_is_a_valid_zip(self):
        import io, zipfile

        identity = self.approved()
        self.o.commit(identity)
        r = self.o.call("archive", {})
        status, headers, data = self.o.request(
            "GET", r["download"], headers={"Cookie": "openproof_owner=" + self.o.token}
        )
        self.assertEqual(status, 200)
        names = zipfile.ZipFile(io.BytesIO(data)).namelist()
        self.assertIn("manifest.json", names)
        self.assertIn("checkpoint-copy.json", names)
        self.assertFalse(r["trust_root_included"])

    def test_http_rejects_foreign_origin_missing_cookie_csrf_and_bad_host(self):
        o = self.o
        value = {"document": "report", "expected_version": 0, "content": "hello"}
        self.assertEqual(
            o.post(
                "session",
                {"token": o.token},
                {"Origin": "https://attacker.example"},
                auth=False,
            )[0],
            403,
        )
        self.assertEqual(
            o.post(
                "session", {"token": o.token}, {"Host": "attacker.example"}, auth=False
            )[0],
            403,
        )
        self.assertEqual(o.post("session", {"token": "wrong"}, auth=False)[0], 403)
        self.assertEqual(o.post("propose", value, auth=False)[0], 403)
        self.assertEqual(
            o.post(
                "propose", value, {"Cookie": "openproof_owner=" + o.token}, auth=False
            )[0],
            403,
        )
        self.assertEqual(
            o.post("propose", value, {"X-OpenProof-CSRF": "0" * 64})[0], 403
        )
        # Duplicate keys and floats are refused before any route runs.
        status, _, _ = o.request(
            "POST",
            "/api/propose",
            '{"document":"a","document":"b","expected_version":0,"content":"x"}',
            {
                "Origin": o.origin,
                "Content-Type": "application/json",
                "Cookie": "openproof_owner=" + o.token,
                "X-OpenProof-CSRF": o.csrf,
            },
        )
        self.assertEqual(status, 409)
        self.assertEqual(o.post("propose", value)[0], 200)
        status, headers, _ = o.request("GET", "/")
        headers = dict(headers)
        self.assertEqual(status, 200)
        self.assertIn("frame-ancestors 'none'", headers["Content-Security-Policy"])
        self.assertEqual(o.request("GET", "/api/status")[0], 401)

    def test_owner_form_refuses_a_stale_version(self):
        self.assertEqual(self.o.current_version("report"), 0)
        identity = self.approved()
        self.o.commit(identity)
        self.assertEqual(self.o.current_version("report"), 1)
        status, data = self.o.post(
            "propose", {"document": "report", "expected_version": 0, "content": "old"}
        )
        self.assertEqual(status, 409)
        self.assertIn("report is at version 1", data["error"])
        self.assertTrue(self.o.propose("report", 1, "new")["proposal_id"])
        self.assertTrue(self.o.propose("fresh-doc", 0, "new")["proposal_id"])

    def test_review_shows_the_current_text_without_binding_it(self):
        identity = self.proposed()
        review = self.o.review(identity)
        # A new document: there is no current text.
        self.assertEqual(review["current"], {"version": 0, "content": None})
        self.o.approve(identity, review["review_token"])
        self.o.commit(identity)
        second = self.o.propose("report", 1, "second text")["proposal_id"]
        review = self.o.review(second)
        self.assertEqual(
            review["current"],
            {"version": 1, "content": "<script>untrusted text</script>"},
        )
        self.assertEqual(review["proposal"]["content"], "second text")
        # The approval still binds only the proposal.
        self.o.approve(second, review["review_token"])
        self.assertEqual(
            self.o.commit(second)["verification_status"], "local_consistency_verified"
        )


if __name__ == "__main__":
    unittest.main()
