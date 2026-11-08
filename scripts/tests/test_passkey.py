import os
import contextlib, hashlib, http.client, io, json, subprocess, sys, tempfile, threading, time, unittest
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
from owner_app import Owner, Server, b64encode, b64decode, approval_digest
from witness_workflow import initialize, call, ref, renew
from paged_workflow import enable
from portable_history import export_history

ORIGIN = "http://localhost:8765"
GO = os.environ.get(
    "OPENPROOF_GO_VERIFY", str(ROOT / "outputs/v0.9/openproof-go-verify")
)


class SoftAuthenticator:
    """A software stand-in for a platform passkey, for tests only."""

    def __init__(self, rp_id="localhost", flags=0x05):
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.rp_id = rp_id
        self.flags = flags

    def auth_data(self):
        rp = hashlib.sha256(self.rp_id.encode()).digest()
        return rp + bytes([self.flags]) + b"\0\0\0\0"

    def client(self, kind, challenge, origin=ORIGIN, extra=None):
        data = dict(type=kind, challenge=challenge, origin=origin)
        data.update(extra or {})
        return json.dumps(data, separators=(",", ":")).encode()

    def register(self, begin, origin=ORIGIN, kind="webauthn.create"):
        spki = self.key.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return dict(
            credential_id=b64encode(b"credential-1"),
            client_data_json=b64encode(self.client(kind, begin["challenge"], origin)),
            authenticator_data=b64encode(self.auth_data()),
            public_key=b64encode(spki),
            algorithm=-7,
        )

    def assert_(self, challenge, origin=ORIGIN, kind="webauthn.get", extra=None):
        client = self.client(kind, challenge, origin, extra)
        auth = self.auth_data()
        signed = auth + hashlib.sha256(client).digest()
        signature = self.key.sign(signed, ec.ECDSA(hashes.SHA256()))
        return dict(
            authenticator_data=b64encode(auth),
            client_data_json=b64encode(client),
            signature=b64encode(signature),
        )


class PasskeyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=ROOT / "outputs")
        self.h = Path(self.temp.name) / "home"
        initialize(self.h)
        enable(self.h)
        self.o = Owner(self.h)
        self.o.origin = ORIGIN
        self.device = SoftAuthenticator()

    def tearDown(self):
        self.temp.cleanup()

    def register(self):
        return self.o.register_finish(self.device.register(self.o.register_begin()))

    def approve(self, content="passkey approved text", version=0):
        identity = self.o.broker.propose("report", version, content)["proposal_id"]
        review = self.o.review(identity)
        return identity, self.o.approve(identity, review["review_token"])

    def go_verify(self):
        archive = Path(self.temp.name) / ("archive-" + str(time.time_ns()))
        export_history(self.h, archive)
        root = ref.read(self.h / "root-public.json")["public_key"]
        cmd = [
            GO,
            "verify-archive",
            root,
            str(archive / "checkpoint-copy.json"),
            str(archive),
            str(int(time.time())),
        ]
        return archive, cmd, subprocess.run(cmd, capture_output=True)

    def test_base64url_is_strict(self):
        self.assertEqual(b64decode(b64encode(b"\xff\xfe"), 2), b"\xff\xfe")
        for bad in ["", "a", "ab==", "a+b/", "_x", "ab c"]:
            with self.assertRaises(ValueError):
                b64decode(bad, 64)
        with self.assertRaises(ValueError):
            b64decode(b64encode(b"x" * 3), 2)

    def test_registration_challenge_checks_and_new_trust_epoch(self):
        epoch = ref.read(self.h / "trust.json")["epoch"]
        begin = self.o.register_begin()
        self.assertEqual(begin["rp_id"], "localhost")
        self.assertEqual(len(b64decode(begin["challenge"], 32)), 32)
        bad = [
            self.device.register(dict(challenge=b64encode(b"\0" * 32))),
            self.device.register(begin, kind="webauthn.get"),
            self.device.register(begin, origin="http://127.0.0.1:8765"),
            SoftAuthenticator(flags=0x01).register(begin),
            SoftAuthenticator(rp_id="example.com").register(begin),
            dict(self.device.register(begin), algorithm=-257),
        ]
        for value in bad:
            self.o.registration = dict(
                challenge=begin["challenge"], time=time.monotonic()
            )
            with self.assertRaises(ValueError):
                self.o.register_finish(value)
        self.assertNotIn("owner_passkey", ref.read(self.h / "trust.json"))
        with self.assertRaises(ValueError):
            self.o.register_finish(self.device.register(begin))
        result = self.register()
        trust = ref.read(self.h / "trust.json")
        self.assertEqual(result["installed_epoch"], epoch + 1)
        self.assertEqual(trust["epoch"], epoch + 1)
        point = self.device.key.public_key().public_bytes(
            serialization.Encoding.X962,
            serialization.PublicFormat.UncompressedPoint,
        )
        self.assertEqual(
            trust["owner_passkey"],
            dict(
                public_key=point.hex(),
                rp_id="localhost",
                origin=ORIGIN,
                from_sequence=1,
            ),
        )
        self.assertEqual(ref.read(self.h / "trust-signed.json")["payload"], trust)
        for state in ["receiver/state", "witness/state", "verifier"]:
            self.assertEqual(
                call(["trust-floor", self.h / state])["epoch"], epoch + 1, state
            )
        self.assertTrue(self.o.status()["passkey"]["configured"])
        with self.assertRaises(ValueError):
            self.o.register_begin()
        renewed = renew(self.h)
        self.assertEqual(renewed["installed_epoch"], epoch + 2)
        self.assertEqual(
            ref.read(self.h / "trust.json")["owner_passkey"], trust["owner_passkey"]
        )
        stripped = dict(ref.read(self.h / "trust.json"), epoch=epoch + 3)
        del stripped["owner_passkey"]
        path = Path(self.temp.name) / "stripped.json"
        path.write_text(json.dumps(stripped))
        from witness_workflow import install_trust

        with self.assertRaises(ValueError):
            install_trust(self.h, path)
        # A stolen root key alone cannot drop the passkey from installed states.
        signed = call(["sign-trust-untracked", self.h / "root/key.secret"], stripped)
        root = ref.read(self.h / "root-public.json")["public_key"]
        with self.assertRaises(RuntimeError):
            call(["install-signed", self.h / "receiver/state", root], signed)
        with self.assertRaises(RuntimeError):
            call(["verifier-install", self.h / "verifier"], signed)

    def test_approval_with_assertion_executes_and_verifies(self):
        self.register()
        identity, challenge = self.approve()
        self.assertEqual(challenge["status"], "passkey_required")
        self.assertEqual(challenge["credential_id"], b64encode(b"credential-1"))
        self.assertTrue(self.o.broker.file("proposals", identity).exists())
        self.assertFalse(self.o.broker.file("approved", identity).exists())
        assertion = self.device.assert_(challenge["challenge"])
        result = self.o.approve_passkey(
            identity, challenge["assertion_token"], assertion
        )
        self.assertEqual(result, {"status": "approved", "id": identity})
        stored = ref.read(self.o.broker.file("approved", identity))
        self.assertEqual(stored["owner_assertion"], assertion)
        self.assertEqual(
            b64encode(bytes.fromhex(approval_digest(stored))), challenge["challenge"]
        )
        committed = self.o.broker.commit(identity)
        self.assertEqual(
            committed["verification_status"], "local_consistency_verified", committed
        )
        self.assertEqual(committed["document_version"], 1)
        _, _, r = self.go_verify()
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_missing_or_invalid_assertion_cannot_execute(self):
        self.register()
        identity, challenge = self.approve()
        token = challenge["assertion_token"]
        with self.assertRaises(ValueError):
            self.o.approve_passkey(identity, "0" * 64, {})
        bad = [
            self.device.assert_(b64encode(b"\0" * 32)),
            self.device.assert_(challenge["challenge"], origin="http://localhost:1"),
            self.device.assert_(challenge["challenge"], kind="webauthn.create"),
            self.device.assert_(challenge["challenge"], extra={"crossOrigin": True}),
            SoftAuthenticator().assert_(challenge["challenge"]),
            SoftAuthenticator(flags=0x01).assert_(challenge["challenge"]),
        ]
        pending = dict(self.o.assertions[token])
        for assertion in bad:
            # Each rejected attempt consumes the pending approval; restore it.
            self.o.assertions[token] = dict(pending, time=time.monotonic())
            with self.assertRaises((ValueError, RuntimeError)):
                self.o.approve_passkey(identity, token, assertion)
            self.assertFalse(self.o.broker.file("approved", identity).exists())
        # A process that can read the authority key signs a request without a passkey.
        proposal = ref.read(self.o.broker.file("proposals", identity))
        forged = call(
            ["approve", self.h / "authority/key.secret", self.h / "trust.json"],
            proposal,
        )
        ref_path = self.o.broker.file("approved", identity)
        ref_path.write_text(json.dumps(forged))
        result = self.o.broker.commit(identity)
        self.assertEqual(result["execution_status"], "not_committed", result)
        self.assertEqual(result["error_code"], "admission_failed")
        # An assertion copied from a different approval does not match this digest.
        other, other_challenge = self.approve("other text", 0)
        copied = dict(
            forged, owner_assertion=self.device.assert_(other_challenge["challenge"])
        )
        ref_path.write_text(json.dumps(copied))
        self.assertEqual(
            self.o.broker.commit(identity)["execution_status"], "not_committed"
        )
        self.assertEqual(call(["head", self.h / "receiver/state"])["count"], 0)
        with self.assertRaises(RuntimeError):
            # The terminal approval path refuses once a passkey is installed.
            with contextlib.redirect_stdout(io.StringIO()):
                self.o.broker.approve(other, reader=lambda prompt: prompt[5:-2])

    def test_without_passkey_flow_is_unchanged_and_assertion_rejected(self):
        identity, result = self.approve()
        self.assertEqual(result, {"status": "approved", "id": identity})
        stored = ref.read(self.o.broker.file("approved", identity))
        self.assertNotIn("owner_assertion", stored)
        challenge = b64encode(bytes.fromhex(approval_digest(stored)))
        with_assertion = dict(stored, owner_assertion=self.device.assert_(challenge))
        with self.assertRaises(RuntimeError):
            call(["check-assertion", self.h / "trust.json"], with_assertion)
        self.o.broker.file("approved", identity).write_text(json.dumps(with_assertion))
        self.assertEqual(
            self.o.broker.commit(identity)["execution_status"], "not_committed"
        )
        self.o.broker.file("approved", identity).write_text(json.dumps(stored))
        self.assertEqual(self.o.broker.commit(identity)["document_version"], 1)

    def test_history_before_enrollment_still_verifies(self):
        identity, _ = self.approve("before passkey")
        self.o.broker.commit(identity)
        self.register()
        self.assertEqual(
            ref.read(self.h / "trust.json")["owner_passkey"]["from_sequence"], 2
        )
        identity, challenge = self.approve("after passkey", 1)
        self.o.approve_passkey(
            identity,
            challenge["assertion_token"],
            self.device.assert_(challenge["challenge"]),
        )
        result = self.o.broker.commit(identity)
        self.assertEqual(result["verification_status"], "local_consistency_verified")
        archive, cmd, r = self.go_verify()
        self.assertEqual(r.returncode, 0, r.stderr)
        manifest = ref.read(archive / "manifest.json")
        for entry in manifest["entries"]:
            f = archive / entry["file"]
            value = ref.read(f)
            requests = value["page"]["requests"]
            if len(requests) == 2:
                self.assertNotIn("owner_assertion", requests[0])
                del requests[1]["owner_assertion"]
                f.write_text(json.dumps(value))
                entry["sha256"] = hashlib.sha256(f.read_bytes()).hexdigest()
        (archive / "manifest.json").write_text(json.dumps(manifest))
        self.assertNotEqual(subprocess.run(cmd, capture_output=True).returncode, 0)

    def test_http_routes_use_localhost_origin(self):
        server = Server(self.o, 0)
        self.assertTrue(self.o.origin.startswith("http://localhost:"))
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            host = self.o.origin.removeprefix("http://")

            def post(path, body, extra=None):
                c = http.client.HTTPConnection("127.0.0.1", server.server_port)
                headers = {
                    "Host": host,
                    "Origin": self.o.origin,
                    "Content-Type": "application/json",
                    "Cookie": "openproof_owner=" + self.o.token,
                    "X-OpenProof-CSRF": self.o.csrf,
                }
                headers.update(extra or {})
                c.request("POST", "/api/" + path, json.dumps(body), headers)
                r = c.getresponse()
                data = json.loads(r.read())
                c.close()
                return r.status, data

            ip = "127.0.0.1:" + str(server.server_port)
            self.assertEqual(post("passkey/register/begin", {}, {"Host": ip})[0], 403)
            code, begin = post("passkey/register/begin", {})
            self.assertEqual(code, 200)
            code, result = post(
                "passkey/register/finish",
                self.device.register(begin, origin=self.o.origin),
            )
            self.assertEqual(code, 200, result)
            code, value = post(
                "propose",
                {"document": "report", "expected_version": 0, "content": "http text"},
            )
            review = post("review", {"id": value["proposal_id"]})[1]
            code, challenge = post(
                "approve",
                {"id": value["proposal_id"], "review_token": review["review_token"]},
            )
            self.assertEqual(challenge["status"], "passkey_required")
            body = {
                "id": value["proposal_id"],
                "assertion_token": challenge["assertion_token"],
                "assertion": self.device.assert_(
                    b64encode(b"\1" * 32), origin=self.o.origin
                ),
            }
            self.assertEqual(post("approve/passkey", body)[0], 409)
            review = post("review", {"id": value["proposal_id"]})[1]
            code, challenge = post(
                "approve",
                {"id": value["proposal_id"], "review_token": review["review_token"]},
            )
            body["assertion_token"] = challenge["assertion_token"]
            body["assertion"] = self.device.assert_(
                challenge["challenge"], origin=self.o.origin
            )
            self.assertEqual(
                post("approve/passkey", body),
                (200, {"status": "approved", "id": value["proposal_id"]}),
            )
            code, result = post("commit", {"id": value["proposal_id"]})
            self.assertEqual(
                result["verification_status"], "local_consistency_verified"
            )
        finally:
            server.shutdown()
            server.server_close()
            thread.join()


if __name__ == "__main__":
    unittest.main()
