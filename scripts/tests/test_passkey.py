import os
import base64, contextlib, hashlib, io, json, subprocess, sys, tempfile, time, unittest
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
from witness_workflow import initialize, call, ref, renew
from paged_workflow import enable
from portable_history import export_history
from owner_client import OwnerClient

ORIGIN = None  # Set per test from the running owner app.


def b64encode(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def b64decode(text):
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


GO = os.environ.get(
    "OPENPROOF_GO_VERIFY", str(ROOT / "outputs/v0.9/openproof-go-verify")
)


def approval_digest(request):
    payload = request["approval"]["payload"]
    preimage = b"OpenProof/v1/document-approval/1\0" + ref.canonical(payload)
    return hashlib.sha256(preimage).hexdigest()


class SoftAuthenticator:
    """A software stand-in for a platform passkey, for tests only."""

    def __init__(self, rp_id="localhost", flags=0x05):
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.rp_id = rp_id
        self.flags = flags

    def auth_data(self):
        rp = hashlib.sha256(self.rp_id.encode()).digest()
        return rp + bytes([self.flags]) + b"\0\0\0\0"

    def client(self, kind, challenge, origin=None, extra=None):
        data = dict(type=kind, challenge=challenge, origin=origin or ORIGIN)
        data.update(extra or {})
        return json.dumps(data, separators=(",", ":")).encode()

    def register(self, begin, origin=None, kind="webauthn.create"):
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

    def assert_(self, challenge, origin=None, kind="webauthn.get", extra=None):
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
        self.o = OwnerClient(self.h)
        global ORIGIN
        ORIGIN = self.o.origin
        self.device = SoftAuthenticator()

    def tearDown(self):
        self.o.close()
        self.temp.cleanup()

    def register(self):
        return self.o.register_finish(self.device.register(self.o.register_begin()))

    def approve(self, content="passkey approved text", version=0):
        identity = self.o.broker.propose("report", version, content)["proposal_id"]
        review = self.o.review(identity)
        return identity, self.o.approve(identity, review["review_token"])

    def gate_state(self, identity):
        return call(["gate-approved", self.h, self.h / "trust.json", identity])["state"]

    def receive(self, request):
        h = self.h
        return call(
            [
                "receive",
                h / "receiver/state",
                h / "receiver/key.secret",
                h / "trust.json",
            ],
            request,
        )

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

    def test_registration_challenge_checks_and_new_trust_epoch(self):
        epoch = ref.read(self.h / "trust.json")["epoch"]
        begin = self.o.register_begin()
        self.assertEqual(begin["rp_id"], "localhost")
        self.assertEqual(len(b64decode(begin["challenge"])), 32)
        bad = [
            lambda b: self.device.register(dict(challenge=b64encode(b"\0" * 32))),
            lambda b: self.device.register(b, kind="webauthn.get"),
            lambda b: self.device.register(b, origin="http://127.0.0.1:8765"),
            lambda b: SoftAuthenticator(flags=0x01).register(b),
            lambda b: SoftAuthenticator(rp_id="example.com").register(b),
            lambda b: dict(self.device.register(b), algorithm=-257),
        ]
        for make in bad:
            # Every attempt, accepted or not, uses up the registration challenge.
            with self.assertRaises(ValueError):
                self.o.register_finish(make(self.o.register_begin()))
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
                origin=self.o.origin,
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

        with self.assertRaisesRegex(RuntimeError, "cannot be removed"):
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
        self.assertEqual(self.gate_state(identity), "awaiting_passkey")
        with self.assertRaises(FileNotFoundError):
            self.o.broker.commit(identity)
        assertion = self.device.assert_(challenge["challenge"])
        result = self.o.approve_passkey(
            identity, challenge["assertion_token"], assertion
        )
        self.assertEqual(result, {"status": "approved", "id": identity})
        stored = self.o.broker.request(identity)
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

    def test_superseded_approval_is_refused_and_marked(self):
        """Two approvals for the same version: after the first executes, the
        second is refused without a change and is no longer offered."""
        self.register()
        ids = []
        for content in ["first", "second"]:
            identity, challenge = self.approve(content=content, version=0)
            self.o.approve_passkey(
                identity,
                challenge["assertion_token"],
                self.device.assert_(challenge["challenge"]),
            )
            ids.append(identity)
        first = self.o.broker.commit(ids[0])
        self.assertEqual(first["verification_status"], "local_consistency_verified")
        second = self.o.broker.commit(ids[1])
        self.assertEqual(second["execution_status"], "not_committed")
        self.assertEqual(second["error_code"], "admission_failed")
        stages = {i["id"]: i["stage"] for i in self.o.status()["items"]}
        self.assertEqual(stages[ids[1]], "Superseded")
        self.assertEqual(self.o.current_version("report"), 1)

    def test_missing_or_invalid_assertion_cannot_execute(self):
        self.register()
        identity, challenge = self.approve()
        with self.assertRaises(ValueError):
            self.o.approve_passkey(identity, "0" * 64, {})
        bad = [
            lambda c: self.device.assert_(b64encode(b"\0" * 32)),
            lambda c: self.device.assert_(c, origin="http://localhost:1"),
            lambda c: self.device.assert_(c, kind="webauthn.create"),
            lambda c: self.device.assert_(c, extra={"crossOrigin": True}),
            lambda c: SoftAuthenticator().assert_(c),
            lambda c: SoftAuthenticator(flags=0x01).assert_(c),
        ]
        for make in bad:
            # Each rejected attempt uses up the pending approval; approve again.
            review = self.o.review(identity)
            again = self.o.approve(identity, review["review_token"])
            with self.assertRaises(ValueError):
                self.o.approve_passkey(
                    identity, again["assertion_token"], make(again["challenge"])
                )
            self.assertEqual(self.gate_state(identity), "awaiting_passkey")
        # A process that can read the authority key signs a request without a passkey.
        proposal = self.o.broker.review(identity)["proposal"]
        forged = call(
            ["approve", self.h / "authority/key.secret", self.h / "trust.json"],
            proposal,
        )
        # A file in the earlier approved/ folder is not read by the gate.
        (self.h / "approved").mkdir(mode=0o700)
        (self.h / "approved" / (identity + ".json")).write_text(json.dumps(forged))
        with self.assertRaises(FileNotFoundError):
            self.o.broker.commit(identity)
        # The receiver refuses the forged request without an assertion.
        with self.assertRaisesRegex(RuntimeError, "required"):
            self.receive(forged)
        # An assertion copied from a different approval does not match this digest.
        other, other_challenge = self.approve("other text", 0)
        copied = dict(
            forged, owner_assertion=self.device.assert_(other_challenge["challenge"])
        )
        with self.assertRaisesRegex(RuntimeError, "challenge"):
            self.receive(copied)
        review = self.o.review(identity)
        again = self.o.approve(identity, review["review_token"])
        with self.assertRaises(ValueError):
            self.o.approve_passkey(
                identity,
                again["assertion_token"],
                self.device.assert_(other_challenge["challenge"]),
            )
        self.assertEqual(call(["head", self.h / "receiver/state"])["count"], 0)
        with self.assertRaises(RuntimeError):
            # The terminal approval path refuses once a passkey is installed.
            with contextlib.redirect_stdout(io.StringIO()):
                self.o.broker.approve(other, reader=lambda prompt: prompt[5:-2])

    def test_without_passkey_flow_is_unchanged_and_assertion_rejected(self):
        identity, result = self.approve()
        self.assertEqual(result, {"status": "approved", "id": identity})
        stored = self.o.broker.request(identity)
        self.assertNotIn("owner_assertion", stored)
        challenge = b64encode(bytes.fromhex(approval_digest(stored)))
        with_assertion = dict(stored, owner_assertion=self.device.assert_(challenge))
        with self.assertRaises(RuntimeError):
            call(["check-assertion", self.h / "trust.json"], with_assertion)
        with self.assertRaisesRegex(RuntimeError, "unexpected"):
            self.receive(with_assertion)
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
        self.assertTrue(self.o.origin.startswith("http://localhost:"))
        post = self.o.post
        ip = "127.0.0.1:" + str(self.o.port)
        self.assertEqual(post("passkey/register/begin", {}, {"Host": ip})[0], 403)
        code, begin = post("passkey/register/begin", {})
        self.assertEqual(code, 200)
        code, result = post("passkey/register/finish", self.device.register(begin))
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
            "assertion": self.device.assert_(b64encode(b"\1" * 32)),
        }
        self.assertEqual(post("approve/passkey", body)[0], 409)
        review = post("review", {"id": value["proposal_id"]})[1]
        code, challenge = post(
            "approve",
            {"id": value["proposal_id"], "review_token": review["review_token"]},
        )
        body["assertion_token"] = challenge["assertion_token"]
        body["assertion"] = self.device.assert_(challenge["challenge"])
        self.assertEqual(
            post("approve/passkey", body),
            (200, {"status": "approved", "id": value["proposal_id"]}),
        )
        code, result = post("commit", {"id": value["proposal_id"]})
        self.assertEqual(result["verification_status"], "local_consistency_verified")
        # The passkey binds the port: a restart on another port is refused.
        self.o.close()
        bad = subprocess.run(
            [
                str(ROOT / "target/debug/openproof-witness"),
                "owner-app",
                "--home",
                str(self.h),
                "--port",
                str(self.o.port + 1),
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertIn("registered for", bad.stderr)
        self.o = OwnerClient(self.h)
        self.assertEqual(self.o.origin, ORIGIN)


if __name__ == "__main__":
    unittest.main()
