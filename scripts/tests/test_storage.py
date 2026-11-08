"""Wire-level S3-shaped TLS fixtures. Not real-provider interoperability evidence."""

import contextlib, hashlib, http.server, io, json, os, socket, ssl, sys, tempfile, threading, unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
from witness_workflow import call, save, ref
from storage_adapter import capture, execute, client
from tls_fixtures import certificates


class S3Fixture(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def reply(self, code, body=b""):
        self.close_connection = True
        self.send_response(code)
        self.send_header("Connection", "close")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("x-amz-request-id", "synthetic-fixture")
        self.end_headers()
        self.wfile.write(body)

    def do_PUT(self):
        s = self.server
        s.attempts += 1
        if self.headers.get("If-None-Match") != "*" or not self.headers.get(
            "Authorization", ""
        ).startswith("AWS4-HMAC-SHA256 "):
            return self.reply(400)
        raw = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        if self.path in s.objects:
            return self.reply(412)
        if s.redirect:
            return self.reply(307)
        s.objects[self.path] = raw
        s.writes += 1
        if s.lose_reply:
            self.connection.shutdown(socket.SHUT_RDWR)
            self.connection.close()
            return
        self.reply(200)

    def do_GET(self):
        s = self.server
        if s.deny_read:
            return self.reply(403)
        if self.path not in s.objects:
            return self.reply(404)
        self.reply(200, s.objects[self.path] if not s.bad_read else b"wrong bytes")


class Storage(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=ROOT / "outputs")
        self.d = Path(self.tmp.name)
        certificates(self.d)
        self.server = http.server.HTTPServer(("127.0.0.1", 0), S3Fixture)
        self.server.objects = {}
        self.server.attempts = 0
        self.server.writes = 0
        self.server.lose_reply = False
        self.server.deny_read = False
        self.server.bad_read = False
        self.server.redirect = False
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(self.d / "server.pem", self.d / "server.key")
        self.server.socket = ctx.wrap_socket(self.server.socket, server_side=True)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.authority = call(["keygen", self.d / "authority.secret"])["public_key"]
        self.adapter = call(["keygen", self.d / "adapter.secret"])["public_key"]
        self.c = {
            "version": "openproof-storage-config/1",
            "endpoint": "https://127.0.0.1:" + str(self.server.server_port),
            "bucket": "test-bucket",
            "region": "us-east-1",
            "access_key_env": "OPENPROOF_TEST_ACCESS",
            "secret_key_env": "OPENPROOF_TEST_SECRET",
            "session_token_env": None,
            "ca_file": str(self.d / "ca.pem"),
        }
        save(self.d / "configuration.json", self.c)
        (self.d / "report.txt").write_text(
            "Public storage adapter fixture. No external upload."
        )
        self.env = patch.dict(
            os.environ,
            {
                "OPENPROOF_TEST_ACCESS": "fixture-access",
                "OPENPROOF_TEST_SECRET": "fixture-secret",
            },
        )
        self.env.start()
        with contextlib.redirect_stdout(io.StringIO()):
            capture(
                self.d / "configuration.json",
                self.d / "report.txt",
                "reports/status.txt",
                self.d / "authority.secret",
                self.d / "job",
                reader=lambda prompt: prompt.split("Type ", 1)[1].split(
                    " to approve", 1
                )[0],
            )

    def tearDown(self):
        self.env.stop()
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()
        self.tmp.cleanup()

    def run_job(self, **kw):
        return execute(
            self.d / "job",
            self.d / "configuration.json",
            self.authority,
            self.d / "adapter.secret",
            **kw,
        )

    def test_conditional_upload_readback_and_no_repeat_put(self):
        result = self.run_job()
        self.assertEqual(result["status"], "read_back_match")
        self.assertTrue(result["provider_acknowledged_this_call"])
        self.assertEqual(self.server.writes, 1)
        self.assertEqual(
            self.server.objects["/test-bucket/reports/status.txt"],
            (self.d / "job/report.txt").read_bytes(),
        )
        self.run_job()
        self.assertEqual(self.server.attempts, 1)
        from jsonschema import Draft202012Validator

        schema = ref.read(ROOT / "schemas/openproof-storage-v1.schema.json")
        for name in result["observations"]:
            bundle = ref.read(self.d / "job" / name)
            self.assertFalse(
                call(["storage-verify", self.authority, self.adapter], bundle)[
                    "independent_storage_proof"
                ]
            )
            for kind, domain, key in [
                ("authorization", "storage-upload-authorization/1", self.authority),
                ("observation", "storage-adapter-observation/1", self.adapter),
            ]:
                record = bundle[kind]
                Draft202012Validator(schema).validate(record["payload"])
                ref.public(key).verify(
                    bytes.fromhex(record["signature"]),
                    ("OpenProof/v1/" + domain + "\0").encode()
                    + ref.canonical(record["payload"]),
                )

    def test_lost_reply_is_reconciled_without_resubmission(self):
        self.server.lose_reply = True
        result = self.run_job()
        self.assertTrue(result["read_back_matches"])
        self.assertFalse(result["provider_acknowledged_this_call"])
        self.run_job()
        self.assertEqual(self.server.attempts, 1)
        self.assertEqual(self.server.writes, 1)

    def test_acknowledgment_does_not_imply_readback_or_independence(self):
        self.server.deny_read = True
        r = self.run_job()
        self.assertEqual(r["status"], "provider_acknowledged_read_back_unconfirmed")
        self.assertFalse(r["independent_storage_proof"])
        self.server.deny_read = False
        self.server.bad_read = True
        self.assertEqual(self.run_job()["status"], "outcome_unconfirmed")
        self.assertEqual(self.server.attempts, 1)

    def test_changed_bytes_destination_and_wrong_authority_never_dispatch(self):
        with self.assertRaises(RuntimeError):
            execute(
                self.d / "job",
                self.d / "configuration.json",
                self.adapter,
                self.d / "adapter.secret",
            )
        c = dict(self.c, bucket="different")
        (self.d / "configuration.json").write_text(json.dumps(c))
        with self.assertRaises(ValueError):
            self.run_job()
        (self.d / "configuration.json").write_text(json.dumps(self.c))
        (self.d / "job/report.txt").write_text("changed")
        with self.assertRaises(ValueError):
            self.run_job()
        self.assertEqual(self.server.attempts, 0)

    def test_external_disabled_scope_and_read_only(self):
        with self.assertRaises(ValueError):
            client(
                dict(self.c, endpoint="https://example.invalid"), "reports/status.txt"
            )
        r = self.run_job(read_only=True)
        self.assertEqual(r["status"], "outcome_unconfirmed")
        self.assertEqual(self.server.attempts, 0)
        s = client(self.c, "reports/status.txt")
        with self.assertRaises(ValueError):
            s.put_object(Bucket="another-bucket", Key="reports/status.txt", Body=b"bad")
        self.assertEqual(self.server.attempts, 0)

    def test_existing_matching_object_does_not_prove_this_upload_created_it(self):
        self.server.objects["/test-bucket/reports/status.txt"] = (
            self.d / "job/report.txt"
        ).read_bytes()
        r = self.run_job()
        self.assertTrue(r["read_back_matches"])
        self.assertFalse(r["provider_acknowledged_this_call"])
        self.assertFalse(r["causation_proven"])
        self.assertEqual(self.server.writes, 0)

    def test_expired_approval_and_reserved_but_unsent_job_never_dispatch(self):
        import time
        from unittest.mock import Mock

        path = self.d / "job/authorization.json"
        a = ref.read(path)
        old = dict(
            a["payload"],
            not_before=int(time.time()) - 600,
            expires_at=int(time.time()) - 300,
        )
        path.write_text(
            json.dumps(call(["storage-authorize", self.d / "authority.secret"], old))
        )
        with self.assertRaises(RuntimeError):
            self.run_job()
        self.assertEqual(self.server.attempts, 0)
        path.write_text(json.dumps(a))
        fake = Mock()
        fake.put_object.side_effect = RuntimeError(
            "simulated transport failure before send"
        )
        fake.get_object.side_effect = RuntimeError("unavailable")
        with patch("storage_adapter.client", return_value=fake):
            self.assertEqual(self.run_job()["status"], "outcome_unconfirmed")
        self.assertTrue((self.d / "job/attempt.json").exists())
        self.run_job()
        self.assertEqual(self.server.attempts, 0)
