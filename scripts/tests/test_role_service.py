"""The Rust mTLS role service (`openproof-witness serve-role`) and the
owner-side routing to it."""

import http.client, json, shutil, socket, ssl, subprocess, sys, tempfile, unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
from witness_workflow import BINARY, Broker, initialize, call, ref
from tls_fixtures import certificates


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class Services:
    """Role services for one home's role folders, with fixture TLS."""

    def __init__(
        self, d, home, pki, keys=None, accept=True, roles=("receiver", "witness")
    ):
        self.d, self.ports, self.processes = d, {}, []
        for role in roles:
            port = free_port()
            role_dir = d / ("svc-" + role)
            role_dir.mkdir(exist_ok=True)
            for name in ["trust.json", "trust-signed.json"]:
                shutil.copy(home / name, role_dir / name)
            command = [
                str(BINARY),
                "serve-role",
                "--role",
                role,
                "--state",
                str(home / role / "state"),
                "--key",
                str((keys or {}).get(role, home / role / "key.secret")),
                "--trust",
                str(role_dir / "trust.json"),
                "--signed-trust",
                str(role_dir / "trust-signed.json"),
                "--cert",
                str(d / "server.pem"),
                "--tls-key",
                str(d / "server.key"),
                "--ca",
                str(d / "ca.pem"),
                "--client-fingerprint",
                pki["client"],
                "--port",
                str(port),
            ] + (["--accept-trust-updates"] if accept else [])
            p = subprocess.Popen(
                command, stdout=subprocess.PIPE, stderr=subprocess.PIPE
            )
            assert b"listening" in p.stdout.readline(), p.stderr.read()
            self.ports[role] = port
            self.processes.append(p)

    def config(self):
        d = self.d
        return {
            "version": "openproof-service-client/1",
            **{
                role: {
                    "url": "https://127.0.0.1:" + str(port),
                    "ca": str(d / "ca.pem"),
                    "cert": str(d / "client.pem"),
                    "key": str(d / "client.key"),
                }
                for role, port in self.ports.items()
            },
        }

    def request(self, role, path, value, identity="client"):
        context = ssl.create_default_context(cafile=self.d / "ca.pem")
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        if identity:
            context.load_cert_chain(
                self.d / (identity + ".pem"), self.d / (identity + ".key")
            )
        c = http.client.HTTPSConnection(
            "127.0.0.1", self.ports[role], context=context, timeout=10
        )
        try:
            c.request(
                "POST", path, json.dumps(value), {"Content-Type": "application/json"}
            )
            r = c.getresponse()
            return r.status, json.loads(r.read())
        finally:
            c.close()

    def close(self):
        for p in self.processes:
            p.kill()
            p.wait()
            p.stdout.close()
            p.stderr.close()


class RoleServiceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=ROOT / "outputs")
        self.d = Path(self.tmp.name)
        self.h = self.d / "home"
        initialize(self.h)
        self.pki = certificates(self.d)
        self.services = None

    def tearDown(self):
        if self.services:
            self.services.close()
        self.tmp.cleanup()

    def test_mtls_identity_scope_tamper_replay_and_witness(self):
        s = self.services = Services(self.d, self.h, self.pki)
        with self.assertRaises((ssl.SSLError, ConnectionError, OSError)):
            s.request("receiver", "/v1/head", {}, None)
        self.assertEqual(s.request("receiver", "/v1/head", {}, "unlisted")[0], 403)
        # Each role serves only its own operations.
        self.assertEqual(s.request("receiver", "/v1/checkpoint", {})[0], 400)
        self.assertEqual(s.request("witness", "/v1/receive", {"request": {}})[0], 400)
        self.assertEqual(s.request("receiver", "/v1/head", {"extra": 1})[0], 400)
        q = call(
            ["approve", self.h / "authority/key.secret", self.h / "trust.json"],
            {
                "document": "report",
                "expected_version": 0,
                "content": "Public TLS fixture",
            },
        )
        bad = dict(q, content="changed")
        self.assertEqual(s.request("receiver", "/v1/receive", {"request": bad})[0], 409)
        code, r = s.request("receiver", "/v1/receive", {"request": q})
        self.assertEqual(code, 200)
        # A replay returns the original receipt; recovery reads the same one.
        self.assertEqual(s.request("receiver", "/v1/receive", {"request": q})[1], r)
        self.assertEqual(s.request("receiver", "/v1/recover", {"request": q})[1], r)
        self.assertEqual(
            s.request("receiver", "/v1/document", {"document": "absent"})[0], 404
        )
        code, cp = s.request("witness", "/v1/witness", {"receipt": r})
        self.assertEqual(code, 200)
        self.assertEqual(cp["payload"]["count"], 1)
        self.assertEqual(s.request("receiver", "/v1/head", {})[1]["count"], 1)

    def test_broker_routes_only_owner_configured_services(self):
        # Role keys live only with the services; the owner home keeps none.
        keys = {}
        for role in ["receiver", "witness"]:
            keys[role] = self.d / (role + ".secret")
            (self.h / role / "key.secret").rename(keys[role])
        s = self.services = Services(self.d, self.h, self.pki, keys)
        (self.h / "service-client.json").write_text(json.dumps(s.config()))
        b = Broker(self.h)
        p = b.propose("report", 0, "TLS-backed owner workflow")
        import contextlib, io

        with contextlib.redirect_stdout(io.StringIO()):
            b.approve(
                p["proposal_id"], reader=lambda _: "APPROVE " + p["content_sha256"][:12]
            )
        result = b.commit(p["proposal_id"])
        self.assertEqual(result["verification_status"], "local_consistency_verified")
        self.assertEqual(b.commit(p["proposal_id"])["document_version"], 1)
        # Administration is not forwarded to the operator's service.
        with self.assertRaisesRegex(RuntimeError, "operator"):
            call(["revoke", self.h / "receiver/state", "00" * 32])
        # A new trust epoch reaches both services through the opt-in route.
        from witness_workflow import renew

        epoch = ref.read(self.h / "trust.json")["epoch"]
        self.assertEqual(renew(self.h)["installed_epoch"], epoch + 1)
        p = b.propose("report", 1, "after renewal")
        with contextlib.redirect_stdout(io.StringIO()):
            b.approve(
                p["proposal_id"], reader=lambda _: "APPROVE " + p["content_sha256"][:12]
            )
        self.assertEqual(b.commit(p["proposal_id"])["document_version"], 2)

    def test_trust_updates_are_opt_in_and_keep_role_keys(self):
        def signed(change, step):
            t = ref.read(self.h / "trust.json")
            t["epoch"] += step
            change(t)
            return call(
                ["sign-trust", self.h / "root/key.secret", self.h / "root/signer"], t
            )

        s = self.services = Services(
            self.d, self.h, self.pki, accept=False, roles=("receiver",)
        )
        code, body = s.request(
            "receiver", "/v1/install-trust", {"signed": signed(lambda t: None, 1)}
        )
        self.assertEqual(
            (code, body["error"]),
            (400, "Trust updates are not accepted by this operator"),
        )
        s.close()
        s = self.services = Services(self.d, self.h, self.pki, roles=("receiver",))
        other = call(["keygen", self.d / "other.secret"])["public_key"]
        code, body = s.request(
            "receiver",
            "/v1/install-trust",
            {"signed": signed(lambda t: t.update(witness=other), 2)},
        )
        self.assertEqual((code, body["error"]), (400, "Role key change refused"))
        epoch = ref.read(self.h / "trust.json")["epoch"] + 3
        code, body = s.request(
            "receiver", "/v1/install-trust", {"signed": signed(lambda t: None, 3)}
        )
        self.assertEqual((code, body), (200, {"installed_epoch": epoch}))
        # The service restarts cleanly from the trust files it wrote.
        self.assertEqual(ref.read(self.d / "svc-receiver/trust.json")["epoch"], epoch)
        s.close()
        self.services = Services.__new__(Services)
        self.services.processes = []
        p = subprocess.Popen(
            [
                str(BINARY),
                "serve-role",
                "--role",
                "receiver",
                "--state",
                str(self.h / "receiver/state"),
                "--key",
                str(self.h / "receiver/key.secret"),
                "--trust",
                str(self.d / "svc-receiver/trust.json"),
                "--signed-trust",
                str(self.d / "svc-receiver/trust-signed.json"),
                "--cert",
                str(self.d / "server.pem"),
                "--tls-key",
                str(self.d / "server.key"),
                "--ca",
                str(self.d / "ca.pem"),
                "--client-fingerprint",
                self.pki["client"],
                "--port",
                "0",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self.services.processes.append(p)
        self.assertIn(b"listening", p.stdout.readline())


if __name__ == "__main__":
    unittest.main()
