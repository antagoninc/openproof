import http.client, json, ssl, sys, tempfile, threading, unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
from role_service import RoleServer
from witness_workflow import initialize, call
from tls_fixtures import certificates


class TransportTests(unittest.TestCase):
    def test_mtls_identity_scope_tamper_replay_and_witness(self):
        with tempfile.TemporaryDirectory(dir=ROOT / "outputs") as directory:
            d = Path(directory)
            h = d / "home"
            initialize(h)
            pki = certificates(d)
            servers = []
            threads = []
            for role in ["receiver", "witness"]:
                s = RoleServer(
                    role,
                    h / role / "state",
                    h / role / "key.secret",
                    h / "trust.json",
                    h / "trust-signed.json",
                    d / "server.pem",
                    d / "server.key",
                    d / "ca.pem",
                    [pki["client"]],
                )
                servers.append(s)
                t = threading.Thread(target=s.serve_forever, daemon=True)
                t.start()
                threads.append(t)

            def request(server, path, value, identity="client"):
                context = ssl.create_default_context(cafile=d / "ca.pem")
                context.minimum_version = ssl.TLSVersion.TLSv1_3
                if identity:
                    context.load_cert_chain(
                        d / (identity + ".pem"), d / (identity + ".key")
                    )
                c = http.client.HTTPSConnection(
                    "127.0.0.1", server.server_port, context=context, timeout=5
                )
                try:
                    c.request(
                        "POST",
                        path,
                        json.dumps(value),
                        {"Content-Type": "application/json"},
                    )
                    r = c.getresponse()
                    return r.status, json.loads(r.read())
                finally:
                    c.close()

            try:
                with self.assertRaises((ssl.SSLError, ConnectionError)):
                    request(servers[0], "/v1/head", {}, None)
                self.assertEqual(
                    request(servers[0], "/v1/head", {}, "unlisted")[0], 403
                )
                self.assertEqual(request(servers[0], "/v1/checkpoint", {})[0], 400)
                q = call(
                    ["approve", h / "authority/key.secret", h / "trust.json"],
                    {
                        "document": "report",
                        "expected_version": 0,
                        "content": "Public TLS fixture",
                    },
                )
                bad = dict(q, content="changed")
                self.assertEqual(
                    request(servers[0], "/v1/receive", {"request": bad})[0], 409
                )
                code, r = request(servers[0], "/v1/receive", {"request": q})
                self.assertEqual(code, 200)
                self.assertEqual(
                    request(servers[0], "/v1/receive", {"request": q})[1], r
                )
                self.assertEqual(
                    request(servers[0], "/v1/recover", {"request": q})[1], r
                )
                code, cp = request(servers[1], "/v1/witness", {"receipt": r})
                self.assertEqual(code, 200)
                self.assertEqual(cp["payload"]["count"], 1)
                self.assertEqual(request(servers[0], "/v1/head", {})[1]["count"], 1)
            finally:
                for s in servers:
                    s.shutdown()
                    s.server_close()
                for t in threads:
                    t.join()

    def test_broker_routes_only_owner_configured_services(self):
        import shutil
        from owner_app import Owner
        from paged_workflow import enable
        from portable_history import export_history

        with tempfile.TemporaryDirectory(dir=ROOT / "outputs") as directory:
            d = Path(directory)
            remote = d / "remote"
            initialize(remote)
            enable(remote)
            local = d / "local"
            pki = certificates(d)
            servers = []
            threads = []
            config = {"version": "openproof-service-client/1"}
            for role in ["receiver", "witness"]:
                server = RoleServer(
                    role,
                    remote / role / "state",
                    remote / role / "key.secret",
                    remote / "trust.json",
                    remote / "trust-signed.json",
                    d / "server.pem",
                    d / "server.key",
                    d / "ca.pem",
                    [pki["client"]],
                )
                servers.append(server)
                t = threading.Thread(target=server.serve_forever, daemon=True)
                t.start()
                threads.append(t)
                config[role] = {
                    "url": "https://127.0.0.1:" + str(server.server_port),
                    "ca": str(d / "ca.pem"),
                    "cert": str(d / "client.pem"),
                    "key": str(d / "client.key"),
                }
            from role_transport import initialize_client
            from witness_workflow import ref

            config_path = d / "client.json"
            config_path.write_text(json.dumps(config))
            initialize_client(
                local,
                remote / "authority/key.secret",
                ref.read(remote / "root-public.json")["public_key"],
                remote / "trust-signed.json",
                config_path,
            )
            self.assertFalse((local / "receiver/key.secret").exists())
            self.assertFalse((local / "witness/key.secret").exists())
            self.assertFalse((local / "root/key.secret").exists())
            try:
                o = Owner(local)
                identity = o.broker.propose("report", 0, "TLS-backed owner workflow")[
                    "proposal_id"
                ]
                r = o.review(identity)
                o.approve(identity, r["review_token"])
                result = o.broker.commit(identity)
                self.assertEqual(
                    result["verification_status"], "local_consistency_verified"
                )
                self.assertEqual(o.broker.commit(identity)["document_version"], 1)
                self.assertEqual(call(["head", remote / "receiver/state"])["count"], 1)
                export_history(local, d / "archive")
                with self.assertRaises(RuntimeError):
                    call(["revoke", local / "receiver/state", "00" * 32])
            finally:
                for server in servers:
                    server.shutdown()
                    server.server_close()
                for t in threads:
                    t.join()
