"""The role service (`openproof-role serve`) on a Unix socket, and the
owner-side routing to it."""

import json, os, shutil, socket, subprocess, sys, tempfile, unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
from witness_workflow import Broker, initialize, call, ref

ROLE = ROOT / "target/debug/openproof-role"


def serve(role, state, key, trust, signed, sock, uids, accept=True, publish=None):
    command = [
        str(ROLE),
        "serve",
        "--role",
        role,
        "--state",
        str(state),
        "--key",
        str(key),
        "--trust",
        str(trust),
        "--signed-trust",
        str(signed),
        "--socket",
        str(sock),
    ]
    for uid in uids:
        command += ["--client-uid", str(uid)]
    if accept:
        command.append("--accept-trust-updates")
    if publish:
        command += ["--publish", str(publish)]
    return subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def post(sock, path, value):
    """One request to a role service; returns (code, JSON body). The path
    names the operation: "/v1/head" is the operation "head"."""
    raw = json.dumps({"op": path.removeprefix("/v1/"), "body": value}).encode()
    return exchange(sock, len(raw).to_bytes(4, "big") + raw)


def raw(sock, wire):
    """Send bytes to a role service and read all that it answers."""
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
        s.settimeout(10)
        s.connect(str(sock))
        response = b""
        try:
            s.sendall(wire)
            s.shutdown(socket.SHUT_WR)
            while chunk := s.recv(65536):
                response += chunk
        except ConnectionError:
            pass  # The service closed without reading all of it.
    return response


def exchange(sock, wire):
    """One framed answer: a 4-byte length, then JSON with a code and a body."""
    response = raw(sock, wire)
    answer = json.loads(response[4:])
    assert int.from_bytes(response[:4], "big") == len(response) - 4
    return answer["code"], answer["body"]


class Services:
    """Role services for one home's role folders."""

    def __init__(
        self,
        d,
        sockets,
        home,
        keys=None,
        accept=True,
        roles=("receiver", "witness"),
        uids=None,
        publish=None,
    ):
        self.sockets, self.processes = {}, []
        for role in roles:
            role_dir = d / ("svc-" + role)
            role_dir.mkdir(exist_ok=True)
            for name in ["trust.json", "trust-signed.json"]:
                shutil.copy(home / name, role_dir / name)
            sock = sockets / (role + ".sock")
            p = serve(
                role,
                home / role / "state",
                (keys or {}).get(role, home / role / "key.secret"),
                role_dir / "trust.json",
                role_dir / "trust-signed.json",
                sock,
                uids or [os.getuid()],
                accept,
                publish if role == "receiver" else None,
            )
            line = p.stdout.readline()
            assert b"listening" in line, p.stderr.read()
            self.sockets[role] = sock
            self.processes.append(p)

    def config(self):
        return {
            "version": "openproof-service-client/3",
            **{role: {"socket": str(s)} for role, s in self.sockets.items()},
        }

    def request(self, role, path, value):
        return post(self.sockets[role], path, value)

    def close(self):
        for p in self.processes:
            p.kill()
            p.wait()
            p.stdout.close()
            p.stderr.close()


class RoleServiceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=ROOT / "outputs")
        # Socket paths are limited to about 100 bytes: keep them short.
        self.short = tempfile.TemporaryDirectory(prefix="opsock-")
        self.d = Path(self.tmp.name)
        self.s = Path(self.short.name)
        self.h = self.d / "home"
        initialize(self.h)
        self.services = None

    def tearDown(self):
        if self.services:
            self.services.close()
        self.tmp.cleanup()
        self.short.cleanup()

    def approved(self, content, version=0, document="report"):
        return call(
            ["approve", self.h / "authority/key.secret", self.h / "trust.json"],
            {"document": document, "expected_version": version, "content": content},
        )

    def test_unlisted_accounts_are_refused(self):
        other = os.getuid() + 1
        s = self.services = Services(self.d, self.s, self.h, uids=[other])
        # The service closes the connection without reading or answering.
        for path, value in [
            ("/v1/head", {}),
            ("/v1/receive", {"request": self.approved("x")}),
        ]:
            try:
                answer = s.request("receiver", path, value)
            except (ConnectionError, ValueError, IndexError):
                answer = None
            self.assertIsNone(answer)
        self.assertEqual(call(["head", self.h / "receiver/state"])["count"], 0)

    def test_scope_tamper_replay_and_witness(self):
        s = self.services = Services(self.d, self.s, self.h)
        # The socket is open to every account; the peer check decides.
        self.assertEqual(os.stat(s.sockets["receiver"]).st_mode & 0o777, 0o666)
        # Each role serves only its own operations.
        self.assertEqual(s.request("receiver", "/v1/checkpoint", {})[0], 400)
        self.assertEqual(s.request("witness", "/v1/receive", {"request": {}})[0], 400)
        self.assertEqual(s.request("receiver", "/v1/head", {"extra": 1})[0], 400)
        # A message that is not one bounded frame gets no answer. A frame
        # that is not exactly an operation and a body is refused.
        sock = s.sockets["receiver"]
        frame = lambda text: len(text).to_bytes(4, "big") + text
        for wire in [
            b"",
            b"\0\0",
            b"\0\0\0\0",
            b"\x7f\xff\xff\xff{}",
            (1_048_577).to_bytes(4, "big") + b"x" * 1_048_577,
            frame(b'{"op": "head", "body": {}}')[:-1],
            b"POST /v1/head HTTP/1.1\r\nContent-Length: 2\r\n\r\n{}",
        ]:
            self.assertEqual(raw(sock, wire), b"", wire[:40])
        for text in [
            b"not json",
            b'{"op": "head"}',
            b'{"op": "head", "body": {}, "extra": 1}',
            b'{"op": "head", "op": "head", "body": {}}',
            b'{"op": 1, "body": {}}',
            b'{"op": "absent", "body": {}}',
            b'{"op": "/v1/head", "body": {}}',
            b'{"op": "head", "body": []}',
        ]:
            self.assertEqual(exchange(sock, frame(text))[0], 400, text)
        self.assertEqual(
            exchange(sock, frame(b'{"op": "head", "body": {}}')),
            (200, {"count": 0}),
        )
        q = self.approved("Public fixture")
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
        code, doc = s.request("receiver", "/v1/document", {"document": "report"})
        self.assertEqual(
            (code, doc), (200, {"version": 1, "content": "Public fixture"})
        )
        code, cp = s.request("witness", "/v1/witness", {"receipt": r})
        self.assertEqual(code, 200)
        self.assertEqual(cp["payload"]["count"], 1)
        self.assertEqual(s.request("receiver", "/v1/head", {})[1]["count"], 1)
        code, again = s.request("witness", "/v1/checkpoint", {})
        self.assertEqual((code, again["payload"]["head"]), (200, cp["payload"]["head"]))
        code, page = s.request("receiver", "/v1/page", {"start": 1, "checkpoint": cp})
        self.assertEqual((code, len(page["receipts"])), (200, 1))
        code, package = s.request("receiver", "/v1/export", {"checkpoint": cp})
        self.assertEqual((code, len(package["receipts"])), (200, 1))
        code, proof = s.request(
            "witness", "/v1/tlog-inclusion", {"sequence": 1, "size": 1}
        )
        self.assertEqual((code, proof), (200, {"proof": []}))

    def test_protected_files(self):
        folder = self.d / "published"
        folder.mkdir(mode=0o755)
        os.chmod(folder, 0o755)
        h = self.h

        def start(role="receiver", publish=folder):
            return serve(
                role,
                h / role / "state",
                h / role / "key.secret",
                h / "trust.json",
                h / "trust-signed.json",
                self.s / (role + ".sock"),
                [os.getuid()],
                publish=publish,
            )

        # Only the receiver publishes, and only into a folder that no other
        # account can write. Otherwise the service does not start.
        for role, mode, message in [
            ("witness", 0o755, b"to the receiver"),
            ("receiver", 0o775, b"only this account can write"),
        ]:
            os.chmod(folder, mode)
            p = start(role)
            out, err = p.communicate(timeout=20)
            self.assertNotEqual(p.returncode, 0)
            self.assertIn(message, err)
        os.chmod(folder, 0o755)
        s = self.services = Services(self.d, self.s, h, publish=folder)
        self.assertIsNone(s.request("witness", "/v1/status", {})[1]["published"])
        empty = {"folder": str(folder), "not_published": []}
        self.assertEqual(s.request("receiver", "/v1/status", {})[1]["published"], empty)
        # The owner app shows what the receiver service reports.
        (h / "service-client.json").write_text(json.dumps(s.config()))
        sys.path.insert(0, str(Path(__file__).parent))
        from owner_client import OwnerClient

        o = OwnerClient(h)
        try:
            self.assertEqual(o.status()["published"], empty)
        finally:
            o.close()
            (h / "service-client.json").unlink()
        q = self.approved("Rule one\n", document="agent-rules")
        refused = dict(q, content="Rule 1\n")
        self.assertEqual(
            s.request("receiver", "/v1/receive", {"request": refused})[0], 409
        )
        self.assertEqual(os.listdir(folder), [])
        code, receipt = s.request("receiver", "/v1/receive", {"request": q})
        self.assertEqual(code, 200)
        file = folder / "agent-rules"
        self.assertEqual(file.read_bytes(), b"Rule one\n")
        self.assertEqual(file.stat().st_mode & 0o7777, 0o644)
        import hashlib

        self.assertEqual(
            hashlib.sha256(file.read_bytes()).hexdigest(),
            receipt["payload"]["content_sha256"],
        )
        # A replay, a refused request, a status request and a restart each
        # write a lost or changed file again.
        file.unlink()
        self.assertEqual(
            s.request("receiver", "/v1/receive", {"request": refused})[0], 409
        )
        self.assertEqual(file.read_bytes(), b"Rule one\n")
        file.unlink()
        self.assertEqual(
            s.request("receiver", "/v1/receive", {"request": q})[1], receipt
        )
        self.assertEqual(file.read_bytes(), b"Rule one\n")
        file.write_text("Rule two\n")
        self.assertEqual(s.request("receiver", "/v1/status", {})[1]["published"], empty)
        self.assertEqual(file.read_bytes(), b"Rule one\n")
        s.close()
        file.unlink()
        (folder / ".left").write_text("x")
        p = start()
        s.processes = [p]
        self.assertIn(b"listening", p.stdout.readline())
        self.assertEqual(os.listdir(folder), ["agent-rules"])
        self.assertEqual(file.read_bytes(), b"Rule one\n")
        # The next version replaces the file. A name with a capital letter is
        # stored and receipted as before, and is reported as not published.
        sock = self.s / "receiver.sock"
        q2 = self.approved("Rule two\n", 1, "agent-rules")
        self.assertEqual(post(sock, "/v1/receive", {"request": q2})[0], 200)
        self.assertEqual(file.read_bytes(), b"Rule two\n")
        upper = self.approved("x", document="Notes")
        self.assertEqual(post(sock, "/v1/receive", {"request": upper})[0], 200)
        self.assertEqual(os.listdir(folder), ["agent-rules"])
        self.assertEqual(
            post(sock, "/v1/status", {})[1]["published"],
            {"folder": str(folder), "not_published": ["Notes"]},
        )
        # A folder that is no longer safe: changes are still receipted, and
        # the status says that nothing is confirmed as published.
        os.chmod(folder, 0o777)
        q3 = self.approved("Rule three\n", 2, "agent-rules")
        self.assertEqual(post(sock, "/v1/receive", {"request": q3})[0], 200)
        self.assertEqual(file.read_bytes(), b"Rule two\n")
        self.assertEqual(
            post(sock, "/v1/status", {})[1]["published"],
            {"folder": str(folder), "not_published": None},
        )
        os.chmod(folder, 0o755)
        self.assertEqual(
            post(sock, "/v1/status", {})[1]["published"]["not_published"], ["Notes"]
        )
        self.assertEqual(file.read_bytes(), b"Rule three\n")
        # One document that cannot be written is reported. It stops neither
        # the other files nor a restart.
        (folder / "blocked").mkdir()
        q4 = self.approved("b", document="blocked")
        self.assertEqual(post(sock, "/v1/receive", {"request": q4})[0], 200)
        q5 = self.approved("Rule four\n", 3, "agent-rules")
        self.assertEqual(post(sock, "/v1/receive", {"request": q5})[0], 200)
        self.assertEqual(file.read_bytes(), b"Rule four\n")
        missing = ["Notes", "blocked"]
        self.assertEqual(
            post(sock, "/v1/status", {})[1]["published"]["not_published"], missing
        )
        s.close()
        file.unlink()
        p = start()
        s.processes = [p]
        self.assertIn(b"listening", p.stdout.readline())
        self.assertEqual(file.read_bytes(), b"Rule four\n")
        self.assertEqual(
            post(sock, "/v1/status", {})[1]["published"]["not_published"], missing
        )

    def test_socket_path_must_be_a_socket_or_absent(self):
        taken = self.s / "receiver.sock"
        taken.write_text("not a socket")
        h = self.h
        p = serve(
            "receiver",
            h / "receiver/state",
            h / "receiver/key.secret",
            h / "trust.json",
            h / "trust-signed.json",
            taken,
            [os.getuid()],
        )
        out, err = p.communicate(timeout=20)
        self.assertNotEqual(p.returncode, 0)
        self.assertIn(b"not a socket", err)
        self.assertEqual(taken.read_text(), "not a socket")

    def test_broker_routes_only_owner_configured_services(self):
        # Role keys live only with the services; the owner home keeps none.
        keys = {}
        for role in ["receiver", "witness"]:
            keys[role] = self.d / (role + ".secret")
            (self.h / role / "key.secret").rename(keys[role])
        s = self.services = Services(self.d, self.s, self.h, keys)
        (self.h / "service-client.json").write_text(json.dumps(s.config()))
        b = Broker(self.h)
        p = b.propose("report", 0, "Service-backed owner workflow")
        import contextlib, io

        with contextlib.redirect_stdout(io.StringIO()):
            b.approve(
                p["proposal_id"], reader=lambda _: "APPROVE " + p["content_sha256"][:12]
            )
        result = b.commit(p["proposal_id"])
        self.assertEqual(result["verification_status"], "local_consistency_verified")
        self.assertEqual(b.commit(p["proposal_id"])["document_version"], 1)
        # Administration is neither forwarded to the service nor run locally
        # by the operator tool on a state that a service owns.
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
        # A home that still names version 1 (mTLS) services is told to reinstall.
        old = dict(version="openproof-service-client/1", receiver={}, witness={})
        (self.h / "service-client.json").write_text(json.dumps(old))
        with self.assertRaisesRegex(RuntimeError, "Reinstall"):
            call(["head", self.h / "receiver/state"])

    def test_trust_updates_are_opt_in_and_keep_role_keys(self):
        def signed(change, step):
            t = ref.read(self.h / "trust.json")
            t["epoch"] += step
            change(t)
            return call(
                ["sign-trust", self.h / "root/key.secret", self.h / "root/signer"], t
            )

        s = self.services = Services(
            self.d, self.s, self.h, accept=False, roles=("receiver",)
        )
        code, body = s.request(
            "receiver", "/v1/install-trust", {"signed": signed(lambda t: None, 1)}
        )
        self.assertEqual(
            (code, body["error"]),
            (400, "Trust updates are not accepted by this operator"),
        )
        s.close()
        s = self.services = Services(self.d, self.s, self.h, roles=("receiver",))
        other = call(["keygen", self.d / "other.secret"])["public_key"]
        code, body = s.request(
            "receiver",
            "/v1/install-trust",
            {"signed": signed(lambda t: t.update(witness=other), 2)},
        )
        self.assertEqual((code, body["error"]), (400, "Role key change refused"))
        epoch = ref.read(self.h / "trust.json")["epoch"] + 3
        code, status = s.request("receiver", "/v1/status", {})
        self.assertEqual((code, status["owner_passkey"]), (200, None))
        # A trust with an owner passkey: the service then reports it itself.
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives import serialization

        point = (
            ec.generate_private_key(ec.SECP256R1())
            .public_key()
            .public_bytes(
                serialization.Encoding.X962,
                serialization.PublicFormat.UncompressedPoint,
            )
            .hex()
        )
        passkey = dict(
            public_key=point,
            rp_id="localhost",
            origin="http://localhost:8765",
            from_sequence=1,
        )
        code, body = s.request(
            "receiver",
            "/v1/install-trust",
            {"signed": signed(lambda t: t.update(owner_passkey=passkey), 3)},
        )
        self.assertEqual((code, body), (200, {"installed_epoch": epoch}))
        code, status = s.request("receiver", "/v1/status", {})
        self.assertEqual((code, status["epoch"]), (200, epoch))
        self.assertEqual(status["owner_passkey"], passkey)
        # The service restarts cleanly from the trust files it wrote, and
        # replaces its own stale socket.
        self.assertEqual(ref.read(self.d / "svc-receiver/trust.json")["epoch"], epoch)
        s.close()
        self.services = Services.__new__(Services)
        self.services.processes = []
        p = serve(
            "receiver",
            self.h / "receiver/state",
            self.h / "receiver/key.secret",
            self.d / "svc-receiver/trust.json",
            self.d / "svc-receiver/trust-signed.json",
            self.s / "receiver.sock",
            [os.getuid()],
        )
        self.services.processes.append(p)
        self.assertIn(b"listening", p.stdout.readline())
        code, body = post(self.s / "receiver.sock", "/v1/head", {})
        self.assertEqual((code, body), (200, {"count": 0}))


if __name__ == "__main__":
    unittest.main()
