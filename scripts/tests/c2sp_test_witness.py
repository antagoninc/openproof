"""A minimal C2SP witness for tests, written from c2sp.org/tlog-witness,
c2sp.org/signed-note and c2sp.org/tlog-cosignature. It is not OpenProof code and
shares none: it checks the log's note signature and the RFC 6962 consistency proof
on its own, and cosigns with Ed25519 (type 0x04). The CI interop job checks the
same flow against litewitness, an independent implementation."""

import base64, hashlib, struct, threading, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

DASH = "— "


def key_id(name, kind, public):
    return hashlib.sha256(name.encode() + b"\n" + bytes([kind]) + public).digest()[:4]


def vkey(name, kind, public):
    return "%s+%s+%s" % (
        name,
        key_id(name, kind, public).hex(),
        base64.b64encode(bytes([kind]) + public).decode(),
    )


def node(l, r):
    return hashlib.sha256(b"\x01" + l + r).digest()


def consistent(old, new, old_root, new_root, proof):
    """RFC 9162 section 2.1.4.2."""
    if old > new:
        return False
    if old == new:
        return not proof and old_root == new_root
    if old == 0:
        return not proof
    path = ([old_root] if old & (old - 1) == 0 else []) + list(proof)
    if not path:
        return False
    fn, sn = old - 1, new - 1
    while fn & 1:
        fn >>= 1
        sn >>= 1
    fr = sr = path[0]
    for c in path[1:]:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            fr, sr = node(c, fr), node(c, sr)
            if not fn & 1:
                while not fn & 1 and fn:
                    fn >>= 1
                    sn >>= 1
        else:
            sr = node(sr, c)
        fn >>= 1
        sn >>= 1
    return fr == old_root and sr == new_root and sn == 0


class Witness:
    def __init__(self, name="witness.test/1"):
        self.name = name
        self.key = Ed25519PrivateKey.generate()
        self.public = self.key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        self.logs = {}  # origin -> (log public key, size, root)
        self.lock = threading.Lock()

    @property
    def vkey(self):
        return vkey(self.name, 0x04, self.public)

    def add_log(self, origin, log_vkey):
        name, kid, key = log_vkey.split("+", 2)
        raw = base64.b64decode(key)
        assert (
            name == origin and raw[0] == 0x01 and key_id(name, 1, raw[1:]).hex() == kid
        )
        self.logs[origin] = (raw[1:], 0, hashlib.sha256(b"").digest())

    def handle(self, text):
        """Returns (status, content type, body) for an add-checkpoint request."""
        head, _, note = text.partition("\n\n")
        lines = head.split("\n")
        if not lines[0].startswith("old "):
            return 400, "text/plain", "missing old"
        old = int(lines[0][4:])
        proof = [base64.b64decode(l) for l in lines[1:] if l]
        body, _, sigs = note.partition("\n\n")
        body += "\n"
        origin, size, root = body.split("\n")[:3]
        size, root = int(size), base64.b64decode(root)
        if origin not in self.logs:
            return 404, "text/plain", "unknown log"
        public, have, have_root = self.logs[origin]
        trusted = False
        for line in sigs.splitlines():
            name, _, b64 = line[len(DASH) :].partition(" ")
            raw = base64.b64decode(b64)
            if name == origin and raw[:4] == key_id(origin, 1, public):
                try:
                    Ed25519PublicKey.from_public_bytes(public).verify(
                        raw[4:], body.encode()
                    )
                    trusted = True
                except InvalidSignature:
                    pass
        if not trusted:
            return 403, "text/plain", "no trusted signature"
        if old > size:
            return 400, "text/plain", "old beyond size"
        if old != have:
            return 409, "text/x.tlog.size", "%d\n" % have
        if not consistent(old, size, have_root, root, proof):
            return 422, "text/plain", "inconsistent"
        self.logs[origin] = (public, size, root)
        ts = int(time.time())
        msg = ("cosignature/v1\ntime %d\n" % ts + body).encode()
        sig = (
            key_id(self.name, 4, self.public)
            + struct.pack(">Q", ts)
            + self.key.sign(msg)
        )
        return (
            200,
            "text/plain",
            "%s%s %s\n" % (DASH, self.name, base64.b64encode(sig).decode()),
        )

    def serve(self):
        witness = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                text = self.rfile.read(int(self.headers["Content-Length"])).decode()
                with witness.lock:
                    status, kind, body = (
                        witness.handle(text)
                        if self.path.endswith("/add-checkpoint")
                        else (404, "text/plain", "")
                    )
                self.send_response(status)
                self.send_header("Content-Type", kind)
                self.end_headers()
                self.wfile.write(body.encode())

            def log_message(self, *a):
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        return server, "http://127.0.0.1:%d" % server.server_address[1]
