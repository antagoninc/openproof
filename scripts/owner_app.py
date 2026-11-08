#!/usr/bin/env python3
"""Local owner UI. Loopback only, explicit session, exact review binding, no arbitrary tools."""

import argparse, base64, errno, hashlib, hmac, http.cookies, json, os, secrets, sys, time, threading, webbrowser, uuid, zipfile, re
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from witness_workflow import (
    ROOT,
    Broker,
    initialize,
    call,
    save,
    ref,
    home_lock,
    require_admission,
    enroll_passkey,
)
from paged_workflow import enable, replace_json

RP_ID = "localhost"
FLAG_USER_PRESENT = 0x01
FLAG_USER_VERIFIED = 0x04


def b64encode(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def b64decode(text, limit):
    """Strict base64url without padding, as browsers produce it."""
    if not isinstance(text, str) or not re.fullmatch("[A-Za-z0-9_-]+", text):
        raise ValueError("base64url required")
    raw = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    if b64encode(raw) != text or not 0 < len(raw) <= limit:
        raise ValueError("noncanonical or oversized base64url")
    return raw


def approval_digest(request):
    payload = request["approval"]["payload"]
    preimage = b"OpenProof/v1/document-approval/1\0" + ref.canonical(payload)
    return hashlib.sha256(preimage).hexdigest()


def sec1_point(spki):
    """SPKI DER from getPublicKey() to lowercase hex SEC1 uncompressed P-256."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    key = serialization.load_der_public_key(spki)
    if not isinstance(key, ec.EllipticCurvePublicKey) or key.curve.name != "secp256r1":
        raise ValueError("passkey must be ECDSA P-256")
    raw = key.public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
    )
    return raw.hex()


def client_data(encoded, kind, challenge, origin):
    data = ref.load_bytes(b64decode(encoded, 2048))
    ref.fields(data, ["type", "challenge", "origin"], set(data))
    if data["type"] != kind or data["challenge"] != challenge:
        raise ValueError("passkey challenge rejected")
    if data["origin"] != origin or data.get("crossOrigin", False) is not False:
        raise ValueError("passkey origin rejected")


class Owner:
    def __init__(self, home):
        self.home = Path(home).resolve()
        self.broker = Broker(home)
        self.token = secrets.token_hex(32)
        self.csrf = secrets.token_hex(32)
        self.reviews = {}
        self.registration = None
        self.assertions = {}
        self.origin = ""

    def passkey(self):
        """Owner passkey from the installed trust, plus the stored credential id."""
        configured = ref.read(self.home / "trust.json").get("owner_passkey")
        credential = None
        if configured and (self.home / "passkey.json").exists():
            stored = ref.read(self.home / "passkey.json")
            if stored.get("public_key") == configured["public_key"]:
                credential = stored.get("credential_id")
        return configured, credential

    def passkey_status(self):
        configured, _ = self.passkey()
        return dict(
            configured=bool(configured),
            origin=configured["origin"] if configured else self.origin,
            available=self.origin.startswith("http://" + RP_ID + ":"),
        )

    def register_begin(self):
        with home_lock(self.home):
            require_admission(self.home)
        if self.passkey()[0]:
            raise ValueError("An owner passkey is already set up")
        if not self.origin.startswith("http://" + RP_ID + ":"):
            raise ValueError("Passkeys need the localhost origin")
        challenge = secrets.token_bytes(32)
        self.registration = dict(challenge=b64encode(challenge), time=time.monotonic())
        return dict(
            challenge=self.registration["challenge"],
            rp_id=RP_ID,
            user_id=b64encode(secrets.token_bytes(16)),
            user_name="owner",
        )

    def register_finish(self, v):
        ref.fields(
            v,
            [
                "credential_id",
                "client_data_json",
                "authenticator_data",
                "public_key",
                "algorithm",
            ],
        )
        pending = self.registration
        self.registration = None
        if not pending or time.monotonic() - pending["time"] > 300:
            raise ValueError("Passkey setup expired; start again")
        if v["algorithm"] != -7:
            raise ValueError("Passkey must use ES256")
        client_data(
            v["client_data_json"], "webauthn.create", pending["challenge"], self.origin
        )
        auth = b64decode(v["authenticator_data"], 1024)
        flags = FLAG_USER_PRESENT | FLAG_USER_VERIFIED
        if len(auth) < 37 or auth[:32] != hashlib.sha256(RP_ID.encode()).digest():
            raise ValueError("Passkey relying party rejected")
        if auth[32] & flags != flags:
            raise ValueError("Passkey user verification required")
        b64decode(v["credential_id"], 1023)
        point = sec1_point(b64decode(v["public_key"], 1024))
        result = enroll_passkey(
            self.home, dict(public_key=point, rp_id=RP_ID, origin=self.origin)
        )
        replace_json(
            self.home / "passkey.json",
            dict(credential_id=v["credential_id"], public_key=point),
        )
        return dict(
            status="passkey_installed", installed_epoch=result["installed_epoch"]
        )

    def current_version(self, document):
        """The receiver's current version of a document, 0 when absent."""
        try:
            return call(["document", self.home / "receiver/state", document])["version"]
        except Exception:
            return 0

    def status(self):
        h = self.home
        items = []
        for folder in ["proposals", "approved"]:
            for path in sorted((h / folder).glob("*.json")):
                item = {
                    "id": path.stem,
                    "stage": (
                        "Awaiting approval" if folder == "proposals" else "Approved"
                    ),
                }
                try:
                    value = ref.read(path)
                    p = (
                        value
                        if folder == "proposals"
                        else dict(
                            document=value["approval"]["payload"]["document"],
                            expected_version=value["approval"]["payload"][
                                "expected_version"
                            ],
                            content=value["content"],
                        )
                    )
                    item.update(
                        document=p["document"], expected_version=p["expected_version"]
                    )
                    if folder == "approved":
                        r = call(["recover", h / "receiver/state"], value)
                        if r:
                            item.update(
                                stage="Committed",
                                document_version=r["payload"]["document_version"],
                            )
                        elif (
                            self.current_version(p["document"]) > p["expected_version"]
                        ):
                            # The document moved on after this approval: the
                            # receiver will refuse it, so do not offer Execute.
                            item["stage"] = "Superseded"
                        elif time.time() > value["approval"]["payload"]["expires_at"]:
                            item["stage"] = "Approval expired"
                except Exception:
                    item["stage"] = "Needs recovery"
                items.append(item)
        index = {i["id"]: i for i in items}
        for path in sorted(
            (h / "evidence").glob("*/assessment.json"),
            key=lambda p: p.stat().st_mtime_ns,
        ):
            try:
                a = ref.read(path)
                item = index.get(a["proposal_id"])
                cp = ref.read(path.parent / "checkpoint.json")["payload"]
                fresh = 0 <= time.time() - cp["observed_at"] <= 300
                if (
                    item
                    and a.get("verification_status") == "local_consistency_verified"
                ):
                    item.update(
                        stage="Verified locally" if fresh else "Evidence needs refresh",
                        evidence_id=path.parent.name,
                        complete_history=a.get("complete_history", False),
                        assessment_recorded=True,
                    )
            except Exception:
                pass
        from recovery_center import rotation_status

        rotation = rotation_status(h)
        return dict(
            rotation_resumable=rotation["can_resume"],
            rotation_message=rotation.get("message", ""),
            items=items,
            remote_services=(h / "service-client.json").exists(),
            paging=(h / "paging.json").exists(),
            paused=(h / "rotation-pending.json").exists(),
            passkey=self.passkey_status(),
            scope="Local receiver database; one host owner. Saved assessments are observations, not a fresh independent audit.",
        )

    def review(self, identity):
        with home_lock(self.home):
            require_admission(self.home)
            p = ref.read(self.broker.file("proposals", identity))
        self.reviews = {
            k: v for k, v in self.reviews.items() if time.monotonic() - v["time"] < 300
        }
        if len(self.reviews) >= 100:
            raise ValueError("Too many outstanding reviews")
        token = secrets.token_hex(32)
        digest = hashlib.sha256(ref.canonical(p)).hexdigest()
        self.reviews[token] = dict(
            identity=identity, digest=digest, time=time.monotonic()
        )
        return dict(
            review_token=token,
            proposal=p,
            proposal_sha256=digest,
            content_sha256=hashlib.sha256(p["content"].encode()).hexdigest(),
        )

    def repropose(self, identity):
        with home_lock(self.home):
            require_admission(self.home)
            q = ref.read(self.broker.file("approved", identity))
            if time.time() <= q["approval"]["payload"]["expires_at"]:
                raise ValueError("Approval still active")
            if call(["recover", self.home / "receiver/state"], q) is not None:
                raise ValueError("Recover the committed request instead")
            p = dict(
                document=q["approval"]["payload"]["document"],
                expected_version=q["approval"]["payload"]["expected_version"],
                content=q["content"],
            )
        # Exact expected-version binding prevents a second update if the original
        # commits concurrently after this read. New authorization still requires review.
        return self.broker.propose(**p)

    def approve(self, identity, token):
        review = self.reviews.pop(token, None)
        if (
            not review
            or review["identity"] != identity
            or time.monotonic() - review["time"] > 300
        ):
            raise ValueError("Review expired; review the action again")
        with home_lock(self.home):
            require_admission(self.home)
            p = ref.read(self.broker.file("proposals", identity))
            if hashlib.sha256(ref.canonical(p)).hexdigest() != review["digest"]:
                raise ValueError("Proposal changed; review it again")
            if len(list((self.home / "approved").glob("*.json"))) >= 1000:
                raise ValueError("Approval storage capacity reached")
            q = call(
                [
                    "approve",
                    self.home / "authority/key.secret",
                    self.home / "trust.json",
                ],
                p,
            )
            configured, credential = self.passkey()
            if not configured:
                save(self.broker.file("approved", identity), q)
                self.broker.file("proposals", identity).unlink(missing_ok=True)
                return {"status": "approved", "id": identity}
        # The signed request is held until the owner's passkey signs its digest.
        self.assertions = {
            k: v
            for k, v in self.assertions.items()
            if time.monotonic() - v["time"] < 300
        }
        if len(self.assertions) >= 100:
            raise ValueError("Too many outstanding passkey approvals")
        token = secrets.token_hex(32)
        digest = approval_digest(q)
        self.assertions[token] = dict(
            identity=identity,
            proposal=review["digest"],
            request=q,
            digest=digest,
            time=time.monotonic(),
        )
        return dict(
            status="passkey_required",
            id=identity,
            assertion_token=token,
            approval_sha256=digest,
            challenge=b64encode(bytes.fromhex(digest)),
            rp_id=configured["rp_id"],
            credential_id=credential,
        )

    def approve_passkey(self, identity, token, assertion):
        pending = self.assertions.pop(token, None)
        if (
            not pending
            or pending["identity"] != identity
            or time.monotonic() - pending["time"] > 300
        ):
            raise ValueError("Passkey approval expired; review the action again")
        ref.fields(assertion, ["authenticator_data", "client_data_json", "signature"])
        if not all(isinstance(x, str) for x in assertion.values()):
            raise ValueError("Invalid passkey assertion")
        q = dict(pending["request"], owner_assertion=assertion)
        with home_lock(self.home):
            require_admission(self.home)
            p = ref.read(self.broker.file("proposals", identity))
            if hashlib.sha256(ref.canonical(p)).hexdigest() != pending["proposal"]:
                raise ValueError("Proposal changed; review it again")
            if len(list((self.home / "approved").glob("*.json"))) >= 1000:
                raise ValueError("Approval storage capacity reached")
            checked = call(["check-assertion", self.home / "trust.json"], q)
            if checked["approval_sha256"] != pending["digest"]:
                raise ValueError("Approval digest mismatch")
            save(self.broker.file("approved", identity), q)
            self.broker.file("proposals", identity).unlink(missing_ok=True)
        return {"status": "approved", "id": identity}


class Server(HTTPServer):
    allow_reuse_address = False

    def __init__(self, owner, port):
        self.owner = owner
        # Bind loopback only, but advertise localhost: WebAuthn rejects IP addresses.
        super().__init__(("127.0.0.1", port), Handler)
        owner.origin = "http://" + RP_ID + ":" + str(self.server_port)

    def get_request(self):
        sock, address = super().get_request()
        sock.settimeout(5)
        return sock, address


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass  # Never log session secrets or proposed report bytes.

    def reply(self, code, value, kind="application/json", cookie=False):
        raw = json.dumps(value).encode() if kind == "application/json" else value
        self.send_response(code)
        self.send_header("Content-Type", kind)
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; script-src 'self'; style-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
        )
        if cookie:
            self.send_header(
                "Set-Cookie",
                "openproof_owner="
                + self.server.owner.token
                + "; HttpOnly; SameSite=Strict; Path=/",
            )
        self.end_headers()
        self.wfile.write(raw)

    def authenticated(self):
        try:
            cookie = http.cookies.SimpleCookie(self.headers.get("Cookie", ""))
            return hmac.compare_digest(
                cookie["openproof_owner"].value, self.server.owner.token
            )
        except Exception:
            return False

    def host_ok(self):
        return self.headers.get("Host") == self.server.owner.origin.removeprefix(
            "http://"
        )

    def do_GET(self):
        if not self.host_ok():
            return self.reply(403, {"error": "Host rejected"})
        if self.path in ["/", "/app.js", "/app.css"]:
            name = {"/": "index.html", "/app.js": "app.js", "/app.css": "app.css"}[
                self.path
            ]
            kind = {
                "/": "text/html; charset=utf-8",
                "/app.js": "text/javascript; charset=utf-8",
                "/app.css": "text/css; charset=utf-8",
            }[self.path]
            return self.reply(200, (ROOT / "app" / name).read_bytes(), kind)
        if not self.authenticated():
            return self.reply(401, {"error": "Open this app using its local launcher"})
        try:
            if self.path == "/api/session":
                return self.reply(200, {"csrf": self.server.owner.csrf})
            if self.path == "/api/certificates":
                from recovery_center import certificate_status

                return self.reply(200, certificate_status(self.server.owner.home))
            if self.path == "/api/recovery":
                from recovery_center import inventory

                return self.reply(200, inventory(self.server.owner))
            if self.path == "/api/status":
                return self.reply(200, self.server.owner.status())
            if re.fullmatch(r"/api/download/[0-9a-f]{32}", self.path):
                path = (
                    self.server.owner.home
                    / "exports"
                    / (self.path.rsplit("/", 1)[1] + ".zip")
                )
                if path.is_symlink() or path.stat().st_size > 256 * 1024 * 1024:
                    raise ValueError("archive bound")
                return self.reply(200, path.read_bytes(), "application/zip")
            self.reply(404, {"error": "Unknown route"})
        except Exception:
            self.reply(
                409,
                {
                    "error": "Local state could not be read. Retain evidence and inspect the owner logs."
                },
            )

    def do_POST(self):
        o = self.server.owner
        if not self.host_ok() or self.headers.get("Origin") != o.origin:
            return self.reply(403, {"error": "Origin rejected"})
        try:
            if (
                self.headers.get("Transfer-Encoding")
                or self.headers.get("Content-Type") != "application/json"
            ):
                raise ValueError("Invalid request encoding")
            n = int(self.headers.get("Content-Length", "0"))
            if not 0 < n <= 32768:
                raise ValueError("Request too large or empty")
            v = ref.load_bytes(self.rfile.read(n))
            ref.fields(v, {"token"} if self.path == "/api/session" else set(v))
            if self.path == "/api/session":
                if not isinstance(v["token"], str) or not hmac.compare_digest(
                    v["token"], o.token
                ):
                    return self.reply(403, {"error": "Session rejected"})
                return self.reply(200, {"csrf": o.csrf}, cookie=True)
            if not self.authenticated() or not hmac.compare_digest(
                self.headers.get("X-OpenProof-CSRF", ""), o.csrf
            ):
                return self.reply(403, {"error": "Owner session required"})
            if self.path == "/api/propose":
                ref.fields(v, ["document", "expected_version", "content"])
                result = o.broker.propose(**v)
            elif self.path == "/api/review":
                ref.fields(v, ["id"])
                result = o.review(v["id"])
            elif self.path == "/api/repropose":
                ref.fields(v, ["id"])
                result = o.repropose(v["id"])
            elif self.path == "/api/approve":
                ref.fields(v, ["id", "review_token"])
                result = o.approve(v["id"], v["review_token"])
            elif self.path == "/api/approve/passkey":
                ref.fields(v, ["id", "assertion_token", "assertion"])
                result = o.approve_passkey(
                    v["id"], v["assertion_token"], v["assertion"]
                )
            elif self.path == "/api/passkey/register/begin":
                ref.fields(v, [])
                result = o.register_begin()
            elif self.path == "/api/passkey/register/finish":
                result = o.register_finish(v)
            elif self.path == "/api/commit":
                ref.fields(v, ["id"])
                result = o.broker.commit(v["id"])
                result.pop("evidence_directory", None)
            elif self.path == "/api/recover":
                ref.fields(v, ["id"])
                from recovery_center import recover

                result = recover(o, v["id"])
                result.pop("evidence_directory", None)
            elif self.path == "/api/paging":
                ref.fields(v, [])
                result = enable(o.home)
            elif self.path == "/api/rotation/prepare":
                ref.fields(v, ["confirmation"])
                if v["confirmation"] != "ROTATE LOCAL KEYS":
                    raise ValueError("Explicit owner confirmation required")
                from owner_rotation import prepare

                result = prepare(o.home)
            elif self.path == "/api/rotation/resume":
                ref.fields(v, [])
                from owner_rotation import resume

                result = resume(o.home)
            elif self.path == "/api/archive":
                ref.fields(v, [])
                from portable_history import export_history

                folder = o.home / "exports"
                folder.mkdir(mode=0o700, exist_ok=True)
                if len(list(folder.glob("*.zip"))) >= 20:
                    raise ValueError("Export capacity; archive existing exports first")
                identity = uuid.uuid4().hex
                directory = folder / identity
                export_history(o.home, directory)
                with zipfile.ZipFile(
                    folder / (identity + ".zip"), "x", compression=zipfile.ZIP_DEFLATED
                ) as archive:
                    for path in sorted(directory.iterdir()):
                        archive.write(path, path.name)
                result = {
                    "download": "/api/download/" + identity,
                    "trust_root_included": False,
                }

            else:
                return self.reply(404, {"error": "Unknown route"})
            self.reply(200, result)
        except (ValueError, KeyError, TypeError):
            self.reply(
                409,
                {
                    "error": "Request or review no longer valid. Refresh and review the exact action again."
                },
            )
        except Exception:
            self.reply(
                409,
                {
                    "error": "Operation interrupted. Retry the same approved action to recover its outcome; do not create a replacement approval."
                },
            )


def bind(owner, port):
    """Bind loopback. A fixed port can stay in TIME_WAIT briefly after a restart;
    wait for it instead of setting SO_REUSEADDR."""
    for attempt in range(120):
        try:
            return Server(owner, port)
        except OSError as e:
            if port == 0 or e.errno != errno.EADDRINUSE or attempt == 119:
                raise
            if attempt == 0:
                print("Waiting for port " + str(port) + " to be free…", flush=True)
            time.sleep(1)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--home", default=str(ROOT / "outputs/owner-home"))
    p.add_argument("--port", type=int, default=0)
    p.add_argument("--open", action="store_true")
    p.add_argument("--session-file")
    p.add_argument("--demo", action="store_true")
    a = p.parse_args()
    home = Path(a.home).resolve()
    if not home.exists():
        initialize(home)
        enable(home)
    owner = Owner(home)
    configured, _ = owner.passkey()
    if configured:
        # The passkey is bound to its exact origin, so the port must not change.
        registered = int(configured["origin"].rsplit(":", 1)[1])
        if a.port not in [0, registered]:
            raise SystemExit(
                "The owner passkey is registered for "
                + configured["origin"]
                + "; use --port "
                + str(registered)
            )
        a.port = registered
    if a.demo and not owner.status()["items"]:
        owner.broker.propose(
            "welcome-report",
            0,
            "Welcome to OpenProof. This public demonstration stores exactly this text in the local receiver database. Review, approve, and execute are separate decisions. No model was called.",
        )
    server = bind(owner, a.port)
    url = server.owner.origin + "/#" + server.owner.token
    if a.session_file:
        save(Path(a.session_file), {"url": url, "pid": os.getpid()})
    if a.open:
        webbrowser.open(url)
    print(
        "OpenProof owner app is running at "
        + server.owner.origin
        + " (use --open to establish your owner session).",
        flush=True,
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
