#!/usr/bin/env python3
"""Local owner UI. Loopback only, explicit session, exact review binding, no arbitrary tools."""

import argparse, hashlib, hmac, http.cookies, json, secrets, sys, time, threading, webbrowser, uuid, zipfile, re
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
)
from paged_workflow import enable


class Owner:
    def __init__(self, home):
        self.home = Path(home).resolve()
        self.broker = Broker(home)
        self.token = secrets.token_hex(32)
        self.csrf = secrets.token_hex(32)
        self.reviews = {}
        self.origin = ""

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
            save(self.broker.file("approved", identity), q)
            self.broker.file("proposals", identity).unlink(missing_ok=True)
        return {"status": "approved", "id": identity}


class Server(HTTPServer):
    allow_reuse_address = False

    def __init__(self, owner, port):
        self.owner = owner
        super().__init__(("127.0.0.1", port), Handler)
        owner.origin = "http://127.0.0.1:" + str(self.server_port)

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
    if a.demo and not owner.status()["items"]:
        owner.broker.propose(
            "welcome-report",
            0,
            "Welcome to OpenProof. This public demonstration stores exactly this text in the local receiver database. Review, approve, and execute are separate decisions. No model was called.",
        )
    server = Server(owner, a.port)
    url = server.owner.origin + "/#" + server.owner.token
    if a.session_file:
        save(Path(a.session_file), {"url": url, "pid": __import__("os").getpid()})
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
