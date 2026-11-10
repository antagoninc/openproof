"""Test client for the Rust owner app: starts `openproof-witness owner-app`
for one home and drives it over HTTP like the browser does."""

import http.client, json, subprocess, sys, time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
from witness_workflow import BINARY, Broker, ref

# Requests that only the review origin (the passkey's) serves.
REVIEW = {"review", "approve", "approve/passkey", "passkey/register/begin"}
REVIEW.add("passkey/register/finish")


class OwnerClient:
    def __init__(self, home, port=0, session_name="session.json"):
        self.home = Path(home).resolve()
        self.broker = Broker(self.home)
        self.session_file = self.home.parent / (
            session_name + "-" + str(time.time_ns())
        )
        self.process = subprocess.Popen(
            [
                str(BINARY),
                "owner-app",
                "--home",
                str(self.home),
                "--port",
                str(port),
                "--session-file",
                str(self.session_file),
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
        )
        for _ in range(300):
            if self.session_file.exists() and self.session_file.stat().st_size:
                break
            if self.process.poll() is not None:
                raise RuntimeError(self.process.stderr.read().decode())
            time.sleep(0.05)
        session = json.loads(self.session_file.read_text())
        self.origin, self.token = session["url"].split("/#")
        self.port = int(self.origin.rsplit(":", 1)[1])
        self.review_origin = session["review_origin"]
        self.review_port = int(self.review_origin.rsplit(":", 1)[1])
        status, data = self.post("session", {"token": self.token}, auth=False)
        if status != 200:
            raise RuntimeError(data)
        self.csrf = data["csrf"]

    def close(self):
        self.process.kill()
        self.process.wait()
        self.process.stderr.close()

    def request(self, method, path, body=None, headers=None, origin=None):
        origin = origin or self.origin
        port = int(origin.rsplit(":", 1)[1])
        c = http.client.HTTPConnection("127.0.0.1", port, timeout=60)
        h = {"Host": origin.removeprefix("http://")}
        h.update(headers or {})
        c.request(method, path, body, h)
        r = c.getresponse()
        data = r.read()
        c.close()
        return r.status, r.getheaders(), data

    def post(self, path, body, extra=None, auth=True):
        origin = self.review_origin if path in REVIEW else self.origin
        headers = {"Origin": origin, "Content-Type": "application/json"}
        if auth:
            headers["Cookie"] = "openproof_owner=" + self.token
            headers["X-OpenProof-CSRF"] = self.csrf
        headers.update(extra or {})
        status, _, data = self.request(
            "POST", "/api/" + path, json.dumps(body), headers, origin
        )
        return status, json.loads(data)

    def call(self, path, body):
        status, data = self.post(path, body)
        if status != 200:
            raise ValueError(data.get("error"))
        return data

    def get(self, path):
        status, _, data = self.request(
            "GET", "/api/" + path, headers={"Cookie": "openproof_owner=" + self.token}
        )
        if status != 200:
            raise ValueError(json.loads(data).get("error"))
        return json.loads(data)

    def propose(self, document, expected_version, content):
        return self.call(
            "propose",
            dict(document=document, expected_version=expected_version, content=content),
        )

    def review(self, identity):
        return self.call("review", {"id": identity})

    def approve(self, identity, token):
        return self.call("approve", {"id": identity, "review_token": token})

    def approve_passkey(self, identity, token, assertion):
        return self.call(
            "approve/passkey",
            {"id": identity, "assertion_token": token, "assertion": assertion},
        )

    def register_begin(self):
        return self.call("passkey/register/begin", {})

    def register_finish(self, value):
        return self.call("passkey/register/finish", value)

    def current_version(self, document):
        return self.call("current-version", {"document": document})["version"]

    def status(self):
        return self.get("status")

    def commit(self, identity):
        return self.call("commit", {"id": identity})

    def passkey(self):
        configured = ref.read(self.home / "trust.json").get("owner_passkey")
        credential = None
        if configured and (self.home / "passkey.json").exists():
            stored = ref.read(self.home / "passkey.json")
            if stored.get("public_key") == configured["public_key"]:
                credential = stored.get("credential_id")
        return configured, credential
