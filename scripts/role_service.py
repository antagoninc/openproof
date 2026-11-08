#!/usr/bin/env python3
"""Experimental bounded mTLS role transport. Administrative commands stay offline."""

import argparse, hashlib, hmac, json, os, ssl, subprocess, tempfile
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from witness_workflow import call, ref


class NotFound(Exception):
    """A read for a record this role does not hold."""


class RoleServer(HTTPServer):
    request_queue_size = 8

    def __init__(
        self,
        role,
        state,
        key,
        trust,
        signed_trust,
        cert,
        tls_key,
        ca,
        clients,
        host="127.0.0.1",
        port=0,
        tls_bundle=None,
        accept_trust_updates=False,
    ):
        if role not in ["receiver", "witness"]:
            raise ValueError("role")
        self.role = role
        self.state = Path(state)
        self.key = Path(key)
        self.trust = Path(trust)
        self.signed_trust = Path(signed_trust)
        self.accept_trust_updates = accept_trust_updates
        root = call(["role-status", self.state])["root"]
        if not root:
            raise ValueError("Provision a pinned role root before serving")
        expected = call(["trust-payload", root], ref.read(signed_trust))
        if ref.read(self.trust) != expected:
            raise ValueError("Plain trust differs from authenticated trust")
        from certificate_lifecycle import context, active_policy

        self.tls_bundle = tls_bundle
        self.tls_generation = None
        self.policy = (
            active_policy(tls_bundle)[1]
            if tls_bundle
            else context(cert, tls_key, ca, clients)
        )
        super().__init__((host, port), RoleHandler)

    def refresh_tls(self):
        if self.tls_bundle:
            from certificate_lifecycle import active_policy

            self.tls_generation, self.policy = active_policy(self.tls_bundle)
        return self.policy

    def get_request(self):
        sock, addr = super().get_request()
        sock.settimeout(5)
        try:
            wrapped = self.refresh_tls()[0].wrap_socket(sock, server_side=True)
            wrapped.openproof_generation = self.tls_generation
            return wrapped, addr
        except Exception:
            sock.close()
            raise OSError("TLS configuration or handshake rejected") from None

    def install_trust(self, signed):
        """Install a root-signed trust epoch. The role state checks the root
        signature, refuses rollback and refuses to remove or replace a pinned
        owner passkey. This role also refuses a change of role keys."""
        if not self.accept_trust_updates:
            raise ValueError("Trust updates are not accepted by this operator")
        root = call(["role-status", self.state])["root"]
        new = call(["trust-payload", root], signed)
        old = ref.read(self.trust)
        if new["receiver"] != old["receiver"] or new["witness"] != old["witness"]:
            raise ValueError("Role key change refused")
        call(["install-signed", self.state, root], signed)
        for path, data in [(self.signed_trust, signed), (self.trust, new)]:
            pending = path.with_name(path.name + ".pending")
            pending.write_text(json.dumps(data, ensure_ascii=False))
            os.replace(pending, path)
        return {"installed_epoch": new["epoch"]}

    def dispatch(self, path, value):
        if path == "/v1/install-trust":
            ref.fields(value, ["signed"])
            return self.install_trust(value["signed"])
        if path == "/v1/head":
            ref.fields(value, [])
            return call(["head", self.state])
        if path == "/v1/status":
            ref.fields(value, [])
            return call(["role-status", self.state])
        if self.role == "receiver":
            if path == "/v1/document":
                ref.fields(value, ["document"])
                try:
                    return call(["document", self.state, value["document"]])
                except RuntimeError as e:
                    if "no rows" in str(e):
                        raise NotFound("document not found: no rows") from None
                    raise
            if path == "/v1/export":
                ref.fields(value, ["checkpoint"])
                return call(["export", self.state, self.trust], value["checkpoint"])
            if path == "/v1/page-historical":
                ref.fields(value, ["start", "checkpoint", "trust"])
                ref.integer(value["start"])
                # An allowlisted client has read access to this role's history.
                # Caller-supplied historical trust is used only for this read-only
                # export and is never installed or used to authorize an effect.
                with tempfile.NamedTemporaryFile(
                    mode="w+", dir=self.state, prefix="history-", suffix=".json"
                ) as f:
                    json.dump(value["trust"], f)
                    f.flush()
                    return call(
                        ["export-page-historical", self.state, f.name, value["start"]],
                        value["checkpoint"],
                    )
            if path == "/v1/receive":
                ref.fields(value, ["request"])
                return call(
                    ["receive", self.state, self.key, self.trust], value["request"]
                )
            if path == "/v1/recover":
                ref.fields(value, ["request"])
                return call(["recover", self.state], value["request"])
            if path == "/v1/receipt":
                ref.fields(value, ["sequence"])
                ref.integer(value["sequence"])
                return call(["receipt", self.state, value["sequence"]])
            if path == "/v1/page":
                ref.fields(value, ["start", "checkpoint"])
                ref.integer(value["start"])
                return call(
                    ["export-page", self.state, self.trust, value["start"]],
                    value["checkpoint"],
                )
        if self.role == "witness":
            if path == "/v1/witness":
                ref.fields(value, ["receipt"])
                return call(
                    ["witness", self.state, self.key, self.trust], value["receipt"]
                )
            if path == "/v1/checkpoint":
                ref.fields(value, [])
                return call(["checkpoint", self.state, self.key, self.trust])
        raise ValueError("Unknown operation")


class RoleHandler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def reply(self, code, value):
        raw = json.dumps(value).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(raw)

    def do_POST(self):
        certificate = self.connection.getpeercert(binary_form=True)
        fingerprint = hashlib.sha256(certificate).hexdigest()
        try:
            allowed = self.server.refresh_tls()[1]
        except Exception:
            return self.reply(503, {"error": "tls_configuration_unavailable"})
        if (
            getattr(self.connection, "openproof_generation", None)
            != self.server.tls_generation
        ):
            return self.reply(409, {"error": "tls_generation_changed_reconnect"})
        if fingerprint not in allowed:
            return self.reply(403, {"error": "client_not_authorized"})
        try:
            if (
                self.headers.get("Transfer-Encoding")
                or self.headers.get("Content-Type") != "application/json"
            ):
                raise ValueError("encoding")
            size = int(self.headers.get("Content-Length", "0"))
            if not 0 < size <= 1048576:
                raise ValueError("size")
            value = ref.load_bytes(self.rfile.read(size))
            result = self.server.dispatch(self.path, value)
            self.reply(200, result)
        except NotFound as e:
            self.reply(404, {"error": str(e)})
        except (ValueError, KeyError, TypeError):
            self.reply(400, {"error": "invalid_operation"})
        except Exception:
            self.reply(
                409,
                {
                    "error": "operation_unconfirmed",
                    "recovery": "Read the durable receipt for this exact request before retrying or reporting failure.",
                },
            )

    def do_GET(self):
        self.reply(405, {"error": "post_required"})


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ["role", "state", "key", "trust", "signed-trust"]:
        p.add_argument("--" + name, required=True)
    for name in ["cert", "tls-key", "ca"]:
        p.add_argument("--" + name)
    p.add_argument("--tls-bundle")
    p.add_argument("--client-fingerprint", action="append")
    p.add_argument("--bind", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8443)
    p.add_argument(
        "--accept-trust-updates",
        action="store_true",
        help="Install root-signed trust epochs sent by the allowlisted client",
    )
    a = p.parse_args()
    if a.tls_bundle:
        if any([a.cert, a.tls_key, a.ca, a.client_fingerprint]):
            p.error("Use a TLS bundle or manual TLS arguments, not both")
    elif not all([a.cert, a.tls_key, a.ca, a.client_fingerprint]):
        p.error("Provide all manual TLS arguments or --tls-bundle")
    server = RoleServer(
        a.role,
        a.state,
        a.key,
        a.trust,
        a.signed_trust,
        a.cert,
        a.tls_key,
        a.ca,
        a.client_fingerprint,
        a.bind,
        a.port,
        tls_bundle=a.tls_bundle,
        accept_trust_updates=a.accept_trust_updates,
    )
    print(
        "Authenticated "
        + a.role
        + " service listening on "
        + a.bind
        + ":"
        + str(server.server_port),
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
