"""Owner-configured HTTPS role client. No redirects, proxies or caller-selected routes."""

import json, ssl, urllib.request, urllib.parse
from pathlib import Path


def dispatch(home, role, args, value):
    from witness_workflow import ref

    config = ref.read(Path(home) / "service-client.json")
    ref.fields(config, ["version", "receiver", "witness"])
    if config["version"] != "openproof-service-client/1":
        raise ValueError("Unknown service client version")
    target = config[role]
    ref.fields(target, ["url", "ca", "cert", "key"])
    url = urllib.parse.urlsplit(target["url"])
    if (
        url.scheme != "https"
        or not url.hostname
        or url.username
        or url.password
        or url.query
        or url.fragment
        or url.path not in ("", "/")
    ):
        raise ValueError("Explicit HTTPS origin required")
    operation = args[0]
    body = {}
    mapping = {
        "head": "head",
        "role-status": "status",
        "receive": "receive",
        "recover": "recover",
        "witness": "witness",
        "checkpoint": "checkpoint",
        "receipt": "receipt",
        "export": "export",
        "export-page": "page",
        "export-page-historical": "page-historical",
        "document": "document",
    }
    if operation not in mapping:
        raise RuntimeError(
            "Remote role administration must be performed by that operator"
        )
    if operation in ["receive", "recover"]:
        body = {"request": value}
    elif operation == "witness":
        body = {"receipt": value}
    elif operation == "receipt":
        body = {"sequence": int(args[2])}
    elif operation == "document":
        body = {"document": args[2]}
    elif operation == "export":
        body = {"checkpoint": value}
    elif operation in ["export-page", "export-page-historical"]:
        body = {"checkpoint": value, "start": int(args[3])}
        if operation == "export-page-historical":
            body["trust"] = ref.read(args[2])
    context = ssl.create_default_context(cafile=target["ca"])
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.load_cert_chain(target["cert"], target["key"])

    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *args, **kwargs):
            raise RuntimeError("Role service redirect refused")

    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        urllib.request.HTTPSHandler(context=context),
        NoRedirect(),
    )
    request = urllib.request.Request(
        target["url"].rstrip("/") + "/v1/" + mapping[operation],
        data=json.dumps(body, ensure_ascii=False).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with opener.open(request, timeout=10) as response:
        return ref.load_bytes(response.read(ref.MAX + 1))


def initialize_client(home, authority_key, root, signed_trust, configuration):
    """Provision a new owner home without receiver/witness or root private keys."""
    from witness_workflow import call, save, ref
    from owner_rotation import copy_private

    h = Path(home).resolve()
    signed = ref.read(signed_trust)
    trust = call(["trust-payload", root], signed)
    if call(["key-public", authority_key])["public_key"] != trust["authority"]:
        raise ValueError("Authority key does not match signed trust")
    config = ref.read(configuration)
    ref.fields(config, ["version", "receiver", "witness"])
    h.mkdir(mode=0o700, parents=True, exist_ok=False)
    for name in [
        "authority",
        "receiver",
        "witness",
        "evidence",
    ]:
        (h / name).mkdir(mode=0o700)
    copy_private(authority_key, h / "authority/key.secret")
    save(h / "root-public.json", {"public_key": root})
    save(h / "genesis-root.json", {"public_key": root})
    save(h / "trust.json", trust)
    save(h / "trust-signed.json", signed)
    save(h / "service-client.json", config)
    save(h / "paging.json", {"version": 1})
    call(["verifier-init", h / "verifier", root])
    call(["verifier-install", h / "verifier"], signed)
    for role in ["receiver", "witness"]:
        if call(["role-status", h / role / "state"])["root"] != root:
            raise ValueError("Remote root differs from provisioned root")
    return {
        "initialized": str(h),
        "role_private_keys_on_client": False,
        "root_private_key_on_client": False,
    }


if __name__ == "__main__":
    import argparse

    p = argparse.ArgumentParser()
    p.add_argument("--home", required=True)
    p.add_argument("--authority-key", required=True)
    p.add_argument("--root", required=True)
    p.add_argument("--signed-trust", required=True)
    p.add_argument("--configuration", required=True)
    a = p.parse_args()
    print(
        json.dumps(
            initialize_client(
                a.home, a.authority_key, a.root, a.signed_trust, a.configuration
            ),
            indent=2,
        )
    )
