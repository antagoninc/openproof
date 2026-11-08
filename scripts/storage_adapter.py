#!/usr/bin/env python3
"""Bounded S3 conditional creation. Default transport is loopback HTTPS only."""

import argparse, base64, hashlib, json, os, stat, time, urllib.parse, uuid
from pathlib import Path
from witness_workflow import call, ref, save, home_lock

LIMIT = 65536


def report_bytes(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as f:
        if not stat.S_ISREG(os.fstat(f.fileno()).st_mode):
            raise ValueError("Regular report file required")
        raw = f.read(LIMIT + 1)
    if not 1 <= len(raw) <= LIMIT:
        raise ValueError("Report must be 1..65536 bytes")
    raw.decode("utf-8")
    return raw


def config(path):
    c = ref.read(path)
    ref.fields(
        c,
        [
            "version",
            "endpoint",
            "bucket",
            "region",
            "access_key_env",
            "secret_key_env",
            "session_token_env",
            "ca_file",
        ],
    )
    if c["version"] != "openproof-storage-config/1":
        raise ValueError("Unknown storage configuration")
    for k in ["access_key_env", "secret_key_env"]:
        if not isinstance(c[k], str) or not __import__("re").fullmatch(
            "[A-Z][A-Z0-9_]{0,79}", c[k]
        ):
            raise ValueError("Explicit credential environment names required")
    if c["session_token_env"] is not None and not __import__("re").fullmatch(
        "[A-Z][A-Z0-9_]{0,79}", c["session_token_env"]
    ):
        raise ValueError("Token environment name")
    if not isinstance(c["region"], str) or not __import__("re").fullmatch(
        "[a-z0-9-]{1,40}", c["region"]
    ):
        raise ValueError("Explicit region required")
    return c


def capture(configuration, source, object_key, secret, out, reader=input):
    c = config(configuration)
    raw = report_bytes(source)
    authority = call(["key-public", secret])["public_key"]
    now = int(time.time())
    p = {
        "version": "openproof-storage-upload/1",
        "authority": authority,
        "endpoint": c["endpoint"],
        "bucket": c["bucket"],
        "object_key": object_key,
        "content_sha256": hashlib.sha256(raw).hexdigest(),
        "content_bytes": len(raw),
        "nonce": uuid.uuid4().hex + uuid.uuid4().hex,
        "not_before": now,
        "expires_at": now + 300,
    }
    # Review captured bytes, destination and length. Reading the source again after
    # approval could substitute different bytes, so only this captured copy is saved.
    print(
        json.dumps(
            {
                "destination": {k: p[k] for k in ["endpoint", "bucket", "object_key"]},
                "content_sha256": p["content_sha256"],
                "content_bytes": len(raw),
                "report": raw.decode(),
            },
            indent=2,
        )
    )
    confirmation = "UPLOAD " + hashlib.sha256(ref.canonical(p)).hexdigest()
    if (
        reader(
            "Type " + confirmation + " to approve this exact destination and report: "
        )
        != confirmation
    ):
        raise ValueError("Owner approval declined")
    authorization = call(["storage-authorize", secret], p)
    out = Path(out).resolve()
    out.mkdir(parents=True, exist_ok=False, mode=0o700)
    fd = os.open(out / "report.txt", os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(raw)
        f.flush()
        os.fsync(f.fileno())
    save(out / "authorization.json", authorization)
    return {
        "job": str(out),
        "authorization_sha256": call(["storage-check", authority], authorization)[
            "authorization_sha256"
        ],
    }


def client(c, object_key, allow_external=False):
    import boto3
    from botocore.config import Config

    origin = urllib.parse.urlsplit(c["endpoint"])
    if (
        origin.scheme != "https"
        or origin.path
        or origin.query
        or origin.fragment
        or origin.username
        or origin.password
    ):
        raise ValueError("HTTPS origin required")
    if not allow_external and origin.hostname != "127.0.0.1":
        raise ValueError(
            "External transport disabled; only loopback fixtures are permitted by default"
        )
    credentials = {
        "aws_access_key_id": os.environ[c["access_key_env"]],
        "aws_secret_access_key": os.environ[c["secret_key_env"]],
    }
    if not all(credentials.values()):
        raise ValueError("Empty credentials")
    if c["session_token_env"]:
        credentials["aws_session_token"] = os.environ[c["session_token_env"]]
    result = boto3.client(
        "s3",
        region_name=c["region"],
        endpoint_url=c["endpoint"],
        verify=c["ca_file"] or True,
        config=Config(
            signature_version="s3v4",
            connect_timeout=5,
            read_timeout=5,
            retries={"total_max_attempts": 1},
            proxies={},
            s3={"addressing_style": "path"},
        ),
        **credentials,
    )
    expected = c["endpoint"] + "/" + c["bucket"] + "/" + object_key
    sent = {"put": False}

    def scope(request, **kwargs):
        if request.method not in ["PUT", "GET"] or request.url != expected:
            raise ValueError("Redirect or destination change refused")
        if request.method == "PUT":
            if sent["put"]:
                raise ValueError("Automatic PUT resubmission refused")
            sent["put"] = True

    result.meta.events.register("before-send.s3", scope)
    return result


def execute(
    job, configuration, authority, adapter_key, allow_external=False, read_only=False
):
    job = Path(job).resolve()
    c = config(configuration)
    with home_lock(job):
        a = ref.read(job / "authorization.json")
        p = a["payload"]
        raw = report_bytes(job / "report.txt")
        if (
            p["endpoint"] != c["endpoint"]
            or p["bucket"] != c["bucket"]
            or p["content_sha256"] != hashlib.sha256(raw).hexdigest()
            or p["content_bytes"] != len(raw)
        ):
            raise ValueError("Approved destination or bytes changed")
        attempt = job / "attempt.json"
        prior = attempt.exists()
        mode = "storage-check-history" if prior or read_only else "storage-check"
        digest = call([mode, authority], a)["authorization_sha256"]
        if prior and ref.read(attempt)["authorization_sha256"] != digest:
            raise ValueError("Attempt binding mismatch")
        s3 = client(c, p["object_key"], allow_external)
        adapter = call(["key-public", adapter_key])["public_key"]
        observations = []
        if adapter == authority:
            raise ValueError("Use a distinct adapter signing key")

        def observe(kind, started):
            value = {
                "version": "openproof-storage-observation/1",
                "adapter": adapter,
                "authorization_sha256": digest,
                "kind": kind,
                "request_started_at": started,
                "observed_at": int(time.time()),
            }
            signed = call(["storage-observe", adapter_key], value)
            bundle = {"authorization": a, "observation": signed}
            call(["storage-verify", authority, adapter], bundle)
            name = "observation-" + uuid.uuid4().hex + ".json"
            save(job / name, bundle)
            observations.append(name)

        acknowledged = False
        start = int(time.time())
        if not prior and not read_only:
            # Durable reservation is never cleared or automatically retried. A crash
            # before dispatch also stays uncertain; read-back cannot prove causation.
            save(attempt, {"authorization_sha256": digest, "request_started_at": start})
            fd = os.open(job, os.O_RDONLY)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
            # Recheck freshness immediately before the network call.
            call(["storage-check", authority], a)
            try:
                response = s3.put_object(
                    Bucket=p["bucket"],
                    Key=p["object_key"],
                    Body=raw,
                    ContentLength=len(raw),
                    ContentType="text/plain; charset=utf-8",
                    IfNoneMatch="*",
                    ChecksumSHA256=base64.b64encode(
                        hashlib.sha256(raw).digest()
                    ).decode(),
                )
                if response["ResponseMetadata"]["HTTPStatusCode"] == 200:
                    observe("provider_acknowledgment", start)
                    acknowledged = True
            except Exception:
                pass  # Outcome uncertain; no second PUT, including on 409/412.
        matched = False
        start = int(time.time())
        try:
            response = s3.get_object(Bucket=p["bucket"], Key=p["object_key"])
            body = response["Body"]
            try:
                observed = body.read(LIMIT + 1)
            finally:
                body.close()
            candidate = (
                len(observed) == p["content_bytes"]
                and hashlib.sha256(observed).hexdigest() == p["content_sha256"]
            )
            if candidate:
                observe("read_back_match", start)
                matched = True
        except Exception:
            pass
        result = {
            "status": (
                "read_back_match"
                if matched
                else (
                    "provider_acknowledged_read_back_unconfirmed"
                    if acknowledged
                    else "outcome_unconfirmed"
                )
            ),
            "put_attempted_this_call": not prior and not read_only,
            "provider_acknowledged_this_call": acknowledged,
            "read_back_matches": matched,
            "observations": observations,
            "independent_storage_proof": False,
            "causation_proven": False,
            "scope": "Adapter observations through the configured TLS endpoint; same-provider read-back is not independent evidence or proof this request created the object.",
        }
        save(job / ("result-" + uuid.uuid4().hex + ".json"), result)
        return result


def main():
    p = argparse.ArgumentParser(description=__doc__)
    s = p.add_subparsers(dest="cmd", required=True)
    a = s.add_parser("approve")
    a.add_argument("--source", required=True)
    a.add_argument("--object-key", required=True)
    a.add_argument("--authority-key", required=True)
    a.add_argument("--out", required=True)
    for name in ["execute", "read-back"]:
        a = s.add_parser(name)
        a.add_argument("--job", required=True)
        a.add_argument("--authority", required=True)
        a.add_argument("--adapter-key", required=True)
        a.add_argument("--allow-external", action="store_true")
    for a in s.choices.values():
        a.add_argument("--configuration", required=True)
    a = p.parse_args()
    if a.cmd == "approve":
        if not __import__("sys").stdin.isatty():
            raise ValueError("Interactive owner review required")
        result = capture(
            a.configuration, a.source, a.object_key, a.authority_key, a.out
        )
    else:
        result = execute(
            a.job,
            a.configuration,
            a.authority,
            a.adapter_key,
            a.allow_external,
            a.cmd == "read-back",
        )
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
