# Bounded S3-compatible report pilot

**Local preparation only. No real provider has been contacted or approved.** The current demonstration uses a loopback HTTPS fixture, synthetic report, synthetic credentials and simulated owner approval. It is not a full S3 server or an independent SigV4 verifier. Real provider interoperability remains an acceptance gate.

## What is bound

The original `openproof-storage-upload/1` authorization binds a separately trusted authority, exact HTTPS origin, bucket, object key, SHA-256, UTF-8 byte length, nonce and a validity window of at most 300 seconds. Rust validates and signs it under a distinct OPEC-1 signature domain. Reports are limited to 64 KiB. Object names use a conservative ASCII subset and reject empty/traversal segments. No redirect can expand the approved destination.

The owner approves the captured bytes and full destination. Execution reads that captured copy and rejects changed content or destination. This standalone pilot uses an explicitly supplied authority key; it does not automatically inherit the owner app's signed trust/revocation lifecycle, and it is not exposed as an agent tool. Retiring authority or provider credentials is an operator responsibility. Do not treat this as a production authorization gateway.

## Execution and uncertainty

The adapter uses the pinned official Boto3 SDK with TLS verification, explicit credential environment names, no proxy, path addressing and a conditional `PutObject` with `IfNoneMatch='*'`, exact length and SHA-256 checksum. See [AWS PutObject documentation](https://docs.aws.amazon.com/boto3/latest/reference/services/s3/client/put_object.html). A compatible provider must implement the precondition correctly; no fallback to unconditional writes is allowed.

A durable per-job attempt record is written before dispatch. The SDK is configured for one attempt, and an additional send guard rejects automatic PUT resubmission or destination changes. Any uncertain outcome—including an interruption before sending—leaves the reservation intact. Subsequent execution calls perform read-back only. There is no claim of global nonce enforcement across copied/rolled-back jobs; provider conditional creation and trusted local state remain essential assumptions.

Observations use a separate signature domain and a distinct adapter key:

| Observation | Meaning | Does not establish |
|---|---|---|
| Provider acknowledgment | Adapter reports an HTTP success from its configured TLS endpoint | Independently signed provider receipt, durable retention or object truth |
| Read-back match | Adapter retrieved matching bytes from the same configured provider | Independent custody, continuous persistence, or that this request created a pre-existing object |
| Unconfirmed | No supported successful observation was retained | Proof that no effect occurred |

`storage-verify` verifies adapter statements and their approval binding. It explicitly returns `independent_storage_proof: false`. Neither observation is automatically promoted into a witnessed document execution receipt. Offline recipients must independently trust both public keys.

## Try the local fixture

The storage commands are experimental and are not in the default build.

```sh
cargo build --workspace --locked --features openproof-witness/experimental
outputs/local-venv/bin/python -m pip install -r scripts/requirements.txt
outputs/local-venv/bin/python scripts/storage_demo.py --out outputs/NEW_STORAGE_DEMO
```

Open `demo.html` in that output folder. The demo creates one object and proves the retry path did not issue another PUT. Its public-key copies are convenience data, not independent trust anchors.

## Future approved provider configuration

The configuration fields are `version` (`openproof-storage-config/1`), `endpoint`, `bucket`, `region`, `access_key_env`, `secret_key_env`, `session_token_env` (null when unused), and `ca_file` (null for standard CA verification). Store only environment-variable names, never secret values. Use narrowly scoped credentials for one disposable test bucket/prefix, without list/delete/admin permissions. No credential discovery or metadata-service fallback is needed because access and secret values must be supplied explicitly.

After the owner selects and approves the destination, generate a fresh authority key and a different adapter key using `openproof-witness keygen`, retain their public keys independently, and review a public report:

```sh
outputs/local-venv/bin/python scripts/storage_adapter.py approve \
  --configuration CONFIG.json --source PUBLIC_REPORT.txt --object-key reports/demo.txt \
  --authority-key AUTHORITY.secret --out NEW_PRIVATE_JOB
```

The command requires an interactive exact-digest confirmation. The separate `execute` command requires the job, configuration, independently supplied `--authority` public key and `--adapter-key`. Non-loopback transport additionally requires `--allow-external`; it has not been used during this milestone. `read-back` never dispatches PUT, even without an existing attempt record. Do not paste provider secrets into the chat or distribute job keys.

Before any real-provider claim, test: exact conditional creation, pre-existing matching/different objects, lost replies, unsupported preconditions, redirects/region behavior, read denial, checksum mismatch, version/retention policy and credential retirement. Capture the exact source/SDK/provider versions and results. Provider read-back through the same account still does not satisfy independent operation or human review.
