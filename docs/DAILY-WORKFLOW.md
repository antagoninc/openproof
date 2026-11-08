# OpenProof daily workflow · v0.6

Review a report, authorize its exact bytes, execute the bounded action, and take its evidence elsewhere. This remains a local experimental tool. The Rust gate owns authorization enforcement, trust checks, durable nonce consumption and artifact receipts. Python provides the operator workflow and independent verification.

## Start in one command

From the project folder, with Rust, Python 3.11+ and a running local Docker engine:

```sh
python3 scripts/openproof.py setup
```

Setup creates a project-local environment, installs pinned Python dependencies, builds the Rust workspace, and builds the minimal worker image. It may download public dependencies and images. It does not invoke Claude, publish anything, or copy your home/source tree into a container. Existing output folders and keys are never repurposed as a run.

```sh
outputs/local-venv/bin/python scripts/openproof.py doctor
outputs/local-venv/bin/python scripts/openproof.py run --provider fixture
outputs/local-venv/bin/python scripts/openproof.py history
```

`doctor` reports local readiness and whether an API credential is configured, never its value. Runtime inspection remains authoritative: readiness is not certification. Runs get new folders under `outputs/runs/`; `--out` can select another new folder.

## Review before signing

`run` requires an interactive terminal. It displays the exact captured UTF-8 report as a JSON string, its byte length and SHA-256, `artifact.write`, the fixed `urn:openproof:artifact` resource, and the destination directory. Unicode/control characters are escaped so report content cannot control the terminal. The final job name is derived from a newly generated nonce; the worker cannot choose it.

Type the displayed `APPROVE <digest-prefix>` phrase to continue. Anything else cancels before key generation, signed authorization or execution. Report bytes are captured in memory before the prompt and those same bytes are hashed for authorization. Editing `proposal.txt` does not change the approved action; returned changed bytes are rejected by the Rust gate. The approval observation records the full digest. It is a local host observation, not a cryptographic proof of a person's identity. There is no reusable approval token or delayed approval queue.

For a real report, configure `ANTHROPIC_API_KEY` in your environment and use `--provider claude`. This makes a paid report-generation request **before** the execution approval prompt; execution approval does not approve or cancel an already-made model call. Only the fixed public project summary is sent. Fixture mode is the default and has no model cost.

Historical, for an experiment (kept at the git tag `experiments-2026-11-08`): The underlying `isolated_agent.py --approval demo` remains an explicit automated regression/demo path. It is not the daily human-approval path and must not be exposed as a human-approval enforcing endpoint. All host scripts and configuration remain trusted. The demo exercises denied variants before the allowed request; it is not a general agent tool service.

## Failure and recovery

| Situation | Behavior | Next action |
|---|---|---|
| Approval declined | No signed authorization or state | Review/revise and create a new run |
| Docker missing or unreachable | Readiness rejects daily run before provider call | Start/fix local Docker; rerun readiness |
| Worker crashes, hangs, floods output | No returned request accepted; removal and absence checked | Inspect error and worker cleanup |
| Host interrupted normally | Cleanup runs; no automatic dispatch retry | Inspect existing state |
| Removal cannot be confirmed | Explicit error names container; run does not report success | Inspect/remove that specific container after checking it |
| Crash after nonce reservation | Nonce stays consumed, potentially indeterminate | Inspect artifacts and state; never replay automatically |
| Evidence expired or altered | Fresh verification fails | Obtain appropriate fresh signed trust material; do not change clocks to force green status |

```sh
target/debug/openproof doctor outputs/runs/RUN/state
target/debug/openproof state outputs/runs/RUN/state
```

A new run is a new authorization, not recovery of an uncertain earlier effect. Preserve the original folder. SIGKILL, host power loss and daemon failure cannot guarantee Python cleanup; process-crash tests do not prove hardware durability. No autonomous recovery/retry is implemented.

The worker explicitly requests Docker's built-in seccomp profile, checks that selection in container configuration, and checks `Seccomp: 2` and `NoNewPrivs: 1` in its own kernel status before processing input. These are observed/configured restrictions under a trusted image/daemon/kernel, not independent attestation or proof against escapes. References: [Docker seccomp](https://docs.docker.com/engine/security/seccomp/) and [Docker container options](https://docs.docker.com/reference/cli/docker/container/run/).

## Export and independently verify

```sh
outputs/local-venv/bin/python scripts/openproof.py export outputs/runs/RUN --out outputs/evidence.json
outputs/local-venv/bin/python scripts/openproof.py verify outputs/evidence.json --anchor /path/to/trusted-anchor.json
```

The original `openproof-portable/1` envelope contains only bundle, context, signed trust snapshot and base64 output. It has no executable code, absolute paths, API key, private keys, replay database or embedded root anchor. Export is packaging, not verification: even expired evidence can be retained, but verification rejects a stale snapshot. The JSON envelope is capped at 1 MiB; this deliberately supports small reports, not arbitrary artifact sizes.

Obtain the root anchor through an independently trusted channel and pin its audience and minimum revision. Copying `anchor.json` from the same unknown sender as the evidence does **not** establish independent trust. For this local demonstration the owner can provision the generated root as a test anchor; that is not an external identity certificate. Signed context is checked through the chain and role snapshot; consumers must also decide whether that authenticated action is the particular action they intended to accept.

On another machine, copy the public verifier files with this layout, install the pinned `cryptography` dependency, then verify offline:

```text
scripts/portable.py
reference/python/openproof_ref.py
reference/python/openproof_trust.py
reference/python/requirements.txt
evidence.json
```

```sh
python3 -m pip install -r reference/python/requirements.txt
python3 scripts/portable.py evidence.json --anchor /separately/provisioned/anchor.json
```

No Docker, Rust binary, original run directory, network or model API is needed for verification once dependencies are installed. Local tests verify in an independent Linux container with network disabled and the anchor supplied separately. This tests cross-environment portability, not a second physical machine or independently audited verifier.

## History and freshness

`history` lists at most the newest 200 directory names, verifies available evidence again against each run-local anchor, and labels incomplete/expired/altered records. It never treats a saved check or green HTML as current proof. The HTML viewer remains a static snapshot: open it to inspect the report and evidence, regenerate it for fresh verification. Demo snapshots expire after one hour. Historical verification still requires a fresh snapshot and does not create a trusted timestamp.

## Repeat the checks

```sh
outputs/local-venv/bin/python -m unittest discover -s scripts/tests -v
outputs/local-venv/bin/python scripts/check_fuzz_lock.py
outputs/local-venv/bin/python scripts/exercise_isolation.py --image-id-file outputs/local-worker/image-id
outputs/local-venv/bin/python scripts/validate.py --out outputs/new-validation --isolation-image-id-file outputs/local-worker/image-id
```

The failure suite uses synthetic crash/hang/flood jobs and interrupts a host process; no model calls. The validation pipeline also runs existing Rust concurrency/crash/replay tests and rejects shared fuzz/build dependency drift. A matching lockfile does not by itself establish fuzz coverage: run a new bounded fuzz campaign after changes.

The completed v0.5 review is retained unchanged. These v0.6 changes require their own independent review before stronger security claims or release. Nothing is published by these commands.
