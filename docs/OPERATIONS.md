# Daily operations and measured limits

The recovery center and TLS generation tools are experimental local operator tools. They do not establish independent administration, provide emergency compromised-key recovery, or replace a human review.

## Recovery center

Select **Check recovery** in the owner workspace. It reports receiver/witness sequence counts, saved-checkpoint age, exact approved actions and planned handover state. These are observations of configured state, not a fresh proof that no newer event exists.

**Recover existing result** is available only when a durable receiver receipt was found. The server uses a receipt-only broker path that refuses dispatch if the receipt is absent, even if the browser's earlier observation is stale. It may deliver existing receipts to the witness and refresh verification evidence. Approval and execution remain separate owner decisions in Activity.

- Committed but unwitnessed: recover the exact approved action; do not create replacement approval.
- Approved but uncommitted: no recovery button; execution is a separate decision.
- Expired and uncommitted: review a new proposal separately, retaining the original evidence.
- Stale checkpoint: refresh existing evidence through recovery and obtain a current independent pin before sharing verification claims.
- Planned handover: resume only the retained plan within its supported window, or reconcile publication when all stores already applied it. Expired partial transitions remain paused for operator review. Never remove the pause file, reset trust, or improvise rollback.
- Unreadable state or unavailable service: report uncertainty; do not assume failure means no effect.

CLI equivalent:

```sh
outputs/local-venv/bin/python scripts/recovery_center.py OWNER_HOME
outputs/local-venv/bin/python scripts/recovery_center.py OWNER_HOME --recover APPROVED_ACTION_ID
```

## Certificate health

The owner workspace warns on startup when its configured client/CA certificates are expiring, expired, not yet valid or unreadable. Recovery inspection shows dates and fingerprints without private-key contents or configuration paths. This inspects locally configured certificates; it does not fetch remote server certificates or certify chain/hostname authorization. Remote operators must monitor their own leaf certificates and complete CA chains.

```sh
outputs/local-venv/bin/python scripts/certificate_lifecycle.py inspect CERTIFICATE.pem --warning-days 30
outputs/local-venv/bin/python scripts/certificate_lifecycle.py check --directory PRIVATE_TLS_BUNDLE
```

Exit zero means currently valid outside the warning window; warnings and invalid inputs return nonzero. Inspect reports are local observations. TLS still performs peer certificate and hostname verification on connections.

## Staged TLS renewal and client replacement

TLS configuration is distinct from evidence-signing keys. These tools do not issue certificates, rotate signing roles or automate a CA. Obtain replacement certificates from the selected operator's CA with appropriate SANs, server/client usages and validity dates. Keep unencrypted TLS private keys owner-readable only (`0600`) and bundle directories private (`0700`). Protect the bundle under the service account's custody; do not copy development keys.

1. Stage the server certificate, matching key, client CA bundle and explicit client certificate fingerprints. For an overlap period include both old and replacement client fingerprints, each as its own repeated flag.

```sh
outputs/local-venv/bin/python scripts/certificate_lifecycle.py stage \
  --directory PRIVATE_TLS_BUNDLE --cert NEW_SERVER.pem --key NEW_SERVER.key \
  --ca CLIENT_CA.pem --client-fingerprint OLD_CLIENT_SHA256 \
  --client-fingerprint NEW_CLIENT_SHA256
```

2. Retain the returned generation and expected-current values. Staging validates dates, key matching, server usage, CA basic constraints, permissions and hashes. It does **not** prove that a remote client trusts the server chain or hostname; test those connections before retirement. Intermediate server chains may be included; local inspection reports the first leaf, while peer TLS verification checks the chain.
3. Explicitly activate that exact generation, supplying the previously observed generation (or `none` for first activation). A stale expectation rejects concurrent changes.

```sh
outputs/local-venv/bin/python scripts/certificate_lifecycle.py activate \
  --directory PRIVATE_TLS_BUNDLE --generation STAGED_GENERATION \
  --expected-current PREVIOUS_GENERATION_OR_none
```

4. Run the role service with `--tls-bundle PRIVATE_TLS_BUNDLE` instead of manual `--cert`, `--tls-key`, `--ca` and `--client-fingerprint` arguments. All ordinary role/state/trust arguments remain required. The service revalidates the active generation before admitting a connection and before each authorized operation. A generation change requires an existing connection to reconnect. Invalid active files cause connection rejection, without silently falling back to old authorization or stopping the accept loop.
5. Test both clients, then update the owner-controlled service-client configuration to the replacement client credentials. Use the operator's private configuration-change procedure; there is no agent-facing credential editor.
6. Stage and activate a second generation containing only the replacement client fingerprint. Confirm the retired client is denied and the new client succeeds. Record hashes, identities, times and results. Retain old generation records securely for diagnosis; do not automatically reactivate them, since that can restore retired permissions.

The atomic pointer uses flushed files and a directory sync. Process-level tests cover stage failure, stale activation, live overlap, server certificate replacement, retirement, held connections and corrupt active configuration. Power-loss durability, remote CA lifecycle, HSM custody, automated revocation distribution and independently administered deployment remain separate acceptance gates.

## Reproducible measurements

```sh
outputs/local-venv/bin/python scripts/operations_benchmark.py \
  --go-binary outputs/tooling/openproof-go-verify --samples 64 \
  --content-bytes 1024 --concurrency 1 4 8 --out outputs/NEW_BENCHMARK
```

Run with other local campaigns stopped. The report records OS, architecture, logical CPU count, binary hashes, samples, median/p95 latency, observed throughput, stored/archive bytes and maximum child-process peak RSS. This memory metric is the largest child process over the invocation, **not** the sum of concurrent memory or resident service memory. Rust is the existing debug executable; Python process startup and the broker's serialization are included. Approval preparation is outside timing. Offline verification uses five warm-cache checks.

The workload uses independent synthetic documents and locally generated test anchors. Benchmark archives are not independent witness evidence. No performance SLO, internet-scale claim or safe production capacity follows from these small measurements. Storage growth includes local retained evidence; no automatic pruning is implemented. A longer-lived deployment must measure archival and retention behavior on its own hosts.

Current explicit prototype bounds include 8 KiB document content, 32 receipts per page, 512 KiB serialized pages, 1 MiB transport input, a serialized broker and bounded evidence admission. These are implementation bounds, not measured service capacities. Do not raise them without tests and review.

## Longer adversarial campaigns

```sh
outputs/local-venv/bin/python scripts/fuzz_campaign.py --targets witness_state \
  --seconds 900 --workers 1 --seed 20261109 --out outputs/NEW_FUZZ_RUN
outputs/local-venv/bin/python scripts/recovery_campaign.py --cycles 60 \
  --seed 20261109 --out outputs/NEW_CRASH_RUN
```

Use fresh output directories and at least 3 GiB free disk. Retain failing inputs and logs; do not auto-fix, reset real state or delete unrelated data. Recovery campaigns inject process exits after actual receive, witness and page-verification CLI calls, then recover exact approvals and assert one durable version. They do not simulate arbitrary torn writes, kernel crashes or physical power loss. Bounded fuzz sequences are measured coverage, not evidence that no vulnerabilities exist.

The owner selected weekly Monday 3 a.m. local checks in the desktop app. Availability depends on that app and computer being able to run scheduled work. The recurring task uses disposable state only and does not publish, contact reviewers, call model services or alter operational certificates/trust.
