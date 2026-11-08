# Trusted code inventory

This file lists the code that OpenProof's guarantees depend on. A defect in a
file listed here can break a guarantee. A defect in a file that is not listed
can break a feature, but not a guarantee. Reviewers and auditors start here.

Counts are non-blank lines at the commit that last changed this file. Update
this file in the same change that adds or removes trusted code.

## The one path

OpenProof's main path is the witnessed document workflow:

1. An agent **proposes** a change to a document (MCP tool or broker call).
2. The owner **reviews** the exact content in the local owner app and
   **approves** it. Approval signs the exact document, version, content hash,
   receiver and a single-use nonce, valid for at most 10 minutes.
3. The owner separately **executes**. The receiver checks the approval,
   applies the change atomically and signs a **receipt**.
4. The **witness** adds the receipt to its signed, hash-linked history and
   signs a **checkpoint**.
5. Anyone holding the trusted root and a checkpoint **verifies** the exported
   history offline with the separate Go verifier.

Everything else in the repository is either support for this path or an
experiment. See "Outside the trusted code" below.

## The guarantees

| ID | Guarantee | Holds today when | Does not hold when |
|---|---|---|---|
| G1 | The receiver changes a document only for content, version and receiver that an active authority approved, at most once, before the approval expires. With an owner passkey in the trust, each approval also carries a user-verified passkey assertion over its digest. | The approving key is out of the agent's reach, or an owner passkey is installed ([PASSKEY.md](PASSKEY.md)). | No passkey is installed and a process that runs as the owner's account reads `authority/key.secret`. With a passkey: that process changes the receiver's state directly (roles share one account), or the owner confirms a passkey prompt for content they did not mean to approve. |
| G2 | Every receipt is in the witness's signed, ordered history. Omission, reordering or a fork is detected against a trusted checkpoint. | The witness key is held by a party other than the receiver. | Today the witness runs under the same account as the receiver. One party can then sign a consistent false history. |
| G3 | A third party can verify an exported history offline, without Antagon code other than the Go verifier, given the trusted root and a current checkpoint. | The verifier binary and root are obtained independently of the archive. | The verifier or root comes from the same archive it checks. |

## Trusted code by guarantee

| File | Lines | G1 | G2 | G3 | Role |
|---|---:|:-:|:-:|:-:|---|
| `crates/openproof-core/src/lib.rs` | 320 | ✓ | ✓ | | Canonical bytes (OPEC-1), domain-separated Ed25519 signatures, strict parsing |
| `crates/openproof-witness/src/lib.rs` | 791 | ✓ | ✓ | | Trust configuration, approvals, receiver admission and replay state, receipts, witness checkpoints |
| `crates/openproof-witness/src/passkey.rs` | 254 | ✓ | | | Owner passkey: trust field validation, WebAuthn assertion check, passkey pin (tests excluded from the count) |
| `crates/openproof-witness/src/main.rs` | 452 | ✓ | ✓ | | Command dispatcher; private-key file reads; approval signing; assertion pre-check |
| `crates/openproof-witness/src/pages.rs` | 290 | | ✓ | | Bounded history pages (enabled by the owner app) |
| `crates/openproof-witness/src/clock_recovery.rs` | 241 | ✓ | ✓ | | Signed-time floors and clock repair |
| `crates/openproof-witness/src/verifier.rs` | 246 | | ✓ | | Rust history and checkpoint verification |
| `scripts/witness_workflow.py` | 596 | ✓ | | | Broker: proposal, approval and execution steps; key paths; home lock; passkey trust epoch |
| `scripts/owner_app.py` | 577 | ✓ | | | Local owner app: session, CSRF, exact review token, approval route, passkey registration and assertion |
| `app/app.js`, `app/index.html` | 609 | ✓ | | | What the owner sees is what the owner approves; WebAuthn calls |
| `scripts/witness_mcp.py` | 119 | ✓ | | | Agent-facing tools: propose and commit only, never approve |
| `scripts/paged_workflow.py` | 88 | | ✓ | | Enables paging for the owner home |
| `reference/go-witness/main.go`, `archive.go`, `passkey.go` | 752 | | | ✓ | Independent Go verifier of exported histories, including owner assertions |
| `scripts/verify_history.py` | 19 | | | ✓ | Wrapper that runs the independently obtained Go verifier |

Total trusted code: about 2,600 lines of Rust, 1,400 of Python, 610 of
JavaScript/HTML and 750 of Go. The Rust total now includes the `p256` and
`base64` crates as dependencies (not counted here).

## Outside the trusted code

These parts are useful but no guarantee above depends on them. They are
**experimental** unless stated otherwise. They are not part of the default
story in the README and are excluded from the first human audit scope.

| Area | Files | Status |
|---|---|---|
| Planned key handover (six-party) | `crates/openproof-witness/src/rotation.rs`, `scripts/owner_rotation.py`, `scripts/prepare_rotation.py` | Experimental |
| Storage pilot (S3 conditional create) | `crates/openproof-witness/src/storage.rs`, `scripts/storage_adapter.py`, `scripts/storage_demo.py` | Experimental |
| Remote role services (mTLS) | `scripts/role_service.py`, `scripts/role_transport.py`, `scripts/certificate_lifecycle.py`, `deployment/` | Experimental; becomes trusted when a witness runs remotely |
| Archive retention | `scripts/archive_store.py` | Experimental |
| Isolated report agent | `isolation/`, `scripts/isolated_agent.py`, `scripts/isolation_runner.py`, `scripts/claude_report.py` | Experimental demonstration |
| Comparisons and labs | `scripts/compare_*.py`, `scripts/assurance_lab.py`, `scripts/operations_benchmark.py` | Measurement only |
| Original v1 action bundles | `crates/openproof-trust`, `crates/openproof-runtime`, `crates/openproof-cli` | Kept for compatibility; not on the main path |
| Viewers | `scripts/history_viewer.py`, `scripts/render_evidence.py` | Display only; output is marked unverified |

## Reduction plan

1. Move the approval gate (`owner_app.py` approval route and the broker's
   approve step) into a Rust binary, so the most exposed trusted code is also
   the most reviewable.
2. Put `rotation.rs` and `storage.rs` behind a Cargo feature that is off by
   default, so the default witness binary does not contain them.
3. Keep the trusted total under about 4,000 lines and record it here.
