# Trusted code inventory

This file lists the code that OpenProof's guarantees depend on. A defect in a
file listed here can break a guarantee. A defect in a file that is not listed
can break a feature, but not a guarantee. Reviewers and auditors start here.

Counts are non-blank lines at the commit that last changed this file. Test
modules are not counted. Update this file in the same change that adds or
removes trusted code.

## The one path

OpenProof's main path is the witnessed document workflow:

1. An agent **proposes** a change to a document (MCP tool or broker call).
2. The owner **reviews** the exact content in the local owner app and
   **approves** it. The Rust approval gate (`gate.rs`) makes this decision.
   It signs only the stored proposal whose review binding the owner saw.
   Approval signs the exact document, version, content hash, receiver and a
   single-use nonce, valid for at most 10 minutes. With an owner passkey, the
   gate stores the approval only after it verifies the passkey assertion.
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
| G1 | The receiver changes a document only for content, version and receiver that an active authority approved, at most once, before the approval expires. With an owner passkey in the trust, each approval also carries a user-verified passkey assertion over its digest. | An owner passkey is installed ([PASSKEY.md](PASSKEY.md)) and the receiver runs under its own account ([LOCAL-ROLES.md](LOCAL-ROLES.md)). | No passkey is installed and a process that runs as the owner's account reads `authority/key.secret`. With a passkey but without separate role accounts: that process changes the receiver's state directly. In every case: the owner confirms a passkey prompt for content they did not mean to approve, or someone with the administrator password changes the role accounts. |
| G2 | Every receipt is in the witness's signed, ordered history. Omission, reordering or a fork is detected against a trusted checkpoint. | The witness key is held by a party other than the receiver. | The witness runs on the owner's computer. Separate role accounts keep the witness key from the owner account, but the root key is still in the owner home and one administrator controls both accounts. |
| G3 | A third party can verify an exported history offline, without Antagon code other than the Go verifier, given the trusted root and a current checkpoint. | The verifier binary and root are obtained independently of the archive. | The verifier or root comes from the same archive it checks. |

## Trusted code by guarantee

| File | Lines | G1 | G2 | G3 | Role |
|---|---:|:-:|:-:|:-:|---|
| `crates/openproof-core/src/lib.rs` | 320 | ✓ | ✓ | | Canonical bytes (OPEC-1), domain-separated Ed25519 signatures, strict parsing |
| `crates/openproof-witness/src/lib.rs` | 798 | ✓ | ✓ | | Trust configuration, approvals, receiver admission and replay state, receipts, witness checkpoints |
| `crates/openproof-witness/src/gate.rs` | 588 | ✓ | | | Approval gate: proposal store, review binding, approval signing, passkey-pending approvals, approved store checked on read, import of earlier homes |
| `crates/openproof-witness/src/passkey.rs` | 254 | ✓ | | | Owner passkey: trust field validation, WebAuthn assertion check, passkey pin |
| `crates/openproof-witness/src/main.rs` | 391 | ✓ | ✓ | | Command dispatcher; private-key file reads; assertion pre-check |
| `crates/openproof-witness/src/pages.rs` | 290 | | ✓ | | Bounded history pages (enabled by the owner app) |
| `crates/openproof-witness/src/clock_recovery.rs` | 241 | ✓ | ✓ | | Signed-time floors and clock repair |
| `crates/openproof-witness/src/verifier.rs` | 246 | | ✓ | | Rust history and checkpoint verification |
| `scripts/witness_workflow.py` | 582 | ✓ | | | Broker: relays propose, review and approve to the gate; execution steps; key paths; home lock; passkey trust epoch |
| `scripts/owner_app.py` | 580 | ✓ | | | Local owner app: session, CSRF, one-use review token, stale-version refusal, relays approvals and assertions to the gate, passkey registration |
| `app/app.js`, `app/index.html` | 632 | ✓ | | | What the owner sees is what the owner approves; WebAuthn calls |
| `scripts/witness_mcp.py` | 119 | ✓ | | | Agent-facing tools: propose and commit only, never approve |
| `scripts/paged_workflow.py` | 88 | | ✓ | | Enables paging for the owner home |
| `reference/go-witness/main.go`, `archive.go`, `passkey.go` | 752 | | | ✓ | Independent Go verifier of exported histories, including owner assertions |
| `scripts/verify_history.py` | 19 | | | ✓ | Wrapper that runs the independently obtained Go verifier |

Trusted only when separate role accounts are installed ([LOCAL-ROLES.md](LOCAL-ROLES.md)):

| File | Lines | G1 | G2 | G3 | Role |
|---|---:|:-:|:-:|:-:|---|
| `scripts/local_roles.py` | 841 | ✓ | ✓ | | Accounts, root-owned code and runtime, writability checks, key and state move, TLS, daemons, uninstall |
| `scripts/role_service.py` | 251 | ✓ | ✓ | | Bounded mTLS role service; opt-in trust-epoch install that refuses role-key changes |
| `scripts/role_transport.py` | 136 | ✓ | ✓ | | Owner-side mTLS client with fixed operations |
| `scripts/certificate_lifecycle.py` | 259 | ✓ | ✓ | | Server TLS context checks (imported by the role service) |

Total trusted code: about 3,130 lines of Rust, 1,390 of Python, 630 of
JavaScript/HTML and 750 of Go. The Rust total includes the `p256` and
`base64` crates as dependencies (not counted here).

The approval decision is in Rust. The gate signs only a stored proposal
whose review binding matches the one the owner app passes back. With a
passkey, the gate stores nothing executable until the owner's assertion over
the approval digest verifies. Limits:

- Without a passkey, code that runs as the owner can still call the gate and
  approve any stored proposal. The gate cannot tell an owner's click from a
  script. Such code can also read `authority/key.secret`.
- The Python files above stay trusted for what the owner sees (the review
  screen and its binding) and for passkey registration.

## Outside the trusted code

Build the experimental Rust parts with
`cargo build --workspace --locked --features openproof-witness/experimental`.
`scripts/validate.py` builds and tests both the default and the experimental
build, and checks that the default binaries do not contain the experimental
commands.

These parts are useful but no guarantee above depends on them. They are
**experimental** unless stated otherwise. They are not part of the default
story in the README and are excluded from the first human audit scope.

| Area | Files | Status |
|---|---|---|
| Planned key handover (six-party) | `crates/openproof-witness/src/rotation.rs`, `crates/openproof-witness/src/cli_experimental.rs`, `scripts/owner_rotation.py`, `scripts/prepare_rotation.py` | Experimental; Cargo feature `experimental`, not in the default build |
| Storage pilot (S3 conditional create) | `crates/openproof-witness/src/storage.rs`, `crates/openproof-witness/src/cli_experimental.rs`, `scripts/storage_adapter.py`, `scripts/storage_demo.py` | Experimental; Cargo feature `experimental`, not in the default build |
| Remote role services (mTLS) | `scripts/role_service.py`, `scripts/role_transport.py`, `scripts/certificate_lifecycle.py`, `deployment/` | Experimental; trusted when separate role accounts are installed (listed above) or a witness runs remotely |
| Archive retention | `scripts/archive_store.py` | Experimental |
| Isolated report agent | `isolation/`, `scripts/isolated_agent.py`, `scripts/isolation_runner.py`, `scripts/claude_report.py` | Experimental demonstration |
| Comparisons and labs | `scripts/compare_*.py`, `scripts/assurance_lab.py`, `scripts/operations_benchmark.py` | Measurement only |
| Original v1 action bundles | `crates/openproof-trust`, `crates/openproof-runtime`, `crates/openproof-cli` | Kept for compatibility; not on the main path |
| Viewers | `scripts/history_viewer.py`, `scripts/render_evidence.py` | Display only; output is marked unverified |

## Reduction plan

1. Done. The approval gate is in the Rust binary (`gate.rs`, commands
   `gate-propose`, `gate-review`, `gate-approve`, `gate-approve-terminal`,
   `gate-approve-passkey`, `gate-approved`, `gate-list`). `owner_app.py` and
   the broker keep HTTP, session, CSRF and the review token, and relay every
   approval-state change to the gate.
2. Done. `rotation.rs`, `storage.rs` and their commands are behind the Cargo
   feature `experimental`, off by default.
3. Keep the trusted total under about 4,000 lines and record it here. Not
   met: the total is about 5,900 lines, and about 7,390 with separate role
   accounts installed. Step 1 added about 590 lines of Rust
   and removed about 45 lines of Python. Next candidates: move passkey
   registration checks out of `owner_app.py` into Rust, and shrink `lib.rs`.
