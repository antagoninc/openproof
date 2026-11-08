# Trusted code inventory

This file lists the code that OpenProof's guarantees depend on. A defect in a
file listed here can break a guarantee. A defect in a file that is not listed
can break a feature, but not a guarantee. Reviewers and auditors start here.

Counts are non-blank lines at the commit that last changed this file. Test
modules are not counted. Update this file in the same change that adds or
removes trusted code.

## The one path

OpenProof's main path is the witnessed document workflow:

1. An agent **proposes** a change to a document (`openproof-witness mcp`).
2. The owner **reviews** the exact content in the local owner app
   (`openproof-witness owner-app`) and **approves** it. The Rust approval gate
   (`gate.rs`) makes this decision.
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

Everything on the main path is one Rust binary, `openproof-witness`, plus the
owner app page it serves and the separate Go verifier.

| File | Lines | G1 | G2 | G3 | Role |
|---|---:|:-:|:-:|:-:|---|
| `crates/openproof-core/src/lib.rs` | 320 | ✓ | ✓ | | Canonical bytes (OPEC-1), domain-separated Ed25519 signatures, strict parsing |
| `crates/openproof-witness/src/lib.rs` | 766 | ✓ | ✓ | | Trust configuration, approvals, receiver admission and replay state, receipts, witness checkpoints |
| `crates/openproof-witness/src/gate.rs` | 585 | ✓ | | | Approval gate: proposal store, review binding, approval signing, passkey-pending approvals, approved store checked on read |
| `crates/openproof-witness/src/passkey.rs` | 254 | ✓ | | | Owner passkey: trust field validation, WebAuthn assertion check, passkey pin |
| `crates/openproof-witness/src/main.rs` | 468 | ✓ | ✓ | | Command dispatcher, private-key file reads, in-process calls |
| `crates/openproof-witness/src/broker.rs` | 770 | ✓ | ✓ | | Home lock, propose, execute an approved request, witness catch-up, evidence pages, trust epochs, history export |
| `crates/openproof-witness/src/owner_app.rs` | 808 | ✓ | | | Owner app: loopback HTTP, session, CSRF, Host and Origin checks, one-use review and assertion tokens, passkey registration checks |
| `crates/openproof-witness/src/http.rs` | 202 | ✓ | ✓ | | Bounded HTTP/1.1 parsing; strict JSON (no duplicate keys or floats) |
| `crates/openproof-witness/src/mcp.rs` | 138 | ✓ | | | Agent tools: propose and commit only, never approve |
| `crates/openproof-witness/src/pages.rs` | 290 | | ✓ | | Bounded history pages |
| `crates/openproof-witness/src/clock_recovery.rs` | 241 | ✓ | ✓ | | Signed-time floors and clock repair |
| `crates/openproof-witness/src/verifier.rs` | 246 | | ✓ | | Rust history and checkpoint verification |
| `crates/openproof-witness/src/zip.rs` | 72 | | | | Stored ZIP writer for the evidence download (no reader) |
| `app/app.js`, `app/index.html` | 603 | ✓ | | | What the owner sees is what the owner approves; WebAuthn calls |
| `reference/go-witness/main.go`, `archive.go`, `passkey.go` | 752 | | | ✓ | Independent Go verifier of exported histories, including owner assertions |
| `scripts/verify_history.py` | 68 | | | ✓ | Wrapper that runs the independently obtained Go verifier |

Trusted only when separate role accounts are installed ([LOCAL-ROLES.md](LOCAL-ROLES.md)):

| File | Lines | G1 | G2 | G3 | Role |
|---|---:|:-:|:-:|:-:|---|
| `crates/openproof-witness/src/serve.rs` | 372 | ✓ | ✓ | | mTLS role service (rustls, TLS 1.3, client certificate pinned by fingerprint); opt-in trust-epoch install that refuses role-key changes |
| `crates/openproof-witness/src/transport.rs` | 158 | ✓ | ✓ | | Owner-side mTLS client with a fixed operation mapping |
| `scripts/local_roles.py` | 746 | ✓ | ✓ | | Installer: accounts, root-owned binary, writability checks, key and state move, TLS certificates, daemons, uninstall |

Total trusted code: about 5,690 lines of Rust, 600 of JavaScript/HTML, 750 of
Go and 70 of Python: about 7,110 lines. With separate role accounts, add 530
lines of Rust and 750 of Python (the installer, which runs once as root).
The Rust total uses the `p256`, `base64` and `rustls` (with `ring` and
`webpki`) crates as dependencies (not counted here).

The approval decision is in Rust. The gate signs only a stored proposal
whose review binding matches the one the owner app passes back. With a
passkey, the gate stores nothing executable until the owner's assertion over
the approval digest verifies. Limits:

- Without a passkey, code that runs as the owner can still call the gate and
  approve any stored proposal. The gate cannot tell an owner's click from a
  script. Such code can also read `authority/key.secret`.
- The owner app page (`app/`) stays trusted for what the owner sees.

## Outside the trusted code

The experiments that used to be in this tree are kept, unchanged, at the git
tag `experiments-2026-11-08` ([EXPERIMENTS.md](EXPERIMENTS.md)). No guarantee
depends on them.

| Area | Files | Status |
|---|---|---|
| Planned key handover and storage pilot formats | `crates/openproof-witness/src/rotation.rs`, `storage.rs`, `cli_experimental.rs` | Experimental; Cargo feature `experimental`, not in the default build |
| Original v1 action bundles | `crates/openproof-trust`, `crates/openproof-runtime`, `crates/openproof-cli` | Kept for compatibility; not on the main path |
| Python bindings and tools | `scripts/witness_workflow.py`, `scripts/paged_workflow.py`, `scripts/portable_history.py`, `scripts/witness_client.py`, conformance suites, `scripts/validate.py` | Call the binary for tests and tools; the legacy `upgrade-trust` migration stays here |
| Tests | `scripts/tests/`, Rust test modules, `scripts/*_smoke.mjs` | Test material |

## Reduction plan

1. Done. The approval gate is in Rust (`gate.rs`).
2. Done. `rotation.rs`, `storage.rs` and their commands are behind the Cargo
   feature `experimental`, off by default.
3. Done (8 Nov 2026). The owner app, broker, agent tools and role service
   moved from Python to Rust; trusted Python fell from about 1,390 lines to
   70 (plus the role-account installer). The experiments left the tree.
4. Keep the trusted total under about 4,000 lines and record it here. Not
   met: about 7,110 lines. The Rust port added lines while it removed the
   Python interpreter and its packages from the trusted path. Next
   candidates: shrink `owner_app.rs` and `broker.rs`, move the role-account
   installer's certificate generation into Rust, and drop `zip.rs` in favour
   of a plain folder export.
