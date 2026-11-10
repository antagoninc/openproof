# Trusted code inventory

This file lists the code that OpenProof's guarantees depend on. A file is
trusted for a guarantee when a defect in it can break that guarantee under the
condition in which the guarantee is said to hold. A defect in a file that is not
listed can break a feature, or make OpenProof refuse to act, but not break a
guarantee. Reviewers and auditors start here.

`scripts/tcb_count.py` makes the counts below: non-blank lines, without Rust
test modules or Go test files. Validation runs it with `--check`, which fails
when the total is over the budget in that script (4,750 lines), when a source
file of the trusted crates is not listed, when a trusted crate depends on
another workspace crate, when the review origin serves or loads a file that is
not listed, or when the totals in this file differ from the count. Update this file in the same change that adds or removes trusted code.

## The one path

OpenProof's main path is the witnessed document workflow:

1. An agent **proposes** a change to a document (`openproof-witness mcp`).
2. The owner **reviews** the exact content on the owner app's review page,
   on the passkey's own origin, and **approves** it. The Rust approval gate (`gate.rs`) signs only the stored
   proposal whose review binding the owner saw. Approval signs the exact
   document, version, content hash, receiver and a single-use nonce, valid for
   at most 10 minutes. With an owner passkey, the review page checks the
   signed approval against what it shows, computes the passkey challenge from
   it, and the gate stores the approval only after it verifies the assertion.
3. The owner separately **executes**. The receiver checks the approval and the
   assertion, applies the change atomically and signs a **receipt**.
4. The **witness** adds the receipt to its signed, hash-linked history and
   signs a **checkpoint**.
5. Anyone holding the trusted root and a checkpoint **verifies** the exported
   history offline with the separate Go verifier.

With separate role accounts, the receiver and the witness run as
`openproof-role serve` under their own accounts. The owner's binary,
`openproof-witness`, reaches them only through their Unix sockets.

## The guarantees

| ID | Guarantee | Holds today when | Does not hold when |
|---|---|---|---|
| G1 | The receiver changes a document only for content, version and receiver that an active authority approved, at most once, before the approval expires. With an owner passkey in the trust, each approval also carries a user-verified passkey assertion over its digest. | An owner passkey is installed ([PASSKEY.md](PASSKEY.md)) and the receiver runs under its own account ([LOCAL-ROLES.md](LOCAL-ROLES.md)). `local_roles.py status` shows both: `"separated": true` and `"passkey_required_by_receiver": true`. | No passkey is installed and a process that runs as the owner's account reads `authority/key.secret`. With a passkey but without separate role accounts: that process changes the receiver's state directly. In every case: the owner confirms a passkey prompt for content they did not mean to approve, or someone with the administrator password changes the role accounts. |
| G2 | Every receipt is in the witness's signed, ordered history. Omission, reordering or a fork is detected against a trusted checkpoint. | The witness key is held by a party other than the receiver. | The witness runs on the owner's computer. Separate role accounts keep the witness key from the owner account, but the root key is still in the owner home and one administrator controls both accounts. |
| G3 | A third party can verify an exported history offline, without Antagon code other than the Go verifier, given the trusted root and a current checkpoint. | The verifier binary and root are obtained independently of the archive. | The verifier or root comes from the same archive it checks. |

## Why the owner's side is not trusted

Under G1's condition, the receiver runs under its own account and checks every
request it is sent, whoever sends it: an active authority's signature over the
exact content hash, document, version and receiver; the validity window; the
single-use nonce; and an assertion from the owner passkey over that approval's
digest (`admit_owner_assertion` in `apply`). The assertion must come from the
passkey's registered origin. The trust the receiver admits under is installed
only with a root signature, and a later trust can neither remove nor replace
the passkey (`pin_owner_passkey`).

So code that runs as the owner can propose, block, delay or send bytes, but
cannot get a change admitted that the passkey did not sign. That holds for the
owner app's server, the broker, the approval gate, the MCP tools, the client
that talks to the role services, and `openproof-tool`.

Two things the receiver cannot check, and how they are closed:

- **That the owner saw what the passkey signs.** The authenticator shows no
  content. The review page keeps its own copy of the proposal it shows. Before
  any passkey prompt it checks the signed approval against that copy: the
  document, the version, the content hash it computes itself, a window of at
  most 10 minutes that, by the page's clock, has started (within a minute) and
  not ended. Then it
  computes the approval digest itself (`app/approval.js`) and uses it as the
  passkey challenge. The server never chooses it. The page shows the full new
  text first. Its line diff compares against the current text that the server
  reports, which the page cannot check; the page says so.
- **That no other page asks the passkey.** Any script on the passkey's origin
  can ask for an assertion. So the owner app serves two origins on two ports.
  The review origin is the passkey's: it serves only the review page, the
  passkey set-up page, their modules and their requests (`REVIEW_FILES` and
  `REVIEW_POSTS` in `owner_app.rs`). The workspace (dashboard) runs on the
  other origin. An assertion that a workspace script obtains carries the
  workspace origin, and the gate and the receiver refuse it. The workspace
  cannot read or script the review page's document, and both send
  `Cross-Origin-Opener-Policy: same-origin` and allow no workers or frames.

So the review origin's code is trusted for what the owner sees, and the server
is not, except the origin tables and the page table between the `TCB:` markers
in `owner_app.rs`.

The passkey set-up page runs on the review origin, so it is listed. The
server's enrollment code is not: a defect there installs a key that no
authenticator matches (then no approval succeeds, which the owner sees at
once) or installs no passkey (which `status` shows, below). A defect alone
cannot install a key that someone else holds; only an attacker in the owner's
account at set-up time can. Set up the passkey on a computer you trust at that
time.

`local_roles.py status` is the check of G1's condition. It uses the Python
standard library only and asks the role services directly on their sockets:
the receiver service reports the passkey from the trust it enforces. Install
keeps a root-owned copy of the script in `BASE/libexec`. Run `status` from that
copy with the system Python. Code in the owner's account can still change what
the owner's own terminal shows, so the check that does not depend on that
account is `status` run by the administrator ([LOCAL-ROLES.md](LOCAL-ROLES.md)).

These limits stay: code that controls the owner's browser or account can
change what the screen shows, and the owner can confirm a prompt for content
they did not mean to approve. See the G1 row above.

## Trusted code by guarantee

| File | Lines | G1 | G2 | G3 | Role |
|---|---:|:-:|:-:|:-:|---|
| `crates/openproof-core/src/lib.rs` | 320 | ✓ | ✓ | | Canonical bytes (OPEC-1), domain-separated Ed25519 signatures, strict parsing |
| `crates/openproof-receiver/src/lib.rs` | 642 | ✓ | ✓ | | Trust, approvals, receiver admission and replay state, receipts, witness checkpoints, export |
| `crates/openproof-receiver/src/passkey.rs` | 255 | ✓ | | | Owner passkey: trust field validation, WebAuthn assertion check, passkey pin |
| `crates/openproof-receiver/src/roles.rs` | 72 | ✓ | ✓ | | Root-signed trust install for a role state; verified export |
| `crates/openproof-receiver/src/pages.rs` | 82 | ✓ | ✓ | | Bounded history pages; the paged store bound inside admission |
| `crates/openproof-receiver/src/tlog.rs` | 198 | | ✓ | | The history as an RFC 6962 tree; C2SP checkpoints signed by the witness key |
| `crates/openproof-receiver/src/clock.rs` | 9 | ✓ | ✓ | | The signing clock floor |
| `crates/openproof-receiver/src/http.rs` | 197 | ✓ | ✓ | | Bounded HTTP/1.1 parsing; strict JSON (no duplicate keys or floats) |
| `crates/openproof-receiver/src/keys.rs` | 45 | ✓ | ✓ | | Private key and bounded file reads |
| `crates/openproof-receiver/src/files.rs` | 35 | ✓ | ✓ | | New and atomically replaced private files |
| `crates/openproof-role/src/main.rs` | 381 | ✓ | ✓ | | The role service: Unix socket, peer account check, fixed operations, opt-in trust install that refuses role-key changes |
| `scripts/local_roles.py` | 837 | ✓ | | | Installer (runs once as root): accounts, root-owned role binary, writability checks, a copy of the owner's role files made without following links, key and state move, daemons, uninstall; `status` |
| `app/review.html`, `app/review.js` | 298 | ✓ | | | The review page: what the owner sees and approves |
| `app/approval.js` | 122 | ✓ | | | The approval check and the passkey challenge, in the page |
| `app/common.js` | 86 | ✓ | | | Requests and text-only rendering for the review origin's pages |
| `app/setup.html`, `app/setup.js` | 105 | ✓ | | | The passkey set-up page, on the review origin |
| `crates/openproof-witness/src/owner_app.rs`, `TCB:` regions | 70 | ✓ | | | The two origins and what each serves, the page table, the content security policy |
| `reference/go-witness/main.go`, `archive.go`, `passkey.go`, `tlog.go` | 921 | | | ✓ | Independent Go verifier of exported histories, including owner assertions and, when given, a quorum of witness cosignatures over the whole history |
| `scripts/verify_history.py` | 68 | | | ✓ | Wrapper that runs the independently obtained Go verifier |

Totals: G1 3,556 lines, G2 1,981, G3 989. Files shared between guarantees
count in each. **Total trusted code: 4,743 lines**, down from about 9,700 under
G1's condition before this change (8,370 listed, plus 1,350 for the role
accounts).

As before, style sheets are listed apart and not counted: the review origin's
`app/base.css` (484 lines) is trusted for what the owner sees. The workspace's
`app/app.css` is not.

Not counted, as before: the Rust dependencies `rusqlite` (with bundled SQLite),
`ed25519-dalek`, `p256`, `sha2`, `serde`, `serde_json`, `base64`, `hex`,
`rand_core`, `zeroize` and `libc`; the Go standard library and
`filippo.io/edwards25519`; the browser. `rustls` and `ring` are no longer used.

The trusted Rust forbids `unsafe` code, except one function in
`openproof-role`: `peer_uid`, which reads the connecting account with
`getsockopt(SO_PEERCRED)` on Linux and `getpeereid` on macOS.

## Outside the trusted code

| Area | Files | Why a defect cannot break a guarantee |
|---|---|---|
| Owner side | `crates/openproof-witness` (`gate.rs`, `broker.rs`, `owner_app.rs` outside its `TCB:` regions, `mcp.rs`, `transport.rs`, `zip.rs`, `verifier.rs`, `pages.rs`, `clock_recovery.rs`, `tlog.rs`) | The receiver checks every request it admits; the review page checks every approval before the passkey signs it |
| Operator and test commands | `openproof-tool` (`crates/openproof-witness/src/bin/openproof-tool/`) | Not on the main path, never run by the role services. It refuses a role state that a role service owns. `approve` there signs without the gate's review binding; the receiver refuses such a request when a passkey is in force |
| Workspace pages | `app/index.html`, `app/app.js`, `app/app.css` | They run on the workspace origin: an assertion obtained there is refused, and they cannot script the review origin's pages |
| Witness network submitter | `scripts/tlog_submit.py` | It only carries bytes; cosignatures are checked when saved and again by the Go verifier ([WITNESS-NETWORK.md](WITNESS-NETWORK.md)) |
| Planned key handover and storage pilot formats | `crates/openproof-witness/src/rotation.rs`, `storage.rs`, `openproof-tool` experimental commands | Experimental; Cargo feature `experimental`, not in the default build |
| Original v1 action bundles | `crates/openproof-trust`, `crates/openproof-runtime`, `crates/openproof-cli` | Kept for compatibility; not on the main path |
| Python bindings and tools | `scripts/witness_workflow.py`, `scripts/paged_workflow.py`, `scripts/portable_history.py`, `scripts/witness_client.py`, conformance suites, `scripts/validate.py` | They call the binaries for tests and tools |
| TRACE link | `integrations/trace/` | No guarantee depends on it |
| Tests | `scripts/tests/`, Rust test modules, `scripts/*_smoke.mjs`, `scripts/browser_cdp.mjs` | Test material |

The experiments that used to be in this tree are kept, unchanged, at the git
tag `experiments-2026-11-08`, and the TLS role service at commit `51c0978`
([EXPERIMENTS.md](EXPERIMENTS.md)).

## Reduction history

1. Done. The approval gate is in Rust (`gate.rs`).
2. Done. `rotation.rs`, `storage.rs` and their commands are behind the Cargo
   feature `experimental`, off by default.
3. Done (8 Nov 2026). The owner app, broker, agent tools and role service
   moved from Python to Rust. The experiments left the tree.
4. Done (10 Nov 2026), about 9,700 lines to 4,743:
   - The review page checks what the passkey signs and computes the challenge
     itself. It runs on the passkey's origin, which serves nothing else but
     the set-up page; the workspace has its own origin. The owner app's
     server, the broker and the gate left the trusted list.
   - The receiver and the witness moved to their own crate,
     `openproof-receiver`, and the role services to their own binary,
     `openproof-role`. The root-owned binary no longer contains the owner app,
     the broker, the gate or the operator commands.
   - Operator and test commands moved to `openproof-tool`, which is not
     installed. The installed binaries no longer contain `approve`, which signs
     without a review binding.
   - The role services use Unix sockets with a kernel-checked peer account
     instead of loopback TLS. `rustls`, `ring` and the installer's
     `cryptography` package left the trusted path. `local_roles.py` uses the
     Python standard library only, never runs code from the checkout as root,
     never follows a link in the owner home, and `status` runs from a
     root-owned copy.
5. Open. The aim is under 4,000 lines. Next candidates: a smaller installer
   (`local_roles.py`, 837 lines, the largest trusted file after the receiver)
   and the full-package export bound inside admission in
   `openproof-receiver/src/lib.rs`.
