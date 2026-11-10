# OpenProof owner workspace · v0.9

## Start on this Mac

Double-click **Open OpenProof.command** in the project folder. The launcher runs the existing local Python environment and opens an authenticated browser session. It creates a private development home under `outputs/owner-home` on first use, with paging enabled. Keep the terminal open; Control-C stops the app. Reopen the launcher after a restart. Keys and state remain in the home.

From a terminal:

```sh
cargo build --workspace --locked
target/debug/openproof-witness owner-app --home outputs/owner-home --open
```

The app listens only on `127.0.0.1`, on two ports, with addresses `http://localhost:PORT` because passkeys do not work on IP addresses. The review origin is the passkey's: it serves only the review page and the passkey set-up page. Its port is the one given with `--port`, or an automatically selected one; once an owner passkey is set up, the app always uses the registered port ([PASSKEY.md](PASSKEY.md)). The workspace runs on a second, automatically selected port, and the launcher's link opens it. An assertion obtained on the workspace origin is refused, so only the review origin's pages can approve ([TCB.md](TCB.md)). It is an owner interface for a trusted local account/browser, not a multi-user or remotely hosted administration service. The first URL establishes a secret session and is removed from browser history by the page. Do not share session URLs or session files. There is no analytics, external font, CDN, external model call, or remote asset dependency.

## Daily flow

1. Enter the exact document content and expected current version. Creating a proposal grants no permission.
2. Review the document, version, full content and content digest on the review page. It is a separate page (`/review`) that loads only `review.js`, `approval.js`, `common.js` and `base.css`, never the workspace's code. It computes the content digest itself. It also shows, for display only, the lines the change adds and removes against the receiver's current text; the approval binds the proposal alone. The review token expires after five minutes and can be used only once. Changing any proposal field invalidates it.
3. Approve, then separately choose execution. The Rust approval gate makes the approval decision. It signs only the stored proposal with the review binding that you saw. With a passkey, the review page first checks the signed approval against what it shows and computes the passkey challenge itself, and the gate stores the approval only after it verifies your passkey assertion ([PASSKEY.md](PASSKEY.md)). The receiver checks the signed content/version/nonce binding and the assertion, and commits its own document database and receipt atomically.
4. Use **Recover / refresh** on the same action after an interruption. Durable recovery precedes new dispatch. A committed update with unavailable evidence is not reported as fully verified.
5. An expired, uncommitted approval can be proposed for fresh review. The app first checks for a durable receipt; it never automatically grants new authorization. Exact expected-version binding still prevents two updates if the original commits concurrently.

The workspace lists what needs the owner (review, execute, recover) apart from the history of executed and closed actions, with each action's progress through proposed, approved, executed and checked. It follows the system light or dark setting. The activity list displays recorded local assessments and marks old checkpoints as needing refresh. Opening the list does not independently reverify every historical signature. Committed and checked counters overlap because they describe stages of the same action. A signature is not proof of model truth, physical-world effects or operator independence.

The UI's writes require its owner session, same-origin request, correct Host and an anti-CSRF header. Browsers do not scope cookies by port, so the session cookie is also sent to other local web servers on `localhost` that the browser visits; that exposes the session, not approvals, which need the passkey on the review origin. Reports are rendered as text, never executable HTML. The browser session remains a high-trust owner capability. Other processes with the same account/Docker administration are outside this isolation boundary. Do not expose the owner app through a reverse proxy or tunnel.

## Where proposals and approvals are kept

The approval gate keeps proposals, passkey-pending approvals and approved requests in `HOME/authority/gate/gate.db` (SQLite, private directory and file, no links). Earlier homes kept them as JSON files in `HOME/proposals/` and `HOME/approved/`. The gate imports those files once, when it first opens the home. After that it does not read those folders, and a file added there has no effect. The import leaves the files in place. The gate checks every approved request again when it reads it: a valid signature from a known authority, the exact content, the proposal that its id commits to, and a valid passkey assertion if it carries one.

## Incremental evidence and archival

New homes use bounded pages. Existing homes can explicitly enable paging from the app. The first use replays retained history into stream verification; subsequent commits process only new receipts. Pages are saved before verifier advancement, so a lost response can resume from durable state. A matching final checkpoint is required before a local verification result. Storage remains bounded: 1,000 approved entries, 1,000 evidence directories and the existing logical evidence budget. No private record is silently deleted to recover capacity.

**Export evidence** writes a portable, public-evidence-only directory and ZIP under the selected home's `exports` directory. It replays retained epochs from genesis, including planned handovers. No root trust anchor, signing key, environment file or database is included. The checkpoint copy in the archive is convenience data; a recipient must obtain a trusted root and current checkpoint separately. Exports are capped at 4,096 entries/1 MiB per entry in the independent verifier, with a 256 MiB aggregate verifier bound. The UI limits retained ZIP exports to 20. Export does not prune live state or approved records. Owner-approved physical storage migration/pruning remains separate work.

```sh
outputs/v0.9/openproof-go-verify verify-archive \
  SEPARATELY_TRUSTED_GENESIS_ROOT CURRENT_CHECKPOINT.json EXTRACTED_ARCHIVE UNIX_TIME
```

For a live check use the actual current Unix time. The final checkpoint must be within five minutes. Historical epochs are checked at their signed checkpoint times, with monotonic epoch/configuration rules, preserved nonces/document versions, current issuer eligibility, six-party transition signatures and root continuity. The final independently provided checkpoint must match exactly. The Go verifier does not call Rust. It reconstructs the archive in memory; it is not a second persistent database verifier and cannot detect rollback if the caller also supplies an old checkpoint and invented time.

## Planned local key change

The owner app no longer offers a planned key change. The earlier Python controller is kept at the git tag `experiments-2026-11-08` ([EXPERIMENTS.md](EXPERIMENTS.md)). The Rust handover formats stay behind the `experimental` Cargo feature.

## Verification records

See `outputs/v0.9/VALIDATION.md` for measured results. Browser fixtures use simulated human approval of public synthetic content; they do not authorize or publish a real report. The UI, paging controller, archive verifier, handover controller and transport need a fresh external human review. Earlier reviews do not cover these additions.

## Trust renewal and role services

Local development trust lasts one day. Run `openproof-witness renew HOME` before resuming after expiry; renewal retains keys and history. With [separate role accounts](LOCAL-ROLES.md), the owner home holds a `service-client.json` and the binary sends every role command to the role services over their Unix sockets; renewal and passkey set-up reach them through the services' opt-in trust update. Remote role services over TLS are no longer part of this tree ([EXPERIMENTS.md](EXPERIMENTS.md)).
