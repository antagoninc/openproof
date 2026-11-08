# OpenProof owner workspace · v0.9

## Start on this Mac

Double-click **Open OpenProof.command** in the project folder. The launcher runs the existing local Python environment and opens an authenticated browser session. It creates a private development home under `outputs/owner-home` on first use, with paging enabled. Keep the terminal open; Control-C stops the app. Reopen the launcher after a restart. Keys and state remain in the home.

From a terminal:

```sh
cargo build --workspace --locked
outputs/local-venv/bin/python scripts/owner_app.py --open
```

The app listens only on `127.0.0.1`, on an automatically selected port. It is an owner interface for a trusted local account/browser, not a multi-user or remotely hosted administration service. The first URL establishes a secret session and is removed from browser history by the page. Do not share session URLs or session files. There is no analytics, external font, CDN, external model call, or remote asset dependency.

## Daily flow

1. Enter the exact document content and expected current version. Creating a proposal grants no permission.
2. Review the document, version, full content and content digest. The review token expires after five minutes and can be used only once. Changing any proposal field invalidates it.
3. Approve, then separately choose execution. The receiver checks the signed content/version/nonce binding and commits its own document database and receipt atomically.
4. Use **Recover / refresh** on the same action after an interruption. Durable recovery precedes new dispatch. A committed update with unavailable evidence is not reported as fully verified.
5. An expired, uncommitted approval can be proposed for fresh review. The app first checks for a durable receipt; it never automatically grants new authorization. Exact expected-version binding still prevents two updates if the original commits concurrently.

The activity list displays recorded local assessments and marks old checkpoints as needing refresh. Opening the list does not independently reverify every historical signature. Committed and checked counters overlap because they describe stages of the same action. A signature is not proof of model truth, physical-world effects or operator independence.

The UI's writes require its owner session, same-origin request, correct Host and an anti-CSRF header. Reports are rendered as text, never executable HTML. The browser session remains a high-trust owner capability. Other processes with the same account/Docker administration are outside this isolation boundary. Do not expose the owner app through a reverse proxy or tunnel.

## Incremental evidence and archival

New homes use bounded pages. Existing homes can explicitly enable paging from the app. The first use replays retained history into stream verification; subsequent commits process only new receipts. Pages are saved before verifier advancement, so a lost response can resume from durable state. A matching final checkpoint is required before a local verification result. Storage remains bounded: 1,000 approved entries, 1,000 evidence directories and the existing logical evidence budget. No private record is silently deleted to recover capacity.

**Export evidence** writes a portable, public-evidence-only directory and ZIP under the selected home's `exports` directory. It replays retained epochs from genesis, including planned handovers. No root trust anchor, signing key, environment file or database is included. The checkpoint copy in the archive is convenience data; a recipient must obtain a trusted root and current checkpoint separately. Exports are capped at 4,096 entries/1 MiB per entry in the independent verifier, with a 256 MiB aggregate verifier bound. The UI limits retained ZIP exports to 20. Export does not prune live state or approved records. Owner-approved physical storage migration/pruning remains separate work.

```sh
outputs/v0.9/openproof-go-verify verify-archive \
  SEPARATELY_TRUSTED_GENESIS_ROOT CURRENT_CHECKPOINT.json EXTRACTED_ARCHIVE UNIX_TIME
```

For a live check use the actual current Unix time. The final checkpoint must be within five minutes. Historical epochs are checked at their signed checkpoint times, with monotonic epoch/configuration rules, preserved nonces/document versions, current issuer eligibility, six-party transition signatures and root continuity. The final independently provided checkpoint must match exactly. The Go verifier does not call Rust. It reconstructs the archive in memory; it is not a second persistent database verifier and cannot detect rollback if the caller also supplies an old checkpoint and invented time.

## Planned local key change

The app can prepare and resume a **same-owner** root/receiver/witness change. Resolve all approved requests first. Preparation catches up the witness/verifier and retains an exact cutover, old/new keys and signed records in a private job directory. Admission is paused before any role state changes. Each local database transition is transactional. The controller reconciles the exact recorded handover after an interruption, publishes files while paused, and resumes admission only after all roles/configurations are complete.

```sh
outputs/local-venv/bin/python scripts/owner_rotation.py prepare HOME
outputs/local-venv/bin/python scripts/owner_rotation.py resume HOME
```

This is not a distributed transaction or compromise recovery. If an unfinished role's original handover expires, automatic resume fails closed and admission stays paused. Preserve the job and all state for operator reconciliation; do not remove the pause marker or substitute a new root. Hardware power-loss durability, arbitrary administrative edits during a handover and recovery after all keys are lost are not established. Never use this same-owner convenience workflow as evidence of independent custody.

## Verification records

See `outputs/v0.9/VALIDATION.md` for measured results. Browser fixtures use simulated human approval of public synthetic content; they do not authorize or publish a real report. The UI, paging controller, archive verifier, handover controller and transport need a fresh external human review. Earlier reviews do not cover these additions.

## Trust renewal and remote roles

Local development trust lasts one day. Use the existing owner CLI `scripts/witness_workflow.py renew HOME` before resuming after expiry; renewal retains keys and history. A service-backed owner home is provisioned explicitly with `scripts/role_transport.py` and the remote operators' public trust/client TLS material. The owner UI then uses those endpoints while retaining only the authority private key. Remote trust renewal and handover remain coordinated operator tasks; the local rotation button is hidden for these homes.
