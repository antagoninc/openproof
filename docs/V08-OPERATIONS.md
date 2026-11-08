# v0.8 · Bounded history and a Linux pilot

This milestone is an experimental local implementation. It does not complete independent operations, remote transport or a human security audit. Existing agent/MCP homes retain their conservative full-package storage bounds. Paging and planned rotation are explicit operator workflows, not automatic broker migrations.

## Docker: what is separated

`deployment/Dockerfile.roles` builds and tests the public Cargo workspace on a digest-pinned Linux image. The staging script copies only Cargo files, crates, synthetic fixtures and public examples. The final image copies the executable from a separate build stage; test state and generated fixture keys stay outside the runtime image.

```sh
outputs/local-venv/bin/python scripts/build_roles.py --out outputs/my-linux-build
outputs/local-venv/bin/python scripts/docker_roles_pilot.py \
  --image-id-file outputs/my-linux-build/image-id --out outputs/my-linux-pilot
```

Four non-root containers represent owner, receiver, witness and verifier. They have distinct private mounts, read-only root filesystems, dropped capabilities, process/memory limits and disabled networks. Public messages move through explicit host-mediated input/output. The pilot exercises changed requests, witness outage, durable recovery, idempotent retry, changed pages and page replay. Approval is simulated for public fixture content. Containers are removed after the experiment; role state remains in the private output directory.

All roles still share one Docker engine, kernel/VM and host administrator. Docker administration can access every role. There is no remote service listener, mTLS deployment, independent organization, HSM or container escape proof. Do not expose this CLI as an unauthenticated HTTP endpoint. Separate hosts/operators and authenticated transport require a further deployment design and review.

## Bounded pages

The original `openproof-history-page/1` schema carries a checkpoint, a starting sequence and at most 32 receipts with their approvals. Exports stay at or below 512 KiB. Opt-in paged receiver storage stops transactionally at 100,000 events or 128 MiB of logical retained event/document/replay data; this is not a physical SQLite disk quota. The broker's separate evidence/approval budgets remain in force.

```sh
target/debug/openproof-witness enable-pages RECEIVER_STATE TRUST.json
outputs/local-venv/bin/python scripts/witness_pages.py \
  --receiver RECEIVER_STATE --verifier VERIFIER_STATE \
  --signed-trust SIGNED_TRUST.json --checkpoint CHECKPOINT.json --out outputs/pages-run
```

Initialize and provision the verifier's root independently first. Obtain the checkpoint from the configured witness. The page driver stores each page before advancing durable verification. Intermediate prefixes are explicitly pending. Only a final matching checkpoint produces `checkpoint_complete`; gaps still leave completeness unknown. Nonces, document versions, issuer history and confirmed checkpoint floors persist across pages. A page-run starting above sequence one depends on previously retained evidence/state and is not a standalone portable history.

`page-progress DIR` reads progress. `reset-pages DIR` discards only an unconfirmed prefix, restoring the last saved confirmed stream state while preserving trust/checkpoint floors. It is not permission to restore an old database backup. History and verifier-state archival/migration to another physical store remain operator tasks; no automatic deletion occurs.

## Planned handover

This original protocol requires six signatures over identical `openproof-rotation/1` bytes: old/new root, old/new receiver and old/new witness. The signing domain is `witness-planned-rotation/1`. The verifier and both roles must already agree on a fresh cutover checkpoint. The new trust epoch must increase. Confirmed history, document versions and consumed nonces survive.

1. Stop admission through the broker and keep it stopped for the entire handover. Drain witness and paged verifier to the same checkpoint. Retain old signed trust and all evidence.
2. Generate new role keys in their respective custody boundaries. Prepare the new public trust configuration. Keep authority history/revocations consistent.
3. Run `scripts/prepare_rotation.py --help` to prepare a public proposal. Each operator reviews all fields, then uses `openproof-witness sign-rotation KEY < PROPOSAL.json`. Do not centralize six private keys to simulate operator independence.
4. Assemble the six envelopes in the schema's named fields. Check with `openproof-witness check-rotation OLD_ROOT OLD_SIGNED_TRUST.json < HANDOVER.json`.
5. Apply separately at each stopped role using `rotate-state STATE OLD_SIGNED_TRUST.json < HANDOVER.json`. Each local state change is transactional; the three-role deployment is not a distributed atomic transaction. Preserve receipts of every successful application. Replay is rejected. If interrupted, keep admission stopped and reconcile installed roots and the stored rotation audit record before applying only unfinished roles. Do not blindly retry or delete state.
6. Initialize the new root's signing ledger, sign the new trust, install it on the verifier and publish the new configuration/keys only after all role states are reconciled. Resume through a deployment-specific adapter that understands the handover; the legacy broker does not automate this migration.

Pre-cutover receipts are verified under their retained old trust/checkpoint. Post-cutover pages continue from the existing verified head under new keys. Go's current full-package verifier does not implement this transition. Cross-epoch historical broker retries and packaging are not automatically upgraded.

**Compromise is different.** If an old root or receiver might be compromised, stop new admission, isolate the affected role, retain databases/logs/evidence, revoke according to the surviving trust policy and obtain independent checkpoint corroboration. Do not use signatures from a suspected compromised old key as proof that a planned migration repaired history. Emergency re-rooting, fork adjudication and automatic compromise recovery are not implemented.

## Owner view and build evidence

```sh
outputs/local-venv/bin/python scripts/owner_dashboard.py HOME --out outputs/owner-overview.html
```

The static view inspects durable receipts and performs fresh stateless full-package checks. It has no scripts, approval controls or network requests. It labels stale/changed evidence as needing attention; it cannot establish independent custody or durable verifier rollback protection. Paged/rotated homes need the dedicated verifier result, not this legacy broker view.

`release_evidence.py sign` signs an original `openproof-local-build/1` statement binding the validation source manifest, executables, step results and provenance. `verify` requires a separately supplied public key, expected builder ID and source-manifest digest, and recomputes artifact hashes. A local signer can still lie about its build; no SLSA level, reproducibility or independent builder is claimed. Never distribute the signing key with evidence.

## Review and release gates

The private review snapshot includes source and licenses, excludes outputs/keys/databases and records hashes. A named human reviewer, scope, budget and transfer approval are still needed. No external reviewer has been contacted and no public release is authorized. Go, paging, handover, dashboard and build-signing additions require fresh external review; earlier AI reviews do not cover this milestone.
