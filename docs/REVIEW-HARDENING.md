# v0.7.2 · Remaining review hardening

This milestone implements the remaining code-addressable Claude F3/F4/F6/F7 items. It does not make the project a production service or turn an AI review into a human audit. F1/F2/F5 fixes from v0.7.1 remain enforced.

## Signed trust and persistent verification

`Trust` now has its own original signing domain, `witness-trust/1`, using the existing `OpenProof/v1/` prefix and OPEC-1 canonicalization. The strict signed envelope is described by `schemas/openproof-witness-trust-v1.schema.json`. The root key is separately provisioned; it cannot be learned from an untrusted evidence package, and it must differ from all active/historical role keys. Receiver/witness role migration is rejected in a previously initialized verifier.

```sh
# Trust administrator; only this host needs the private root.
openproof-witness signer-init signer-state ROOT_PUBLIC_KEY
openproof-witness sign-trust root.secret signer-state < trust.json > trust-signed.json
# Each role operator independently authenticates ROOT_PUBLIC_KEY.
openproof-witness role-init role/state ROOT_PUBLIC_KEY
openproof-witness install-signed role/state ROOT_PUBLIC_KEY < trust-signed.json
# Independent verifier initializes a NEW private state directory once.
openproof-witness verifier-init verifier-state ROOT_PUBLIC_KEY
openproof-witness verifier-install verifier-state < trust-signed.json
openproof-witness verify-trusted verifier-state trust-signed.json checkpoint.json < package.json
```

Do not transfer redirected output after a command fails. Use a new staging filename, check the exit status and parse it as JSON before moving it to the agreed delivery location. Never overwrite a known-good trust/pin file with an empty failed-command result.

Role state now pins the root too. `install-signed` verifies that pinned root, atomically authorizes the exact trust digest/epoch, and advances role floors. Every admission/gap/witness operation checks its plain in-memory trust against that authorized digest inside the transaction. Tampering with a plain file cannot authorize effects or poison the epoch. `role-pin` explicitly upgrades an existing role store without replacing an existing anchor. Rootless `init`/`install` remain legacy low-level APIs; the broker refuses unanchored role stores.

The persistent verifier checks the root signature, trust expiration, epoch/configuration floor and monotonic local clock. It adopts a valid newer trust revision **even if the submitted package is invalid or revoked**, so a rejected package cannot restore obsolete authority. An explicit install command permits revocation updates without any evidence package.

Successful verification persists checkpoint count/head/time. A later full package must contain the previously accepted head at the same sequence; increasing the count cannot hide a fork. Checkpoints older than five minutes fail this live-verification path. A newer signature for the same unchanged head is allowed. This supplies a bounded freshness rule and local rollback/fork memory, not global gossip, proof that no newer checkpoint exists, or protection against restoring the verifier's entire filesystem. No transport is added by these commands: each operator must authenticate its root and obtain pins directly from its witness.

Legacy `verify TRUST PIN` and library `assess` remain stateless inspection APIs. They do not authenticate the provenance of a plain trust file or persist floors. They are not the recommended multi-operator acceptance path. Existing timeline rendering remains stateless inspection; use `verify-trusted` separately for a live acceptance decision.

## Local broker assurance and upgrades

Fresh homes create a separate root key, signed trust file and persistent verifier state. The broker uses this verifier but still shares one host account. Successful tool results say `status: local_consistency_check`, `verification_status: local_consistency_verified`, `verification_scope: local_consistency_check`, and `independent_operators: false`. The original cryptographic result is retained as `evidence_status`. Gaps retain `unknown_due_to_disclosed_gap`, `complete_history: false`, and `document_version_continuity_verified: false`.

Old homes fail before dispatch until the owner explicitly upgrades:

```sh
outputs/local-venv/bin/python scripts/witness_workflow.py upgrade-trust /absolute/home
```

The command preserves role keys, documents, nonces and receipts. It provisions a root/verifier/signing ledger, pins both role stores, and retains `trust-upgrade.json` only while the staged update is incomplete. A successful update removes the candidate. Repeating upgrade after renewal uses the authenticated current configuration. Stale/conflicting or expired candidates are retained under an abandoned filename and replaced with a fresh revision above all known floors. An existing root identity with a missing secret fails without generating a replacement key. Renewals derive from the root-authenticated signed payload, not the plain copy. This is initial local trust provisioning, not proof of external independence or a general root-rotation protocol. Do not run it to replace an existing trusted root. Partial publication failures remain fail-closed; retry the retained configuration while admission is stopped. Renewal signs a new configuration and installs it at all three stores before publication.

## Agent-facing data minimization and storage bounds

MCP returns `evidence_id`, not an absolute path. The owner CLI retains the local path for inspection; owners resolve an opaque ID under their configured home's `evidence/` directory. Both tool and JSON-RPC errors use fixed error codes without exception strings. Keys and arbitrary paths cannot be supplied through tools.

Approved requests are capped at 1000; evidence has a 1000-entry/64 MiB conservative budget with space reserved for the next bounded artifact. New updates stop before admission when evidence storage is full. Existing evidence is never automatically deleted. Partial evidence directories are cleaned up, successful output is published by directory rename, and identical checkpoint/trust/proposal results share an evidence ID. The owner must manage retained approvals/evidence. These limits bound local storage; they do not provide fair multi-tenant scheduling.

## Keys, configuration and export

Unix key loading opens with `O_NOFOLLOW | O_NONBLOCK`, then checks the opened descriptor is a private regular file, and reads through that same descriptor. Symlinks and FIFOs are rejected. Secret input, decoded seed and generated hex buffers are zeroized on normal/error destruction. This reduces retained copies; it is not protection against a privileged process, paging, crash dumps or hardware attacks. Parent directories and the host remain trusted.

Trust validation rejects duplicate list entries and active-authority overlap with historical/revoked lists. A retired authority may appear in both historical and revoked lists: its metadata is retained while its evidence is denied. To revoke the active authority, install a new active key and move the old one into historical/revoked lists; do not represent a disabled service using an ambiguous active-and-revoked configuration.

`export STATE TRUST < CHECKPOINT` now checks the witness signature, receiver binding and checkpoint time before constructing the exact prefix. The deliberately named `export-unverified STATE` and library `export` remain owner-only raw assembly tools for forensic recovery; their output must never be treated as an acceptance result. Full package verification remains necessary after either export path.

## Safe clock recovery

```sh
openproof-witness clock-status role/state
openproof-witness clock-repair role/state trust.json authority.secret
```

The state tracks both its admission clock floor and the latest time used for a signed receipt/checkpoint. An owner-authorized repair can lower an installation-only clock jump, but never below the signed-time floor. It requires the exact installed trust epoch/digest and active authority key. A signed `witness-clock-repair/1` record captures the old/new/signed floors and trust digest. Audit history is capped at 64 repairs. Documents, nonces, events, trust floors and revocations are preserved. Verifier clock floors cannot be changed through this role-recovery command. Independent operators use an offline root-signed token so the root secret stays on the administrator's host:

```sh
# Verifier host, after correcting its clock:
openproof-witness verifier-clock-request verifier-state > repair-request.json
# Root administrator host, after reviewing the request:
openproof-witness sign-verifier-clock-repair root.secret < repair-request.json > repair-token.json
# Verifier host; only public signed objects cross the boundary:
openproof-witness apply-verifier-clock-repair verifier-state trust-signed.json < repair-token.json
```

The token binds the exact old floor, new floor, trust epoch/digest and checkpoint count/head/time. It is valid for ten minutes after its proposed new floor, fails after state changes or replay, and cannot rewind below the accepted checkpoint time. Application preserves all trust/checkpoint floors and retains the signed `verifier-clock-repair/1` record. Installed trust may have expired during an outage; signature and exact installed digest still bind repair, and ordinary verification remains blocked until trust is renewed. The older `verifier-clock-repair ... ROOT_KEY` convenience command is only for single-owner local setups; independent operators must use the token path. Neither path resets verifier state.

Recovery, receipt, head, document, clock-status and export use non-migrating read-only SQLite connections. Existing databases conservatively migrate their old clock floor as already signed only on a write connection, because the previous schema cannot distinguish emitted future checkpoints from installation-only time. If future-dated evidence has already been signed, wait until the signed-time floor or design a separately reviewed migration. Silently editing the database or rewriting signed timestamps is not a safe fix.

## Trust-signing discipline

The default `sign-trust KEY SIGNER_STATE` command persists a root-bound signing ledger. Identical requests at an existing epoch return the existing record; conflicting content at that epoch and new configurations below the signing floor fail. Treat every signed configuration as published. The explicitly named `sign-trust-untracked` and the general library signing primitive remain low-level tools, not the managed signing path. Keep signer state intact and backed up securely; replacing it defeats its memory, just as replacing verifier state defeats verifier floors.

## Review closure boundaries

| Item | Disposition |
|---|---|
| F1/F2/F5 | v0.7.1 fixes retained; bounded admission, recovery, concurrent-prefix export and pending lifecycle |
| F3 | Explicit local-only status in saved and agent-facing results; gap uncertainty retained |
| F4 | Signed trust, pinned roots in role and verifier state, persistent floors and bounded checkpoint age; authenticated distribution remains operational |
| F6 | Opaque MCP evidence IDs and fixed errors; paths remain available to the owner CLI |
| F7 | Descriptor key reads/zeroization, trust-list validation, conservative clock repair, explicit continuity downgrade, verified export |

Still separate engineering/deployment work: unlimited/paginated history, receiver/witness/root migration for this protocol, public transparency/gossip, authenticated remote transport, stronger key custody, Linux/power-loss validation, independent organizations and external human audit. These are not represented as completed by closing the local findings.
