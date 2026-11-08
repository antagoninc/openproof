# Recovery without repeating an action

OpenProof v0.4 deliberately prefers a consumed nonce and an uncertain result to automatic re-execution. Stop request admission before maintenance. Keep the state directory private and retain all database, WAL and artifact files together.

| Durable state | What is known | Operator action |
|---|---|---|
| No reservation | No dispatch is recorded | A valid request may be submitted; do not infer this from a restored backup |
| `reserved` | The nonce was consumed; work may have happened | Inspect files offline. Never erase the reservation or retry that nonce |
| `indeterminate` | Work or persistence failed after reservation | Preserve evidence and reconcile the actual output; do not manufacture a success receipt |
| `completed` | Executor persisted a receipt and output digest | Verify evidence and artifact bytes; this remains an executor assertion |

`openproof doctor STATE` reports readable records and the number of uncertain operations. It is not a forensic audit, integrity certification or proof that no operations were lost.

Tests terminate child processes before reservation, after reservation, before output, after output, before completion update and after completion. These cover application process termination, not power loss, disk controller behavior or all filesystem failures.

## Backups and clocks

Stop all writers before copying state, or use an operator-managed SQLite-consistent backup that includes matching artifacts. Preserve the original and restore into a quarantined location. A backup can omit consumed nonces: **never resume admission against a restored backup simply because its database opens**. Reconcile against a separately retained operation ledger or retire the deployment and reauthorize genuinely new work after human reconciliation. No automatic backup rollback detection is implemented.

Store the active root, audience and minimum snapshot revision independently from the state backup. Reinstall a fresh snapshot with that independent revision floor before admission; this detects stale snapshots but cannot reconstruct missing consumed nonces. A persisted trust clock watermark rejects observed backwards movement during trusted installs and dispatch reservations. It cannot detect an altered clock that still advances, rollback of the entire database, or manipulation between checks. Correct clock problems under stopped admission; never lower the watermark to make tests or production requests pass.

## Planned root handover

Both old and new roots sign the same `openproof-root-transition/1` payload. It names the audience, roots, validity window and exact next snapshot revision. Use separate offline key custody for each signature. The new root signs that next snapshot.

1. Stop request admission and wait for active jobs to finish. Inspect uncertain jobs.
2. Retain the current independently provisioned anchor and a consistent backup for investigation.
3. Run `openproof sign-root-transition INPUT OLD_SECRET OLD_SIGNED` and the equivalent command under new-root custody to create `NEW_SIGNED`.
4. Run `openproof rotate-root STATE OLD_SIGNED NEW_SIGNED OLD_ANCHOR NEW_SNAPSHOT`. Retain the printed new anchor independently. If the command commits but its output is lost, reconstruct the anchor from the verified transition; do not roll back the database.
5. Replace callers' trusted anchor with the new root and revision, then resume admission using the new snapshot.

The transaction retires the old root in this state, preserves the original nonce namespace, and advances its snapshot floor. New roots already used in the state are rejected. Root retirement applies only to this stateful trusted gate: stateless/offline verifiers must be provisioned with the new anchor separately. Legacy `execute` is not a trust-managed endpoint and must not be exposed as an alternate route.

This is planned rotation, not recovery from a compromised root. A stolen old root can authorize an attacker-controlled successor. Compromise recovery requires an independent operator trust decision, external reconciliation, new trust distribution and a separate reviewed procedure; the tool does not assert that it can solve this automatically.
