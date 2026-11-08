# Compatibility and migration policy

OpenProof is experimental. Cargo package versions and signed evidence format versions are separate. A package update never silently reinterprets existing signed bytes.

- Preserve OPEC-1 canonical bytes, domain separators and published known-answer vectors. A change in signed semantics, field acceptance or canonicalization requires an explicit format/domain version and new positive/negative vectors.
- Reject unknown formats and fields. Do not guess formats or silently downgrade after verification fails.
- Existing v1 evidence, trust, page and rotation formats remain unchanged by the preview usability work. Local build evidence v2 includes the Go binary; the verifier retains explicit v1 support.
- Test Rust and Go acceptance/rejection on the same corpus. A compatibility discrepancy blocks release until explained and fixed.
- Upgrades require backups, recorded trusted roots/checkpoint floors and a tested recovery procedure. Database migration, pruning and emergency compromised-root recovery are not promised. Never clear replay state to make an upgrade pass.
- Planned handover requires the existing six-signature protocol and exact retained plan. It is not emergency recovery. Preserve epoch records for offline reconstruction.
- Before breaking changes, document old/new behavior, affected artifacts, migration commands, rollback limits and deprecation window. No stable support window is promised before an explicitly approved release.

The storage pilot introduces separate `openproof-storage-upload/1` and `openproof-storage-observation/1` records. They are not document receipts or TRACE records. Rust CLI verification and independent Python signature checks cover the pilot; the Go archive verifier does not verify these storage observations. No document wire format changed.
