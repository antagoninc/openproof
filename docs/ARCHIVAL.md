# Long-lived evidence and backup reconciliation

The new retention test advances an explicit test clock through 42 logical days, renewing signed trust daily and making 168 updates. It verifies replay behavior, page reconstruction and rejection of a day-14 receiver backup against the later retained checkpoint. It preserves private directory permissions when copying quiescent fixture state. This is accelerated logical-time coverage, not six weeks of elapsed deployment, live database backup safety, or physical power-loss testing.

## Copy verified public history without pruning live state

Export the existing portable history, obtain the trusted genesis root and a current checkpoint through the verifier's own channel, and use a separately obtained Go verifier:

```sh
outputs/local-venv/bin/python scripts/archive_store.py seal EXPORTED_HISTORY \
  --root TRUSTED_GENESIS_ROOT --checkpoint EXTERNAL_CURRENT_CHECKPOINT.json \
  --go-binary TRUSTED_GO_VERIFIER --out NEW_ARCHIVE_DIRECTORY
```

The command verifies before and after copying, copies only explicitly named public evidence files, regenerates an unverified viewer, records the check, and emits a SHA-256 seal over the copied files. Retain the printed seal digest separately. The destination must be new; no receiver/witness/verifier database or live record is deleted or rewritten.

```sh
outputs/local-venv/bin/python scripts/archive_store.py check ARCHIVE_DIRECTORY \
  --expected-sha256 SEPARATELY_RETAINED_SEAL_DIGEST
```

This checks byte integrity and archive membership against the retained digest. It does not establish current trust, non-revocation, fresh witnessing or independent custody. File permissions reduce accidental writes; a host administrator can change files and an unpinned seal. Old captured checkpoints remain old even when the archive's hash is unchanged. Fresh verification needs a newly exported history and independently provisioned current pin.

## Restore discipline

Stop admission before restoring live state. Preserve roots, checkpoint floors, handover records and the original request/receipt relationship. Reconcile the restored receiver against the independently retained newer witness checkpoint. A missing suffix is incomplete history, not permission to reset verification state or start again at an old version. The fixture restores into a separate directory and shows rejection; it does not implement automatic repair or claim that backups are inherently safe.

Physical store pruning, online database compaction/migration, emergency root recovery and automated restoration remain unsupported. Operators must run the acceptance procedure on expendable copies of their actual infrastructure before proposing any destructive retention action.
