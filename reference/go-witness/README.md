# Go witness verifier

A separately implemented offline verifier for full `openproof-witness/1` packages. No Rust calls, FFI or shared implementation. Authored within the same AI-assisted project: this is implementation diversity, not independent authorship, external review or certification.

```sh
# From this directory; caches and binary stay inside the project.
GOMODCACHE="$PWD/../../outputs/tooling/go-mod" GOCACHE="$PWD/../../outputs/tooling/go-cache" go test ./...
GOMODCACHE="$PWD/../../outputs/tooling/go-mod" GOCACHE="$PWD/../../outputs/tooling/go-cache" go build -o ../../outputs/v0.8/openproof-go-verify .
../../outputs/v0.8/openproof-go-verify verify TRUST.json CHECKPOINT.json PACKAGE.json UNIX_TIME
```

The caller must independently authenticate the supplied trust and checkpoint. The original `verify` command remains stateless. The new `verify-archive ROOT PIN DIRECTORY NOW` reconstructs signed trust, paged history and planned root/role handovers from genesis, requiring a separately trusted root and current checkpoint; it does not maintain a separate persistent rollback database. Its result cannot substitute for the Rust stateful verifier. Time is an explicit caller input for controlled conformance testing; do not use an invented time to conceal stale evidence.

OPEC-1 canonicalization and protocol validation are implemented here. Ed25519 verification uses Go's standard library; pinned `filippo.io/edwards25519 v1.1.0` is used for canonical point and small-order checks. Its BSD-3-Clause license is retained in `licenses/edwards25519.txt`. `go.sum` pins fetched dependencies. The locally available Go 1.20.3 toolchain was used for these experiments; current production toolchain support and a Go vulnerability audit have not been established.

For portable archive format, historical-time semantics, bounds and trust provisioning, see [the owner guide](../../docs/OWNER-APP.md). New archives preserve nonce/document/issuer state across pages and handovers. End-to-end tests create real Rust-signed archives and reject omitted/reordered entries, wrong roots/pins, changed content and corrupted handover signatures.
