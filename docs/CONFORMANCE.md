# Protocol hardening

The separately implemented Python verifier in reference/python/openproof_ref.py parses strict JSON, implements OPEC-1, checks scope and chain bindings, and verifies Ed25519 using Python cryptography/OpenSSL with additional scalar and small-order point checks. It does not invoke Rust. It was authored in this same development session; it is not an independent external security review.

Run `python3 scripts/conformance.py` after building the debug CLI. Requires the pinned cryptography package in reference/python/requirements.txt. The suite compares 224 positive/negative cases and three fixed preimage/signature vectors across implementations. Immutable fixture hashes are in fixtures/v1/sha256.json. Passing this corpus does not establish equivalence for every adversarial curve encoding.

Four property tests each generate 256 cases: Unicode round trips, map ordering, deterministic signing/tampering, and arbitrary parser bytes. Rust also consumes the Python-generated golden fixtures.

Two cargo-fuzz targets cover evidence/parser/canonicalization and policy validation. They use libFuzzer and the nightly address sanitizer. Example with a standard nightly setup:

```sh
cargo +nightly fuzz run evidence -- -max_total_time=60 -max_len=8192
cargo +nightly fuzz run policy -- -max_total_time=60 -max_len=8192
```

This machine's isolated tools are in outputs/tooling; run with RUSTUP_HOME pointing to outputs/tooling/rustup and add outputs/tooling/bin to PATH. Corpus and results from the bounded local campaign are retained in outputs/v0.2. Bounded runs are smoke campaigns, not exhaustive security testing.

## Trust conformance

Run `python3 scripts/trust_conformance.py` after the debug build. It compares 94 retained vectors in `fixtures/trust-v1/conformance.json` against Rust and the independent Python/OpenSSL implementation in `reference/python/openproof_trust.py`. Cases cover signatures, root pins, revision/window boundaries, missing null fields, current/historical policy and revocation. No Rust code is called by the Python verifier.
