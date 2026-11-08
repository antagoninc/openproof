# License, provenance, and proprietary boundaries

OpenProof is a standalone Antagon project. Its Rust protocol, schema, CLI, documentation and synthetic tests are original to this repository. No other Antagon repositories, credentials, models, datasets, customer material or evaluation systems were imported. No TRACE source or specification was copied. Conceptual inspiration does not imply implementation compatibility or affiliation.

Antagon, Inc. licenses OpenProof under the Apache License 2.0 (`LICENSE`). The licence covers the files in this repository only. It does not cover or relicense any separate proprietary Antagon material, names, logos, trademarks, models, datasets or services.

Dependency source remains under each dependency's license. `Cargo.lock` records exact versions. Before distribution, produce a transitive dependency/license inventory and preserve all required notices. The root license is not a blanket license for dependencies. No legal clearance, exhaustive IP review, trademark clearance, or security audit has been performed.

Allowed here: original protocol code, public cryptographic libraries, synthetic fixtures, documentation, and security tests. Excluded: proprietary adapters, internal policy rules, production secrets, customer traces, training/evaluation data, private weights, and commercial inference code. Future integrations should use documented interfaces and separate repositories; do not copy commercial internals into this tree.

Test keys with fixed seeds are public test material only. Generated CLI-test keys are disposable, not Antagon credentials. Demo outputs disclose no private signing seeds. Keep `outputs/`, `target/`, and `*.secret` out of commits. The initial private GitHub import is scanned with Gitleaks. Exact public fixture-key values have narrowly scoped exceptions in .gitleaks.toml; all default detector rules remain enabled. A passing scan is not proof that no secret exists.

The source is published on GitHub. The crates disable Cargo publication: no crate is published to crates.io, and no versioned release is made until the human-review gate in [RELEASE-CHECKLIST.md](RELEASE-CHECKLIST.md) is met.

## v0.5 adapter dependencies

The host adapter additionally uses certifi 2026.10.23 (Mozilla Public License 2.0 certificate bundle), installed separately from PyPI, not copied into project source. Python cryptography and its dependencies remain separately installed test/adapter dependencies. The declared Rust dependency-license gate does not constitute a complete audit of Python packages or the Docker base image. The worker image uses the official Python image pinned by digest at build time; its components retain their upstream licenses. Claude is an external service, not bundled code or a model redistributed by this project. Do not store API credentials in source, Docker build contexts or run records.

The v0.7 comparison installs the public agentrust-trace 0.11.0 distribution and dependencies only under excluded outputs, with a retained dependency freeze and distribution digest. They retain their upstream licenses and are not OpenProof-authored implementation. The OpenProof receiver/witness protocol and schema are original; no TRACE source or schema was imported into them. Comparisons are local experiments, not a compatibility or superiority claim.
