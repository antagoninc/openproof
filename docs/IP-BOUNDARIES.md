# License, provenance, and proprietary boundaries

This is a newly authored standalone project. Its Rust protocol, schema, CLI, documentation, and synthetic tests were created for this request. No existing Antagon project directories, repositories, credentials, models, datasets, customer material, or evaluation systems were imported or used. No TRACE source or specification was copied. Conceptual inspiration does not imply implementation compatibility or affiliation.

The proposed open-source license is Apache License 2.0 (`LICENSE`). Copyright remains with the applicable rights holders. This notice does not settle ownership of generated contributions or grant rights the contributor does not hold. The license covers eligible files in this new project only. It does not cover or relicense any separate proprietary Antagon material, names, logos, trademarks, models, datasets, services, or patents beyond the express license terms.

Dependency source remains under each dependency's license. `Cargo.lock` records exact versions. Before distribution, produce a transitive dependency/license inventory and preserve all required notices. The root license is not a blanket license for dependencies. No legal clearance, exhaustive IP review, trademark clearance, or security audit has been performed.

Allowed here: original protocol code, public cryptographic libraries, synthetic fixtures, documentation, and security tests. Excluded: proprietary adapters, internal policy rules, production secrets, customer traces, training/evaluation data, private weights, and commercial inference code. Future integrations should use documented interfaces and separate repositories; do not copy commercial internals into this tree.

Test keys with fixed seeds are public test material only. Generated CLI-test keys are disposable, not Antagon credentials. Demo outputs disclose no private signing seeds. Keep `outputs/`, `target/`, and `*.secret` out of commits. The initial private GitHub import is scanned with Gitleaks. Exact public fixture-key values have narrowly scoped exceptions in .gitleaks.toml; all default detector rules remain enabled. A passing scan is not proof that no secret exists.

No remote or public release is configured. Both packages disable Cargo publication. These settings are guardrails, not authorization to publish elsewhere. Explicit owner approval is still required before any GitHub upload, repository publication, or public release.

## v0.5 adapter dependencies

The host adapter additionally uses certifi 2026.10.23 (Mozilla Public License 2.0 certificate bundle), installed separately from PyPI, not copied into project source. Python cryptography and its dependencies remain separately installed test/adapter dependencies. The declared Rust dependency-license gate does not constitute a complete audit of Python packages or the Docker base image. The worker image uses the official Python image pinned by digest at build time; its components retain their upstream licenses. Claude is an external service, not bundled code or a model redistributed by this project. Do not store API credentials in source, Docker build contexts or run records.

The v0.7 comparison installs the public agentrust-trace 0.11.0 distribution and dependencies only under excluded outputs, with a retained dependency freeze and distribution digest. They retain their upstream licenses and are not OpenProof-authored implementation. The OpenProof receiver/witness protocol and schema are original; no TRACE source or schema was imported into them. Comparisons are local experiments, not a compatibility or superiority claim.
