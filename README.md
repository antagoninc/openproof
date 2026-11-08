<p align="center">
  <img src="docs/assets/openproof-banner.svg" alt="Antagon OpenProof — signed evidence, explicit trust" width="100%">
</p>

# Antagon OpenProof

**Rust-first evidence for AI actions. Signed approvals. Execution receipts. Offline verification.**

OpenProof connects an exact authorization to a bounded action, a receiver's execution receipt, and a witness checkpoint. It helps an owner answer: **What did I approve? What was reported as executed? Does the evidence agree?**

<p>
  <a href="#quick-start"><strong>Quick start</strong></a> &nbsp;·&nbsp;
  <a href="#the-owner-workspace">Owner workspace</a> &nbsp;·&nbsp;
  <a href="#what-the-evidence-means">Trust boundaries</a> &nbsp;·&nbsp;
  <a href="docs/VALIDATION.md">Validation</a> &nbsp;·&nbsp;
  <a href="docs/ROADMAP.md">Roadmap</a>
</p>

> **v0.9.0 · Experimental · No production-security claim**
> Signatures authenticate statements. They do not prove that a model is truthful, a physical-world effect occurred, or an operator is independent. The current milestone has not received a human security audit.

## The owner workspace

**Propose → review → approve → execute → recover → export.**

| Capability | What it does |
|---|---|
| **Exact approval** | Binds the reviewed document, version and content; approval and execution are separate decisions |
| **Execution receipts** | Atomically updates the receiver's document database and records its signed receipt |
| **Witnessed history** | Tracks ordered receipts, signed checkpoints and explicitly disclosed gaps |
| **Incremental evidence** | Verifies bounded pages while retaining nonce, version and checkpoint state |
| **Planned key handover** | Preserves history through a six-party signed transition with stopped admission and recovery |
| **Portable verification** | Reconstructs signed history offline in a separate Go implementation |
| **Storage pilot** | Binds report bytes and destination for conditional S3 creation; distinguishes adapter acknowledgment from read-back |
| **Daily recovery** | Inspects interrupted actions and refreshes existing receipts without dispatching unexecuted work |
| **Certificate lifecycle** | Warns about expiry and stages explicit TLS renewals/client retirement |
| **Authenticated services** | Uses mutual TLS and explicit client identities for receiver/witness endpoints |

The local browser app provides exact-content review, readable outcomes, retry/recovery and evidence export. It renders model-provided text as text, never as commands or executable HTML. Agent-facing tools can propose and commit approved work; they cannot grant owner approval.

## Quick start

Use macOS or Linux with Rust/Cargo, Python 3.11 and Go installed. The repeatable CI configuration pins Rust **1.92.0** and Go **1.27.3**. Docker is needed only for container experiments.

```sh
git clone https://github.com/antagoninc/openproof.git
cd openproof

python3 scripts/quickstart.py
```

The first-run command installs the pinned Python dependencies in a project-local environment, builds Rust and Go, runs eight synthetic assurance experiments, opens their interactive results, and starts a fresh owner workspace with an unapproved sample. No Docker or model account is needed. Use `--check --no-open` for a noninteractive check.

On macOS, after setup, double-click **[Open OpenProof.command](Open%20OpenProof.command)**. The app uses a private local home under `outputs/owner-home` and listens only on loopback. Keep the terminal open while using it; Control-C stops the app. No external model call is made by startup or fixture demonstrations.

For a synthetic command-line demonstration:

```sh
outputs/local-venv/bin/python scripts/witness_demo.py --out outputs/my-demo
```

Choose a new output directory for each demonstration. These examples simulate approval of public test content; they are not evidence of human approval of a real action.

**[Owner guide →](docs/OWNER-APP.md)** · [Agent/MCP workflow](docs/WITNESSED-WORKFLOW.md) · [Authenticated services](docs/AUTHENTICATED-SERVICES.md)

## Explore and verify

The first-run experiment explorer shows altered content, substituted signers, duplicate receipts and omitted history rejected by real checks. An identical approved retry recovers the original receipt without another update. These are simulated approvals, not human consent.

Evidence exports include a readable, script-free `viewer.html` and `VERIFY.txt`. The viewer is explicitly **unverified display**. Use your independently obtained Go verifier and separately trusted genesis root and current checkpoint to generate a fresh offline result:

```sh
outputs/local-venv/bin/python scripts/verify_history.py EXTRACTED_ARCHIVE \
  --root TRUSTED_GENESIS_ROOT_HEX --checkpoint SEPARATELY_TRUSTED_CHECKPOINT.json \
  --go-binary outputs/tooling/openproof-go-verify --out outputs/my-offline-check
```

[Storage pilot](docs/STORAGE-PILOT.md) · [Archive retention](docs/ARCHIVAL.md) · [TRACE comparison scope](docs/COMPARISON.md) · [Daily operations and measurements](docs/OPERATIONS.md) · [Compatibility policy](docs/COMPATIBILITY.md) · [Controlled preview checklist](docs/RELEASE-CHECKLIST.md)

## What the evidence means

| Result | Supported interpretation | Not established |
|---|---|---|
| Valid approval | The configured authority signed the exact scoped request | Good intent or a safe policy |
| Receiver receipt | The receiver signed a statement about its stored document update | Arbitrary external or physical effects |
| Matching witness checkpoint | The signed history matches the supplied checkpoint | Independent administration or honest signers |
| Complete verified history | Required receipts/approvals connect under the selected trust and checkpoint | Protection when the caller also rolls back its trusted anchors |
| Disclosed gap | The verifier identifies incomplete knowledge | Complete execution history |

The owner UI, receiver and witness can run under one host account. That arrangement is useful for development, but it is **not independent custody**. Docker containers still share a host administrator. The service client can operate without root/receiver/witness private keys; separately administered infrastructure still requires actual operators and deployment work.

The Go verifier is separately implemented without calling Rust, but it shares project authorship. It is not an external audit. Its archive mode requires a separately trusted root, a current checkpoint and the actual current time. Planned migration is not compromised-key recovery.

## Validation

The recorded v0.9 local milestone passed:

| Check | Recorded result |
|---|---|
| Rust workspace | **117 tests** on macOS and Linux |
| Python workflows and boundaries | **57 tests** |
| Cross-implementation cases | **520 cases** across evidence, trust and witness suites |
| Browser workflow | Desktop and mobile review, approval, execution and retry |
| Bounded fuzz campaigns | **4,390,141 executions**; the new stateful target covered only **78 sequences** |
| Repeat Linux build | Identical witness executable bytes on the same host and pinned image |

The initial private import also passed [Linux and macOS hosted validation](https://github.com/antagoninc/openproof/actions/runs/42453339807). That run covers its recorded commit; later changes require fresh validation. The [sanitized validation summary](docs/VALIDATION.md) explains scope and limitations. Generated logs, private keys, databases, browser sessions and runtime homes are deliberately excluded from Git.

To run the complete validation, install `cargo-audit` and use a fresh directory:

```sh
cargo install cargo-audit --version 0.22.2 --locked
outputs/local-venv/bin/python scripts/validate.py --out outputs/my-validation
```

The workflow performs checks and builds only. It does not publish packages, upload runtime artifacts or create a release. See the [build guide](docs/BUILD.md).

## Project map

| Path | Purpose |
|---|---|
| `crates/openproof-core` | Original evidence schema, OPEC-1 canonicalization, domain-separated signatures |
| `crates/openproof-runtime` | Bounded local execution, replay state and recovery |
| `crates/openproof-trust` | Signed trust, revision floors and planned trust transitions |
| `crates/openproof-witness` | Document receiver, witness, pages and role handovers |
| `crates/openproof-cli` | Evidence and execution CLI |
| `app` / `scripts` | Owner UI, adapters, transport, demonstrations and validation |
| `reference` | Separate Python and Go verification implementations |
| `schemas` / `fixtures` / `fuzz` | Versioned formats, public synthetic evidence and fuzz targets |

## Documentation

[Protocol](docs/PROTOCOL.md) · [Threat model](docs/threatmodel.md) · [Security policy](SECURITY.md) · [Recovery](docs/RECOVERY.md) · [Trust](docs/TRUST.md) · [Operator handoff](docs/handoff/OPERATORS.md) · [Human review brief](docs/handoff/REVIEW-BRIEF.md) · [Roadmap](docs/ROADMAP.md)

Some historical guides mention `outputs/...` records from the local development workspace. Those paths are not distributed evidence; use the sanitized validation summary for repository-readable results or regenerate fixtures locally.

## Contributing and licensing

See [CONTRIBUTING.md](CONTRIBUTING.md). Protocol changes need a versioning decision, byte vectors, negative tests and explicit trust assumptions.

Eligible project source is licensed under **[Apache-2.0](LICENSE)**; dependencies retain their own licenses. Read the [IP boundaries](docs/IP-BOUNDARIES.md). Proprietary Antagon code, models, datasets and credentials do not belong in this repository. Antagon branding is not a grant of trademark rights.

OpenProof is independently authored. No TRACE compatibility, code reuse or security superiority is claimed. Public visibility and release publication require separate owner approval.
