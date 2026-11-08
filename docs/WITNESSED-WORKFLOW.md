# Witnessed document updates · v0.7.2

See [v0.7.2 signed trust, upgrades and review hardening](REVIEW-HARDENING.md) for the current acceptance path and CLI changes.

OpenProof now has an original Rust document receiver and witness, a narrow MCP broker, a small Python client, a local timeline, and a version-pinned TRACE experiment. This milestone implements one complete workflow. It does not establish superiority over TRACE or production security.

## What each role establishes

| Role | Authority and state | Evidence |
|---|---|---|
| Owner authority | Persistent private approval key; separate interactive owner command | Exact document identifier, expected version, content hash, receiver key, nonce and short validity window |
| Document receiver | Separate private key and private SQLite database | Transactionally committed document version/content hash, bound to approval and ordered receiver history |
| Witness | Separate private key and separate SQLite database | Signed count/head checkpoint for the contiguous receiver history it accepted |
| Verifier | Independently supplied public trust configuration and checkpoint | Signature/binding/order/content/version checks and exact checkpoint equality |

The broker owns credential selection and destinations. Agent-facing MCP tools accept a proposal or a proposal ID; they cannot select executable commands, key files, state paths, or grant approval. The receiver checks authorization independently even if called without the MCP wrapper. There is no general shell, arbitrary URL, filesystem-write, or model tool adapter.

The protected outcome is **a committed update in the receiver's own document database**. The receiver is trusted to observe and report that outcome. A witness authenticates receipt history, not document truth. A dishonest receiver with its signing key remains outside the demonstrated guarantee.

All roles run as separate native processes with separate keys and state in this local demonstration. They share the host account; this is not isolation against that account, a hostile same-user process, a compromised receiver, or a compromised witness. Deploying independently operated services requires a separately reviewed authenticated transport and credential custody. No independent organization witnessed these tests.

## Run the actual workflow

Build and initialize once:

```sh
cargo build --workspace --locked
outputs/local-venv/bin/python scripts/witness_workflow.py init outputs/document-service
outputs/local-venv/bin/python scripts/witness_workflow.py propose outputs/document-service examples/witness/proposal.json
```

Keep the returned proposal ID. In a separate owner terminal:

```sh
outputs/local-venv/bin/python scripts/witness_workflow.py approve outputs/document-service PROPOSAL_ID
outputs/local-venv/bin/python scripts/witness_workflow.py commit outputs/document-service PROPOSAL_ID
```

Approval displays the exact escaped content and document/version before signing. Requests expire after five minutes. A changed document version requires a fresh proposal and approval. Editing a saved unsigned proposal after approval does not change the captured, signed request. Approved requests are immutable new files. Unsigned proposals expire after 24 hours; at the 1000-pending limit, the oldest unsigned proposal is evicted to admit a new one. Approval removes its pending copy only after saving the signed request. Evicted IDs must be proposed again. A broker lock protects proposal admission, approval capture/save and commits across local processes. Owner input happens outside the lock, using the exact captured proposal, so an unanswered review cannot block already-approved commits. Approved requests and evidence are never evicted. This bounds pending storage; it does not provide fair scheduling against an actively flooding principal. Proposal IDs are random bearer references, not authenticated agent identities or holder-bound delegation credentials.

`commit` returns the evidence directory. Inspect the document directly:

```sh
target/debug/openproof-witness document outputs/document-service/receiver/state project-status
```

The demo helper uses explicitly **simulated approval responses**, never real human-consent claims:

```sh
outputs/local-venv/bin/python scripts/witness_demo.py --out outputs/new-witness-demo
```

## MCP and Python integration

Configure a local MCP client to launch this stdio server with an owner-selected home:

```sh
outputs/local-venv/bin/python scripts/witness_mcp.py --home /absolute/path/to/outputs/document-service
```

The adapter implements initialization, ping, tools/list and tools/call for MCP protocol `2025-11-25`. JSON-RPC messages use newline-delimited JSON and are capped at 32 KiB; notifications cannot trigger actions. The supported tools are `document_propose` and `document_commit`. There is no approval tool. Requests with key/path overrides or extra arguments are rejected. This is a small local integration, not a general MCP authorization proxy or full conformance certification. See [MCP transports](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports) and [tools](https://modelcontextprotocol.io/specification/2025-11-25/server/tools).

```python
from witness_client import Client  # Run Python with PYTHONPATH=scripts.
with Client("outputs/document-service") as client:
    proposal = client.tool("document_propose", {
        "document": "project-status", "expected_version": 0,
        "content": "Synthetic report text"
    })
    print(proposal["proposal_id"])
    # The owner approves in a separate terminal. The SDK cannot approve.
    # client.tool("document_commit", {"proposal_id": proposal["proposal_id"]})
```

The Rust crate exposes typed `apply`, `witness`, `assess`, `install`, `revoke`, and export APIs. The Python SDK is synchronous and intended for a local trusted broker. Real user integration effort has not been measured.

## Replay, interruption and recovery

The receiver uses an immediate SQLite transaction. Document content/version, nonce consumption, signed receipt and ordered event are committed together. A process exit before commit leaves no effect. A process exit after commit but before reply leaves the committed receipt retrievable by retrying the identical still-valid request. Changed content, changed approval under the same nonce, or a competing expected version fails.

These semantics apply to this transactional SQLite document adapter. They are not general exactly-once guarantees for arbitrary external APIs, restored databases or hardware failures.

If the witness is unavailable after commit, the result says `execution_status: committed`, `status: committed_unwitnessed`, and `witness_status: confirmation_unavailable`. The witness may have accepted a receipt whose reply was lost; this result does not assert that witnessing never occurred. Retrying the same approved ID retrieves the exact stored receipt through a read-only recovery command, even after approval expiry or authority retirement. It catches up missing receipts in sequence, including gaps, without executing a second update. New admission still enforces current approval validity, authority and revocation. Historical verification still rejects revoked authority evidence.

Broker calls are serialized across processes. Direct Rust callers remain outside that lock, so export independently selects the exact checkpoint prefix and checks its count/head. Later receiver events cannot invalidate that prefix. Trust installation/renewal also participates in the broker lock; manual operators must still stop direct admission during trust changes.

Consumers must inspect `execution_status` and `verification_status`, not simply successful JSON transport. `not_committed` means admission failed and read-only lookup found no committed matching request. `outcome_unknown` means receiver state could not be determined. `witnessed_evidence_failed` means a checkpoint was received but evidence export/verification failed. None of these statuses is verified success. Do not create a fresh proposal to retry a committed or unknown outcome.

Owner recovery tools (private local state access is required):

```sh
target/debug/openproof-witness recover /receiver/state < approved-request.json
target/debug/openproof-witness head /receiver/state
target/debug/openproof-witness receipt /receiver/state SEQUENCE
```

`recover` returns the existing matching receipt or null; it validates the original signature/content binding but never authorizes a mutation. Receipt-by-sequence lets operators transfer an omitted receipt even if the original approval expired. Ordinary `receive` keeps its existing expiry checks.

## Trust and operational keys

Keys persist as private Unix 0600 files under private 0700 role directories. Keys are never returned by MCP, placed in evidence packages or sent to the comparison environment. This is software key custody for a local prototype, not an HSM or OS-keystore implementation. Back up custody securely outside any proposed publication; development keys are Git-ignored.

The legacy `trust.json` is an operator-provisioned plain trust input. v0.7.2 adds root-signed `trust-signed.json` and the persistent `verify-trusted` path described in REVIEW-HARDENING.md; the local broker uses that path. It has an epoch, expiration, active authority, retained historical authorities and conservative authority revocations. Receiver/witness persist an epoch/configuration digest and a clock floor. Lower epochs, changed content at the same epoch and backwards clock movement fail. Trust and state rollback by the host owner is outside this guarantee.

Refresh local trust (default lifetime one day):

```sh
outputs/local-venv/bin/python scripts/witness_workflow.py renew outputs/document-service
```

For an owner-prepared configuration, stop admission and use `install-trust HOME FILE`. The helper installs both stores before atomically publishing the configuration. If the second store fails, retain the candidate and retry **that same configuration**; the old configuration may already be rejected by the first store. The helper does not silently roll back or generate a new candidate.

Planned authority rotation: generate a new private key with `openproof-witness keygen`, add the old public authority to `previous_authorities`, set the new active authority, advance the epoch, install the candidate, then replace the owner authority key while admission is stopped. Retired authority approvals cannot newly dispatch; their previously observed receipts remain verifiable. Add a compromised authority to `revoked_authorities` to reject its historical evidence conservatively. Receiver and witness key rotation is deliberately rejected by the owner helper pending a migration protocol. An installed `owner_passkey` is carried into every later trust unchanged; states refuse a trust that removes or replaces it ([PASSKEY.md](PASSKEY.md)).

Receiver-local `revoke STATE NONCE_OR_AUTHORITY_KEY` stops subsequent admissions. It does not retroactively undo a committed document or automatically update an offline verifier's trust file. There are no background revocation fetches. Offline verifiers must be supplied appropriate current trust inputs.

## Detecting missing evidence

Every receiver event signs a sequence number and previous-event digest. Witness admission rejects missing/reordered events and conflicting events at an already witnessed sequence. Verification requires the complete contiguous chain to equal a **separately pinned** witness checkpoint.

This detects truncation relative to that checkpoint. It cannot establish that a checkpoint is the newest in existence if the verifier has no independent source of freshness. A pinned fresh witness can expose a restored receiver history; rolling back every store and every verifier pin defeats the local mechanism.

The receiver's owner may emit a signed `gap` event with a bounded reason through the privileged CLI. Verification returns `unknown_due_to_disclosed_gap`, never complete history. Gaps cannot be inserted by the agent tool. A gap does not justify accepting a conflicting document update or invent missing receipts.

Only the emitted receiver history is covered. Rejected proposals, operations performed outside this receiver, and events never emitted before checkpointing are not proven complete. This is a linear signed hash chain, not a public Merkle transparency service or a consensus system.

## Offline evidence and timeline

```sh
target/debug/openproof-witness verify /trusted/trust.json /trusted/checkpoint.json < package.json
outputs/local-venv/bin/python scripts/witness_workflow.py timeline package.json --trust /trusted/trust.json --checkpoint /trusted/checkpoint.json --out timeline.html
```

Do not accept trust or a checkpoint merely because the evidence producer supplied them. The demo stores local copies for inspection; independently provision them when crossing a trust boundary. The HTML is a static, escaped, script-free view and does not silently fetch newer evidence. It distinguishes verified role statements from complete history and physical effects.

## Original protocol

[Structural schema](../schemas/openproof-witness-v1.schema.json) and Rust types define `openproof-witness/1`. OPEC-1 canonicalization and strict Ed25519 verification reuse the existing OpenProof core. New domain identifiers are `document-approval/1`, `receiver-receipt/1`, and `witness-checkpoint/1`, under the core's `OpenProof/v1/` prefix. Signatures cannot substitute across these domains. The witness head hashes receipt signing preimages; ordered sequence and previous digest bind the full chain. Typed parsing rejects unknown/duplicate fields and alternate struct-array encodings. CLI inputs are capped at 1 MiB, contents at 8 KiB, and exports at 4096 events. New receiver updates and gap events check the projected full package inside the same transaction, using maximum-width checkpoint time, pretty-JSON bytes with reserved overhead, and canonical size. Capacity rejection rolls back the document, event and consumed nonce. This intentionally stops admission before an unexportable history is created; it does not offer unlimited history or pagination. Identical accepted retries and read-only recovery remain available at capacity. Do not reset databases to bypass the cap; migrate only through a future reviewed protocol. Preexisting oversized databases are not silently truncated or repaired: admission fails closed and the broker reports evidence failures explicitly. Python evidence serialization retains UTF-8 rather than expanding non-ASCII characters. Verification indexes approval digests once instead of rescanning every request for every receipt.

## Comparison and remaining work

[Version-pinned experiment](../outputs/v0.7/comparison-final/REPORT.md) tests TRACE `agentrust-trace==0.11.0` and the current Rust release. Distribution digest, dependency freeze and platform are retained. Common tests cover valid evidence, signed-field mutation and incorrect trusted keys. Latency and peak memory are measured for explicitly different workloads; neither those numbers nor the small test corpus establish a security winner. TRACE's untested deployment capabilities are not scored as absent. Its [verification documentation](https://trace.agentrust-io.com/docs/verification/) describes additional receipt and transparency checks beyond the tested SDK path.

Remaining deployment gates: independently operated receiver/witness transport, stronger key custody, authenticated agent/delegation identity, receiver/witness key migration, external human review, broader comparative corpus and real integration/usability studies. No public service or release was created. A focused Claude Opus 5.5 AI static review covered 22 v0.7 files; it was not a human audit. The v0.7.1 patch addresses confirmed F1/F2/F5. v0.7.2 adds the remaining hardening and a Claude AI retest with follow-up fixes; see REVIEW-HARDENING.md and its validation report. No external human audit has been performed. Broker results now use `local_consistency_check` and `local_consistency_verified` for successful local checks. Broker results explicitly label `verification_scope: local_consistency_check` and `independent_operators: false`; cryptographic verification is not organizational independence.
