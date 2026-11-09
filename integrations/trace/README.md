# OpenProof approvals as TRACE `approval-outcome` references

A [TRACE](https://github.com/agentrust-io/trace-spec) Trust Record says what an
AI agent ran, where, and under which policy. OpenProof records what the owner
approved, and proves that exactly that was executed, once. This folder links
the two with no change to either specification. It is also the draft of a
crosswalk for TRACE's `docs/crosswalks/`, in the same form as the existing
CHAP crosswalk.

> **Informative.** Nothing here changes TRACE v0.2 fields, wire formats or
> conformance requirements, and nothing here changes OpenProof's formats.

## The link

TRACE already has the slot. The `references` block (TRACE v0.2 section 3.1.2)
registers `rel: "approval-outcome"` for "an attributable human approval
attached to a step-up or defer decision". An OpenProof approval fills it.

| TRACE `references` field | Value for an OpenProof approval | Notes |
|---|---|---|
| `rel` | `approval-outcome` | Registered value. |
| `id` | `openproof/approval/<approval digest>` | The SHA-256 of the approval's domain-separated OPEC-1 signing bytes. It is unique and content-derived, so it cannot name a different approval. |
| `resolver` | the OpenProof owner's evidence store, as a URI | The party obliged to keep the approval resolvable. |
| `digest` | `sha256:` over the RFC 8785 form of the approved request | The request is the signed approval, the exact content and the owner's passkey assertion. |
| `retention` | optional | Nothing in either specification enforces it. |

`openproof_trace.reference()` builds this entry. Both sides canonicalize the
referenced object with RFC 8785 through the `rfc8785` package, the library
TRACE uses. OpenProof objects carry only strings and non-negative integers
below 2^53, so the number cases where RFC 8785 implementations disagree
cannot occur.

## What an OpenProof approval adds

The CHAP crosswalk names three things a Trust Record and an approval log do
not establish. An OpenProof approval and its resolver records establish two of
them, and the third more strongly:

| Gap named in the CHAP crosswalk | What OpenProof records |
|---|---|
| That the approval was checked before the action ran | The OpenProof receiver applies a change only for a valid, unexpired, single-use approval, and signs a receipt that names the approval digest. |
| That the executed action is the approved draft | The receipt binds the approval digest, the document, the new version and the SHA-256 of the exact content. |
| Who approved | The approval is signed by the authority key in a root-signed trust, and carries a user-verified WebAuthn assertion (passkey) over the approval digest. |

## Verifier steps

Given a Trust Record, the resolver's store and an OpenProof trust root
obtained separately:

1. Verify the Trust Record as usual. An unresolvable reference is not a reason
   to reject it (TRACE section 3.1.2, rule 3).
2. Resolve `id`. If the store has no such entry, report the approval as
   unconfirmed.
3. Recompute the RFC 8785 SHA-256 of the stored request and compare it with
   `digest`. A mismatch means the store no longer holds what the record cited.
4. Verify the root-signed trust, then the approval signature under the trust's
   authority key, the content hash, the receiver named in the approval, and,
   when the trust has an owner passkey, the passkey assertion over the
   approval digest.
5. If the store has a receipt, verify it under the trust's receiver key and
   check that it names this approval, this document, the next version and the
   same content hash. No receipt means approved but not executed.
6. Verify the witness checkpoint under the trust's witness key and check that
   it covers the receipt's sequence.

`openproof_trace.check()` performs these steps and reports each finding and
one verdict. It needs only `rfc8785` and `cryptography`: no OpenProof binary
and no TRACE library. A complete check that the receipt is in the witness's
history, with no omission or fork, is the OpenProof Go verifier's job over an
exported archive.

## Example set

`generate_examples.py` runs a real OpenProof home and writes the set in
[`examples/`](examples/). Every Trust Record verifies; what differs is what the
reference resolves to.

| Record | Store | Verdict |
|---|---|---|
| `01-approval-executed.json` | `openproof-approvals.json` | approval-confirmed-and-executed |
| `02-approval-altered-after-issue.json` | `openproof-approvals-altered.json` | approval-contradicted |
| `03-approved-not-executed.json` | `openproof-approvals.json` | approved-not-executed |
| `04-reference-unresolvable.json` | `openproof-approvals.json` | approval-unconfirmed |
| `05-approval-outside-trust.json` | `openproof-approvals.json` | approval-not-attributable |

- `02` is the same approval with its content rewritten in the store after the
  record was issued.
- `03` is a second approval of the same document version. The receiver refused
  it because the first one executed first, so it has no receipt.
- `05` is an approval signed by a key the owner's trust does not name.

`scripts/tests/test_trace_bridge.py` recomputes every verdict from the
committed bytes, and fails each verifier step on its own defect. The TRACE
signature and `rfc8785` digest code was also checked against TRACE's own
committed CHAP example records: all four records verify and the CHAP digest
recomputes.

## Boundary

- A resolved approval is not attested evidence in TRACE's sense, and it does
  not change whether the Trust Record verifies. That is TRACE's rule and this
  link keeps it.
- The receiver and witness in the example run on one computer under one
  owner. Independent witnessing needs a witness run by another party.
- The passkey in the example set is a software P-256 key standing in for a
  platform authenticator.
