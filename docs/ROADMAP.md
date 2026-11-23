# Roadmap

This file says where OpenProof is, what is open, and what comes next. It
gives no dates. It claims no comparison with, and no superiority over, any
other system.

## Where it is: version 0.9.0

One path works on one computer:
**propose → review → approve with passkey → execute → witness → verify offline.**

| Built | Document |
|---|---|
| Approval of the exact content with a passkey, checked by the review page and again by the receiver | [PASSKEY.md](PASSKEY.md) |
| The receiver and the witness under their own accounts, with a status check of the result | [LOCAL-ROLES.md](LOCAL-ROLES.md) |
| Approved documents as files that only the receiver's account can change | [PROTECTED-FILES.md](PROTECTED-FILES.md) |
| The witness history as a transparency log that other witnesses can cosign | [WITNESS-NETWORK.md](WITNESS-NETWORK.md) |
| A separate Go verifier of exported histories | [README](../README.md#verify-offline) |
| Agent tools that can propose and execute approved work, and cannot approve | [WITNESSED-WORKFLOW.md](WITNESSED-WORKFLOW.md) |
| A link from OpenProof approvals to TRACE Trust Records | [integrations/trace](../integrations/trace/README.md) |
| A counted list of the trusted code, 4,335 lines | [TCB.md](TCB.md) |
| A threat model for this version | [threatmodel.md](threatmodel.md) |

## Open gates

These stop stronger statements. None is met today.

1. **An independent witness.** G2 holds only when a party other than the
   receiver runs the witness. The cosigning code is built and tested against
   test witnesses and against litewitness. OpenProof's log is not on a
   public witness list.
2. **A human security review.** None has been done. The brief is
   [handoff/REVIEW-BRIEF.md](handoff/REVIEW-BRIEF.md). Reviews by AI models
   were done and are labelled as such; they do not count for this gate.
3. **Replacement of a lost passkey.** Not supported. A home whose passkey is
   lost approves no new change.
4. **A release.** No versioned release, signed binary or package exists.
   Install is a build from source. No build has been reproduced on a
   separate machine by another party. The first versioned release waits for
   the human review ([RELEASE-CHECKLIST.md](RELEASE-CHECKLIST.md)).
5. **Independent operators on separate hosts.** The role services run on the
   owner's computer only. A remote role service needs a reviewed transport
   first ([handoff/OPERATORS.md](handoff/OPERATORS.md)).
6. **Trusted code under 4,000 lines.** It is 4,335. The candidate that is
   left is small ([TCB.md](TCB.md#reduction-history)).

## Next

In this order. The order can change after the review.

1. Replacement of a lost passkey, with a design that is reviewed before the
   build, because it changes trusted code.
2. A human review of one fixed commit, a public report, and a retest of the
   corrections.
3. The first versioned release from the reviewed commit.
4. Cosigning by independent witnesses, then the question of G2's condition.

Later, not designed yet: approved actions other than a document change.

## Limits that stay

A signature is a statement by the key's holder. It is not proof that a model
told the truth, that an effect outside the receiver occurred, or that an
operator is independent. The [threat model](threatmodel.md) lists what is
out of scope.

## History

This repository starts with the import of version 0.9 on 8 Nov 2026. The
versions before it were: the canonical encoding and signatures (0.1), a local
execution gate (0.2), trust rotation and revocation (0.3, 0.4), an isolated
report agent (0.5, 0.6), the document receiver and the witness (0.7), the Go
verifier and paged history (0.8), and the owner app (0.9). The earlier text
of this file, with each milestone's record, is in its git history.
Experiments that left the tree are at the git tag `experiments-2026-11-08`
([EXPERIMENTS.md](EXPERIMENTS.md)).
