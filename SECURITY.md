# Security policy

OpenProof is experimental software, version 0.9.0. No human security review
has been done. No versioned release has been published. The code that this
policy covers is the `main` branch of this repository.

Read the three guarantees and their conditions in the [README](README.md),
the [threat model](docs/threatmodel.md) and the
[trusted code inventory](docs/TCB.md) before you rely on OpenProof for
anything.

## Report a vulnerability

Report it in private. On GitHub, open the **Security** tab of this
repository and select **Report a vulnerability**. Do not open a public issue
for a suspected vulnerability.

Give:

- the commit that you tested;
- the guarantee (G1, G2 or G3) or the boundary of the threat model that is
  affected;
- what the attacker needs before the attack (for example: code in the
  owner's account, a changed archive);
- the steps or a test that shows it, with what you saw and what you
  expected.

Do not send secrets, real keys or other people's data. Test only on your own
computers, with your own OpenProof home.

Antagon is a small company. We read each report and answer it, and we do not
promise a time. A confirmed defect is corrected on `main` with a test that
fails without the correction. We name the reporter in the change if the
reporter wants that. There is no bounty.

## What is a vulnerability here

- A change to a receiver's document without a valid approval, under G1's
  condition.
- A second effect from one approval, or a receipt that does not match what
  was changed.
- A history that the witness or the Go verifier accepts with an omitted,
  reordered or replaced event.
- A review page that lets the passkey sign something other than the content
  that it shows, without control of the browser or of the owner's account.
- A status check that reports `"separated": true` or
  `"passkey_required_by_receiver": true` when that is false, apart from the
  limits that [TCB.md](docs/TCB.md) lists.
- A way for an agent tool to approve, or to choose a key, a path or a
  command.

## What is a stated limit, not a vulnerability

The [threat model](docs/threatmodel.md) lists these under each boundary and
under "Out of scope". The main ones:

- The administrator, root, and an owner's account with administrator rights.
- No passkey, or no separate role accounts: G1's condition is then not met.
- A witness on the owner's computer: G2's condition is then not met.
- A verifier or a root taken from the archive that is checked.
- Code in the owner's account that blocks or delays work.
- The owner confirms a passkey prompt for content that they did not read.

A report that shows a limit to be worse than the documents say is welcome.

## Rules for changes to the trusted code

- A change that is relevant to security needs negative tests, and an update
  of the protocol text when the protocol changes.
- Do not widen the accepted algorithms, versions or encodings without a
  versioning decision.
- A check that was never seen to fail is not verified: remove it once and
  see a test fail.
- Update [docs/TCB.md](docs/TCB.md) and the [threat model](docs/threatmodel.md)
  in the same change.
- Passing tests are not a security claim. A review by an AI model is
  labelled as such and is not a human review.
