# Contributing

The source is public under Apache-2.0. Antagon, Inc. maintains it.

## What helps now

- **Issues.** Report a defect, a document that is wrong or not clear, or a
  step that failed on your computer. Give the commit, your operating system
  and the exact output.
- **Security reports.** Use the private path in [SECURITY.md](SECURITY.md),
  not a public issue.
- **Running it.** Tell us where the quick start or the role-accounts install
  failed or was hard to follow.

## Pull requests

The terms for code from outside Antagon are not set yet: there is no
contributor agreement and no process for outside maintainers. Until they are
set, Antagon does not merge code from outside pull requests. Describe the
change in an issue first. A pull request is still useful as a way to show a
defect or a test.

## Rules for every change

- Keep the project independently authored. Do not bring in Antagon
  proprietary material, or source from other projects without clear rights
  and the required attribution ([docs/IP-BOUNDARIES.md](docs/IP-BOUNDARIES.md)).
- Use synthetic inputs only. No real keys, credentials, customer data or
  private documents, in code, tests or issues.
- Run the validation before you propose a change:
  `python3 scripts/validate.py --out outputs/NEW-DIRECTORY`
  ([docs/BUILD.md](docs/BUILD.md)). It runs the formatters, Clippy with
  warnings denied, all tests, the cross-implementation suites, the
  trusted-code count, the license check and the advisory audit.
- A protocol change needs a versioning decision, an updated schema, byte
  vectors and negative tests.
- A change to the trusted code updates [docs/TCB.md](docs/TCB.md) and the
  [threat model](docs/threatmodel.md) in the same change, and stays inside
  the line budget in `scripts/tcb_count.py`, or raises the budget with a
  stated reason.
- A new check comes with a test that fails when the check is removed.
- Tests and documents keep three things apart: a signed statement, an
  observed result, and a result that another party confirmed.
- Say what was tested and where. Do not write a claim that a test or a
  record in this repository does not show.

## Releases

No versioned release, package or binary is published without the owner's
approval of the exact commit and its claims
([docs/RELEASE-CHECKLIST.md](docs/RELEASE-CHECKLIST.md)).
