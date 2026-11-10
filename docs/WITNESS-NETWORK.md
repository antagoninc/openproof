# Cosigning by independent witnesses

Status: built, and tested against two test witnesses written from the C2SP
specifications. A CI job (`tlog-interop.yml`) runs the same flow against
litewitness, an independent implementation; its first run is on the commit that
adds it. OpenProof's log is not yet on any public witness list. Guarantee
G2's condition is unchanged until it is, and until the cosigners' keys are
pinned by the people who verify.

## What it does

The OpenProof witness keeps every receiver receipt in a signed, ordered history.
On its own, that history is only as honest as whoever runs the witness. Here the
history is also a transparency log that other parties cosign:

- The leaves are the witness's events in sequence order. Each leaf's data is the
  32-byte receipt digest the event already stores. The tree is RFC 6962.
- The witness key signs C2SP checkpoints ([c2sp.org/tlog-checkpoint](https://c2sp.org/tlog-checkpoint)):
  an origin line, the tree size and the root hash, as a signed note.
- `scripts/tlog_submit.py` pushes each checkpoint with an RFC 6962 consistency
  proof to the configured witnesses ([c2sp.org/tlog-witness](https://c2sp.org/tlog-witness)).
  Each witness checks that the new tree extends the last one it cosigned, then
  returns an Ed25519 cosignature ([c2sp.org/tlog-cosignature](https://c2sp.org/tlog-cosignature)).
- `openproof-tool` checks every cosignature before the submitter keeps it. A
  checkpoint is kept only when it meets the configured quorum.
- One key never counts twice, under any name: a cosignature does not commit to
  the cosigner's name. Small-order keys are refused.
- The Go verifier, given the cosigned checkpoint, recomputes the tree root from
  every receipt in an exported history and requires a quorum of cosigners whose
  keys the verifier supplies.

Only tree heads and proofs leave the computer. A witness never sees a receipt,
an approval or a document.

## What it shows, and what it does not

A cosigner that follows the protocol never signs two different trees of the same
log at the same size, and never signs a tree that does not extend the last one it
signed. So, given a checkpoint cosigned by a quorum of witnesses the verifier
trusts:

- The witness cannot later show a different history up to that size, to anyone
  who checks against the same witnesses, without a cosigner misbehaving.
- The witness cannot remove or reorder a receipt that is already covered by a
  cosigned checkpoint.

It does not show:

- That a receipt was ever submitted. The receiver and witness still decide what
  enters the log; cosigners only fix what was there.
- Who runs the cosigners, or that they are independent of each other. The
  verifier chooses which cosigner keys to trust and how many to require.
- Anything about the contents of a receipt. Cosigners see only sizes and hashes.

## Use it

1. Choose an origin you control that will never change, for example
   `openproof.example.org/owners/release-desk`. Do not start it with `OpenProof`.
2. Get the log's verifier key: `openproof-tool tlog-vkey ORIGIN WITNESS_KEY_HEX`,
   with the `witness` key from `trust.json`.
3. Ask each witness operator to add the origin and that key. For the public
   witness network, see [witness-network.org](https://witness-network.org/participate).
4. Write `HOME/tlog/witnesses.json`:

   ```json
   {"origin": "openproof.example.org/owners/release-desk", "quorum": 2,
    "witnesses": [{"name": "...", "url": "https://...", "vkey": "..."}]}
   ```

5. After new receipts, run `python3 scripts/tlog_submit.py HOME`. It writes
   `HOME/tlog/checkpoint.note`.
6. To verify an export with the cosigners, add four arguments to the Go
   verifier: the note, the origin, a JSON list of cosigner vkeys you trust, and
   the quorum.

   ```sh
   openproof-go-verify verify-archive ROOT CHECKPOINT.json ARCHIVE NOW \
     checkpoint.note ORIGIN cosigners.json 2
   ```

The origin is fixed on first use. The witness refuses a different one.

## Tests

- `crates/openproof-witness/src/tlog.rs`: RFC 6962 roots against published
  vectors, every inclusion and consistency proof for trees of 1 to 40 leaves
  (and a tampered one), notes and cosignatures.
- `reference/go-witness/tlog_test.go`: the same vectors, and 13 ways a
  cosigned checkpoint must be refused, including one key under two names and a
  forged cosignature under a small-order key.
- `scripts/tests/test_tlog.py`: the full flow against two test witnesses written
  from the C2SP specifications (`scripts/tests/c2sp_test_witness.py`), including
  a refused bad proof, a lost submitter state, a fixed origin, a quorum the
  verifier cannot meet, and a cosigned tree that does not cover the history.
- `.github/workflows/tlog-interop.yml`: the same flow against litewitness, an
  independent C2SP witness, on every push and weekly.
