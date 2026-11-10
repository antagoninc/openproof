//! The witness history as a transparency log that public witnesses can cosign.
//!
//! The leaves are the witness's events in sequence order; each leaf's data is the
//! 32-byte receipt digest the event already stores. The tree is RFC 6962 (RFC 9162
//! section 2.1). Checkpoints follow C2SP tlog-checkpoint and are signed as C2SP
//! signed notes with the witness key, and add-checkpoint requests follow C2SP
//! tlog-witness. Checking notes and cosignatures is owner-side code, in
//! `openproof-witness`.
//!
//! Only tree heads and proofs leave the witness: a cosigner never sees a receipt.
use crate::{check, connect, connect_read, pin, Result, Trust};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use ed25519_dalek::{Signer, SigningKey};
use rusqlite::{OptionalExtension, TransactionBehavior};
use sha2::{Digest, Sha256};
use std::path::Path;
pub type Hash = [u8; 32];
pub fn leaf_hash(data: &[u8]) -> Hash {
    let mut h = Sha256::new();
    h.update([0u8]);
    h.update(data);
    h.finalize().into()
}
#[doc(hidden)]
pub fn node(l: &Hash, r: &Hash) -> Hash {
    let mut h = Sha256::new();
    h.update([1u8]);
    h.update(l);
    h.update(r);
    h.finalize().into()
}
/// The largest power of two strictly less than n (n >= 2).
#[doc(hidden)]
pub fn split(n: usize) -> usize {
    let mut k = 1;
    while k << 1 < n {
        k <<= 1;
    }
    k
}
/// MTH over already-hashed leaves.
pub fn root(leaves: &[Hash]) -> Hash {
    match leaves.len() {
        0 => Sha256::digest([]).into(),
        1 => leaves[0],
        n => {
            let k = split(n);
            node(&root(&leaves[..k]), &root(&leaves[k..]))
        }
    }
}
/// RFC 6962 section 2.1.1 PATH(m, D[n]).
pub fn inclusion_proof(index: usize, leaves: &[Hash]) -> Result<Vec<Hash>> {
    check(index < leaves.len(), "leaf index out of range")?;
    fn path(m: usize, d: &[Hash], out: &mut Vec<Hash>) {
        if d.len() <= 1 {
            return;
        }
        let k = split(d.len());
        if m < k {
            path(m, &d[..k], out);
            out.push(root(&d[k..]));
        } else {
            path(m - k, &d[k..], out);
            out.push(root(&d[..k]));
        }
    }
    let mut out = vec![];
    path(index, leaves, &mut out);
    Ok(out)
}
/// RFC 6962 section 2.1.2 PROOF(m, D[n]).
pub fn consistency_proof(old: usize, leaves: &[Hash]) -> Result<Vec<Hash>> {
    check(old <= leaves.len(), "old size beyond the tree")?;
    fn sub(m: usize, d: &[Hash], whole: bool, out: &mut Vec<Hash>) {
        if m == d.len() {
            if !whole {
                out.push(root(d));
            }
            return;
        }
        let k = split(d.len());
        if m <= k {
            sub(m, &d[..k], whole, out);
            out.push(root(&d[k..]));
        } else {
            sub(m - k, &d[k..], false, out);
            out.push(root(&d[..k]));
        }
    }
    let mut out = vec![];
    if old > 0 && old < leaves.len() {
        sub(old, leaves, true, &mut out);
    }
    Ok(out)
}
/// A C2SP origin: printable ASCII without spaces, and never an OpenProof signing
/// domain, so a note signature and an OpenProof signature by the same key can
/// never be confused.
pub fn valid_origin(origin: &str) -> bool {
    !origin.is_empty()
        && origin.len() <= 255
        && origin
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"./_-:".contains(&b))
        && !origin.starts_with("OpenProof")
        && !origin.starts_with("cosignature/")
}
#[doc(hidden)]
pub fn key_id(name: &str, kind: u8, public: &[u8; 32]) -> [u8; 4] {
    let mut h = Sha256::new();
    h.update(name.as_bytes());
    h.update(b"\n");
    h.update([kind]);
    h.update(public);
    let d = h.finalize();
    [d[0], d[1], d[2], d[3]]
}
/// The checkpoint body: origin, size and base64 root, each ending in a newline.
pub fn checkpoint_body(origin: &str, size: u64, root_hash: &Hash) -> String {
    format!("{origin}\n{size}\n{}\n", B64.encode(root_hash))
}
/// Sign a checkpoint body as a C2SP signed note with an Ed25519 key (type 0x01).
pub fn sign_note(body: &str, origin: &str, key: &SigningKey) -> String {
    let public = key.verifying_key().to_bytes();
    let mut raw = key_id(origin, 0x01, &public).to_vec();
    raw.extend_from_slice(&key.sign(body.as_bytes()).to_bytes());
    format!("{body}\n\u{2014} {origin} {}\n", B64.encode(raw))
}
/// The witness's leaves: each event's receipt digest, in sequence order.
pub fn leaves(path: &Path) -> Result<Vec<Hash>> {
    let c = connect_read(path)?;
    let mut stmt = c.prepare("SELECT seq,hash FROM events ORDER BY seq")?;
    let mut rows = stmt.query([])?;
    let mut out = vec![];
    while let Some(row) = rows.next()? {
        let seq: u64 = row.get(0)?;
        check(seq == out.len() as u64 + 1, "event sequence gap")?;
        let h: String = row.get(1)?;
        out.push(leaf_hash(&hex::decode(h)?));
    }
    Ok(out)
}
/// Sign the current tree head as a C2SP checkpoint under `origin`, and return the
/// add-checkpoint request body for a witness that last cosigned size `old`. The
/// origin is fixed on first use and refused if it ever changes.
pub fn add_checkpoint_request(
    path: &Path,
    t: &Trust,
    key: &SigningKey,
    origin: &str,
    old: u64,
    time: u64,
) -> Result<String> {
    check(valid_origin(origin), "invalid origin")?;
    check(
        hex::encode(key.verifying_key().to_bytes()) == t.witness,
        "wrong witness signer",
    )?;
    let mut c = connect(path)?;
    let tx = c.transaction_with_behavior(TransactionBehavior::Immediate)?;
    pin(&tx, t, time)?;
    tx.execute(
        "CREATE TABLE IF NOT EXISTS tlog(id INTEGER PRIMARY KEY CHECK(id=1), origin TEXT NOT NULL)",
        [],
    )?;
    let fixed: Option<String> = tx
        .query_row("SELECT origin FROM tlog WHERE id=1", [], |r| r.get(0))
        .optional()?;
    match fixed {
        Some(o) => check(o == origin, "the log origin never changes")?,
        None => {
            tx.execute("INSERT INTO tlog VALUES(1,?1)", [origin])?;
        }
    }
    tx.commit()?;
    let all = leaves(path)?;
    let size = all.len() as u64;
    check(old <= size, "witness is ahead of this log")?;
    let note = sign_note(&checkpoint_body(origin, size, &root(&all)), origin, key);
    let mut body = format!("old {old}\n");
    for h in consistency_proof(old as usize, &all)? {
        body.push_str(&B64.encode(h));
        body.push('\n');
    }
    body.push('\n');
    body.push_str(&note);
    Ok(body)
}
/// The inclusion proof of event `seq` (1-based) in the tree of `size` leaves.
pub fn event_inclusion(path: &Path, seq: u64, size: u64) -> Result<Vec<Hash>> {
    let all = leaves(path)?;
    check(
        seq >= 1 && seq <= size && size <= all.len() as u64,
        "proof range",
    )?;
    inclusion_proof(seq as usize - 1, &all[..size as usize])
}
