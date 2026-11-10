//! Owner-side code: the approval gate, persistent verification, paging
//! checks, clock repair and the experimental formats. The receiver and the
//! witness themselves are in `openproof-receiver`, re-exported here.
#![forbid(unsafe_code)]
use ed25519_dalek::SigningKey;
use openproof_core::{canonical, digest, sign, verify_signature, Evidence, Signed};
pub use openproof_receiver::*;
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use serde::{Deserialize, Serialize};
use std::{fs, path::Path, time::UNIX_EPOCH};
// Experimental: not in the default build. See docs/TCB.md.
#[cfg(feature = "experimental")]
mod storage;
#[cfg(feature = "experimental")]
pub use storage::*;
mod clock_recovery;
pub use clock_recovery::*;
#[cfg(feature = "experimental")]
mod rotation;
#[cfg(feature = "experimental")]
pub use rotation::*;
mod gate;
pub use gate::*;
mod pages;
pub use pages::*;
mod verifier;
pub use verifier::*;
pub mod tlog;
#[derive(Debug, Serialize)]
pub struct Assessment {
    pub verification_scope: String,
    pub authorization_verified: bool,
    pub receiver_observation_verified: bool,
    pub witness_checkpoint_verified: bool,
    pub complete_history: bool,
    pub document_version_continuity_verified: bool,
    pub status: String,
    pub physical_effects_proven: bool,
}
pub fn assess(
    p: &Package,
    t: &Trust,
    pinned: &Signed<Checkpoint>,
    time: u64,
) -> Result<Assessment> {
    t.validate(time)?;
    check(
        p.version == V
            && !p.receipts.is_empty()
            && p.receipts.len() <= 4096
            && p.requests.len() <= 4096,
        "package limit/version",
    )?;
    verify_signature(pinned, &t.witness)?;
    verify_signature(&p.checkpoint, &t.witness)?;
    check(
        canonical(pinned)? == canonical(&p.checkpoint)?,
        "checkpoint differs from independently pinned head",
    )?;
    check(
        p.checkpoint.payload.receiver == t.receiver && p.checkpoint.payload.observed_at <= time,
        "checkpoint receiver/time",
    )?;
    let mut requests = std::collections::HashMap::new();
    for q in &p.requests {
        check(
            requests.insert(digest(&q.approval.payload)?, q).is_none(),
            "duplicate authorization",
        )?;
    }
    let mut head = ZERO.to_string();
    let mut gaps = false;
    let mut used = std::collections::HashSet::new();
    let mut versions = std::collections::HashMap::new();
    let mut last_time = 0;
    for (i, r) in p.receipts.iter().enumerate() {
        verify_signature(r, &t.receiver)?;
        let x = &r.payload;
        check(
            x.sequence == i as u64 + 1
                && x.previous == head
                && x.observed_at <= p.checkpoint.payload.observed_at
                && x.observed_at >= last_time,
            "missing, reordered or invalid event time",
        )?;
        last_time = x.observed_at;
        if x.kind == "gap" {
            gaps = true;
        } else {
            let q = requests
                .get(&x.approval_sha256)
                .ok_or("missing authorization")?;
            validate_request(q, t, x.observed_at)?;
            check_owner_assertion(q, t, x.sequence)?;
            check(
                used.insert(q.approval.payload.nonce.clone()),
                "duplicate authorization nonce",
            )?;
            check(
                x.document == q.approval.payload.document
                    && x.document_version == q.approval.payload.expected_version + 1
                    && x.content_sha256 == hash(q.content.as_bytes()),
                "receiver outcome contradicts authorization",
            )?;
            let previous = versions.get(&x.document).copied().unwrap_or(0);
            if !gaps {
                check(
                    q.approval.payload.expected_version == previous,
                    "document version discontinuity",
                )?;
            }
            versions.insert(x.document.clone(), x.document_version);
        }
        head = digest(&r.payload)?;
    }
    check(
        p.checkpoint.payload.count == p.receipts.len() as u64 && p.checkpoint.payload.head == head,
        "truncated or conflicting history",
    )?;
    check(
        p.requests.len() == used.len(),
        "unrelated request in evidence",
    )?;
    Ok(Assessment {
        verification_scope: "stateless".into(),
        authorization_verified: true,
        receiver_observation_verified: true,
        witness_checkpoint_verified: true,
        complete_history: !gaps,
        document_version_continuity_verified: !gaps,
        status: if gaps {
            "unknown_due_to_disclosed_gap"
        } else {
            "receiver_confirmed_and_witnessed"
        }
        .into(),
        physical_effects_proven: false,
    })
}
pub fn install(path: &Path, t: &Trust, time: u64) -> Result<()> {
    let mut c = connect(path)?;
    let tx = c.transaction_with_behavior(TransactionBehavior::Immediate)?;
    pin(&tx, t, time)?;
    tx.commit()?;
    Ok(())
}
pub fn revoke(path: &Path, value: &str) -> Result<()> {
    check(valid_hash(value), "revoke expects nonce or key hex")?;
    connect(path)?.execute("INSERT OR IGNORE INTO revoked VALUES(?1)", [value])?;
    Ok(())
}
pub fn gap(
    path: &Path,
    reason: &str,
    t: &Trust,
    key: &SigningKey,
    time: u64,
) -> Result<Signed<Receipt>> {
    check(
        hex::encode(key.verifying_key().to_bytes()) == t.receiver,
        "wrong receiver signer",
    )?;
    let mut c = connect(path)?;
    let tx = c.transaction_with_behavior(TransactionBehavior::Immediate)?;
    pin(&tx, t, time)?;
    let (n, h) = tip(&tx)?;
    let r = sign(
        Receipt {
            version: V.into(),
            kind: "gap".into(),
            sequence: n + 1,
            previous: h,
            approval_sha256: ZERO.into(),
            document: String::new(),
            document_version: 0,
            content_sha256: ZERO.into(),
            observed_at: time,
            reason: reason.into(),
        },
        key,
    )?;
    tx.execute(
        "INSERT INTO events VALUES(?1,?2,?3,NULL)",
        params![n + 1, digest(&r.payload)?, serde_json::to_string(&r)?],
    )?;
    history_budget(&tx, &t.receiver)?;
    signed_time(&tx, time)?;
    tx.commit()?;
    Ok(r)
}
#[cfg(test)]
mod tests;
