//! Planned handover at an already confirmed checkpoint. Emergency recovery is separate.
use super::*;
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rotation {
    pub version: String,
    pub old_root: String,
    pub new_root: String,
    pub old_trust_sha256: String,
    pub new_trust: Trust,
    pub checkpoint: Signed<Checkpoint>,
    pub not_before: u64,
    pub expires_at: u64,
}
impl Evidence for Rotation {
    const DOMAIN: &'static str = "witness-planned-rotation/1";
    fn validate(&self) -> openproof_core::Result<()> {
        if self.version != "openproof-rotation/1"
            || !valid_hash(&self.old_trust_sha256)
            || self.not_before > self.expires_at
            || self.expires_at - self.not_before > 600
        {
            return Err(openproof_core::Error("invalid rotation".into()));
        }
        openproof_core::public_key(&self.old_root)?;
        openproof_core::public_key(&self.new_root)?;
        self.new_trust
            .validate(0)
            .map_err(|e| openproof_core::Error(e.to_string()))?;
        Ok(())
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Handover {
    pub old_root: Signed<Rotation>,
    pub new_root: Signed<Rotation>,
    pub old_receiver: Signed<Rotation>,
    pub new_receiver: Signed<Rotation>,
    pub old_witness: Signed<Rotation>,
    pub new_witness: Signed<Rotation>,
}
pub fn validate_handover(old: &Signed<Trust>, root: &str, h: &Handover, time: u64) -> Result<()> {
    verify_signature(old, root)?;
    old.payload.validate(time)?;
    let r = &h.old_root.payload;
    r.new_trust.validate(time)?;
    check(
        r.old_root == root
            && r.old_trust_sha256 == hash(&canonical(&old.payload)?)
            && r.not_before <= time
            && time <= r.expires_at
            && r.new_trust.epoch > old.payload.epoch,
        "rotation root/trust/window",
    )?;
    let t = &r.new_trust;
    check(
        r.new_root != t.authority
            && r.new_root != t.receiver
            && r.new_root != t.witness
            && !t.previous_authorities.contains(&r.new_root)
            && !t.revoked_authorities.contains(&r.new_root),
        "rotation root role reuse",
    )?;
    let envelope = [
        (&h.old_root, root),
        (&h.new_root, r.new_root.as_str()),
        (&h.old_receiver, old.payload.receiver.as_str()),
        (&h.new_receiver, t.receiver.as_str()),
        (&h.old_witness, old.payload.witness.as_str()),
        (&h.new_witness, t.witness.as_str()),
    ];
    for (signed, key) in envelope {
        check(
            canonical(&signed.payload)? == canonical(r)?,
            "rotation payload mismatch",
        )?;
        verify_signature(signed, key)?;
    }
    verify_signature(&r.checkpoint, &old.payload.witness)?;
    check(
        r.checkpoint.payload.receiver == old.payload.receiver
            && r.checkpoint.payload.observed_at <= time
            && time - r.checkpoint.payload.observed_at <= 300,
        "rotation checkpoint binding/freshness",
    )?;
    Ok(())
}
pub fn rotate_state(path: &Path, old: &Signed<Trust>, h: &Handover, time: u64) -> Result<()> {
    let mut c = connect(path)?;
    let tx = c.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let verifier: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE name='verifier')",
        [],
        |r| r.get(0),
    )?;
    let root: String = if verifier {
        tx.query_row("SELECT root FROM verifier WHERE id=1", [], |r| r.get(0))?
    } else {
        tx.query_row("SELECT root FROM role_anchor WHERE id=1", [], |r| r.get(0))?
    };
    validate_handover(old, &root, h, time)?;
    let r = &h.old_root.payload;
    let cp = &r.checkpoint.payload;
    let (epoch, oldhash, clock): (u64, String, u64) = tx.query_row(
        "SELECT epoch,trust_hash,clock FROM control WHERE id=1",
        [],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
    )?;
    check(
        epoch == old.payload.epoch && oldhash == r.old_trust_sha256 && time >= clock,
        "rotation installed trust/clock",
    )?;
    if verifier {
        let (count, head): (u64, String) =
            tx.query_row("SELECT count,head FROM verifier WHERE id=1", [], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })?;
        check(
            count == cp.count && head == cp.head,
            "rotation requires confirmed verifier checkpoint",
        )?;
        pages::stream_schema(&tx)?;
        let (sc, sh): (u64, String) = tx.query_row(
            "SELECT count,head FROM stream_progress WHERE id=1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        check(
            sc == count && sh == head,
            "rotation requires paged verifier state at cutover",
        )?;
        tx.execute(
            "UPDATE verifier SET root=?1,receiver=?2,witness=?3 WHERE id=1",
            params![r.new_root, r.new_trust.receiver, r.new_trust.witness],
        )?;
    } else {
        let (count, head) = tip(&tx)?;
        check(
            count == cp.count && head == cp.head,
            "role not at cutover checkpoint",
        )?;
        tx.execute("UPDATE role_anchor SET root=?1,epoch=?2,trust_hash=?3,receiver=?4,witness=?5 WHERE id=1",params![r.new_root,r.new_trust.epoch,hash(&canonical(&r.new_trust)?),r.new_trust.receiver,r.new_trust.witness])?;
    }
    // Epoch/configuration change is atomic with key identity; replay/history tables remain.
    pin(&tx, &r.new_trust, time)?;
    tx.execute_batch(
        "CREATE TABLE IF NOT EXISTS rotations(epoch INTEGER PRIMARY KEY,record TEXT NOT NULL);",
    )?;
    tx.execute(
        "INSERT INTO rotations VALUES(?1,?2)",
        params![r.new_trust.epoch, serde_json::to_string(h)?],
    )?;
    tx.commit()?;
    Ok(())
}

/// Read-only reconciliation of an exact completed local transition; does not reapply it.
pub fn rotation_applied(path: &Path, h: &Handover) -> Result<bool> {
    let c = connect_read(path)?;
    let exists: bool = c.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE name='rotations')",
        [],
        |r| r.get(0),
    )?;
    if !exists {
        return Ok(false);
    }
    let record: Option<String> = c
        .query_row(
            "SELECT record FROM rotations WHERE epoch=?1",
            [h.old_root.payload.new_trust.epoch],
            |r| r.get(0),
        )
        .optional()?;
    let Some(record) = record else {
        return Ok(false);
    };
    let stored: Handover = openproof_core::parse(record.as_bytes())?;
    check(
        canonical(&stored)? == canonical(h)?,
        "different transition already recorded",
    )?;
    let verifier: bool = c.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE name='verifier')",
        [],
        |r| r.get(0),
    )?;
    let root: String = c.query_row(
        if verifier {
            "SELECT root FROM verifier WHERE id=1"
        } else {
            "SELECT root FROM role_anchor WHERE id=1"
        },
        [],
        |r| r.get(0),
    )?;
    check(
        root == h.old_root.payload.new_root,
        "transition root no longer current",
    )?;
    Ok(true)
}
