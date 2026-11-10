//! Trust installation and history export for a role state pinned to a root.
use super::*;
impl Evidence for Trust {
    const DOMAIN: &'static str = "witness-trust/1";
    fn validate(&self) -> openproof_core::Result<()> {
        self.validate(0)
            .map_err(|e| openproof_core::Error(e.to_string()))
    }
}
pub fn export_verified(
    path: &Path,
    t: &Trust,
    cp: Signed<Checkpoint>,
    time: u64,
) -> Result<Package> {
    t.validate(time)?;
    verify_signature(&cp, &t.witness)?;
    check(
        cp.payload.receiver == t.receiver && cp.payload.observed_at <= time,
        "checkpoint receiver/time",
    )?;
    export(path, cp)
}
pub fn role_install(path: &Path, signed: &Signed<Trust>, root: &str, time: u64) -> Result<()> {
    let mut c = connect(path)?;
    let tx = c.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let (pinned, r, w): (String, Option<String>, Option<String>) = tx.query_row(
        "SELECT root,receiver,witness FROM role_anchor WHERE id=1",
        [],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
    )?;
    check(pinned == root, "role root mismatch")?;
    verify_signature(signed, &pinned)?;
    let t = &signed.payload;
    t.validate(time)?;
    check(
        pinned != t.authority
            && pinned != t.receiver
            && pinned != t.witness
            && !t.previous_authorities.contains(&pinned)
            && !t.revoked_authorities.contains(&pinned),
        "root role reuse",
    )?;
    if let (Some(r), Some(w)) = (r, w) {
        check(
            r == t.receiver && w == t.witness,
            "role migration unsupported",
        )?;
    }
    tx.execute(
        "UPDATE role_anchor SET epoch=?1,trust_hash=?2,receiver=?3,witness=?4 WHERE id=1",
        params![t.epoch, hash(&canonical(t)?), t.receiver, t.witness],
    )?;
    pin(&tx, t, time)?;
    tx.commit()?;
    Ok(())
}
pub fn role_root(path: &Path) -> Result<Option<String>> {
    let c = connect_read(path)?;
    let present: bool = c.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE name='role_anchor')",
        [],
        |r| r.get(0),
    )?;
    if !present {
        return Ok(None);
    }
    Ok(
        c.query_row("SELECT root FROM role_anchor WHERE id=1", [], |r| r.get(0))
            .optional()?,
    )
}
