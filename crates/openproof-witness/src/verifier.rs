//! Persistent verification with a separately provisioned root and signed trust.
use super::*;
pub fn verifier_init(path: &Path, root: &str) -> Result<()> {
    openproof_core::public_key(root)?;
    init(path)?;
    let c = connect(path)?;
    c.execute_batch("CREATE TABLE verifier(id INTEGER PRIMARY KEY,root TEXT NOT NULL,receiver TEXT,witness TEXT,count INTEGER NOT NULL,head TEXT NOT NULL,observed INTEGER NOT NULL);")?;
    c.execute(
        "INSERT INTO verifier VALUES(1,?1,NULL,NULL,0,?2,0)",
        params![root, ZERO],
    )?;
    Ok(())
}
/// The owner's own states (the verifier and the gate) follow a replacement of
/// the owner passkey: when the new trust keeps the passkeys they pinned and
/// adds later ones, the pin moves to the whole list. The receiver and the
/// witness never do this; there only the administrator moves the pin
/// (`replace_owner_passkey`). A passkey can be added only when the receipt
/// before its start is not yet verified: `checked` is the number of receipts
/// that this state has verified. So the receiver's `passkey` receipt for it is
/// still to come and is checked under the new trust (`replacement_receipt`).
pub(crate) fn follow_owner_passkey(
    tx: &rusqlite::Transaction<'_>,
    t: &Trust,
    checked: u64,
) -> Result<()> {
    let has_pin: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE name='owner_passkey_pin')",
        [],
        |r| r.get(0),
    )?;
    if !has_pin {
        return Ok(());
    }
    let pinned: Option<String> = tx
        .query_row("SELECT record FROM owner_passkey_pin WHERE id=1", [], |r| {
            r.get(0)
        })
        .optional()?;
    let Some(pinned) = pinned else { return Ok(()) };
    let all: Vec<&OwnerPasskey> = owner_passkeys(t).collect();
    let added = passkeys_added(&pinned, t)?.unwrap_or(0);
    if added > 0 {
        for k in &all[all.len() - added..] {
            check(
                k.from_sequence > checked + 1,
                "an owner passkey was added behind the receipts already verified",
            )?;
        }
        tx.execute(
            "UPDATE owner_passkey_pin SET record=?1 WHERE id=1",
            [owner_passkey_pin_record(t)?],
        )?;
    }
    Ok(())
}
/// The number of receipts that a verifier state has verified: the pinned
/// checkpoint count, or the paged progress when that is further.
fn verified_count(tx: &rusqlite::Transaction<'_>) -> Result<u64> {
    let pinned: u64 = tx.query_row("SELECT count FROM verifier WHERE id=1", [], |r| r.get(0))?;
    let paged: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE name='stream_progress')",
        [],
        |r| r.get(0),
    )?;
    let progress: Option<u64> = if paged {
        tx.query_row("SELECT count FROM stream_progress WHERE id=1", [], |r| {
            r.get(0)
        })
        .optional()?
    } else {
        None
    };
    Ok(pinned.max(progress.unwrap_or(0)))
}
pub(super) fn install_signed(
    tx: &rusqlite::Transaction<'_>,
    signed: &Signed<Trust>,
    time: u64,
) -> Result<()> {
    let (root, receiver, witness): (String, Option<String>, Option<String>) = tx.query_row(
        "SELECT root,receiver,witness FROM verifier WHERE id=1",
        [],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
    )?;
    verify_signature(signed, &root)?;
    let t = &signed.payload;
    check(
        root != t.authority
            && root != t.receiver
            && root != t.witness
            && !t.previous_authorities.contains(&root)
            && !t.revoked_authorities.contains(&root),
        "trust root must be a separate key",
    )?;
    if let (Some(r), Some(w)) = (receiver, witness) {
        check(
            t.receiver == r && t.witness == w,
            "role migration requires a separate reviewed protocol",
        )?;
    }
    follow_owner_passkey(tx, t, verified_count(tx)?)?;
    pin(tx, t, time)?;
    tx.execute(
        "UPDATE verifier SET receiver=?1,witness=?2 WHERE id=1",
        params![t.receiver, t.witness],
    )?;
    Ok(())
}
/// Install a revocation/floor even when no acceptable evidence package exists.
pub fn verifier_install(path: &Path, signed: &Signed<Trust>, time: u64) -> Result<()> {
    let mut c = connect(path)?;
    let tx = c.transaction_with_behavior(TransactionBehavior::Immediate)?;
    install_signed(&tx, signed, time)?;
    tx.commit()?;
    Ok(())
}
pub fn verify_trusted(
    path: &Path,
    signed: &Signed<Trust>,
    pinned: &Signed<Checkpoint>,
    p: &Package,
    time: u64,
) -> Result<Assessment> {
    // Trust adoption is intentionally durable even if evidence is later rejected.
    verifier_install(path, signed, time)?;
    let mut c = connect(path)?;
    let tx = c.transaction_with_behavior(TransactionBehavior::Immediate)?;
    install_signed(&tx, signed, time)?;
    let mut result = assess(p, &signed.payload, pinned, time)?;
    check(
        time.saturating_sub(pinned.payload.observed_at) <= 300,
        "checkpoint older than five minutes",
    )?;
    let (count, head, observed): (u64, String, u64) = tx.query_row(
        "SELECT count,head,observed FROM verifier WHERE id=1",
        [],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
    )?;
    check(
        pinned.payload.count >= count && pinned.payload.observed_at >= observed,
        "checkpoint rollback",
    )?;
    if count > 0 {
        let prior = p
            .receipts
            .get((count - 1) as usize)
            .ok_or("missing pinned prefix")?;
        check(digest(&prior.payload)? == head, "checkpoint fork")?;
    }
    tx.execute(
        "UPDATE verifier SET count=?1,head=?2,observed=?3 WHERE id=1",
        params![
            pinned.payload.count,
            pinned.payload.head,
            pinned.payload.observed_at
        ],
    )?;
    tx.commit()?;
    result.verification_scope = "root_authenticated_persistent".into();
    Ok(result)
}
/// Pin role admission separately from the mutable trust input file.
pub fn role_pin(path: &Path, root: &str) -> Result<()> {
    openproof_core::public_key(root)?;
    let mut c = connect(path)?;
    let tx = c.transaction_with_behavior(TransactionBehavior::Immediate)?;
    tx.execute_batch("CREATE TABLE IF NOT EXISTS role_anchor(id INTEGER PRIMARY KEY,root TEXT NOT NULL,epoch INTEGER,trust_hash TEXT,receiver TEXT,witness TEXT);")?;
    let old: Option<String> = tx
        .query_row("SELECT root FROM role_anchor WHERE id=1", [], |r| r.get(0))
        .optional()?;
    if let Some(old) = old {
        check(old == root, "role root replacement forbidden")?;
    } else {
        tx.execute("INSERT INTO role_anchor(id,root) VALUES(1,?1)", [root])?;
    }
    tx.commit()?;
    Ok(())
}
pub fn signer_init(path: &Path, root: &str) -> Result<()> {
    openproof_core::public_key(root)?;
    init(path)?;
    let c = connect(path)?;
    c.execute_batch("CREATE TABLE signer(root TEXT NOT NULL); CREATE TABLE signed_trust(epoch INTEGER PRIMARY KEY,digest TEXT NOT NULL,record TEXT NOT NULL);")?;
    c.execute("INSERT INTO signer VALUES(?1)", [root])?;
    Ok(())
}
pub fn sign_trust_tracked(
    path: &Path,
    t: Trust,
    key: &SigningKey,
    time: u64,
) -> Result<Signed<Trust>> {
    t.validate(time)?;
    let mut c = connect(path)?;
    let tx = c.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let root: String = tx.query_row("SELECT root FROM signer", [], |r| r.get(0))?;
    check(
        root == hex::encode(key.verifying_key().to_bytes()),
        "wrong signing root",
    )?;
    let h = hash(&canonical(&t)?);
    let old: Option<(String, String)> = tx
        .query_row(
            "SELECT digest,record FROM signed_trust WHERE epoch=?1",
            [t.epoch],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    if let Some((digest, raw)) = old {
        check(digest == h, "refusing same-epoch trust equivocation")?;
        return Ok(openproof_core::parse(raw.as_bytes())?);
    }
    let floor: u64 = tx.query_row("SELECT COALESCE(MAX(epoch),0) FROM signed_trust", [], |r| {
        r.get(0)
    })?;
    check(t.epoch > floor, "signing epoch rollback")?;
    let signed = sign(t, key)?;
    tx.execute(
        "INSERT INTO signed_trust VALUES(?1,?2,?3)",
        params![signed.payload.epoch, h, serde_json::to_string(&signed)?],
    )?;
    tx.commit()?;
    Ok(signed)
}
pub fn signer_floor(path: &Path) -> Result<u64> {
    Ok(connect_read(path)?.query_row(
        "SELECT COALESCE(MAX(epoch),0) FROM signed_trust",
        [],
        |r| r.get(0),
    )?)
}
pub fn trust_floor(path: &Path) -> Result<u64> {
    Ok(
        connect_read(path)?.query_row("SELECT COALESCE(MAX(epoch),0) FROM control", [], |r| {
            r.get(0)
        })?,
    )
}
