//! Owner approval gate. This is the only code that turns a reviewed proposal into a
//! stored, executable approval. The owner app and the broker only relay bytes to it.
//! See docs/TCB.md and docs/PASSKEY.md.
use super::*;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use rand_core::{OsRng, RngCore};
use rusqlite::Transaction;
use serde_json::{json, Value};
use std::io::Read;

/// Unapproved proposals kept at most. The oldest are reclaimed first.
pub const MAX_PROPOSALS: i64 = 1000;
/// Approved requests kept at most. They are never reclaimed automatically.
pub const MAX_APPROVED: i64 = 1000;
/// Signed approvals that wait for the owner's passkey.
pub const MAX_PENDING: i64 = 100;
/// An unapproved proposal is reclaimed after one day.
pub const PROPOSAL_LIFETIME: u64 = 86400;
/// An approval is valid for 5 minutes. The Approval type allows at most 10.
pub const APPROVAL_WINDOW: u64 = 300;

/// A proposed document update, exactly as the owner reviews it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Proposal {
    pub document: String,
    pub expected_version: u64,
    pub content: String,
}

impl Proposal {
    pub fn validate(&self) -> Result<()> {
        check(name(&self.document), "invalid document id")?;
        check(self.expected_version < i64::MAX as u64, "invalid version")?;
        check(
            !self.content.is_empty() && self.content.len() <= 8192,
            "content must be 1..8192 UTF-8 bytes",
        )
    }

    /// The review binding: SHA-256 of the canonical proposal (document, expected
    /// version and content). The owner app shows these fields and returns this hash.
    pub fn review_sha256(&self) -> Result<String> {
        Ok(hash(&canonical(self)?))
    }
}

/// A proposal id commits to the exact proposal and a random salt. Equal proposals
/// get separate ids, and a stored proposal can be checked against its id.
fn proposal_id(p: &Proposal, salt: &str) -> Result<String> {
    #[derive(Serialize)]
    struct Bound<'a> {
        proposal: &'a Proposal,
        salt: &'a str,
    }
    let mut b = b"OpenProof/v1/gate-proposal/1\0".to_vec();
    b.extend(canonical(&Bound { proposal: p, salt })?);
    Ok(hash(&b))
}

/// Sign an approval of `p` for the trust's receiver, valid for APPROVAL_WINDOW.
pub fn sign_approval(p: &Proposal, t: &Trust, k: &SigningKey, time: u64) -> Result<Request> {
    p.validate()?;
    check(
        hex::encode(k.verifying_key().to_bytes()) == t.authority,
        "wrong authority",
    )?;
    let mut nonce = [0; 32];
    OsRng.fill_bytes(&mut nonce);
    let approval = Approval {
        version: V.into(),
        authority: t.authority.clone(),
        document: p.document.clone(),
        expected_version: p.expected_version,
        content_sha256: hash(p.content.as_bytes()),
        nonce: hex::encode(nonce),
        receiver: t.receiver.clone(),
        not_before: time,
        expires_at: time + APPROVAL_WINDOW,
    };
    Ok(Request {
        approval: sign(approval, k)?,
        content: p.content.clone(),
        owner_assertion: None,
    })
}

fn int(n: u64) -> Result<i64> {
    Ok(i64::try_from(n)?)
}

/// A private real directory: not a link, no group or other permissions.
fn private_dir(path: &Path, create: bool) -> Result<()> {
    let m = match fs::symlink_metadata(path) {
        Err(e) if create && e.kind() == std::io::ErrorKind::NotFound => {
            let mut d = fs::DirBuilder::new();
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt;
                d.mode(0o700);
            }
            d.create(path)?;
            fs::symlink_metadata(path)?
        }
        m => m?,
    };
    check(m.is_dir(), "gate path must be a real directory")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        check(
            m.permissions().mode() & 0o077 == 0,
            "gate directory must be private",
        )?;
    }
    Ok(())
}

/// Open the gate store at HOME/authority/gate/gate.db. Every change is one SQLite
/// transaction with full synchronous writes.
fn open(home: &Path, time: u64) -> Result<Connection> {
    check(cfg!(unix), "Unix private storage required")?;
    let authority = home.join("authority");
    private_dir(&authority, false)?;
    let dir = authority.join("gate");
    private_dir(&dir, true)?;
    let db = dir.join("gate.db");
    match fs::symlink_metadata(&db) {
        Ok(m) => {
            check(m.is_file(), "gate store must be a regular file")?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                check(
                    m.permissions().mode() & 0o077 == 0,
                    "gate store must be private",
                )?;
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let mut o = fs::OpenOptions::new();
            o.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                o.mode(0o600);
            }
            o.open(&db)?;
        }
        Err(e) => return Err(e.into()),
    }
    let mut c = Connection::open_with_flags(
        &db,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE | rusqlite::OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )?;
    c.busy_timeout(std::time::Duration::from_secs(5))?;
    c.execute_batch(
        "PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA fullfsync=ON;
         CREATE TABLE IF NOT EXISTS proposals(id TEXT PRIMARY KEY,proposal TEXT NOT NULL,salt TEXT,created_at INTEGER NOT NULL);
         CREATE TABLE IF NOT EXISTS pending(approval_sha256 TEXT PRIMARY KEY,id TEXT NOT NULL,request TEXT NOT NULL,salt TEXT,expires_at INTEGER NOT NULL);
         CREATE TABLE IF NOT EXISTS approved(id TEXT PRIMARY KEY,request TEXT NOT NULL,salt TEXT);
         CREATE TABLE IF NOT EXISTS legacy_import(id INTEGER PRIMARY KEY,at INTEGER NOT NULL);",
    )?;
    let tx = c.transaction_with_behavior(TransactionBehavior::Immediate)?;
    import_legacy(&tx, home, time)?;
    tx.commit()?;
    Ok(c)
}

/// Read a bounded regular file without following a link.
fn read_regular(path: &Path) -> Option<Vec<u8>> {
    let mut o = fs::OpenOptions::new();
    o.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let f = o.open(path).ok()?;
    if !f.metadata().ok()?.is_file() {
        return None;
    }
    let mut raw = vec![];
    f.take(1_048_577).read_to_end(&mut raw).ok()?;
    (raw.len() <= 1_048_576).then_some(raw)
}

/// Earlier homes kept proposals and approved requests as JSON files. The gate imports
/// them once, when its store is created. After that it never reads those folders.
/// Imported approved requests are checked like every other entry when they are read.
fn import_legacy(tx: &Transaction<'_>, home: &Path, time: u64) -> Result<()> {
    let done: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM legacy_import)", [], |r| {
        r.get(0)
    })?;
    if done {
        return Ok(());
    }
    for folder in ["approved", "proposals"] {
        let dir = home.join(folder);
        if !fs::symlink_metadata(&dir).is_ok_and(|m| m.is_dir()) {
            continue;
        }
        let mut names: Vec<_> = fs::read_dir(&dir)?
            .filter_map(|e| e.ok().map(|e| e.file_name()))
            .collect();
        names.sort();
        for file in names.into_iter().take(4096) {
            let Some(id) = file.to_str().and_then(|s| s.strip_suffix(".json")) else {
                continue;
            };
            let path = dir.join(&file);
            let Some(raw) = read_regular(&path).filter(|_| valid_hash(id)) else {
                continue;
            };
            if folder == "approved" {
                if let Ok(q) = openproof_core::parse::<Request>(&raw) {
                    tx.execute(
                        "INSERT OR IGNORE INTO approved VALUES(?1,?2,NULL)",
                        params![id, serde_json::to_string(&q)?],
                    )?;
                }
            } else if let Ok(p) = openproof_core::parse::<Proposal>(&raw) {
                let created = fs::symlink_metadata(&path)?
                    .modified()?
                    .duration_since(UNIX_EPOCH)?
                    .as_secs();
                if p.validate().is_ok() {
                    tx.execute(
                        "INSERT OR IGNORE INTO proposals SELECT ?1,?2,NULL,?3 WHERE NOT EXISTS(SELECT 1 FROM approved WHERE id=?1)",
                        params![id, serde_json::to_string(&p)?, int(created)?],
                    )?;
                }
            }
        }
    }
    tx.execute("INSERT INTO legacy_import VALUES(1,?1)", [int(time)?])?;
    Ok(())
}

/// A stored proposal, checked again: field rules and, unless imported from an
/// earlier home, its id.
fn load_proposal(tx: &Transaction<'_>, id: &str) -> Result<(Proposal, Option<String>)> {
    let row: Option<(String, Option<String>)> = tx
        .query_row(
            "SELECT proposal,salt FROM proposals WHERE id=?1",
            [id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    let (raw, salt) = row.ok_or("proposal unavailable")?;
    let p: Proposal = openproof_core::parse(raw.as_bytes())?;
    p.validate()?;
    if let Some(salt) = &salt {
        check(
            proposal_id(&p, salt)? == id,
            "stored proposal does not match its id",
        )?;
    }
    Ok((p, salt))
}

/// The gate keeps its own passkey pin, like the roles do. When the receiver state is
/// on this host, the trust must also carry the passkey that the receiver pinned.
fn pin_passkey(tx: &Transaction<'_>, home: &Path, t: &Trust) -> Result<()> {
    pin_owner_passkey(tx, t)?;
    let receiver = home.join("receiver/state");
    if !receiver.join("state.db").exists() {
        return Ok(());
    }
    let c = connect_read(&receiver)?;
    let has_pin: bool = c.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE name='owner_passkey_pin')",
        [],
        |r| r.get(0),
    )?;
    if !has_pin {
        return Ok(());
    }
    let pinned: Option<String> = c
        .query_row("SELECT record FROM owner_passkey_pin WHERE id=1", [], |r| {
            r.get(0)
        })
        .optional()?;
    if let Some(record) = pinned {
        let current = t
            .owner_passkey
            .as_ref()
            .map(serde_json::to_string)
            .transpose()?;
        check(
            current.as_deref() == Some(record.as_str()),
            "trust passkey differs from the receiver's pinned passkey",
        )?;
    }
    Ok(())
}

fn store_approved(tx: &Transaction<'_>, id: &str, q: &Request, salt: Option<&str>) -> Result<()> {
    let exists: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM approved WHERE id=?1)",
        [id],
        |r| r.get(0),
    )?;
    check(!exists, "proposal already approved")?;
    let count: i64 = tx.query_row("SELECT COUNT(*) FROM approved", [], |r| r.get(0))?;
    check(count < MAX_APPROVED, "approval storage capacity reached")?;
    tx.execute(
        "INSERT INTO approved VALUES(?1,?2,?3)",
        params![id, serde_json::to_string(q)?, salt],
    )?;
    tx.execute("DELETE FROM pending WHERE id=?1", [id])?;
    tx.execute("DELETE FROM proposals WHERE id=?1", [id])?;
    Ok(())
}

/// Store a validated proposal and return its id. Agents reach this through the broker.
pub fn gate_propose(home: &Path, p: &Proposal, time: u64) -> Result<Value> {
    p.validate()?;
    let mut c = open(home, time)?;
    let tx = c.transaction_with_behavior(TransactionBehavior::Immediate)?;
    // Only unapproved proposals are reclaimed. Approved requests are never evicted.
    tx.execute(
        "DELETE FROM proposals WHERE created_at<?1",
        [int(time.saturating_sub(PROPOSAL_LIFETIME))?],
    )?;
    let count: i64 = tx.query_row("SELECT COUNT(*) FROM proposals", [], |r| r.get(0))?;
    tx.execute(
        "DELETE FROM proposals WHERE id IN (SELECT id FROM proposals ORDER BY created_at,rowid LIMIT ?1)",
        [(count - (MAX_PROPOSALS - 1)).max(0)],
    )?;
    let mut salt = [0; 32];
    OsRng.fill_bytes(&mut salt);
    let salt = hex::encode(salt);
    let id = proposal_id(p, &salt)?;
    tx.execute(
        "INSERT INTO proposals VALUES(?1,?2,?3,?4)",
        params![id, serde_json::to_string(p)?, salt, int(time)?],
    )?;
    tx.commit()?;
    Ok(json!({
        "proposal_id": id,
        "state": "awaiting_owner_approval",
        "content_sha256": hash(p.content.as_bytes()),
    }))
}

/// What the owner reviews: the exact proposal, its content hash and its review binding.
pub fn gate_review(home: &Path, id: &str, time: u64) -> Result<Value> {
    check(valid_hash(id), "invalid proposal id")?;
    let mut c = open(home, time)?;
    let tx = c.transaction()?;
    let (p, _) = load_proposal(&tx, id)?;
    Ok(json!({
        "proposal_id": id,
        "content_sha256": hash(p.content.as_bytes()),
        "review_sha256": p.review_sha256()?,
        "proposal": p,
    }))
}

/// Sign an approval of the stored proposal, only if it still has the review binding
/// the owner saw. Without an owner passkey the approval is stored as approved. With
/// one it waits, unexecutable, for an assertion over its digest. `terminal` refuses
/// when a passkey is required: a terminal cannot make a WebAuthn assertion.
pub fn gate_approve(
    home: &Path,
    t: &Trust,
    k: &SigningKey,
    id: &str,
    reviewed: &str,
    terminal: bool,
    time: u64,
) -> Result<Value> {
    t.validate(time)?;
    check(
        valid_hash(id) && valid_hash(reviewed),
        "invalid proposal id or review hash",
    )?;
    check(
        !(terminal && t.owner_passkey.is_some()),
        "owner passkey required; approve in the owner app",
    )?;
    let mut c = open(home, time)?;
    let tx = c.transaction_with_behavior(TransactionBehavior::Immediate)?;
    pin_passkey(&tx, home, t)?;
    let (p, salt) = load_proposal(&tx, id)?;
    check(
        p.review_sha256()? == reviewed,
        "proposal changed; review it again",
    )?;
    let q = sign_approval(&p, t, k, time)?;
    let approval_sha256 = digest(&q.approval.payload)?;
    let expires_at = q.approval.payload.expires_at;
    let Some(passkey) = &t.owner_passkey else {
        store_approved(&tx, id, &q, salt.as_deref())?;
        tx.commit()?;
        return Ok(json!({
            "state": "approved",
            "proposal_id": id,
            "approval_sha256": approval_sha256,
            "expires_at": expires_at,
        }));
    };
    tx.execute("DELETE FROM pending WHERE expires_at<?1", [int(time)?])?;
    let count: i64 = tx.query_row("SELECT COUNT(*) FROM pending", [], |r| r.get(0))?;
    check(
        count < MAX_PENDING,
        "too many outstanding passkey approvals",
    )?;
    tx.execute(
        "INSERT INTO pending VALUES(?1,?2,?3,?4,?5)",
        params![
            approval_sha256,
            id,
            serde_json::to_string(&q)?,
            salt,
            int(expires_at)?
        ],
    )?;
    tx.commit()?;
    // The approval itself goes back too: the owner's review page checks it
    // against what it shows and computes the passkey challenge from it.
    Ok(json!({
        "state": "passkey_required",
        "proposal_id": id,
        "approval": q.approval.payload,
        "approval_sha256": approval_sha256,
        "challenge": URL_SAFE_NO_PAD.encode(hex::decode(&approval_sha256)?),
        "rp_id": passkey.rp_id,
        "expires_at": expires_at,
    }))
}

/// Verify the owner's assertion over a pending approval and store it as approved.
/// A pending approval is used once and expires with the approval window. A failed
/// assertion changes nothing.
pub fn gate_approve_passkey(
    home: &Path,
    t: &Trust,
    id: &str,
    approval_sha256: &str,
    a: &PasskeyAssertion,
    time: u64,
) -> Result<Value> {
    t.validate(time)?;
    check(
        valid_hash(id) && valid_hash(approval_sha256),
        "invalid proposal id or approval digest",
    )?;
    let k = t
        .owner_passkey
        .as_ref()
        .ok_or("trust has no owner passkey")?;
    let mut c = open(home, time)?;
    let tx = c.transaction_with_behavior(TransactionBehavior::Immediate)?;
    pin_passkey(&tx, home, t)?;
    let row: Option<(String, String, Option<String>, i64)> = tx
        .query_row(
            "SELECT id,request,salt,expires_at FROM pending WHERE approval_sha256=?1",
            [approval_sha256],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )
        .optional()?;
    let (owner, raw, salt, expires_at) =
        row.ok_or("no pending approval for this digest; review the action again")?;
    check(owner == id, "pending approval belongs to another proposal")?;
    check(
        int(time)? <= expires_at,
        "pending approval expired; review the action again",
    )?;
    let mut q: Request = openproof_core::parse(raw.as_bytes())?;
    check(
        digest(&q.approval.payload)? == approval_sha256,
        "pending approval digest mismatch",
    )?;
    validate_request(&q, t, time)?;
    verify_assertion(a, k, approval_sha256)?;
    q.owner_assertion = Some(a.clone());
    store_approved(&tx, id, &q, salt.as_deref())?;
    tx.commit()?;
    Ok(json!({
        "state": "approved",
        "proposal_id": id,
        "approval_sha256": approval_sha256,
    }))
}

/// Check an approved entry when it is read. It must carry a valid signature from an
/// authority this trust knows, its exact content, the proposal its id commits to,
/// and, when it carries an assertion, a valid one. A row that the gate did not write
/// fails here unless its writer held the authority key.
fn check_stored(q: &Request, t: &Trust, id: &str, salt: Option<&str>) -> Result<()> {
    let a = &q.approval.payload;
    check(
        a.authority == t.authority
            || t.previous_authorities.contains(&a.authority)
            || t.revoked_authorities.contains(&a.authority),
        "stored approval is not from a trusted authority",
    )?;
    verify_signature(&q.approval, &a.authority)?;
    check(
        !q.content.is_empty()
            && q.content.len() <= 8192
            && hash(q.content.as_bytes()) == a.content_sha256,
        "stored request content changed",
    )?;
    if let Some(salt) = salt {
        let p = Proposal {
            document: a.document.clone(),
            expected_version: a.expected_version,
            content: q.content.clone(),
        };
        check(
            proposal_id(&p, salt)? == id,
            "stored request does not match its proposal",
        )?;
    }
    if let Some(assertion) = &q.owner_assertion {
        let k = t
            .owner_passkey
            .as_ref()
            .ok_or("unexpected owner passkey assertion")?;
        verify_assertion(assertion, k, &digest(a)?)?;
    }
    Ok(())
}

/// The state of a proposal. Only an approved entry returns a request, for `receive`.
pub fn gate_approved(home: &Path, t: &Trust, id: &str, time: u64) -> Result<Value> {
    check(valid_hash(id), "invalid proposal id")?;
    // Structure only: an expired trust must not hide a committed request from recovery.
    // The receiver checks expiry, revocation and the passkey before any new effect.
    t.validate(0)?;
    let mut c = open(home, time)?;
    let tx = c.transaction()?;
    let row: Option<(String, Option<String>)> = tx
        .query_row("SELECT request,salt FROM approved WHERE id=?1", [id], |r| {
            Ok((r.get(0)?, r.get(1)?))
        })
        .optional()?;
    if let Some((raw, salt)) = row {
        let q: Request = openproof_core::parse(raw.as_bytes())?;
        check_stored(&q, t, id, salt.as_deref())?;
        return Ok(json!({"state": "approved", "request": q}));
    }
    let awaiting: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM pending WHERE id=?1 AND expires_at>=?2)",
        params![id, int(time)?],
        |r| r.get(0),
    )?;
    let proposed: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM proposals WHERE id=?1)",
        [id],
        |r| r.get(0),
    )?;
    let state = match (awaiting, proposed) {
        (true, _) => "awaiting_passkey",
        (false, true) => "proposed",
        (false, false) => "unknown",
    };
    Ok(json!({ "state": state }))
}

/// Summary of the store for the owner app. Content is not included.
pub fn gate_list(home: &Path, time: u64) -> Result<Value> {
    let mut c = open(home, time)?;
    let tx = c.transaction()?;
    let mut proposals = vec![];
    let mut s = tx.prepare("SELECT id,proposal FROM proposals ORDER BY created_at,rowid")?;
    let mut rows = s.query([])?;
    while let Some(r) = rows.next()? {
        let raw: String = r.get(1)?;
        let p: Proposal = openproof_core::parse(raw.as_bytes())?;
        proposals.push(json!({
            "id": r.get::<_, String>(0)?,
            "document": p.document,
            "expected_version": p.expected_version,
            "content_sha256": hash(p.content.as_bytes()),
        }));
    }
    let mut awaiting = vec![];
    let mut s = tx.prepare(
        "SELECT id,approval_sha256,expires_at FROM pending WHERE expires_at>=?1 ORDER BY id",
    )?;
    let mut rows = s.query([int(time)?])?;
    while let Some(r) = rows.next()? {
        awaiting.push(json!({
            "id": r.get::<_, String>(0)?,
            "approval_sha256": r.get::<_, String>(1)?,
            "expires_at": r.get::<_, i64>(2)?,
        }));
    }
    let mut approved = vec![];
    let mut s = tx.prepare("SELECT id,request FROM approved ORDER BY id")?;
    let mut rows = s.query([])?;
    while let Some(r) = rows.next()? {
        let raw: String = r.get(1)?;
        let q: Request = openproof_core::parse(raw.as_bytes())?;
        let a = &q.approval.payload;
        approved.push(json!({
            "id": r.get::<_, String>(0)?,
            "document": a.document,
            "expected_version": a.expected_version,
            "expires_at": a.expires_at,
            "owner_assertion": q.owner_assertion.is_some(),
        }));
    }
    Ok(json!({"proposals": proposals, "awaiting_passkey": awaiting, "approved": approved}))
}

#[cfg(test)]
#[path = "gate_tests.rs"]
mod tests;
