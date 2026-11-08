//! Original document-receiver and witness protocol. The receiver and witness are trusted roles.
#![forbid(unsafe_code)]
use ed25519_dalek::SigningKey;
use openproof_core::{canonical, digest, sign, verify_signature, Evidence, Signed};
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs,
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};
mod clock_recovery;
pub use clock_recovery::*;
mod rotation;
pub use rotation::*;
mod pages;
pub use pages::*;
mod verifier;
pub use verifier::*;
pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
pub const V: &str = "openproof-witness/1";
pub const ZERO: &str = "0000000000000000000000000000000000000000000000000000000000000000";
pub fn hash(b: &[u8]) -> String {
    hex::encode(Sha256::digest(b))
}
pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("host clock")
        .as_secs()
}
fn check(b: bool, s: &str) -> Result<()> {
    if b {
        Ok(())
    } else {
        Err(s.into())
    }
}
fn valid_hash(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 80
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_".contains(&b))
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Trust {
    pub version: String,
    pub epoch: u64,
    pub expires_at: u64,
    pub authority: String,
    pub previous_authorities: Vec<String>,
    pub revoked_authorities: Vec<String>,
    pub receiver: String,
    pub witness: String,
}
impl Trust {
    pub fn validate(&self, time: u64) -> Result<()> {
        check(
            self.version == V
                && self.epoch > 0
                && self.epoch <= i64::MAX as u64
                && time <= self.expires_at,
            "stale or invalid trust configuration",
        )?;
        check(
            self.previous_authorities.len() <= 64 && self.revoked_authorities.len() <= 64,
            "authority set limit",
        )?;
        for list in [&self.previous_authorities, &self.revoked_authorities] {
            let unique: std::collections::HashSet<_> = list.iter().collect();
            check(
                unique.len() == list.len() && !list.contains(&self.authority),
                "duplicate or active authority overlap",
            )?;
        }
        for k in self
            .previous_authorities
            .iter()
            .chain(self.revoked_authorities.iter())
        {
            openproof_core::public_key(k)?;
            check(k != &self.receiver && k != &self.witness, "role key reused")?;
        }
        for k in [&self.authority, &self.receiver, &self.witness] {
            openproof_core::public_key(k)?;
        }
        check(
            self.authority != self.receiver
                && self.authority != self.witness
                && self.receiver != self.witness,
            "roles must use different keys",
        )
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Approval {
    pub version: String,
    pub authority: String,
    pub document: String,
    pub expected_version: u64,
    pub content_sha256: String,
    pub nonce: String,
    pub receiver: String,
    pub not_before: u64,
    pub expires_at: u64,
}
impl Evidence for Approval {
    const DOMAIN: &'static str = "document-approval/1";
    fn validate(&self) -> openproof_core::Result<()> {
        if self.version != V
            || !name(&self.document)
            || !valid_hash(&self.content_sha256)
            || !valid_hash(&self.nonce)
            || self.expected_version >= i64::MAX as u64
            || self.not_before > self.expires_at
            || self.expires_at - self.not_before > 600
        {
            return Err(openproof_core::Error("invalid document approval".into()));
        }
        openproof_core::public_key(&self.receiver)?;
        openproof_core::public_key(&self.authority)?;
        Ok(())
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub approval: Signed<Approval>,
    pub content: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Receipt {
    pub version: String,
    pub kind: String,
    pub sequence: u64,
    pub previous: String,
    pub approval_sha256: String,
    pub document: String,
    pub document_version: u64,
    pub content_sha256: String,
    pub observed_at: u64,
    pub reason: String,
}
impl Evidence for Receipt {
    const DOMAIN: &'static str = "receiver-receipt/1";
    fn validate(&self) -> openproof_core::Result<()> {
        let update = self.kind == "update"
            && name(&self.document)
            && self.document_version > 0
            && self.reason.is_empty();
        let gap = self.kind == "gap"
            && self.document.is_empty()
            && self.document_version == 0
            && !self.reason.is_empty()
            && self.approval_sha256 == ZERO
            && self.content_sha256 == ZERO;
        if self.version != V
            || !(update || gap)
            || self.reason.len() > 512
            || self.sequence == 0
            || !valid_hash(&self.previous)
            || !valid_hash(&self.approval_sha256)
            || !valid_hash(&self.content_sha256)
        {
            return Err(openproof_core::Error("invalid receiver receipt".into()));
        }
        Ok(())
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Checkpoint {
    pub version: String,
    pub count: u64,
    pub head: String,
    pub observed_at: u64,
    pub receiver: String,
}
impl Evidence for Checkpoint {
    const DOMAIN: &'static str = "witness-checkpoint/1";
    fn validate(&self) -> openproof_core::Result<()> {
        if self.version != V || !valid_hash(&self.head) {
            return Err(openproof_core::Error("invalid checkpoint".into()));
        }
        openproof_core::public_key(&self.receiver)?;
        Ok(())
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Package {
    pub version: String,
    pub requests: Vec<Request>,
    pub receipts: Vec<Signed<Receipt>>,
    pub checkpoint: Signed<Checkpoint>,
}
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
fn validate_request(q: &Request, t: &Trust, time: u64) -> Result<()> {
    let issuer = &q.approval.payload.authority;
    check(
        (issuer == &t.authority || t.previous_authorities.contains(issuer))
            && !t.revoked_authorities.contains(issuer),
        "authority untrusted or revoked",
    )?;
    verify_signature(&q.approval, issuer)?;
    let a = &q.approval.payload;
    check(
        a.receiver == t.receiver && a.not_before <= time && time <= a.expires_at,
        "wrong receiver or expired approval",
    )?;
    check(
        !q.content.is_empty()
            && q.content.len() <= 8192
            && hash(q.content.as_bytes()) == a.content_sha256,
        "changed or oversized content",
    )
}
pub fn init(path: &Path) -> Result<()> {
    check(cfg!(unix), "Unix private storage required")?;
    let mut d = fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        d.mode(0o700);
    }
    d.create(path)?;
    let c = Connection::open(path.join("state.db"))?;
    c.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; CREATE TABLE docs(id TEXT PRIMARY KEY,version INTEGER NOT NULL,content TEXT NOT NULL); CREATE TABLE events(seq INTEGER PRIMARY KEY,hash TEXT UNIQUE NOT NULL,receipt TEXT NOT NULL,request TEXT); CREATE TABLE consumed(nonce TEXT PRIMARY KEY,approval TEXT NOT NULL,receipt TEXT NOT NULL); CREATE TABLE revoked(value TEXT PRIMARY KEY); CREATE TABLE control(id INTEGER PRIMARY KEY,epoch INTEGER NOT NULL,trust_hash TEXT NOT NULL,clock INTEGER NOT NULL);")?;
    Ok(())
}
fn connect_mode(path: &Path, writable: bool) -> Result<Connection> {
    for p in [path.to_path_buf(), path.join("state.db")] {
        let m = fs::symlink_metadata(p)?;
        check(!m.file_type().is_symlink(), "symlinked state")?;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        check(
            fs::metadata(path)?.permissions().mode() & 0o077 == 0,
            "state must be private",
        )?;
    }
    let c = Connection::open_with_flags(
        path.join("state.db"),
        if writable {
            rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE
        } else {
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY
        },
    )?;
    c.busy_timeout(std::time::Duration::from_secs(5))?;
    if !writable {
        c.execute_batch("PRAGMA query_only=ON;")?;
        return Ok(c);
    }
    c.execute_batch("PRAGMA synchronous=FULL; PRAGMA fullfsync=ON;")?;
    // Existing states conservatively treat their old clock floor as already signed.
    c.execute_batch("CREATE TABLE IF NOT EXISTS signing_clock(id INTEGER PRIMARY KEY,floor INTEGER NOT NULL); INSERT OR IGNORE INTO signing_clock SELECT 1,COALESCE(MAX(clock),0) FROM control; CREATE TABLE IF NOT EXISTS clock_repairs(id INTEGER PRIMARY KEY,record TEXT NOT NULL);")?;
    Ok(c)
}
fn connect(path: &Path) -> Result<Connection> {
    connect_mode(path, true)
}
fn connect_read(path: &Path) -> Result<Connection> {
    connect_mode(path, false)
}
fn pin(tx: &rusqlite::Transaction<'_>, t: &Trust, time: u64) -> Result<()> {
    t.validate(time)?;
    check(time <= i64::MAX as u64, "clock range")?;
    let h = hash(&canonical(t)?);
    let anchored: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE name='role_anchor')",
        [],
        |r| r.get(0),
    )?;
    if anchored {
        let approved: Option<(u64, String)> = tx
            .query_row(
                "SELECT epoch,trust_hash FROM role_anchor WHERE id=1 AND epoch IS NOT NULL",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        check(
            approved == Some((t.epoch, h.clone())),
            "role requires root-authenticated installed trust",
        )?;
    }

    let old: Option<(u64, String, u64)> = tx
        .query_row(
            "SELECT epoch,trust_hash,clock FROM control WHERE id=1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .optional()?;
    if let Some((e, d, c)) = old {
        check(
            t.epoch >= e && (t.epoch != e || h == d) && time >= c,
            "trust rollback, equivocation or clock rollback",
        )?;
    }
    tx.execute("INSERT INTO control VALUES(1,?1,?2,?3) ON CONFLICT(id) DO UPDATE SET epoch=excluded.epoch,trust_hash=excluded.trust_hash,clock=excluded.clock",params![t.epoch,h,time])?;
    Ok(())
}
fn tip(tx: &rusqlite::Transaction<'_>) -> Result<(u64, String)> {
    Ok(tx
        .query_row(
            "SELECT seq,hash FROM events ORDER BY seq DESC LIMIT 1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?
        .unwrap_or((0, ZERO.into())))
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
pub fn apply(
    path: &Path,
    q: &Request,
    t: &Trust,
    key: &SigningKey,
    time: u64,
) -> Result<Signed<Receipt>> {
    apply_inner(path, q, t, key, time, || Ok(()))
}
fn apply_inner<F: FnOnce() -> Result<()>>(
    path: &Path,
    q: &Request,
    t: &Trust,
    key: &SigningKey,
    time: u64,
    hook: F,
) -> Result<Signed<Receipt>> {
    check(
        hex::encode(key.verifying_key().to_bytes()) == t.receiver,
        "wrong receiver signer",
    )?;
    check(
        q.approval.payload.authority == t.authority,
        "retired authority cannot dispatch",
    )?;
    validate_request(q, t, time)?;
    let mut c = connect(path)?;
    let tx = c.transaction_with_behavior(TransactionBehavior::Immediate)?;
    pin(&tx, t, time)?;
    let a = &q.approval.payload;
    let revoked: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM revoked WHERE value=?1 OR value=?2)",
        params![a.nonce, t.authority],
        |r| r.get(0),
    )?;
    check(!revoked, "authorization revoked")?;
    let ah = digest(a)?;
    let old: Option<(String, String)> = tx
        .query_row(
            "SELECT approval,receipt FROM consumed WHERE nonce=?1",
            [&a.nonce],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    if let Some((h, r)) = old {
        check(h == ah, "nonce reused for different authorization")?;
        tx.commit()?;
        return Ok(openproof_core::parse(r.as_bytes())?);
    }
    let ver: u64 = tx
        .query_row("SELECT version FROM docs WHERE id=?1", [&a.document], |r| {
            r.get(0)
        })
        .optional()?
        .unwrap_or(0);
    check(ver == a.expected_version, "document version conflict")?;
    let (seq, head) = tip(&tx)?;
    let receipt = sign(
        Receipt {
            version: V.into(),
            kind: "update".into(),
            sequence: seq + 1,
            previous: head,
            approval_sha256: ah.clone(),
            document: a.document.clone(),
            document_version: ver + 1,
            content_sha256: a.content_sha256.clone(),
            observed_at: time,
            reason: String::new(),
        },
        key,
    )?;
    tx.execute("INSERT INTO docs VALUES(?1,?2,?3) ON CONFLICT(id) DO UPDATE SET version=excluded.version,content=excluded.content",params![a.document,ver+1,q.content])?;
    hook()?;
    let raw = serde_json::to_string(&receipt)?;
    tx.execute(
        "INSERT INTO events VALUES(?1,?2,?3,?4)",
        params![
            seq + 1,
            digest(&receipt.payload)?,
            raw,
            serde_json::to_string(q)?
        ],
    )?;
    tx.execute(
        "INSERT INTO consumed VALUES(?1,?2,?3)",
        params![a.nonce, ah, raw],
    )?;
    history_budget(&tx, &t.receiver)?;
    clock_recovery::signed_time(&tx, time)?;
    tx.commit()?;
    Ok(receipt)
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
    clock_recovery::signed_time(&tx, time)?;
    tx.commit()?;
    Ok(r)
}
pub fn witness(
    path: &Path,
    r: &Signed<Receipt>,
    t: &Trust,
    key: &SigningKey,
    time: u64,
) -> Result<Signed<Checkpoint>> {
    check(
        hex::encode(key.verifying_key().to_bytes()) == t.witness,
        "wrong witness signer",
    )?;
    verify_signature(r, &t.receiver)?;
    check(r.payload.observed_at <= time, "future receipt")?;
    let mut c = connect(path)?;
    let tx = c.transaction_with_behavior(TransactionBehavior::Immediate)?;
    pin(&tx, t, time)?;
    let (n, h) = tip(&tx)?;
    let rh = digest(&r.payload)?;
    if r.payload.sequence <= n {
        let existing: String = tx.query_row(
            "SELECT hash FROM events WHERE seq=?1",
            [r.payload.sequence],
            |row| row.get(0),
        )?;
        check(existing == rh, "witness detected equivocation")?;
    } else {
        check(
            r.payload.sequence == n + 1 && r.payload.previous == h,
            "witness detected missing/reordered event",
        )?;
        tx.execute(
            "INSERT INTO events VALUES(?1,?2,?3,NULL)",
            params![n + 1, rh, serde_json::to_string(r)?],
        )?;
    }
    let (count, head) = tip(&tx)?;
    let cp = sign(
        Checkpoint {
            version: V.into(),
            count,
            head,
            observed_at: time,
            receiver: t.receiver.clone(),
        },
        key,
    )?;
    clock_recovery::signed_time(&tx, time)?;
    tx.commit()?;
    Ok(cp)
}
/// Export exactly the supplied checkpoint prefix, even when later updates exist.
/// Signature trust is checked by assess, not by this owner-only read operation.
pub fn export(path: &Path, checkpoint: Signed<Checkpoint>) -> Result<Package> {
    load_package(&connect_read(path)?, checkpoint)
}
fn load_package(c: &Connection, checkpoint: Signed<Checkpoint>) -> Result<Package> {
    check(checkpoint.payload.count <= 4096, "export event limit")?;
    let mut stmt = c.prepare("SELECT receipt,request FROM events WHERE seq<=?1 ORDER BY seq")?;
    let mut rows = stmt.query([checkpoint.payload.count])?;
    let mut receipts: Vec<Signed<Receipt>> = vec![];
    let mut requests = vec![];
    while let Some(row) = rows.next()? {
        check(receipts.len() < 4096, "export event limit")?;
        let raw: String = row.get(0)?;
        receipts.push(openproof_core::parse(raw.as_bytes())?);
        let q: Option<String> = row.get(1)?;
        if let Some(q) = q {
            requests.push(openproof_core::parse(q.as_bytes())?);
        }
    }
    let head = match receipts.last() {
        Some(r) => digest(&r.payload)?,
        None => ZERO.into(),
    };
    check(
        receipts.len() as u64 == checkpoint.payload.count && head == checkpoint.payload.head,
        "checkpoint prefix unavailable",
    )?;
    Ok(Package {
        version: V.into(),
        requests,
        receipts,
        checkpoint,
    })
}
/// Bound all newly admitted histories within the existing wire format. Called inside
/// the mutation transaction, so capacity failure rolls back documents/nonces/events.
fn history_budget(tx: &rusqlite::Transaction<'_>, receiver: &str) -> Result<()> {
    if pages::paged_budget(tx)? {
        return Ok(());
    }
    let (count, head) = tip(tx)?;
    let p = load_package(
        tx,
        Signed {
            payload: Checkpoint {
                version: V.into(),
                count,
                head,
                observed_at: u64::MAX,
                receiver: receiver.into(),
            },
            signature: "0".repeat(128),
        },
    )?;
    // Reserve newline/transport overhead; pretty JSON is the CLI's largest output.
    check(
        serde_json::to_vec_pretty(&p)?.len() + 64 <= 1_048_576,
        "history capacity reached; no update committed",
    )?;
    canonical(&p)?;
    Ok(())
}
/// Owner-only read, not dispatch: historical approval expiry/revocation must not
/// prevent recovery of an already committed outcome. Exact request binding remains.
pub fn recover(path: &Path, q: &Request) -> Result<Option<Signed<Receipt>>> {
    verify_signature(&q.approval, &q.approval.payload.authority)?;
    check(
        !q.content.is_empty()
            && q.content.len() <= 8192
            && hash(q.content.as_bytes()) == q.approval.payload.content_sha256,
        "changed content",
    )?;
    let c = connect_read(path)?;
    let old: Option<(String, String)> = c
        .query_row(
            "SELECT approval,receipt FROM consumed WHERE nonce=?1",
            [&q.approval.payload.nonce],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    match old {
        None => Ok(None),
        Some((h, raw)) => {
            check(
                h == digest(&q.approval.payload)?,
                "nonce conflicts with stored approval",
            )?;
            Ok(Some(openproof_core::parse(raw.as_bytes())?))
        }
    }
}
pub fn stored_receipt(path: &Path, sequence: u64) -> Result<Signed<Receipt>> {
    check(
        sequence > 0 && sequence <= i64::MAX as u64,
        "sequence range",
    )?;
    let raw: String = connect_read(path)?.query_row(
        "SELECT receipt FROM events WHERE seq=?1",
        [sequence],
        |r| r.get(0),
    )?;
    Ok(openproof_core::parse(raw.as_bytes())?)
}
pub fn head(path: &Path) -> Result<u64> {
    Ok(connect_read(path)?
        .query_row("SELECT COALESCE(MAX(seq),0) FROM events", [], |r| r.get(0))?)
}
pub fn document(path: &Path, id: &str) -> Result<(u64, String)> {
    check(name(id), "invalid document id")?;
    Ok(connect_read(path)?.query_row(
        "SELECT version,content FROM docs WHERE id=?1",
        [id],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?)
}
#[cfg(test)]
mod tests;

/// Refresh a witness checkpoint without re-submitting a historical receiver signature.
/// This asserts only the witness's retained head under its currently pinned identity.
pub fn current_checkpoint(
    path: &Path,
    t: &Trust,
    key: &SigningKey,
    time: u64,
) -> Result<Signed<Checkpoint>> {
    check(
        hex::encode(key.verifying_key().to_bytes()) == t.witness,
        "wrong witness signer",
    )?;
    let mut c = connect(path)?;
    let tx = c.transaction_with_behavior(TransactionBehavior::Immediate)?;
    pin(&tx, t, time)?;
    let (count, head) = tip(&tx)?;
    let cp = sign(
        Checkpoint {
            version: V.into(),
            count,
            head,
            observed_at: time,
            receiver: t.receiver.clone(),
        },
        key,
    )?;
    clock_recovery::signed_time(&tx, time)?;
    tx.commit()?;
    Ok(cp)
}
