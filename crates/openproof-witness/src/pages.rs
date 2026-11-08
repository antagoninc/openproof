//! Bounded transport pages with durable, unconfirmed-until-checkpoint verification.
use super::*;
pub const PAGE_VERSION: &str = "openproof-history-page/1";
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoryPage {
    pub version: String,
    pub start: u64,
    pub receipts: Vec<Signed<Receipt>>,
    pub requests: Vec<Request>,
    pub checkpoint: Signed<Checkpoint>,
}
#[derive(Serialize)]
pub struct PageAssessment {
    pub status: String,
    pub processed: u64,
    pub target: u64,
    pub checkpoint_complete: bool,
    pub complete_history: bool,
    pub physical_effects_proven: bool,
}
pub fn enable_pages(path: &Path, t: &Trust, time: u64) -> Result<()> {
    let mut c = connect(path)?;
    let tx = c.transaction_with_behavior(TransactionBehavior::Immediate)?;
    pin(&tx, t, time)?;
    tx.execute_batch("CREATE TABLE IF NOT EXISTS paging(id INTEGER PRIMARY KEY,enabled INTEGER NOT NULL); INSERT OR IGNORE INTO paging VALUES(1,1);")?;
    tx.commit()?;
    Ok(())
}
pub(super) fn paged_budget(tx: &rusqlite::Transaction<'_>) -> Result<bool> {
    let enabled: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE name='paging')",
        [],
        |r| r.get(0),
    )?;
    if !enabled {
        return Ok(false);
    }
    let (count,bytes):(u64,u64)=tx.query_row("SELECT COUNT(*),COALESCE(SUM(length(CAST(receipt AS BLOB))+COALESCE(length(CAST(request AS BLOB)),0)),0) FROM events",[],|r|Ok((r.get(0)?,r.get(1)?)))?;
    let extra:u64=tx.query_row("SELECT (SELECT COALESCE(SUM(length(CAST(content AS BLOB))),0) FROM docs)+(SELECT COALESCE(SUM(length(CAST(receipt AS BLOB))),0) FROM consumed)",[],|r|r.get(0))?;
    check(
        count <= 100_000 && bytes + extra <= 128 * 1024 * 1024,
        "paged store capacity reached; no update committed",
    )?;
    Ok(true)
}
pub fn export_page(
    path: &Path,
    t: &Trust,
    cp: Signed<Checkpoint>,
    start: u64,
    time: u64,
) -> Result<HistoryPage> {
    t.validate(time)?;
    verify_signature(&cp, &t.witness)?;
    check(
        cp.payload.receiver == t.receiver
            && cp.payload.observed_at <= time
            && start > 0
            && start <= cp.payload.count
            && cp.payload.count <= 100_000,
        "page checkpoint/range",
    )?;
    let c = connect_read(path)?;
    let tip: String = c.query_row(
        "SELECT hash FROM events WHERE seq=?1",
        [cp.payload.count],
        |r| r.get(0),
    )?;
    check(tip == cp.payload.head, "checkpoint prefix unavailable")?;
    let mut page = HistoryPage {
        version: PAGE_VERSION.into(),
        start,
        receipts: vec![],
        requests: vec![],
        checkpoint: cp,
    };
    let mut stmt = c.prepare(
        "SELECT receipt,request FROM events WHERE seq>=?1 AND seq<=?2 ORDER BY seq LIMIT 32",
    )?;
    let mut rows = stmt.query(params![start, page.checkpoint.payload.count])?;
    while let Some(row) = rows.next()? {
        let raw: String = row.get(0)?;
        let q: Option<String> = row.get(1)?;
        page.receipts.push(openproof_core::parse(raw.as_bytes())?);
        if let Some(ref raw) = q {
            page.requests.push(openproof_core::parse(raw.as_bytes())?);
        }
        if serde_json::to_vec_pretty(&page)?.len() > 512 * 1024 {
            page.receipts.pop();
            if q.is_some() {
                page.requests.pop();
            }
            break;
        }
    }
    check(!page.receipts.is_empty(), "page unavailable")?;
    Ok(page)
}
pub(super) fn stream_schema(tx: &rusqlite::Transaction<'_>) -> Result<()> {
    tx.execute_batch("CREATE TABLE IF NOT EXISTS stream_progress(id INTEGER PRIMARY KEY,count INTEGER NOT NULL,head TEXT NOT NULL,last_time INTEGER NOT NULL,gaps INTEGER NOT NULL); INSERT OR IGNORE INTO stream_progress VALUES(1,0,'0000000000000000000000000000000000000000000000000000000000000000',0,0); CREATE TABLE IF NOT EXISTS stream_docs(id TEXT PRIMARY KEY,version INTEGER NOT NULL); CREATE TABLE IF NOT EXISTS stream_nonces(nonce TEXT PRIMARY KEY); CREATE TABLE IF NOT EXISTS stream_issuers(key TEXT PRIMARY KEY);")?;
    tx.execute_batch("CREATE TABLE IF NOT EXISTS stream_saved_progress AS SELECT * FROM stream_progress WHERE 0; CREATE TABLE IF NOT EXISTS stream_saved_docs AS SELECT * FROM stream_docs WHERE 0; CREATE TABLE IF NOT EXISTS stream_saved_nonces AS SELECT * FROM stream_nonces WHERE 0; CREATE TABLE IF NOT EXISTS stream_saved_issuers AS SELECT * FROM stream_issuers WHERE 0;")?;
    Ok(())
}
pub fn verify_page(
    path: &Path,
    t: &Signed<Trust>,
    pinned: &Signed<Checkpoint>,
    page: &HistoryPage,
    time: u64,
) -> Result<PageAssessment> {
    verifier_install(path, t, time)?;
    check(
        page.version == PAGE_VERSION
            && page.receipts.len() <= 32
            && page.requests.len() <= 32
            && serde_json::to_vec(page)?.len() <= 512 * 1024,
        "page bounds",
    )?;
    verify_signature(pinned, &t.payload.witness)?;
    check(
        canonical(pinned)? == canonical(&page.checkpoint)?
            && pinned.payload.receiver == t.payload.receiver
            && pinned.payload.observed_at <= time
            && time - pinned.payload.observed_at <= 300
            && pinned.payload.count <= 100_000,
        "page pin/freshness",
    )?;
    let mut c = connect(path)?;
    let tx = c.transaction_with_behavior(TransactionBehavior::Immediate)?;
    super::verifier::install_signed(&tx, t, time)?;
    stream_schema(&tx)?;
    let (floor, known, observed): (u64, String, u64) = tx.query_row(
        "SELECT count,head,observed FROM verifier WHERE id=1",
        [],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
    )?;
    check(
        pinned.payload.count >= floor && pinned.payload.observed_at >= observed,
        "checkpoint rollback",
    )?;
    let (mut count, mut head, mut last, mut gaps): (u64, String, u64, bool) = tx.query_row(
        "SELECT count,head,last_time,gaps FROM stream_progress WHERE id=1",
        [],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
    )?;
    check(
        page.start == count + 1
            && count <= pinned.payload.count
            && (count < pinned.payload.count || page.receipts.is_empty()),
        "page order or replay",
    )?;
    // A changed trust snapshot cannot silently bless previously revoked issuers.
    let mut stmt = tx.prepare("SELECT key FROM stream_issuers")?;
    let issuers = stmt.query_map([], |r| r.get::<_, String>(0))?;
    for issuer in issuers {
        let issuer = issuer?;
        check(
            (issuer == t.payload.authority || t.payload.previous_authorities.contains(&issuer))
                && !t.payload.revoked_authorities.contains(&issuer),
            "previous page authority revoked",
        )?;
    }
    drop(stmt);
    let mut qs = std::collections::HashMap::new();
    for q in &page.requests {
        check(
            qs.insert(digest(&q.approval.payload)?, q).is_none(),
            "duplicate page request",
        )?;
    }
    let mut used = 0;
    for r in &page.receipts {
        verify_signature(r, &t.payload.receiver)?;
        let x = &r.payload;
        check(
            x.sequence == count + 1
                && x.previous == head
                && x.observed_at >= last
                && x.observed_at <= pinned.payload.observed_at,
            "page chain/time",
        )?;
        if x.kind == "gap" {
            gaps = true;
        } else {
            let q = qs
                .remove(&x.approval_sha256)
                .ok_or("page authorization missing")?;
            validate_request(q, &t.payload, x.observed_at)?;
            let a = &q.approval.payload;
            check(
                x.document == a.document
                    && x.document_version == a.expected_version + 1
                    && x.content_sha256 == hash(q.content.as_bytes()),
                "page outcome binding",
            )?;
            let previous: u64 = tx
                .query_row(
                    "SELECT version FROM stream_docs WHERE id=?1",
                    [&a.document],
                    |r| r.get(0),
                )
                .optional()?
                .unwrap_or(0);
            if !gaps {
                check(a.expected_version == previous, "page version discontinuity")?;
            }
            tx.execute("INSERT INTO stream_nonces VALUES(?1)", [&a.nonce])?;
            tx.execute("INSERT INTO stream_docs VALUES(?1,?2) ON CONFLICT(id) DO UPDATE SET version=excluded.version",params![a.document,x.document_version])?;
            tx.execute(
                "INSERT OR IGNORE INTO stream_issuers VALUES(?1)",
                [&a.authority],
            )?;
            used += 1;
        }
        count += 1;
        head = digest(x)?;
        last = x.observed_at;
        if count == floor {
            check(head == known, "paged prefix fork")?;
        }
    }
    check(
        used == page.requests.len() && count <= pinned.payload.count,
        "page extra requests/overflow",
    )?;
    let complete = count == pinned.payload.count;
    if complete {
        check(head == pinned.payload.head, "page final head mismatch")?;
        tx.execute(
            "UPDATE verifier SET count=?1,head=?2,observed=?3 WHERE id=1",
            params![count, head, pinned.payload.observed_at],
        )?;
    }
    tx.execute(
        "UPDATE stream_progress SET count=?1,head=?2,last_time=?3,gaps=?4 WHERE id=1",
        params![count, head, last, gaps],
    )?;
    if complete {
        tx.execute_batch("DELETE FROM stream_saved_progress; INSERT INTO stream_saved_progress SELECT * FROM stream_progress; DELETE FROM stream_saved_docs; INSERT INTO stream_saved_docs SELECT * FROM stream_docs; DELETE FROM stream_saved_nonces; INSERT INTO stream_saved_nonces SELECT * FROM stream_nonces; DELETE FROM stream_saved_issuers; INSERT INTO stream_saved_issuers SELECT * FROM stream_issuers;")?;
    }
    tx.commit()?;
    Ok(PageAssessment {
        status: if !complete {
            "page_prefix_pending_checkpoint"
        } else if gaps {
            "unknown_due_to_disclosed_gap"
        } else {
            "checkpoint_complete"
        }
        .into(),
        processed: count,
        target: pinned.payload.count,
        checkpoint_complete: complete,
        complete_history: complete && !gaps,
        physical_effects_proven: false,
    })
}
pub fn page_progress(path: &Path) -> Result<u64> {
    let c = connect_read(path)?;
    let has: bool = c.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE name='stream_progress')",
        [],
        |r| r.get(0),
    )?;
    if !has {
        return Ok(0);
    };
    Ok(
        c.query_row("SELECT count FROM stream_progress WHERE id=1", [], |r| {
            r.get(0)
        })?,
    )
}

pub fn reset_pages(path: &Path) -> Result<()> {
    let mut c = connect(path)?;
    let tx = c.transaction_with_behavior(TransactionBehavior::Immediate)?;
    stream_schema(&tx)?;
    let saved: u64 = tx.query_row("SELECT COUNT(*) FROM stream_saved_progress", [], |r| {
        r.get(0)
    })?;
    if saved == 0 {
        tx.execute_batch("UPDATE stream_progress SET count=0,head='0000000000000000000000000000000000000000000000000000000000000000',last_time=0,gaps=0; DELETE FROM stream_docs; DELETE FROM stream_nonces; DELETE FROM stream_issuers;")?;
    } else {
        tx.execute_batch("DELETE FROM stream_progress; INSERT INTO stream_progress SELECT * FROM stream_saved_progress; DELETE FROM stream_docs; INSERT INTO stream_docs SELECT * FROM stream_saved_docs; DELETE FROM stream_nonces; INSERT INTO stream_nonces SELECT * FROM stream_saved_nonces; DELETE FROM stream_issuers; INSERT INTO stream_issuers SELECT * FROM stream_saved_issuers;")?;
    }
    tx.commit()?;
    Ok(())
}
