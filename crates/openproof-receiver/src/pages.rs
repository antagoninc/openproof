//! Bounded history pages, read by the receiver's role service.
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
pub fn paged_budget(tx: &rusqlite::Transaction<'_>) -> Result<bool> {
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
