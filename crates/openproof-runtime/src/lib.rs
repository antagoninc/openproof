//! A deliberately narrow local execution gate. The persistent state directory is trusted.
#![forbid(unsafe_code)]
use ed25519_dalek::SigningKey;
use openproof_core::Signed;
use openproof_core::{
    canonical, digest, parse, sign, verify, Bundle, Context, Outcome, Receipt, VERSION,
};
use openproof_trust::{Anchor, Mode, TrustBundle};
use rusqlite::{params, Connection, OpenFlags, OptionalExtension, TransactionBehavior};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

pub const POLICY_VERSION: &str = "openproof-policy/1";
pub const RESOURCE: &str = "urn:openproof:artifact";
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Code {
    InvalidEvidence,
    PolicyDenied,
    Replay,
    Storage,
    Indeterminate,
    InvalidInput,
}
#[derive(Debug)]
pub struct Error {
    pub code: Code,
    pub message: String,
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}: {}", self.code, self.message)
    }
}
impl std::error::Error for Error {}
pub type Result<T> = std::result::Result<T, Error>;
fn err(code: Code, message: impl ToString) -> Error {
    Error {
        code,
        message: message.to_string(),
    }
}
fn storage(e: impl ToString) -> Error {
    err(Code::Storage, e)
}
fn check(ok: bool, code: Code, message: &str) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(err(code, message))
    }
}
pub fn sha256(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
pub fn now() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|v| v.as_secs())
        .map_err(|e| err(Code::InvalidInput, e))
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Grant {
    pub tool: String,
    pub resource: String,
    pub max_argument_bytes: u64,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub version: String,
    pub audience: String,
    pub executor_key: String,
    pub max_validity_seconds: u64,
    pub allow: Vec<Grant>,
}
impl Policy {
    pub fn validate(&self) -> Result<()> {
        check(
            self.version == POLICY_VERSION,
            Code::PolicyDenied,
            "unsupported policy version",
        )?;
        check(
            !self.audience.is_empty()
                && self.audience.len() <= 1024
                && !self.audience.chars().any(char::is_control),
            Code::PolicyDenied,
            "invalid audience",
        )?;
        openproof_core::public_key(&self.executor_key).map_err(|e| err(Code::PolicyDenied, e))?;
        check(
            self.max_validity_seconds > 0 && self.max_validity_seconds <= 86400,
            Code::PolicyDenied,
            "validity ceiling must be 1..86400 seconds",
        )?;
        check(
            !self.allow.is_empty() && self.allow.len() <= 16,
            Code::PolicyDenied,
            "1..16 grants required",
        )?;
        let mut seen = std::collections::HashSet::new();
        for g in &self.allow {
            check(
                matches!(g.tool.as_str(), "artifact.write" | "artifact.sha256")
                    && g.resource == RESOURCE,
                Code::PolicyDenied,
                "unsupported capability",
            )?;
            check(
                g.max_argument_bytes <= openproof_core::MAX_INPUT as u64,
                Code::PolicyDenied,
                "argument limit exceeds 1 MiB",
            )?;
            check(
                seen.insert((&g.tool, &g.resource)),
                Code::PolicyDenied,
                "duplicate grant",
            )?;
        }
        Ok(())
    }
}
#[derive(Debug, Serialize)]
pub struct Execution {
    pub token: String,
    pub artifact_directory: PathBuf,
    pub bundle: Bundle,
    pub context: Context,
    pub replay_protection_enforced: bool,
    pub replay_scope: String,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct Record {
    pub token: String,
    pub action_sha256: String,
    pub state: String,
    pub output_sha256: Option<String>,
}
#[derive(Debug, Serialize)]
pub struct ArtifactReport {
    pub evidence: openproof_core::Report,
    pub artifact_bytes_match_receipt: bool,
}
pub fn verify_artifact(
    bundle: &Bundle,
    context: &Context,
    output: &[u8],
) -> Result<ArtifactReport> {
    let report = verify(bundle, context).map_err(|e| err(Code::InvalidEvidence, e))?;
    let receipt = bundle
        .receipt
        .as_ref()
        .ok_or_else(|| err(Code::InvalidEvidence, "receipt required"))?;
    check(
        receipt.payload.output_sha256 == sha256(output),
        Code::InvalidEvidence,
        "artifact digest mismatch",
    )?;
    Ok(ArtifactReport {
        evidence: report,
        artifact_bytes_match_receipt: true,
    })
}
fn directory(path: &Path) -> Result<()> {
    let m = fs::symlink_metadata(path).map_err(storage)?;
    check(
        m.is_dir() && !m.file_type().is_symlink(),
        Code::Storage,
        "state directory must be a real directory",
    )?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        check(
            m.permissions().mode() & 0o077 == 0,
            Code::Storage,
            "state directory must be private (0700)",
        )?;
    }
    Ok(())
}
fn create_private_dir(path: &Path) -> Result<()> {
    let mut builder = fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(path).map_err(storage)
}
fn sync_dir(path: &Path) -> Result<()> {
    File::open(path).and_then(|f| f.sync_all()).map_err(storage)
}
fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(path).map_err(storage)?;
    f.write_all(bytes).map_err(storage)?;
    f.sync_all().map_err(storage)
}
fn json_new<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    write_new(path, &serde_json::to_vec_pretty(value).map_err(storage)?)
}
pub fn init_state(root: &Path) -> Result<()> {
    check(
        cfg!(unix),
        Code::Storage,
        "execution state is supported on Unix only in this version",
    )?;
    create_private_dir(root)?;
    create_private_dir(&root.join("jobs"))?;
    let db = root.join("replay.sqlite3");
    let connection = Connection::open(&db).map_err(storage)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&db, fs::Permissions::from_mode(0o600)).map_err(storage)?;
    }
    connection.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA fullfsync=ON; PRAGMA checkpoint_fullfsync=ON;
 CREATE TABLE consumptions(token TEXT PRIMARY KEY NOT NULL, action_sha256 TEXT NOT NULL, state TEXT NOT NULL CHECK(state IN ('reserved','completed','indeterminate')), output_sha256 TEXT);
 PRAGMA user_version=1;").map_err(storage)?;
    drop(connection);
    sync_dir(root)?;
    sync_dir(
        root.parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new(".")),
    )
}
fn connect(root: &Path) -> Result<Connection> {
    check(cfg!(unix), Code::Storage, "execution state requires Unix")?;
    directory(root)?;
    directory(&root.join("jobs"))?;
    let db = root.join("replay.sqlite3");
    let m = fs::symlink_metadata(&db).map_err(storage)?;
    check(
        m.is_file() && !m.file_type().is_symlink(),
        Code::Storage,
        "replay database missing or not a regular file",
    )?;
    let c = Connection::open_with_flags(
        db,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(storage)?;
    c.busy_timeout(Duration::from_secs(5)).map_err(storage)?;
    c.pragma_update(None, "synchronous", "FULL")
        .map_err(storage)?;
    c.pragma_update(None, "fullfsync", true).map_err(storage)?;
    c.pragma_update(None, "checkpoint_fullfsync", true)
        .map_err(storage)?;
    let version: i64 = c
        .pragma_query_value(None, "user_version", |r| r.get(0))
        .map_err(storage)?;
    let mode: String = c
        .pragma_query_value(None, "journal_mode", |r| r.get(0))
        .map_err(storage)?;
    check(
        version == 1 && mode == "wal",
        Code::Storage,
        "unsupported state database version or journaling mode",
    )?;
    Ok(c)
}
pub fn records(root: &Path) -> Result<Vec<Record>> {
    let c = connect(root)?;
    let mut s = c
        .prepare("SELECT token,action_sha256,state,output_sha256 FROM consumptions ORDER BY token")
        .map_err(storage)?;
    let rows = s
        .query_map([], |r| {
            Ok(Record {
                token: r.get(0)?,
                action_sha256: r.get(1)?,
                state: r.get(2)?,
                output_sha256: r.get(3)?,
            })
        })
        .map_err(storage)?;
    rows.collect::<std::result::Result<Vec<_>, _>>()
        .map_err(storage)
}
fn token(context: &Context) -> Result<String> {
    let mut bytes = b"OpenProof/gate/nonce/v1\0".to_vec();
    bytes.extend(
        canonical(&(&context.authority_key, &context.audience, &context.nonce)).map_err(storage)?,
    );
    Ok(sha256(&bytes))
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum Checkpoint {
    BeforeReservation,
    Reserved,
    BeforeArtifact,
    ArtifactWritten,
    BeforeCompletion,
    Completed,
}
#[derive(Clone, Copy)]
pub struct TrustInput<'a> {
    pub snapshot: &'a Signed<TrustBundle>,
    pub anchor: &'a Anchor,
}
struct Checks<'a, F> {
    checkpoint: F,
    trust: Option<TrustInput<'a>>,
}
fn verify_request(
    request: &Bundle,
    context: &Context,
    trust: Option<TrustInput<'_>>,
) -> Result<()> {
    if let Some(t) = trust {
        openproof_trust::verify_trusted(
            request,
            context,
            t.snapshot,
            t.anchor,
            context.now,
            Mode::Current,
        )
        .map_err(|e| err(Code::InvalidEvidence, e))?;
    } else {
        verify(request, context).map_err(|e| err(Code::InvalidEvidence, e))?;
    }
    Ok(())
}
fn root_namespace(tx: &rusqlite::Transaction<'_>, anchor: &Anchor) -> Result<String> {
    tx.execute_batch("CREATE TABLE IF NOT EXISTS root_lineage(root TEXT NOT NULL, audience TEXT NOT NULL, origin TEXT NOT NULL, retired INTEGER NOT NULL, PRIMARY KEY(root,audience))").map_err(storage)?;
    let row: Option<(String, bool)> = tx
        .query_row(
            "SELECT origin,retired FROM root_lineage WHERE root=?1 AND audience=?2",
            params![anchor.root_key, anchor.audience],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()
        .map_err(storage)?;
    if let Some((origin, retired)) = row {
        check(
            !retired,
            Code::InvalidEvidence,
            "trust root retired in this state",
        )?;
        Ok(origin)
    } else {
        Ok(anchor.root_key.clone())
    }
}
fn clock_floor(tx: &rusqlite::Transaction<'_>, namespace: &str, time: u64) -> Result<()> {
    let time = i64::try_from(time).map_err(storage)?;
    tx.execute_batch(
        "CREATE TABLE IF NOT EXISTS trust_clock(namespace TEXT PRIMARY KEY, time INTEGER NOT NULL)",
    )
    .map_err(storage)?;
    let old: Option<i64> = tx
        .query_row(
            "SELECT time FROM trust_clock WHERE namespace=?1",
            [namespace],
            |r| r.get(0),
        )
        .optional()
        .map_err(storage)?;
    check(
        old.is_none_or(|old| time >= old),
        Code::InvalidEvidence,
        "clock moved behind persisted trust watermark",
    )?;
    tx.execute("INSERT INTO trust_clock VALUES(?1,?2) ON CONFLICT(namespace) DO UPDATE SET time=excluded.time", params![namespace,time]).map_err(storage)?;
    Ok(())
}
fn pin_snapshot(tx: &rusqlite::Transaction<'_>, t: TrustInput<'_>, audience: &str) -> Result<()> {
    tx.execute_batch("CREATE TABLE IF NOT EXISTS trust_revisions(namespace TEXT PRIMARY KEY, revision INTEGER NOT NULL, snapshot_digest TEXT NOT NULL)").map_err(storage)?;
    let origin = root_namespace(tx, t.anchor)?;
    let namespace = sha256(&canonical(&(&origin, audience)).map_err(storage)?);
    clock_floor(tx, &namespace, now()?)?;
    let revision = i64::try_from(t.snapshot.payload.revision).map_err(storage)?;
    let snapshot_digest = digest(&t.snapshot.payload).map_err(storage)?;
    let previous: Option<(i64, String)> = tx
        .query_row(
            "SELECT revision,snapshot_digest FROM trust_revisions WHERE namespace=?1",
            [&namespace],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()
        .map_err(storage)?;
    if let Some((old, hash)) = previous {
        check(
            revision >= old && (revision != old || hash == snapshot_digest),
            Code::InvalidEvidence,
            "trust rollback or same-revision equivocation",
        )?;
    }
    tx.execute("INSERT INTO trust_revisions VALUES(?1,?2,?3) ON CONFLICT(namespace) DO UPDATE SET revision=excluded.revision,snapshot_digest=excluded.snapshot_digest",params![namespace,revision,snapshot_digest]).map_err(storage)?;
    Ok(())
}
/// Explicitly install a fresh signed snapshot floor, even if every request under it is revoked.
pub fn install_trust(root: &Path, snapshot: &Signed<TrustBundle>, anchor: &Anchor) -> Result<()> {
    openproof_trust::validate_snapshot(snapshot, anchor, now()?)
        .map_err(|e| err(Code::InvalidEvidence, e))?;
    let mut conn = connect(root)?;
    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(storage)?;
    openproof_trust::validate_snapshot(snapshot, anchor, now()?)
        .map_err(|e| err(Code::InvalidEvidence, e))?;
    pin_snapshot(&tx, TrustInput { snapshot, anchor }, &anchor.audience)?;
    tx.commit().map_err(storage)
}
/// Atomic planned root handover; preserves the original replay and revision namespace.
pub fn rotate_root(
    root: &Path,
    old: &Signed<openproof_trust::RootTransition>,
    new: &Signed<openproof_trust::RootTransition>,
    anchor: &Anchor,
    snapshot: &Signed<TrustBundle>,
) -> Result<Anchor> {
    let mut conn = connect(root)?;
    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(storage)?;
    let next = openproof_trust::verify_transition(old, new, anchor, now()?)
        .map_err(|e| err(Code::InvalidEvidence, e))?;
    openproof_trust::validate_snapshot(snapshot, &next, now()?)
        .map_err(|e| err(Code::InvalidEvidence, e))?;
    check(
        snapshot.payload.revision == next.minimum_revision,
        Code::InvalidEvidence,
        "snapshot must match transition revision",
    )?;
    let origin = root_namespace(&tx, anchor)?;
    let namespace = sha256(&canonical(&(&origin, &anchor.audience)).map_err(storage)?);
    // Require an already installed old root floor; do not bootstrap from a handover alone.
    let previous: i64 = tx
        .query_row(
            "SELECT revision FROM trust_revisions WHERE namespace=?1",
            [&namespace],
            |r| r.get(0),
        )
        .map_err(storage)?;
    check(
        next.minimum_revision > previous as u64,
        Code::InvalidEvidence,
        "rotation revision must advance installed floor",
    )?;
    let present: bool = tx
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM root_lineage WHERE root=?1 AND audience=?2)",
            params![next.root_key, next.audience],
            |r| r.get(0),
        )
        .map_err(storage)?;
    let next_namespace = sha256(&canonical(&(&next.root_key, &next.audience)).map_err(storage)?);
    let used: bool = tx
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM trust_revisions WHERE namespace=?1)",
            [next_namespace],
            |r| r.get(0),
        )
        .map_err(storage)?;
    check(
        !present && !used,
        Code::InvalidEvidence,
        "new root already used in this state",
    )?;
    tx.execute("INSERT INTO root_lineage VALUES(?1,?2,?3,1) ON CONFLICT(root,audience) DO UPDATE SET retired=1",params![anchor.root_key,anchor.audience,origin]).map_err(storage)?;
    tx.execute(
        "INSERT INTO root_lineage VALUES(?1,?2,?3,0)",
        params![next.root_key, next.audience, origin],
    )
    .map_err(storage)?;
    pin_snapshot(
        &tx,
        TrustInput {
            snapshot,
            anchor: &next,
        },
        &next.audience,
    )?;
    tx.commit().map_err(storage)?;
    Ok(next)
}
pub fn execute_trusted(
    root: &Path,
    request: &Bundle,
    context: &Context,
    policy_bytes: &[u8],
    arguments: &[u8],
    executor: &SigningKey,
    trust: TrustInput<'_>,
) -> Result<Execution> {
    execute_engine(
        root,
        request,
        context,
        policy_bytes,
        arguments,
        executor,
        Checks {
            checkpoint: |_| {},
            trust: Some(trust),
        },
    )
}
#[cfg(test)]
fn execute_inner<F: Fn(Checkpoint)>(
    root: &Path,
    request: &Bundle,
    context: &Context,
    policy_bytes: &[u8],
    arguments: &[u8],
    executor: &SigningKey,
    checkpoint: F,
) -> Result<Execution> {
    execute_engine(
        root,
        request,
        context,
        policy_bytes,
        arguments,
        executor,
        Checks {
            checkpoint,
            trust: None,
        },
    )
}
/// Uses the host clock, and consumes a nonce durably before any adapter work.
pub fn execute(
    root: &Path,
    request: &Bundle,
    context: &Context,
    policy_bytes: &[u8],
    arguments: &[u8],
    executor: &SigningKey,
) -> Result<Execution> {
    execute_engine(
        root,
        request,
        context,
        policy_bytes,
        arguments,
        executor,
        Checks {
            checkpoint: |_| {},
            trust: None,
        },
    )
}
fn execute_engine<F: Fn(Checkpoint)>(
    root: &Path,
    request: &Bundle,
    context: &Context,
    policy_bytes: &[u8],
    arguments: &[u8],
    executor: &SigningKey,
    checks: Checks<'_, F>,
) -> Result<Execution> {
    check(
        arguments.len() <= openproof_core::MAX_INPUT,
        Code::InvalidInput,
        "arguments exceed 1 MiB",
    )?;
    check(
        request.receipt.is_none(),
        Code::InvalidEvidence,
        "execution requires an unexecuted claim without a receipt",
    )?;
    let mut context = context.clone();
    context.now = now()?;
    verify_request(request, &context, checks.trust)?;
    let policy: Policy = parse(policy_bytes).map_err(|e| err(Code::PolicyDenied, e))?;
    policy.validate()?;
    let pk = hex::encode(executor.verifying_key().to_bytes());
    check(
        pk == context.executor_key
            && pk == policy.executor_key
            && pk != context.actor_key
            && pk != context.authority_key,
        Code::PolicyDenied,
        "executor key not allowed or roles not distinct",
    )?;
    check(
        policy.audience == context.audience && sha256(policy_bytes) == context.policy_sha256,
        Code::PolicyDenied,
        "policy binding mismatch",
    )?;
    let a = &request.authorization.payload;
    let action = &request.action.payload.action;
    check(
        a.expires_at - a.not_before <= policy.max_validity_seconds,
        Code::PolicyDenied,
        "authorization validity exceeds policy",
    )?;
    let grant = policy
        .allow
        .iter()
        .find(|g| g.tool == action.tool && g.resource == action.resource)
        .ok_or_else(|| err(Code::PolicyDenied, "capability denied"))?;
    check(
        arguments.len() as u64 <= grant.max_argument_bytes,
        Code::PolicyDenied,
        "arguments exceed grant",
    )?;
    check(
        sha256(arguments) == action.arguments_sha256,
        Code::InvalidEvidence,
        "exact argument bytes do not match authorization",
    )?;
    let mut conn = connect(root)?;
    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(storage)?;
    context.now = now()?;
    verify_request(request, &context, checks.trust)?;
    if let Some(t) = checks.trust {
        pin_snapshot(&tx, t, &context.audience)?;
    }
    let mut token_context = context.clone();
    if let Some(t) = checks.trust {
        token_context.authority_key = root_namespace(&tx, t.anchor)?;
    }
    let token = token(&token_context)?;
    (checks.checkpoint)(Checkpoint::BeforeReservation);
    let existing: bool = tx
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM consumptions WHERE token=?1)",
            [&token],
            |r| r.get(0),
        )
        .map_err(storage)?;
    check(
        !existing,
        Code::Replay,
        "nonce already consumed in this authority/audience namespace",
    )?;
    tx.execute(
        "INSERT INTO consumptions(token,action_sha256,state) VALUES(?1,?2,'reserved')",
        params![token, digest(&request.action.payload).map_err(storage)?],
    )
    .map_err(storage)?;
    tx.commit().map_err(storage)?;
    (checks.checkpoint)(Checkpoint::Reserved);
    let result = (|| {
        context.now = now()?;
        verify_request(request, &context, checks.trust)?;
        let job = root.join("jobs").join(&token);
        create_private_dir(&job)?;
        sync_dir(&root.join("jobs"))?;
        // The only adapters in this version are pure bounded transformations of captured bytes.
        let output = match action.tool.as_str() {
            "artifact.write" => arguments.to_vec(),
            "artifact.sha256" => format!("{}\n", sha256(arguments)).into_bytes(),
            _ => return Err(err(Code::PolicyDenied, "unsupported adapter")),
        };
        (checks.checkpoint)(Checkpoint::BeforeArtifact);
        write_new(&job.join("output.bin"), &output)?;
        sync_dir(&job)?;
        (checks.checkpoint)(Checkpoint::ArtifactWritten);
        context.now = now()?;
        let receipt = Receipt {
            version: VERSION.into(),
            action_sha256: digest(&request.action.payload).map_err(storage)?,
            observed_at: context.now,
            outcome: Outcome::Succeeded,
            output_sha256: sha256(&output),
        };
        let mut bundle = request.clone();
        bundle.receipt = Some(sign(receipt, executor).map_err(storage)?);
        // An expired/backwards clock after work leaves a consumed, indeterminate operation.
        verify_artifact(&bundle, &context, &output)?;
        verify_request(&bundle, &context, checks.trust)?;
        write_new(&job.join("arguments.bin"), arguments)?;
        write_new(&job.join("policy.json"), policy_bytes)?;
        json_new(&job.join("bundle.json"), &bundle)?;
        json_new(&job.join("context.json"), &context)?;
        sync_dir(&job)?;
        (checks.checkpoint)(Checkpoint::BeforeCompletion);
        conn.execute("UPDATE consumptions SET state='completed',output_sha256=?2 WHERE token=?1 AND state='reserved'",params![token,sha256(&output)]).map_err(storage)?;
        (checks.checkpoint)(Checkpoint::Completed);
        Ok(Execution {
            token: token.clone(),
            artifact_directory: job,
            bundle,
            context,
            replay_protection_enforced: true,
            replay_scope: if checks.trust.is_some() {
                "this intact state directory; trust root + audience + nonce"
            } else {
                "this intact state directory; authority + audience + nonce"
            }
            .into(),
        })
    })();
    if result.is_err() {
        let _ = conn.execute(
            "UPDATE consumptions SET state='indeterminate' WHERE token=?1 AND state='reserved'",
            [&token],
        );
    }
    result.map_err(|e: Error| {
        err(
            Code::Indeterminate,
            format!("nonce consumed; outcome must not be retried automatically: {e}"),
        )
    })
}
#[cfg(test)]
mod tests;
