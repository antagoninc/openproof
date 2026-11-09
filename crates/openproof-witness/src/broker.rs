//! Owner-home broker: propose through the gate, execute an approved request,
//! catch the witness up, and keep verified evidence. Agent tools reach only
//! `propose` and `commit`; approval stays in the gate and the owner app.
use crate::http::strict_json;
use crate::serve::{random_hex, replace, write_new};
use crate::{arg, call};
use openproof_witness::Result;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    path::{Path, PathBuf},
};

pub const ROLES: [&str; 2] = ["receiver", "witness"];

pub fn read_json(path: impl AsRef<Path>) -> Result<Value> {
    let path = path.as_ref();
    let raw = std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
    strict_json(&raw)
}

pub fn save(path: impl AsRef<Path>, value: &Value) -> Result<()> {
    write_new(path.as_ref(), &serde_json::to_vec_pretty(value)?)
}

pub fn replace_json(path: impl AsRef<Path>, value: &Value) -> Result<()> {
    replace(path.as_ref(), &serde_json::to_vec_pretty(value)?)
}

/// One lock per private home, shared with every broker process (flock).
pub fn lock(home: &Path) -> Result<File> {
    let mut o = std::fs::OpenOptions::new();
    o.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    let f = o.open(home.join(".broker.lock"))?;
    f.lock()?;
    Ok(f)
}

pub fn private_home(home: &Path) -> Result<PathBuf> {
    let home = home.canonicalize()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if std::fs::metadata(&home)?.permissions().mode() & 0o077 != 0 {
            return Err("broker directory must be private".into());
        }
    }
    Ok(home)
}

pub fn admission(home: &Path) -> Result<()> {
    if home.join("rotation-pending.json").exists() {
        return Err("planned key handover in progress; admission paused".into());
    }
    Ok(())
}

pub fn checked(id: &str) -> Result<&str> {
    if id.len() == 64
        && id
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        Ok(id)
    } else {
        Err("invalid proposal id".into())
    }
}

fn state(home: &Path, role: &str) -> String {
    arg(home.join(role).join("state"))
}

fn count(v: Value) -> Result<u64> {
    v["count"].as_u64().ok_or_else(|| "count".into())
}

pub fn propose(home: &Path, proposal: &Value) -> Result<Value> {
    let _l = lock(home)?;
    admission(home)?;
    call(&["gate-propose".into(), arg(home)], Some(proposal))
}

pub fn review(home: &Path, id: &str) -> Result<Value> {
    let _l = lock(home)?;
    admission(home)?;
    call(
        &["gate-review".into(), arg(home), checked(id)?.into()],
        None,
    )
}

/// The gate's approved request, checked by the gate when read.
pub fn approved_request(home: &Path, id: &str) -> Result<Value> {
    let r = call(
        &[
            "gate-approved".into(),
            arg(home),
            arg(home.join("trust.json")),
            checked(id)?.into(),
        ],
        None,
    )?;
    if r["state"] != "approved" {
        return Err("proposal is not approved".into());
    }
    Ok(r["request"].clone())
}

/// The receiver's current version of a document: 0 when absent, None when
/// the receiver cannot answer now.
pub fn current_version(home: &Path, document: &str) -> Option<u64> {
    match call(
        &["document".into(), state(home, "receiver"), document.into()],
        None,
    ) {
        Ok(v) => v["version"].as_u64(),
        Err(e) if e.to_string().contains("no rows") => Some(0),
        Err(_) => None,
    }
}

/// The receiver's current text of a document, for showing what a change
/// replaces. `Some(None)` when the document does not exist yet; `None` when
/// the receiver cannot answer now. Display only: approval binds the proposal.
pub fn current_document(home: &Path, document: &str) -> Option<Option<(u64, String)>> {
    match call(
        &["document".into(), state(home, "receiver"), document.into()],
        None,
    ) {
        Ok(v) => Some(Some((
            v["version"].as_u64()?,
            v["content"].as_str()?.to_string(),
        ))),
        Err(e) if e.to_string().contains("no rows") => Some(None),
        Err(_) => None,
    }
}

pub fn recover_receipt(home: &Path, request: &Value) -> Result<Value> {
    call(&["recover".into(), state(home, "receiver")], Some(request))
}

fn evidence_capacity(home: &Path) -> Result<bool> {
    // Reserve room for the next bounded package and its metadata.
    let evidence = home.join("evidence");
    if std::fs::read_dir(&evidence)?.count() >= 1000 {
        return Ok(false);
    }
    fn size(p: &Path) -> Result<u64> {
        let m = std::fs::symlink_metadata(p)?;
        if m.is_dir() {
            let mut total = 0;
            for e in std::fs::read_dir(p)? {
                total += size(&e?.path())?;
            }
            Ok(total)
        } else {
            Ok(if m.is_file() { m.len() } else { 0 })
        }
    }
    Ok(size(&evidence)? <= 62 * 1024 * 1024)
}

fn with(base: &Map<String, Value>, extra: Value) -> Value {
    let mut out = base.clone();
    if let Value::Object(m) = extra {
        out.extend(m);
    }
    Value::Object(out)
}

pub fn commit(home: &Path, id: &str, recover_only: bool) -> Result<Value> {
    let _l = lock(home)?;
    admission(home)?;
    let q = approved_request(home, id)?;
    if !home.join("trust-signed.json").exists() || !home.join("verifier").is_dir() {
        return Err("owner must run upgrade-trust before dispatch".into());
    }
    let root = read_json(home.join("root-public.json"))?["public_key"].clone();
    for role in ROLES {
        if call(&["role-status".into(), state(home, role)], None)?["root"] != root {
            return Err("owner must run upgrade-trust before dispatch".into());
        }
    }
    let mut base = json!({
        "proposal_id": id,
        "verification_scope": "local_consistency_check",
        "independent_operators": false,
        "physical_effects_proven": false,
    })
    .as_object()
    .cloned()
    .unwrap_or_default();
    // Read-only recovery cannot authorize a new mutation. Admission checks stay
    // in receive: expiry, retirement and revocation.
    let mut receipt = recover_receipt(home, &q)?;
    if receipt.is_null() {
        if recover_only {
            return Err("No durable receipt; recovery cannot execute an action".into());
        }
        let not_committed = |code: &str| {
            with(
                &base,
                json!({"status": "not_committed", "execution_status": "not_committed",
                       "verification_status": "not_verified", "error_code": code}),
            )
        };
        if !evidence_capacity(home)? {
            return Ok(not_committed("evidence_storage_capacity"));
        }
        let receive = [
            "receive".into(),
            state(home, "receiver"),
            arg(home.join("receiver/key.secret")),
            arg(home.join("trust.json")),
        ];
        match call(&receive, Some(&q)) {
            Ok(r) => receipt = r,
            // A lost reply may follow a commit. Read durable state before reporting.
            Err(_) => match recover_receipt(home, &q) {
                Err(_) => {
                    return Ok(with(
                        &base,
                        json!({"status": "outcome_unknown", "execution_status": "unknown",
                               "verification_status": "not_verified",
                               "error_code": "receiver_response_unavailable"}),
                    ))
                }
                Ok(r) if r.is_null() => return Ok(not_committed("admission_failed")),
                Ok(r) => receipt = r,
            },
        }
    }
    base.insert("execution_status".into(), json!("committed"));
    base.insert("document".into(), receipt["payload"]["document"].clone());
    base.insert(
        "document_version".into(),
        receipt["payload"]["document_version"].clone(),
    );
    let paging = home.join("paging.json").exists();
    let witness = |value: Option<&Value>, op: &str| {
        call(
            &[
                op.into(),
                state(home, "witness"),
                arg(home.join("witness/key.secret")),
                arg(home.join("trust.json")),
            ],
            value,
        )
    };
    let witnessed = (|| -> Result<Value> {
        let target = count(call(&["head".into(), state(home, "receiver")], None)?)?;
        let start = count(call(&["head".into(), state(home, "witness")], None)?)? + 1;
        if target.saturating_sub(start) > 4096 {
            return Err("catch-up capacity".into());
        }
        for sequence in start..=target {
            let stored = call(
                &[
                    "receipt".into(),
                    state(home, "receiver"),
                    sequence.to_string(),
                ],
                None,
            )?;
            witness(Some(&stored), "witness")?;
        }
        // Replaying this exact receipt returns the witness's current signed head.
        if paging {
            witness(None, "checkpoint")
        } else {
            witness(Some(&receipt), "witness")
        }
    })();
    let Ok(checkpoint) = witnessed else {
        return Ok(with(
            &base,
            json!({"status": "committed_unwitnessed", "verification_status": "not_verified",
                   "witness_status": "confirmation_unavailable",
                   "error_code": "witness_recovery_required"}),
        ));
    };
    let evidence = (|| -> Result<Value> {
        if !evidence_capacity(home)? {
            return Err("evidence capacity".into());
        }
        if paging {
            return finish_paged(home, id, &checkpoint, &base);
        }
        let package = call(
            &[
                "export".into(),
                state(home, "receiver"),
                arg(home.join("trust.json")),
            ],
            Some(&checkpoint),
        )?;
        // The pin comes directly from the configured witness; custody is local.
        let scratch = home.join(format!("checkpoint-{}.json", random_hex()));
        save(&scratch, &checkpoint)?;
        let verified = call(
            &[
                "verify-trusted".into(),
                arg(home.join("verifier")),
                arg(home.join("trust-signed.json")),
                arg(&scratch),
            ],
            Some(&package),
        );
        let _ = std::fs::remove_file(&scratch);
        let mut result = verified?;
        let status = result["status"].clone();
        result["evidence_status"] = status.clone();
        if status != "unknown_due_to_disclosed_gap" {
            result["status"] = json!("local_consistency_check");
        }
        let mut result = with(
            result.as_object().ok_or("assessment")?,
            Value::Object(base.clone()),
        );
        result["verification_status"] = json!("local_consistency_verified");
        result["witness_status"] = json!("confirmed");
        let eid = evidence_id(home, id, &checkpoint)?;
        let run = home.join("evidence").join(&eid);
        if !run.exists() {
            let stage = home
                .join("evidence")
                .join(format!(".pending-{}", random_hex()));
            std::fs::create_dir(&stage)?;
            let staged = (|| -> Result<()> {
                save(stage.join("checkpoint.json"), &checkpoint)?;
                save(stage.join("package.json"), &package)?;
                save(stage.join("assessment.json"), &result)?;
                std::fs::rename(&stage, &run)?;
                Ok(())
            })();
            if stage.exists() {
                let _ = std::fs::remove_dir_all(&stage);
            }
            staged?;
        }
        result["evidence_id"] = json!(eid);
        result["evidence_directory"] = json!(arg(&run));
        Ok(result)
    })();
    Ok(evidence.unwrap_or_else(|_| {
        with(
            &base,
            json!({"status": "witnessed_evidence_failed", "witness_status": "confirmed",
                   "verification_status": "not_verified",
                   "error_code": "evidence_export_or_verification_failed"}),
        )
    }))
}

fn evidence_id(home: &Path, id: &str, checkpoint: &Value) -> Result<String> {
    let signed = read_json(home.join("trust-signed.json"))?;
    let raw = openproof_core::canonical(&json!([id, checkpoint, signed]))?;
    Ok(hex::encode(Sha256::digest(raw)))
}

fn finish_paged(
    home: &Path,
    id: &str,
    checkpoint: &Value,
    base: &Map<String, Value>,
) -> Result<Value> {
    let signed = read_json(home.join("trust-signed.json"))?;
    let eid = evidence_id(home, id, checkpoint)?;
    let run = home.join("evidence").join(&eid);
    if !run.exists() {
        std::fs::create_dir(&run)?;
    }
    for (name, value) in [
        ("checkpoint.json", checkpoint),
        ("trust-signed.json", &signed),
    ] {
        let path = run.join(name);
        if !path.exists() {
            save(&path, value)?;
        } else if read_json(&path)? != *value {
            return Err("evidence identity conflict".into());
        }
    }
    let total = checkpoint["payload"]["count"]
        .as_u64()
        .ok_or("checkpoint count")?;
    let mut progress = count(call(
        &["page-progress".into(), arg(home.join("verifier"))],
        None,
    )?)?;
    let mut result = loop {
        let page = if progress == total {
            json!({"version": "openproof-history-page/1", "start": progress + 1,
                   "receipts": [], "requests": [], "checkpoint": checkpoint})
        } else {
            call(
                &[
                    "export-page".into(),
                    state(home, "receiver"),
                    arg(home.join("trust.json")),
                    (progress + 1).to_string(),
                ],
                Some(checkpoint),
            )?
        };
        let path = run.join(format!("page-{:08}.json", progress + 1));
        if path.exists() {
            if read_json(&path)? != page {
                return Err("saved page conflict".into());
            }
        } else {
            save(&path, &page)?;
        }
        let r = call(
            &[
                "verify-page".into(),
                arg(home.join("verifier")),
                arg(home.join("trust-signed.json")),
                arg(run.join("checkpoint.json")),
            ],
            Some(&page),
        )?;
        if r["checkpoint_complete"] == true {
            break r;
        }
        let processed = r["processed"].as_u64().ok_or("processed")?;
        if processed <= progress {
            return Err("verification made no progress".into());
        }
        progress = processed;
    };
    let complete = result["complete_history"] == true;
    let status = result["status"].clone();
    for (k, v) in base {
        result[k] = v.clone();
    }
    result["evidence_status"] = status;
    result["status"] = json!(if complete {
        "local_consistency_check"
    } else {
        "unknown_due_to_disclosed_gap"
    });
    result["verification_status"] = json!("local_consistency_verified");
    result["witness_status"] = json!("confirmed");
    result["evidence_format"] = json!("incremental_pages");
    result["standalone_history"] = json!(false);
    replace_json(run.join("assessment.json"), &result)?;
    result["evidence_id"] = json!(eid);
    result["evidence_directory"] = json!(arg(&run));
    Ok(result)
}

pub fn enable_paging(home: &Path) -> Result<Value> {
    let _l = lock(home)?;
    admission(home)?;
    call(
        &[
            "enable-pages".into(),
            state(home, "receiver"),
            arg(home.join("trust.json")),
        ],
        None,
    )?;
    if !home.join("genesis-root.json").exists() {
        save(
            home.join("genesis-root.json"),
            &read_json(home.join("root-public.json"))?,
        )?;
    }
    if !home.join("paging.json").exists() {
        save(home.join("paging.json"), &json!({"version": 1}))?;
    }
    Ok(json!({"paging_enabled": true}))
}

fn mkdir_private(path: &Path) -> Result<()> {
    let mut b = std::fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        b.mode(0o700);
    }
    b.create(path)?;
    Ok(())
}

/// A new owner home: separate role keys and states, a root key, a signed trust.
pub fn init_home(home: &Path) -> Result<Value> {
    if home.exists() {
        return Err(format!("{} already exists", home.display()).into());
    }
    if let Some(parent) = home.parent() {
        std::fs::create_dir_all(parent)?;
    }
    mkdir_private(home)?;
    let home = home.canonicalize()?;
    let mut keys = Map::new();
    for role in ["authority", "receiver", "witness"] {
        mkdir_private(&home.join(role))?;
        let k = call(
            &["keygen".into(), arg(home.join(role).join("key.secret"))],
            None,
        )?;
        keys.insert(role.into(), k["public_key"].clone());
        if role != "authority" {
            call(&["init".into(), state(&home, role)], None)?;
        }
    }
    mkdir_private(&home.join("evidence"))?;
    mkdir_private(&home.join("root"))?;
    let root =
        call(&["keygen".into(), arg(home.join("root/key.secret"))], None)?["public_key"].clone();
    let root_text = root.as_str().ok_or("root key")?.to_string();
    save(home.join("root-public.json"), &json!({"public_key": root}))?;
    call(
        &[
            "verifier-init".into(),
            arg(home.join("verifier")),
            root_text.clone(),
        ],
        None,
    )?;
    call(
        &[
            "signer-init".into(),
            arg(home.join("root/signer")),
            root_text.clone(),
        ],
        None,
    )?;
    let mut trust = json!({
        "version": "openproof-witness/1",
        "epoch": 1,
        "expires_at": openproof_witness::now() + 86400,
        "previous_authorities": [],
        "revoked_authorities": [],
    });
    for (k, v) in keys {
        trust[k] = v;
    }
    save(home.join("trust.json"), &trust)?;
    for role in ROLES {
        call(
            &["role-pin".into(), state(&home, role), root_text.clone()],
            None,
        )?;
    }
    let signed = call(
        &[
            "sign-trust".into(),
            arg(home.join("root/key.secret")),
            arg(home.join("root/signer")),
        ],
        Some(&trust),
    )?;
    save(home.join("trust-signed.json"), &signed)?;
    for role in ROLES {
        call(
            &[
                "install-signed".into(),
                state(&home, role),
                root_text.clone(),
            ],
            Some(&signed),
        )?;
    }
    call(
        &["verifier-install".into(), arg(home.join("verifier"))],
        Some(&signed),
    )?;
    Ok(
        json!({"initialized": arg(&home), "trust_expires_in_seconds": 86400,
              "roles": "separate keys/processes/state; same host owner"}),
    )
}

pub fn authenticated_trust(home: &Path) -> Result<Value> {
    let root = read_json(home.join("root-public.json"))?["public_key"]
        .as_str()
        .ok_or("root key")?
        .to_string();
    call(
        &["trust-payload".into(), root],
        Some(&read_json(home.join("trust-signed.json"))?),
    )
}

/// Owner-only staged update. If one store fails, retry with the same trust.
fn install_trust_locked(home: &Path, new: &Value) -> Result<Value> {
    let old = read_json(home.join("trust.json"))?;
    if new["receiver"] != old["receiver"] || new["witness"] != old["witness"] {
        return Err("receiver/witness key rotation requires a future migration protocol".into());
    }
    // The role and verifier states refuse this too; fail before signing.
    if old.get("owner_passkey").is_some() && new.get("owner_passkey") != old.get("owner_passkey") {
        return Err("an installed owner passkey cannot be removed or replaced".into());
    }
    let signed = call(
        &[
            "sign-trust".into(),
            arg(home.join("root/key.secret")),
            arg(home.join("root/signer")),
        ],
        Some(new),
    )?;
    let root = read_json(home.join("root-public.json"))?["public_key"]
        .as_str()
        .ok_or("root key")?
        .to_string();
    for role in ROLES {
        call(
            &["install-signed".into(), state(home, role), root.clone()],
            Some(&signed),
        )?;
    }
    call(
        &["verifier-install".into(), arg(home.join("verifier"))],
        Some(&signed),
    )?;
    replace_json(home.join("trust-signed.json"), &signed)?;
    replace_json(home.join("trust.json"), new)?;
    Ok(json!({"installed_epoch": new["epoch"], "expires_at": new["expires_at"]}))
}

pub fn install_trust(home: &Path, configuration: &Path) -> Result<Value> {
    let new = read_json(configuration)?;
    let _l = lock(home)?;
    install_trust_locked(home, &new)
}

pub fn renew(home: &Path) -> Result<Value> {
    let _l = lock(home)?;
    let mut t = authenticated_trust(home)?;
    t["epoch"] = json!(t["epoch"].as_u64().ok_or("epoch")? + 1);
    t["expires_at"] = json!(openproof_witness::now() + 86400);
    install_trust_locked(home, &t)
}

/// A new root-signed trust epoch that requires the owner's passkey from the
/// next receiver sequence on.
pub fn enroll_passkey(home: &Path, public_key: &str, rp_id: &str, origin: &str) -> Result<Value> {
    let _l = lock(home)?;
    admission(home)?;
    let mut t = authenticated_trust(home)?;
    if t.get("owner_passkey").is_some() {
        return Err("an owner passkey is already installed".into());
    }
    // History up to the current receiver head was approved without a passkey.
    let head = count(call(&["head".into(), state(home, "receiver")], None)?)?;
    t["epoch"] = json!(t["epoch"].as_u64().ok_or("epoch")? + 1);
    t["expires_at"] = json!(openproof_witness::now() + 86400);
    t["owner_passkey"] = json!({"public_key": public_key, "rp_id": rp_id, "origin": origin,
                                "from_sequence": head + 1});
    install_trust_locked(home, &t)
}

/// Export signed public evidence for offline checking. The trust root and the
/// checkpoint pin are provisioned separately.
pub fn export_history(home: &Path, out: &Path) -> Result<Value> {
    let _l = lock(home)?;
    admission(home)?;
    if out.exists() {
        return Err("output folder exists".into());
    }
    std::fs::create_dir_all(out.parent().ok_or("output parent")?)?;
    mkdir_private(out)?;
    let mut entries: Vec<Value> = vec![];
    let mut start = 1u64;
    fn entry(out: &Path, entries: &mut Vec<Value>, value: Value) -> Result<()> {
        let name = format!("entry-{:06}.json", entries.len());
        save(out.join(&name), &value)?;
        let digest = hex::encode(Sha256::digest(std::fs::read(out.join(&name))?));
        entries.push(json!({"file": name, "sha256": digest}));
        if entries.len() > 4096 {
            return Err("Archive entry capacity".into());
        }
        Ok(())
    }
    fn pages(
        home: &Path,
        out: &Path,
        entries: &mut Vec<Value>,
        start: &mut u64,
        signed: &Value,
        cp: &Value,
    ) -> Result<()> {
        // Historical mode checks signatures at the recorded checkpoint time; the
        // offline verifier separately requires a current final pin.
        let trust_path = out.join("working-trust.json");
        save(&trust_path, &signed["payload"])?;
        let total = cp["payload"]["count"].as_u64().ok_or("checkpoint count")?;
        while *start <= total {
            let page = call(
                &[
                    "export-page-historical".into(),
                    state(home, "receiver"),
                    arg(&trust_path),
                    start.to_string(),
                ],
                Some(cp),
            )?;
            let n = page["receipts"].as_array().map_or(0, Vec::len) as u64;
            if n == 0 {
                return Err("empty history page".into());
            }
            *start += n;
            entry(
                out,
                entries,
                json!({"kind": "page", "signed_trust": signed, "page": page}),
            )?;
        }
        // Always keep a final checkpoint, including an empty epoch after handover.
        let last = json!({"version": "openproof-history-page/1", "start": *start,
                          "receipts": [], "requests": [], "checkpoint": cp});
        entry(
            out,
            entries,
            json!({"kind": "page", "signed_trust": signed, "page": last}),
        )?;
        std::fs::remove_file(&trust_path)?;
        Ok(())
    }
    let epochs = home.join("epochs");
    if epochs.exists() {
        let mut dirs: Vec<_> = std::fs::read_dir(&epochs)?.collect::<std::io::Result<Vec<_>>>()?;
        dirs.sort_by_key(|e| e.path());
        for e in dirs {
            let old = read_json(e.path().join("old-trust-signed.json"))?;
            let handover = read_json(e.path().join("handover.json"))?;
            pages(
                home,
                out,
                &mut entries,
                &mut start,
                &old,
                &handover["old_root"]["payload"]["checkpoint"],
            )?;
            entry(
                out,
                &mut entries,
                json!({"kind": "handover", "old_signed_trust": old, "handover": handover}),
            )?;
        }
    }
    let signed = read_json(home.join("trust-signed.json"))?;
    let cp = call(
        &[
            "checkpoint".into(),
            state(home, "witness"),
            arg(home.join("witness/key.secret")),
            arg(home.join("trust.json")),
        ],
        None,
    )?;
    if cp["payload"]["count"].as_u64()
        != Some(count(call(
            &["head".into(), state(home, "receiver")],
            None,
        )?)?)
    {
        return Err("Witness must catch up before archive export".into());
    }
    pages(home, out, &mut entries, &mut start, &signed, &cp)?;
    let n = entries.len();
    save(
        out.join("manifest.json"),
        &json!({"version": "openproof-portable-history/1", "entries": entries}),
    )?;
    // A convenience copy, not a substitute for a separately trusted pin.
    save(out.join("checkpoint-copy.json"), &cp)?;
    std::fs::write(
        out.join("VERIFY.txt"),
        "Verify offline with an independently obtained OpenProof Go verifier:\n\
         openproof-go-verify verify-archive ROOT_PUBLIC_KEY CHECKPOINT_PIN ARCHIVE_DIR NOW\n\
         Obtain the root public key and a current checkpoint pin separately from this archive.\n",
    )?;
    Ok(
        json!({"archive": arg(out), "entries": n, "count": cp["payload"]["count"],
              "trust_root_included": false, "checkpoint_requires_independent_provisioning": true}),
    )
}

/// Owner commands. `None` when the arguments are not a broker command.
pub fn command(a: &[&str]) -> Result<Option<Value>> {
    let home = |h: &str| private_home(Path::new(h));
    Ok(Some(match a {
        ["init-home", h] => init_home(Path::new(h))?,
        ["broker-propose", h] => propose(
            &home(h)?,
            &crate::http::strict_json(&crate::input_bytes()?)?,
        )?,
        ["broker-review", h, id] => review(&home(h)?, id)?,
        ["broker-commit", h, id] => commit(&home(h)?, id, false)?,
        ["broker-recover", h, id] => commit(&home(h)?, id, true)?,
        ["enable-paging", h] => enable_paging(&home(h)?)?,
        ["export-history", h, out] => export_history(&home(h)?, Path::new(out))?,
        ["renew", h] => renew(&home(h)?)?,
        ["install-trust", h, configuration] => install_trust(&home(h)?, Path::new(configuration))?,
        ["enroll-passkey", h] => {
            let v = crate::http::strict_json(&crate::input_bytes()?)?;
            let m = crate::http::fields(&v, &["public_key", "rp_id", "origin"], &[])?;
            let t = |k| crate::http::text(m, k);
            enroll_passkey(&home(h)?, t("public_key")?, t("rp_id")?, t("origin")?)?
        }
        _ => return Ok(None),
    }))
}
