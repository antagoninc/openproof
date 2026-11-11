//! Local owner app. Loopback only, explicit session, exact review binding.
//! The Rust approval gate makes every approval decision; this server keeps
//! the session, the CSRF token and the one-use review and assertion tokens.
//!
//! It serves two origins. The review origin is the passkey's origin: only the
//! review and passkey set-up pages run there, so no other page can obtain a
//! passkey assertion that the gate or the receiver accepts. The workspace
//! (dashboard) runs on a second port. Only the fixed tables between the
//! `TCB:` markers are trusted (docs/TCB.md): the review page checks every
//! approval it is given against what it shows.
use crate::broker::{self, read_json, replace_json, save, ROLES};
use crate::http::{fields, integer, read_request, respond, strict_json, text, Request};
use crate::{arg, call};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use openproof_witness::files::random_hex;
use openproof_witness::{now, Result};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    net::{TcpListener, TcpStream},
    path::PathBuf,
    time::{Duration, Instant},
};

const RP_ID: &str = "localhost";
const TOKEN_LIFE: Duration = Duration::from_secs(300);
// TCB:begin
/// The two origins the app serves.
#[derive(Clone, Copy, PartialEq)]
enum Site {
    Review,
    Workspace,
}
/// The files and requests each origin serves. The review origin serves only
/// the review and set-up pages, their modules and their requests.
const REVIEW_FILES: [&str; 7] = [
    "/review",
    "/setup",
    "/review.js",
    "/setup.js",
    "/common.js",
    "/approval.js",
    "/base.css",
];
const WORKSPACE_FILES: [&str; 6] = [
    "/",
    "/app.js",
    "/common.js",
    "/approval.js",
    "/base.css",
    "/app.css",
];
const REVIEW_POSTS: [&str; 5] = [
    "/api/review",
    "/api/approve",
    "/api/approve/passkey",
    "/api/passkey/register/begin",
    "/api/passkey/register/finish",
];
fn serves(site: Site, path: &str, post: bool) -> bool {
    match (site, post) {
        (Site::Review, false) => REVIEW_FILES.contains(&path) || path == "/api/session",
        (Site::Review, true) => REVIEW_POSTS.contains(&path),
        (Site::Workspace, false) => {
            !REVIEW_FILES.contains(&path) || WORKSPACE_FILES.contains(&path)
        }
        (Site::Workspace, true) => !REVIEW_POSTS.contains(&path),
    }
}
/// The pages, each a separate document. The review and passkey set-up pages
/// load only their own script, the shared modules and base.css: never the
/// workspace's app.js or app.css (docs/TCB.md).
const PAGES: [(&str, &[u8], &str); 10] = [
    ("/", include_bytes!("../../../app/index.html"), HTML),
    ("/review", include_bytes!("../../../app/review.html"), HTML),
    ("/setup", include_bytes!("../../../app/setup.html"), HTML),
    ("/app.js", include_bytes!("../../../app/app.js"), JS),
    ("/review.js", include_bytes!("../../../app/review.js"), JS),
    ("/setup.js", include_bytes!("../../../app/setup.js"), JS),
    ("/common.js", include_bytes!("../../../app/common.js"), JS),
    (
        "/approval.js",
        include_bytes!("../../../app/approval.js"),
        JS,
    ),
    ("/base.css", include_bytes!("../../../app/base.css"), CSS),
    ("/app.css", include_bytes!("../../../app/app.css"), CSS),
];
const HTML: &str = "text/html; charset=utf-8";
const JS: &str = "text/javascript; charset=utf-8";
const CSS: &str = "text/css; charset=utf-8";
/// Every page runs only its own origin's files from this table.
const CSP: &str = "default-src 'self'; script-src 'self'; style-src 'self'; worker-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'";
// TCB:end
const INVALID: &str =
    "Request or review no longer valid. Refresh and review the exact action again.";
/// The trust lasts one day on a local home. Under an expired trust the gate
/// signs nothing and the receiver admits nothing, so say so plainly.
const EXPIRED: &str =
    "The trust configuration expired. Select Renew trust in the workspace, then try again.";
const NEEDS_TRUST: [&str; 6] = [
    "/api/review",
    "/api/approve",
    "/api/approve/passkey",
    "/api/commit",
    "/api/recover",
    "/api/paging",
];
const INTERRUPTED: &str =
    "Operation interrupted. Retry the same approved action to recover its outcome; do not create a replacement approval.";

struct Review {
    id: String,
    bound: String,
    at: Instant,
}

struct Owner {
    home: PathBuf,
    token: String,
    csrf: String,
    /// The review origin, which is the passkey's origin.
    origin: String,
    workspace: String,
    reviews: HashMap<String, Review>,
    assertions: HashMap<String, Review>,
    registration: Option<(String, Instant)>,
}

/// `Err((status, message))` goes to the browser as `{"error": message}`.
type Reply = std::result::Result<Value, (u16, String)>;

fn invalid<E>(_: E) -> (u16, String) {
    (409, INVALID.into())
}

/// Constant-time equality for secrets.
fn same_secret(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

fn token() -> String {
    random_hex() + &random_hex()
}

fn b64(raw: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(raw)
}

/// Strict base64url without padding, as browsers produce it.
fn unb64(text: &str, limit: usize) -> Result<Vec<u8>> {
    if text.is_empty()
        || !text
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err("base64url required".into());
    }
    let raw = URL_SAFE_NO_PAD.decode(text)?;
    if b64(&raw) != text || raw.is_empty() || raw.len() > limit {
        return Err("noncanonical or oversized base64url".into());
    }
    Ok(raw)
}

fn random_bytes<const N: usize>() -> [u8; N] {
    use rand_core::{OsRng, RngCore};
    let mut b = [0u8; N];
    OsRng.fill_bytes(&mut b);
    b
}

impl Owner {
    fn trust(&self) -> Result<Value> {
        read_json(self.home.join("trust.json"))
    }

    /// The installed owner passkey and the stored credential id, if any.
    fn passkey(&self) -> Result<(Option<Value>, Option<String>)> {
        let configured = self.trust()?.get("owner_passkey").cloned();
        let mut credential = None;
        if let Some(c) = &configured {
            if let Ok(stored) = read_json(self.home.join("passkey.json")) {
                if stored["public_key"] == c["public_key"] {
                    credential = stored["credential_id"].as_str().map(String::from);
                }
            }
        }
        Ok((configured, credential))
    }

    /// When the installed trust expires, and whether it has.
    fn trust_expiry(&self) -> Option<(u64, bool)> {
        let at = self.trust().ok()?["expires_at"].as_u64()?;
        Some((at, now() > at))
    }

    fn localhost(&self) -> bool {
        self.origin.starts_with(&format!("http://{RP_ID}:"))
    }

    fn status(&self) -> Result<Value> {
        let h = &self.home;
        let listing = call(&["gate-list".into(), arg(h)], None)?;
        let mut items: Vec<Value> = vec![];
        for p in listing["proposals"].as_array().into_iter().flatten() {
            items.push(json!({"id": p["id"], "stage": "Awaiting approval",
                              "document": p["document"], "expected_version": p["expected_version"]}));
        }
        for a in listing["approved"].as_array().into_iter().flatten() {
            let mut item = json!({"id": a["id"], "stage": "Approved",
                                  "document": a["document"], "expected_version": a["expected_version"]});
            let staged = (|| -> Result<()> {
                let request = broker::approved_request(h, a["id"].as_str().ok_or("id")?)?;
                let r = broker::recover_receipt(h, &request)?;
                let expected = a["expected_version"].as_u64().ok_or("version")?;
                if !r.is_null() {
                    item["stage"] = json!("Committed");
                    item["document_version"] = r["payload"]["document_version"].clone();
                } else if broker::current_version(h, a["document"].as_str().ok_or("document")?)
                    .is_some_and(|v| v > expected)
                {
                    // The document moved on after this approval; the receiver
                    // will refuse it, so Execute is not offered.
                    item["stage"] = json!("Superseded");
                } else if now() > a["expires_at"].as_u64().ok_or("expiry")? {
                    item["stage"] = json!("Approval expired");
                }
                Ok(())
            })();
            if staged.is_err() {
                item["stage"] = json!("Needs recovery");
            }
            items.push(item);
        }
        let mut saved = vec![];
        if let Ok(dir) = std::fs::read_dir(h.join("evidence")) {
            for e in dir.flatten() {
                let path = e.path().join("assessment.json");
                if let Ok(m) = std::fs::metadata(&path) {
                    saved.push((m.modified()?, e.path()));
                }
            }
        }
        saved.sort();
        let mut known = vec![];
        for (_, dir) in saved {
            let (Ok(a), Ok(cp)) = (
                read_json(dir.join("assessment.json")),
                read_json(dir.join("checkpoint.json")),
            ) else {
                continue;
            };
            known.extend(a["document"].as_str().map(String::from));
            let age = now() as i64 - cp["payload"]["observed_at"].as_i64().unwrap_or(0);
            if a["verification_status"] != "local_consistency_verified" {
                continue;
            }
            if let Some(item) = items.iter_mut().find(|i| i["id"] == a["proposal_id"]) {
                item["stage"] = json!(if (0..=300).contains(&age) {
                    "Verified locally"
                } else {
                    "Evidence needs refresh"
                });
                item["evidence_id"] =
                    json!(dir.file_name().map(|n| n.to_string_lossy().into_owned()));
                item["complete_history"] =
                    a.get("complete_history").cloned().unwrap_or(json!(false));
                item["assessment_recorded"] = json!(true);
            }
        }
        // Names for the proposal form: documents this home has acted on.
        let mut documents: Vec<String> = items
            .iter()
            .filter_map(|i| i["document"].as_str().map(String::from))
            .chain(known)
            .collect();
        documents.sort();
        documents.dedup();
        let (configured, _) = self.passkey()?;
        Ok(json!({
            "documents": documents,
            "published": broker::published(h),
            "rotation_resumable": false,
            "rotation_message": "",
            "items": items,
            "remote_services": h.join("service-client.json").exists(),
            "paging": h.join("paging.json").exists(),
            "paused": h.join("rotation-pending.json").exists(),
            "trust": {
                "expires_at": self.trust_expiry().map(|t| t.0),
                "expired": self.trust_expiry().is_some_and(|t| t.1),
            },
            "passkey": {
                "configured": configured.is_some(),
                "origin": configured.as_ref().map(|c| c["origin"].clone()).unwrap_or(json!(self.origin)),
                "available": self.localhost(),
            },
            "scope": "Local receiver database; one host owner. Saved assessments are observations, not a fresh independent audit."
        }))
    }

    fn recovery(&self) -> Result<Value> {
        let h = &self.home;
        let _l = broker::lock(h)?;
        let paused = h.join("rotation-pending.json").exists();
        let mut items = vec![];
        for entry in call(&["gate-list".into(), arg(h)], None)?["approved"]
            .as_array()
            .into_iter()
            .flatten()
        {
            let mut item = json!({"id": entry["id"], "can_recover": false, "status": "unconfirmed",
                "message": "State could not be read. Preserve the original approval and inspect the operator logs."});
            let _ = (|| -> Result<()> {
                let q = broker::approved_request(h, entry["id"].as_str().ok_or("id")?)?;
                let receipt = broker::recover_receipt(h, &q)?;
                item["document"] = q["approval"]["payload"]["document"].clone();
                if !receipt.is_null() {
                    item["status"] = json!("committed");
                    item["document_version"] = receipt["payload"]["document_version"].clone();
                    item["can_recover"] = json!(!paused);
                    item["message"] = json!("A durable receipt exists. Recovery refreshes witness/evidence state without creating a new document update.");
                } else if now()
                    > q["approval"]["payload"]["expires_at"]
                        .as_u64()
                        .ok_or("expiry")?
                {
                    item["status"] = json!("expired_uncommitted");
                    item["message"] = json!("No durable receipt was found. Review a new proposal separately; recovery cannot execute it.");
                } else {
                    item["status"] = json!("approved_uncommitted");
                    item["message"] = json!("No durable receipt was found. Execution is a separate owner decision in Activity.");
                }
                Ok(())
            })();
            items.push(item);
        }
        let mut heads = json!({});
        for role in ROLES {
            heads[role] = call(&["head".into(), arg(h.join(role).join("state"))], None)
                .map(|v| v["count"].clone())
                .unwrap_or(Value::Null);
        }
        let mut latest: Option<i64> = None;
        if let Ok(dir) = std::fs::read_dir(h.join("evidence")) {
            for e in dir.flatten() {
                if let Ok(cp) = read_json(e.path().join("checkpoint.json")) {
                    if let Some(t) = cp["payload"]["observed_at"].as_i64() {
                        latest = Some(latest.map_or(t, |l| l.max(t)));
                    }
                }
            }
        }
        let age = latest.map(|l| now() as i64 - l);
        let services = h.join("service-client.json").exists();
        Ok(json!({
            "items": items,
            "rotation": {"status": if paused { "paused" } else { "not_paused" }, "can_resume": false,
                         "message": if paused { "Admission paused for key handover." } else { "" }},
            "heads": heads,
            "evidence": {
                "last_recorded_at": latest,
                "age_seconds": age,
                "status": match age { None => "none", Some(a) if !(0..=300).contains(&a) => "needs_refresh", _ => "recent_record_only" },
                "scope": "Saved checkpoint age is not a fresh verification or proof that no newer event exists."
            },
            "services": if services { "separate_accounts" } else { "same_account" },
            "scope": "Read-only observations of configured role state. No trust reset, automatic approval or execution."
        }))
    }

    fn propose(&self, v: &Value) -> Reply {
        let m = fields(v, &["document", "expected_version", "content"], &[]).map_err(invalid)?;
        let document = text(m, "document").map_err(invalid)?;
        let expected = integer(m, "expected_version").map_err(invalid)?;
        let content = text(m, "content").map_err(invalid)?;
        // A settings file that is not a JSON object can stop the program that
        // reads it. A help for the owner, not a check that anything relies on.
        if (document.ends_with("settings") || document.ends_with("json"))
            && !serde_json::from_str::<Value>(content).is_ok_and(|v| v.is_object())
        {
            return Err((400, format!(
                "{document} must be a JSON object, because its name ends in \"settings\" or \"json\". Correct the text, or use another document name."
            )));
        }
        if let Some(current) = broker::current_version(&self.home, document) {
            if current != expected {
                return Err((409, format!(
                    "{document} is at version {current}. Propose against version {current}, or use a new document name."
                )));
            }
        }
        broker::propose(&self.home, v).map_err(invalid)
    }

    fn review(&mut self, id: &str) -> Result<Value> {
        let mut r = broker::review(&self.home, id)?;
        // What the change replaces, for display. The review binding and the
        // approval cover only the proposal, never this text.
        r["current"] = match r["proposal"]["document"]
            .as_str()
            .and_then(|d| broker::current_document(&self.home, d))
        {
            Some(Some((version, content))) => json!({"version": version, "content": content}),
            Some(None) => json!({"version": 0, "content": null}),
            None => Value::Null,
        };
        self.reviews.retain(|_, v| v.at.elapsed() < TOKEN_LIFE);
        if self.reviews.len() >= 100 {
            return Err("Too many outstanding reviews".into());
        }
        let t = token();
        let bound = r["review_sha256"]
            .as_str()
            .ok_or("review binding")?
            .to_string();
        self.reviews.insert(
            t.clone(),
            Review {
                id: id.into(),
                bound,
                at: Instant::now(),
            },
        );
        r["review_token"] = json!(t);
        Ok(r)
    }

    fn repropose(&self, id: &str) -> Result<Value> {
        let p = {
            let _l = broker::lock(&self.home)?;
            broker::admission(&self.home)?;
            let q = broker::approved_request(&self.home, id)?;
            let payload = &q["approval"]["payload"];
            if now() <= payload["expires_at"].as_u64().ok_or("expiry")? {
                return Err("Approval still active".into());
            }
            if !broker::recover_receipt(&self.home, &q)?.is_null() {
                return Err("Recover the committed request instead".into());
            }
            json!({"document": payload["document"], "expected_version": payload["expected_version"],
                   "content": q["content"]})
        };
        // The exact expected-version binding prevents a second update if the
        // original commits after this read. A new approval still needs review.
        broker::propose(&self.home, &p)
    }

    fn approve(&mut self, id: &str, review_token: &str) -> Result<Value> {
        let review = self
            .reviews
            .remove(review_token)
            .filter(|r| r.id == id && r.at.elapsed() <= TOKEN_LIFE)
            .ok_or("Review expired; review the action again")?;
        let r = {
            let _l = broker::lock(&self.home)?;
            broker::admission(&self.home)?;
            // The gate refuses unless the stored proposal still has the reviewed
            // binding. With an owner passkey it keeps the approval pending.
            call(
                &[
                    "gate-approve".into(),
                    arg(&self.home),
                    arg(self.home.join("trust.json")),
                    id.into(),
                    review.bound,
                ],
                None,
            )?
        };
        if r["state"] == "approved" {
            return Ok(json!({"status": "approved", "id": id}));
        }
        self.assertions.retain(|_, v| v.at.elapsed() < TOKEN_LIFE);
        if self.assertions.len() >= 100 {
            return Err("Too many outstanding passkey approvals".into());
        }
        let t = token();
        let digest = r["approval_sha256"]
            .as_str()
            .ok_or("approval digest")?
            .to_string();
        self.assertions.insert(
            t.clone(),
            Review {
                id: id.into(),
                bound: digest,
                at: Instant::now(),
            },
        );
        // No challenge is sent: the review page checks `approval` against the
        // content it shows and derives the passkey challenge from it itself.
        Ok(
            json!({"status": "passkey_required", "id": id, "assertion_token": t,
                  "approval": r["approval"], "approval_sha256": r["approval_sha256"],
                  "rp_id": r["rp_id"], "credential_id": self.passkey()?.1}),
        )
    }

    fn approve_passkey(
        &mut self,
        id: &str,
        assertion_token: &str,
        assertion: &Value,
    ) -> Result<Value> {
        let pending = self
            .assertions
            .remove(assertion_token)
            .filter(|r| r.id == id && r.at.elapsed() <= TOKEN_LIFE)
            .ok_or("Passkey approval expired; review the action again")?;
        let _l = broker::lock(&self.home)?;
        broker::admission(&self.home)?;
        // The gate verifies the assertion against the pending approval's digest
        // and stores it as approved, once.
        call(
            &[
                "gate-approve-passkey".into(),
                arg(&self.home),
                arg(self.home.join("trust.json")),
                id.into(),
                pending.bound,
            ],
            Some(assertion),
        )?;
        Ok(json!({"status": "approved", "id": id}))
    }

    fn register_begin(&mut self) -> Result<Value> {
        {
            let _l = broker::lock(&self.home)?;
            broker::admission(&self.home)?;
        }
        if self.passkey()?.0.is_some() {
            return Err("An owner passkey is already set up".into());
        }
        if !self.localhost() {
            return Err("Passkeys need the localhost origin".into());
        }
        let challenge = b64(&random_bytes::<32>());
        self.registration = Some((challenge.clone(), Instant::now()));
        Ok(json!({"challenge": challenge, "rp_id": RP_ID,
                  "user_id": b64(&random_bytes::<16>()), "user_name": "owner"}))
    }

    fn register_finish(&mut self, v: &Value) -> Result<Value> {
        let m = fields(
            v,
            &[
                "credential_id",
                "client_data_json",
                "authenticator_data",
                "public_key",
                "algorithm",
            ],
            &[],
        )?;
        let (challenge, at) = self
            .registration
            .take()
            .ok_or("Passkey setup expired; start again")?;
        if at.elapsed() > TOKEN_LIFE {
            return Err("Passkey setup expired; start again".into());
        }
        if m["algorithm"] != -7 {
            return Err("Passkey must use ES256".into());
        }
        let data = strict_json(&unb64(text(m, "client_data_json")?, 2048)?)?;
        let d = data.as_object().ok_or("client data")?;
        if d.get("type") != Some(&json!("webauthn.create"))
            || d.get("challenge") != Some(&json!(challenge))
        {
            return Err("passkey challenge rejected".into());
        }
        if d.get("origin") != Some(&json!(self.origin))
            || d.get("crossOrigin").is_some_and(|c| c != &json!(false))
        {
            return Err("passkey origin rejected".into());
        }
        let auth = unb64(text(m, "authenticator_data")?, 1024)?;
        if auth.len() < 37 || auth[..32] != Sha256::digest(RP_ID.as_bytes())[..] {
            return Err("Passkey relying party rejected".into());
        }
        if auth[32] & 0x05 != 0x05 {
            return Err("Passkey user verification required".into());
        }
        let credential = text(m, "credential_id")?;
        unb64(credential, 1023)?;
        use p256::elliptic_curve::sec1::ToSec1Point;
        use p256::pkcs8::DecodePublicKey;
        let key = p256::PublicKey::from_public_key_der(&unb64(text(m, "public_key")?, 1024)?)
            .map_err(|_| "passkey must be ECDSA P-256")?;
        let point = hex::encode(key.to_sec1_point(false).as_bytes());
        let result = broker::enroll_passkey(&self.home, &point, RP_ID, &self.origin)?;
        replace_json(
            self.home.join("passkey.json"),
            &json!({"credential_id": credential, "public_key": point}),
        )?;
        Ok(json!({"status": "passkey_installed", "installed_epoch": result["installed_epoch"]}))
    }

    fn archive(&self) -> Result<Value> {
        let folder = self.home.join("exports");
        if !folder.exists() {
            std::fs::create_dir(&folder)?;
        }
        let zips = std::fs::read_dir(&folder)?
            .flatten()
            .filter(|e| e.path().extension().is_some_and(|x| x == "zip"))
            .count();
        if zips >= 20 {
            return Err("Export capacity; archive existing exports first".into());
        }
        let id = random_hex();
        let directory = folder.join(&id);
        broker::export_history(&self.home, &directory)?;
        let mut files = vec![];
        let mut names: Vec<_> = std::fs::read_dir(&directory)?
            .flatten()
            .map(|e| e.path())
            .collect();
        names.sort();
        for p in names {
            if p.is_file() {
                files.push((
                    p.file_name().ok_or("name")?.to_string_lossy().into_owned(),
                    std::fs::read(&p)?,
                ));
            }
        }
        openproof_witness::files::write_new(
            &folder.join(format!("{id}.zip")),
            &crate::zip::store(&files)?,
        )?;
        Ok(json!({"download": format!("/api/download/{id}"), "trust_root_included": false}))
    }

    fn authenticated(&self, r: &Request) -> bool {
        r.header("Cookie").is_some_and(|c| {
            c.split(';')
                .filter_map(|p| p.trim().strip_prefix("openproof_owner="))
                .any(|v| same_secret(v, &self.token))
        })
    }

    fn site_origin(&self, site: Site) -> &str {
        match site {
            Site::Review => &self.origin,
            Site::Workspace => &self.workspace,
        }
    }

    fn host_ok(&self, r: &Request, site: Site) -> bool {
        r.header("Host") == self.site_origin(site).strip_prefix("http://")
    }

    fn session(&self) -> Value {
        json!({"csrf": self.csrf, "review": self.origin, "workspace": self.workspace})
    }

    fn get(&self, r: &Request) -> std::result::Result<(Vec<u8>, &'static str), (u16, String)> {
        // TCB:begin
        if let Some((_, body, kind)) = PAGES.iter().find(|(p, _, _)| *p == r.path) {
            return Ok((body.to_vec(), kind));
        }
        // TCB:end
        if !self.authenticated(r) {
            return Err((401, "Open this app using its local launcher".into()));
        }
        let failed = |_| {
            (
                409,
                "Local state could not be read. Retain evidence and inspect the owner logs."
                    .to_string(),
            )
        };
        let as_json = |v: Value| {
            (
                serde_json::to_vec(&v).unwrap_or_default(),
                "application/json",
            )
        };
        match r.path.as_str() {
            "/api/session" => Ok(as_json(self.session())),
            "/api/status" => self.status().map(as_json).map_err(failed),
            "/api/recovery" => self.recovery().map(as_json).map_err(failed),
            p => match p.strip_prefix("/api/download/") {
                Some(id)
                    if id.len() == 32
                        && id
                            .bytes()
                            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()) =>
                {
                    let path = self.home.join("exports").join(format!("{id}.zip"));
                    let m = std::fs::symlink_metadata(&path).map_err(|e| failed(e.into()))?;
                    if !m.is_file() || m.len() > 256 * 1024 * 1024 {
                        return Err(failed("archive bound".into()));
                    }
                    Ok((
                        std::fs::read(&path).map_err(|e| failed(e.into()))?,
                        "application/zip",
                    ))
                }
                _ => Err((404, "Unknown route".into())),
            },
        }
    }

    fn post(&mut self, r: &Request, site: Site) -> (Reply, bool) {
        if !self.host_ok(r, site) || r.header("Origin") != Some(self.site_origin(site)) {
            return (Err((403, "Origin rejected".into())), false);
        }
        if r.header("Content-Type") != Some("application/json")
            || r.body.is_empty()
            || r.body.len() > 32768
        {
            return (Err(invalid(())), false);
        }
        let Ok(v) = strict_json(&r.body) else {
            return (Err(invalid(())), false);
        };
        if r.path == "/api/session" {
            let ok = fields(&v, &["token"], &[])
                .ok()
                .and_then(|m| m["token"].as_str())
                .is_some_and(|t| same_secret(t, &self.token));
            return if ok {
                (Ok(self.session()), true)
            } else {
                (Err((403, "Session rejected".into())), false)
            };
        }
        if !self.authenticated(r)
            || !r
                .header("X-OpenProof-CSRF")
                .is_some_and(|c| same_secret(c, &self.csrf))
        {
            return (Err((403, "Owner session required".into())), false);
        }
        if NEEDS_TRUST.contains(&r.path.as_str()) && self.trust_expiry().is_some_and(|t| t.1) {
            return (Err((409, EXPIRED.into())), false);
        }
        let id = || -> std::result::Result<String, (u16, String)> {
            let m = fields(&v, &["id"], &[]).map_err(invalid)?;
            Ok(text(m, "id").map_err(invalid)?.to_string())
        };
        let interrupted = |_| (409, INTERRUPTED.to_string());
        let mut strip = |mut x: Value| {
            if let Some(m) = x.as_object_mut() {
                m.remove("evidence_directory");
            }
            x
        };
        let reply = match r.path.as_str() {
            "/api/propose" => self.propose(&v),
            "/api/current-version" => fields(&v, &["document"], &[])
                .and_then(|m| text(m, "document").map(String::from))
                .map_err(invalid)
                .map(|d| match broker::current_document(&self.home, &d) {
                    // The current text lets the owner edit it instead of typing it again.
                    Some(Some((version, content))) => {
                        json!({"document": d, "version": version, "content": content})
                    }
                    Some(None) => json!({"document": d, "version": 0, "content": null}),
                    None => json!({"document": d, "version": null, "content": null}),
                }),
            "/api/review" => id().and_then(|i| self.review(&i).map_err(invalid)),
            "/api/repropose" => id().and_then(|i| self.repropose(&i).map_err(invalid)),
            "/api/approve" => fields(&v, &["id", "review_token"], &[])
                .and_then(|m| {
                    Ok((
                        text(m, "id")?.to_string(),
                        text(m, "review_token")?.to_string(),
                    ))
                })
                .map_err(invalid)
                .and_then(|(i, t)| self.approve(&i, &t).map_err(invalid)),
            "/api/approve/passkey" => fields(&v, &["id", "assertion_token", "assertion"], &[])
                .and_then(|m| {
                    Ok((
                        text(m, "id")?.to_string(),
                        text(m, "assertion_token")?.to_string(),
                        m["assertion"].clone(),
                    ))
                })
                .map_err(invalid)
                .and_then(|(i, t, a)| self.approve_passkey(&i, &t, &a).map_err(invalid)),
            "/api/passkey/register/begin" => fields(&v, &[], &[])
                .map_err(invalid)
                .and_then(|_| self.register_begin().map_err(invalid)),
            "/api/passkey/register/finish" => self.register_finish(&v).map_err(invalid),
            "/api/commit" => id().and_then(|i| {
                broker::commit(&self.home, &i, false)
                    .map(&mut strip)
                    .map_err(interrupted)
            }),
            "/api/recover" => id().and_then(|i| {
                broker::commit(&self.home, &i, true)
                    .map(&mut strip)
                    .map_err(interrupted)
            }),
            "/api/paging" => fields(&v, &[], &[])
                .map_err(invalid)
                .and_then(|_| broker::enable_paging(&self.home).map_err(interrupted)),
            // A new one-day trust epoch, signed with the root key in this home
            // and installed in the receiver, the witness and the verifier. The
            // roles keep their keys and a pinned owner passkey unchanged.
            "/api/renew" => fields(&v, &[], &[]).map_err(invalid).and_then(|_| {
                broker::renew(&self.home).map_err(|_| {
                    (
                        409,
                        "The trust could not be renewed. Check that the receiver and the witness are running, then try again."
                            .to_string(),
                    )
                })
            }),
            "/api/archive" => fields(&v, &[], &[])
                .map_err(invalid)
                .and_then(|_| self.archive().map_err(interrupted)),
            _ => Err((404, "Unknown route".into())),
        };
        (reply, false)
    }

    fn handle(&mut self, stream: &mut TcpStream, r: Request, site: Site) -> Result<()> {
        let mut headers = vec![
            ("X-Content-Type-Options", "nosniff".to_string()),
            ("Referrer-Policy", "no-referrer".to_string()),
            ("Content-Security-Policy", CSP.to_string()),
            ("Cross-Origin-Opener-Policy", "same-origin".to_string()),
        ];
        let post = r.method == "POST";
        // TCB:begin
        let served = self.host_ok(&r, site) && serves(site, &r.path, post);
        // TCB:end
        let (code, kind, body) = if !self.host_ok(&r, site) {
            (
                403,
                "application/json",
                serde_json::to_vec(&json!({"error": "Host rejected"}))?,
            )
        } else if !served {
            (
                404,
                "application/json",
                serde_json::to_vec(&json!({"error": "Not served on this origin"}))?,
            )
        } else if r.method == "GET" {
            match self.get(&r) {
                Ok((body, kind)) => (200, kind, body),
                Err((code, e)) => (
                    code,
                    "application/json",
                    serde_json::to_vec(&json!({"error": e}))?,
                ),
            }
        } else if post {
            let (reply, cookie) = self.post(&r, site);
            if cookie {
                headers.push((
                    "Set-Cookie",
                    format!(
                        "openproof_owner={}; HttpOnly; SameSite=Strict; Path=/",
                        self.token
                    ),
                ));
            }
            match reply {
                Ok(v) => (200, "application/json", serde_json::to_vec(&v)?),
                Err((code, e)) => (
                    code,
                    "application/json",
                    serde_json::to_vec(&json!({"error": e}))?,
                ),
            }
        } else {
            (
                405,
                "application/json",
                serde_json::to_vec(&json!({"error": "Method not allowed"}))?,
            )
        };
        respond(stream, code, kind, &headers, &body)
    }
}

/// Bind loopback. A fixed port can stay in TIME_WAIT briefly after a restart;
/// wait for it instead of reusing the address.
fn bind(port: u16) -> Result<TcpListener> {
    for attempt in 0..120 {
        match TcpListener::bind(("127.0.0.1", port)) {
            Ok(l) => return Ok(l),
            Err(e) if port != 0 && e.kind() == std::io::ErrorKind::AddrInUse && attempt < 119 => {
                if attempt == 0 {
                    println!("Waiting for port {port} to be free…");
                }
                std::thread::sleep(Duration::from_secs(1));
            }
            Err(e) => return Err(e.into()),
        }
    }
    Err("port unavailable".into())
}

pub fn main(rest: &[&str]) -> Result<()> {
    let (mut home, mut port, mut open, mut session, mut demo) = (None, 0u16, false, None, false);
    let mut i = 0;
    while i < rest.len() {
        match rest[i] {
            "--home" => {
                i += 1;
                home = rest.get(i).map(PathBuf::from);
            }
            "--port" => {
                i += 1;
                port = rest.get(i).ok_or("missing port")?.parse()?;
            }
            "--session-file" => {
                i += 1;
                session = rest.get(i).map(PathBuf::from);
            }
            "--open" => open = true,
            "--demo" => demo = true,
            other => return Err(format!("unknown argument {other}").into()),
        }
        i += 1;
    }
    let home = home.ok_or("--home is required")?;
    if !home.exists() {
        broker::init_home(&home)?;
        broker::enable_paging(&broker::private_home(&home)?)?;
    }
    let home = broker::private_home(&home)?;
    let mut owner = Owner {
        home,
        token: token(),
        csrf: token(),
        origin: String::new(),
        workspace: String::new(),
        reviews: HashMap::new(),
        assertions: HashMap::new(),
        registration: None,
    };
    if let (Some(c), _) = owner.passkey()? {
        // The passkey is bound to its exact origin, so the port must not change.
        let origin = c["origin"].as_str().ok_or("passkey origin")?;
        let registered: u16 = origin.rsplit_once(':').ok_or("passkey origin")?.1.parse()?;
        if port != 0 && port != registered {
            return Err(format!(
                "The owner passkey is registered for {origin}; use --port {registered}"
            )
            .into());
        }
        port = registered;
    }
    // The review origin is the passkey's; the workspace gets its own port.
    let review = bind(port)?;
    let workspace = bind(0)?;
    // Bind loopback but advertise localhost: WebAuthn rejects IP addresses.
    owner.origin = format!("http://{RP_ID}:{}", review.local_addr()?.port());
    owner.workspace = format!("http://{RP_ID}:{}", workspace.local_addr()?.port());
    if demo
        && owner.status()?["items"]
            .as_array()
            .is_some_and(Vec::is_empty)
    {
        broker::propose(
            &owner.home,
            &json!({"document": "welcome-report", "expected_version": 0,
            "content": "Welcome to OpenProof. This public demonstration stores exactly this text in the local receiver database. Review, approve, and execute are separate decisions. No model was called."}),
        )?;
    }
    // The local trust lasts one day. Renew it at start when it has ended or
    // ends within two hours, as the Renew button does. The root key that signs
    // it is in this home, so this gives the owner's account nothing new.
    if owner
        .trust_expiry()
        .is_some_and(|(at, _)| at < now() + 2 * 3600)
        && broker::renew(&owner.home).is_ok()
    {
        println!("The local trust was renewed for one day.");
    }
    let url = format!("{}/#{}", owner.workspace, owner.token);
    if let Some(path) = session {
        save(
            &path,
            &json!({"url": url, "review_origin": owner.origin, "pid": std::process::id()}),
        )?;
    }
    if open {
        let opener = if cfg!(target_os = "macos") {
            "open"
        } else {
            "xdg-open"
        };
        let _ = std::process::Command::new(opener).arg(&url).spawn();
    }
    println!(
        "OpenProof owner app is running at {}, with reviews at {} (use --open to establish your owner session).",
        owner.workspace, owner.origin
    );
    // Read each request on its own thread, so an idle browser connection
    // cannot stall the app; handle requests one at a time under the lock.
    let owner = std::sync::Arc::new(std::sync::Mutex::new(owner));
    let open = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let reviews = {
        let (owner, open) = (owner.clone(), open.clone());
        std::thread::spawn(move || serve(review, Site::Review, owner, open))
    };
    serve(workspace, Site::Workspace, owner, open);
    let _ = reviews.join();
    Ok(())
}

fn serve(
    listener: TcpListener,
    site: Site,
    owner: std::sync::Arc<std::sync::Mutex<Owner>>,
    open: std::sync::Arc<std::sync::atomic::AtomicUsize>,
) {
    for stream in listener.incoming() {
        let Ok(mut stream) = stream else { continue };
        if open.load(std::sync::atomic::Ordering::SeqCst) >= 32 {
            continue;
        }
        open.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let (owner, open) = (owner.clone(), open.clone());
        std::thread::spawn(move || {
            let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
            let _ = stream.set_write_timeout(Some(Duration::from_secs(30)));
            if let Ok(r) = read_request(&mut stream, 32768) {
                if let Ok(mut o) = owner.lock() {
                    let _ = o.handle(&mut stream, r, site);
                }
            }
            open.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn base64url_is_strict() {
        assert_eq!(unb64(&b64(b"\xff\xfe"), 2).unwrap(), b"\xff\xfe");
        for bad in ["", "a", "ab==", "a+b/", "_x", "ab c"] {
            assert!(unb64(bad, 64).is_err(), "{bad}");
        }
        assert!(unb64(&b64(b"xxx"), 2).is_err());
    }
}
