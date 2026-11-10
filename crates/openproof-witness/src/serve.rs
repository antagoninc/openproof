//! Bounded mTLS role service. One request per connection, served in order.
//! Clients are allowlisted by certificate fingerprint after CA verification.
//! Administrative commands stay with the role's operator, except an opt-in
//! install of a root-signed trust epoch that keeps the role keys.
use crate::http::{fields, integer, respond, strict_json, text};
use crate::{arg, call};
use openproof_witness::Result;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{net::TcpListener, path::PathBuf, sync::Arc, time::Duration};

struct Role {
    role: String,
    state: PathBuf,
    key: PathBuf,
    trust: PathBuf,
    signed_trust: PathBuf,
    clients: Vec<String>,
    accept_trust_updates: bool,
}

/// `Err((status, body))` is sent to the client as is.
type Reply = std::result::Result<Value, (u16, Value)>;

fn bad() -> (u16, Value) {
    (400, json!({"error": "invalid_operation"}))
}

fn unconfirmed() -> (u16, Value) {
    (
        409,
        json!({"error": "operation_unconfirmed",
               "recovery": "Read the durable receipt for this exact request before retrying or reporting failure."}),
    )
}

pub fn main(rest: &[&str]) -> Result<()> {
    let mut flags = std::collections::BTreeMap::<&str, Vec<&str>>::new();
    let mut accept = false;
    let mut i = 0;
    while i < rest.len() {
        match rest[i] {
            "--accept-trust-updates" => accept = true,
            name @ ("--role"
            | "--state"
            | "--key"
            | "--trust"
            | "--signed-trust"
            | "--cert"
            | "--tls-key"
            | "--ca"
            | "--client-fingerprint"
            | "--bind"
            | "--port") => {
                i += 1;
                flags
                    .entry(name)
                    .or_default()
                    .push(rest.get(i).ok_or("missing value")?);
            }
            other => return Err(format!("unknown argument {other}").into()),
        }
        i += 1;
    }
    let one = |n: &str| -> Result<&str> {
        match flags.get(n).map(Vec::as_slice) {
            Some([v]) => Ok(v),
            _ => Err(format!("give {n} once").into()),
        }
    };
    let role = one("--role")?;
    if !["receiver", "witness"].contains(&role) {
        return Err("role must be receiver or witness".into());
    }
    let clients: Vec<String> = flags
        .get("--client-fingerprint")
        .map(|v| v.iter().map(|s| s.to_string()).collect())
        .unwrap_or_default();
    if clients.is_empty()
        || clients.len() > 100
        || clients.iter().any(|c| {
            c.len() != 64
                || !c
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        })
    {
        return Err("Explicit unique client fingerprints required".into());
    }
    let s = Role {
        role: role.into(),
        state: one("--state")?.into(),
        key: one("--key")?.into(),
        trust: one("--trust")?.into(),
        signed_trust: one("--signed-trust")?.into(),
        clients,
        accept_trust_updates: accept,
    };
    crate::transport::local_only();
    // The plain trust this role uses must be exactly the root-authenticated one.
    let root = call(&["role-status".into(), arg(&s.state)], None)?["root"]
        .as_str()
        .ok_or("Provision a pinned role root before serving")?
        .to_string();
    let expected = call(
        &["trust-payload".into(), root],
        Some(&strict_json(&std::fs::read(&s.signed_trust)?)?),
    )?;
    if strict_json(&std::fs::read(&s.trust)?)? != expected {
        return Err("Plain trust differs from authenticated trust".into());
    }
    let mut roots = rustls::RootCertStore::empty();
    for c in crate::transport::certificates(one("--ca")?)? {
        roots.add(c)?;
    }
    let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
        Arc::new(roots),
        crate::transport::provider(),
    )
    .build()?;
    let config = Arc::new(
        rustls::ServerConfig::builder_with_provider(crate::transport::provider())
            .with_protocol_versions(&[&rustls::version::TLS13])?
            .with_client_cert_verifier(verifier)
            .with_single_cert(
                crate::transport::certificates(one("--cert")?)?,
                crate::transport::private_key(one("--tls-key")?)?,
            )?,
    );
    let bind = flags
        .get("--bind")
        .and_then(|v| v.first())
        .copied()
        .unwrap_or("127.0.0.1");
    let port: u16 = one("--port")?.parse()?;
    let listener = TcpListener::bind((bind, port))?;
    println!(
        "Authenticated {} service listening on {}:{}",
        s.role,
        bind,
        listener.local_addr()?.port()
    );
    // Handshake and read on a thread per connection, so an idle client cannot
    // stall the service; run commands one at a time under the lock.
    let s = std::sync::Arc::new(std::sync::Mutex::new(s));
    let open = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    for tcp in listener.incoming() {
        let Ok(tcp) = tcp else { continue };
        if open.load(std::sync::atomic::Ordering::SeqCst) >= 32 {
            continue;
        }
        open.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let (s, open, config) = (s.clone(), open.clone(), config.clone());
        std::thread::spawn(move || {
            let _ = connection(&s, tcp, config);
            open.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
        });
    }
    Ok(())
}

fn connection(
    s: &std::sync::Mutex<Role>,
    tcp: std::net::TcpStream,
    config: Arc<rustls::ServerConfig>,
) -> Result<()> {
    {
        let _ = tcp.set_read_timeout(Some(Duration::from_secs(5)));
        let _ = tcp.set_write_timeout(Some(Duration::from_secs(5)));
        let conn = rustls::ServerConnection::new(config)?;
        let mut tls = rustls::StreamOwned::new(conn, tcp);
        // A failed handshake or malformed request gets no reply.
        let request = crate::http::read_request(&mut tls, 1_048_576)?;
        let s = s.lock().map_err(|_| "lock")?;
        let fingerprint = tls
            .conn
            .peer_certificates()
            .and_then(|c| c.first())
            .map(|c| hex::encode(Sha256::digest(c.as_ref())));
        let reply: Reply = if request.method != "POST" {
            Err((405, json!({"error": "post_required"})))
        } else if !fingerprint.is_some_and(|f| s.clients.contains(&f)) {
            Err((403, json!({"error": "client_not_authorized"})))
        } else if request.header("Content-Type") != Some("application/json")
            || request.body.is_empty()
        {
            Err(bad())
        } else {
            match strict_json(&request.body) {
                Ok(v) => s.dispatch(&request.path, &v),
                Err(_) => Err(bad()),
            }
        };
        let (code, body) = match reply {
            Ok(v) => (200, v),
            Err(e) => e,
        };
        drop(s);
        let _ = respond(
            &mut tls,
            code,
            "application/json",
            &[],
            &serde_json::to_vec(&body)?,
        );
        tls.conn.send_close_notify();
        let _ = std::io::Write::flush(&mut tls);
    }
    Ok(())
}

impl Role {
    fn run(&self, args: &[String], value: Option<&Value>) -> Reply {
        call(args, value).map_err(|_| unconfirmed())
    }

    fn dispatch(&self, path: &str, v: &Value) -> Reply {
        let st = arg(&self.state);
        let shape = |required: &[&str]| fields(v, required, &[]).map_err(|_| bad());
        let receiver = self.role == "receiver";
        match path {
            "/v1/head" => {
                shape(&[])?;
                self.run(&["head".into(), st], None)
            }
            "/v1/status" => {
                shape(&[])?;
                self.run(&["role-status".into(), st], None)
            }
            "/v1/install-trust" => {
                let m = shape(&["signed"])?;
                self.install_trust(&m["signed"])
            }
            "/v1/document" if receiver => {
                let m = shape(&["document"])?;
                let id = text(m, "document").map_err(|_| bad())?;
                call(&["document".into(), st, id.into()], None).map_err(|e| {
                    if e.to_string().contains("no rows") {
                        (404, json!({"error": "document not found: no rows"}))
                    } else {
                        unconfirmed()
                    }
                })
            }
            "/v1/export" if receiver => {
                let m = shape(&["checkpoint"])?;
                self.run(
                    &["export".into(), st, arg(&self.trust)],
                    Some(&m["checkpoint"]),
                )
            }
            "/v1/page" if receiver => {
                let m = shape(&["start", "checkpoint"])?;
                let start = integer(m, "start").map_err(|_| bad())?;
                self.run(
                    &[
                        "export-page".into(),
                        st,
                        arg(&self.trust),
                        start.to_string(),
                    ],
                    Some(&m["checkpoint"]),
                )
            }
            "/v1/page-historical" if receiver => {
                // An allowlisted client may read history. The caller's historical
                // trust is used only for this read and is never installed.
                let m = shape(&["start", "checkpoint", "trust"])?;
                let start = integer(m, "start").map_err(|_| bad())?;
                let path = self.state.join(format!("history-{}.json", random_hex()));
                write_new(&path, &serde_json::to_vec(&m["trust"]).map_err(|_| bad())?)
                    .map_err(|_| unconfirmed())?;
                let r = self.run(
                    &[
                        "export-page-historical".into(),
                        st,
                        arg(&path),
                        start.to_string(),
                    ],
                    Some(&m["checkpoint"]),
                );
                let _ = std::fs::remove_file(&path);
                r
            }
            "/v1/receive" if receiver => {
                let m = shape(&["request"])?;
                self.run(
                    &["receive".into(), st, arg(&self.key), arg(&self.trust)],
                    Some(&m["request"]),
                )
            }
            "/v1/recover" if receiver => {
                let m = shape(&["request"])?;
                self.run(&["recover".into(), st], Some(&m["request"]))
            }
            "/v1/receipt" if receiver => {
                let m = shape(&["sequence"])?;
                let seq = integer(m, "sequence").map_err(|_| bad())?;
                self.run(&["receipt".into(), st, seq.to_string()], None)
            }
            "/v1/witness" if !receiver => {
                let m = shape(&["receipt"])?;
                self.run(
                    &["witness".into(), st, arg(&self.key), arg(&self.trust)],
                    Some(&m["receipt"]),
                )
            }
            "/v1/tlog-request" if !receiver => {
                let m = shape(&["origin", "old"])?;
                let origin = text(m, "origin").map_err(|_| bad())?;
                let old = integer(m, "old").map_err(|_| bad())?;
                self.run(
                    &[
                        "tlog-request".into(),
                        st,
                        arg(&self.key),
                        arg(&self.trust),
                        origin.into(),
                        old.to_string(),
                    ],
                    None,
                )
            }
            "/v1/tlog-inclusion" if !receiver => {
                let m = shape(&["sequence", "size"])?;
                let seq = integer(m, "sequence").map_err(|_| bad())?;
                let size = integer(m, "size").map_err(|_| bad())?;
                self.run(
                    &[
                        "tlog-inclusion".into(),
                        st,
                        seq.to_string(),
                        size.to_string(),
                    ],
                    None,
                )
            }
            "/v1/checkpoint" if !receiver => {
                shape(&[])?;
                self.run(
                    &["checkpoint".into(), st, arg(&self.key), arg(&self.trust)],
                    None,
                )
            }
            _ => Err(bad()),
        }
    }

    /// Install a root-signed trust epoch. The role state checks the root
    /// signature, refuses rollback and refuses to remove or replace a pinned
    /// owner passkey. This service also refuses a change of role keys.
    fn install_trust(&self, signed: &Value) -> Reply {
        if !self.accept_trust_updates {
            return Err((
                400,
                json!({"error": "Trust updates are not accepted by this operator"}),
            ));
        }
        let st = arg(&self.state);
        let root = self.run(&["role-status".into(), st.clone()], None)?["root"]
            .as_str()
            .ok_or_else(unconfirmed)?
            .to_string();
        let new = call(&["trust-payload".into(), root.clone()], Some(signed)).map_err(|_| bad())?;
        let old = std::fs::read(&self.trust)
            .ok()
            .and_then(|b| strict_json(&b).ok())
            .ok_or_else(unconfirmed)?;
        if new["receiver"] != old["receiver"] || new["witness"] != old["witness"] {
            return Err((400, json!({"error": "Role key change refused"})));
        }
        call(&["install-signed".into(), st, root], Some(signed)).map_err(|_| bad())?;
        for (path, data) in [(&self.signed_trust, signed), (&self.trust, &new)] {
            replace(path, &serde_json::to_vec(data).map_err(|_| unconfirmed())?)
                .map_err(|_| unconfirmed())?;
        }
        Ok(json!({"installed_epoch": new["epoch"]}))
    }
}

pub fn random_hex() -> String {
    use rand_core::{OsRng, RngCore};
    let mut b = [0u8; 16];
    OsRng.fill_bytes(&mut b);
    hex::encode(b)
}

/// Create a new private file; refuse to replace one.
pub fn write_new(path: &std::path::Path, data: &[u8]) -> Result<()> {
    use std::io::Write;
    let mut o = std::fs::OpenOptions::new();
    o.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600);
    }
    let mut f = o.open(path)?;
    f.write_all(data)?;
    f.sync_all()?;
    Ok(())
}

/// Replace a file atomically and make the rename durable.
pub fn replace(path: &std::path::Path, data: &[u8]) -> Result<()> {
    let name = path.file_name().ok_or("file name")?.to_string_lossy();
    let pending = path.with_file_name(format!(".{name}-{}", random_hex()));
    write_new(&pending, data)?;
    std::fs::rename(&pending, path)?;
    if let Some(parent) = path.parent() {
        std::fs::File::open(parent)?.sync_all()?;
    }
    Ok(())
}
