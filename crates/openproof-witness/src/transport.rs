//! Owner-side mTLS client for role services. Only an owner home that contains
//! `service-client.json` sends role commands to services. Callers cannot choose
//! destinations, certificates or operations beyond the fixed mapping below.
use openproof_witness::Result;
use rustls::pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer, ServerName};
use serde_json::{json, Value};
use std::{
    io::{Read, Write},
    net::{TcpStream, ToSocketAddrs},
    path::Path,
    sync::atomic::{AtomicBool, Ordering},
    sync::Arc,
    time::Duration,
};

/// Set by the role service, for all its threads, so its own commands never forward.
static LOCAL_ONLY: AtomicBool = AtomicBool::new(false);
pub fn local_only() {
    LOCAL_ONLY.store(true, Ordering::SeqCst);
}

/// The owner home and role for a role command whose state is `HOME/ROLE/state`
/// in a home with a service client configuration.
fn target<'a>(a: &[&'a str]) -> Option<(&'a Path, &'static str)> {
    if LOCAL_ONLY.load(Ordering::SeqCst) || a.len() < 2 {
        return None;
    }
    let state = Path::new(a[1]);
    let role = match state.parent()?.file_name()?.to_str()? {
        "receiver" => "receiver",
        "witness" => "witness",
        _ => return None,
    };
    let home = state.parent()?.parent()?;
    (state.file_name()? == "state" && home.join("service-client.json").exists())
        .then_some((home, role))
}

pub fn is_remote(a: &[&str]) -> bool {
    target(a).is_some()
}

/// Role commands that read a JSON value from standard input.
pub fn takes_input(a: &[&str]) -> bool {
    matches!(
        a.first(),
        Some(
            &("receive"
                | "recover"
                | "witness"
                | "export"
                | "export-page"
                | "export-page-historical"
                | "install-signed")
        )
    )
}

pub fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

pub fn certificates(path: &str) -> Result<Vec<CertificateDer<'static>>> {
    let certs = CertificateDer::pem_file_iter(path)?.collect::<std::result::Result<Vec<_>, _>>()?;
    if certs.is_empty() {
        return Err(format!("no certificate in {path}").into());
    }
    Ok(certs)
}

/// A private key that only its owner can read.
pub fn private_key(path: &str) -> Result<PrivateKeyDer<'static>> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let m = std::fs::symlink_metadata(path)?;
        if !m.is_file() || m.permissions().mode() & 0o077 != 0 {
            return Err("TLS key must be a private regular file".into());
        }
    }
    Ok(PrivateKeyDer::from_pem_file(path)?)
}

/// Send a role command to its service. `None` when the command stays local.
pub fn forward(a: &[&str], value: Option<&Value>) -> Result<Option<Value>> {
    let Some((home, role)) = target(a) else {
        return Ok(None);
    };
    let need = |v: Option<&Value>| v.cloned().ok_or("input required");
    let (op, body) = match a {
        ["head", _] => ("head", json!({})),
        ["role-status", _] => ("status", json!({})),
        ["receive", ..] => ("receive", json!({"request": need(value)?})),
        ["recover", _] => ("recover", json!({"request": need(value)?})),
        ["witness", ..] => ("witness", json!({"receipt": need(value)?})),
        ["checkpoint", ..] => ("checkpoint", json!({})),
        ["receipt", _, seq] => ("receipt", json!({"sequence": seq.parse::<u64>()?})),
        ["export", ..] => ("export", json!({"checkpoint": need(value)?})),
        ["export-page", _, _, start] => (
            "page",
            json!({"checkpoint": need(value)?, "start": start.parse::<u64>()?}),
        ),
        ["export-page-historical", _, trust, start] => (
            "page-historical",
            json!({
                "checkpoint": need(value)?,
                "start": start.parse::<u64>()?,
                "trust": crate::http::strict_json(&std::fs::read(trust)?)?,
            }),
        ),
        ["document", _, id] => ("document", json!({"document": id})),
        ["tlog-request", _, _, _, origin, old] => (
            "tlog-request",
            json!({"origin": origin, "old": old.parse::<u64>()?}),
        ),
        ["tlog-inclusion", _, seq, size] => (
            "tlog-inclusion",
            json!({"sequence": seq.parse::<u64>()?, "size": size.parse::<u64>()?}),
        ),
        // The service installs with its own pinned root, never a caller-selected one.
        ["install-signed", ..] => ("install-trust", json!({"signed": need(value)?})),
        _ => return Err("Remote role administration must be performed by that operator".into()),
    };
    post(home, role, op, &body).map(Some)
}

fn post(home: &Path, role: &str, op: &str, body: &Value) -> Result<Value> {
    let config = crate::http::strict_json(&std::fs::read(home.join("service-client.json"))?)?;
    let m = crate::http::fields(&config, &["version", "receiver", "witness"], &[])?;
    if m["version"] != "openproof-service-client/1" {
        return Err("Unknown service client version".into());
    }
    let t = crate::http::fields(&m[role], &["url", "ca", "cert", "key"], &[])?;
    let url = crate::http::text(t, "url")?;
    let authority = url
        .strip_prefix("https://")
        .map(|r| r.strip_suffix('/').unwrap_or(r))
        .filter(|r| !r.is_empty() && !r.contains(['/', '@', '?', '#']))
        .ok_or("Explicit HTTPS origin required")?;
    let (host, port) = authority.rsplit_once(':').ok_or("Explicit port required")?;
    let port: u16 = port.parse()?;
    let mut roots = rustls::RootCertStore::empty();
    for c in certificates(crate::http::text(t, "ca")?)? {
        roots.add(c)?;
    }
    let config = rustls::ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_root_certificates(roots)
        .with_client_auth_cert(
            certificates(crate::http::text(t, "cert")?)?,
            private_key(crate::http::text(t, "key")?)?,
        )?;
    let name = ServerName::try_from(host.to_string())?;
    let address = (host, port).to_socket_addrs()?.next().ok_or("no address")?;
    let tcp = TcpStream::connect_timeout(&address, Duration::from_secs(10))?;
    tcp.set_read_timeout(Some(Duration::from_secs(20)))?;
    tcp.set_write_timeout(Some(Duration::from_secs(20)))?;
    let conn = rustls::ClientConnection::new(Arc::new(config), name)?;
    let mut tls = rustls::StreamOwned::new(conn, tcp);
    let raw = serde_json::to_vec(body)?;
    write!(
        tls,
        "POST /v1/{op} HTTP/1.1\r\nHost: {authority}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        raw.len()
    )?;
    tls.write_all(&raw)?;
    tls.flush()?;
    let mut response = Vec::new();
    match Read::take(&mut tls, 1_200_000).read_to_end(&mut response) {
        Ok(_) => {}
        // A peer that closes without close_notify after a complete reply.
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof && !response.is_empty() => {}
        Err(e) => return Err(e.into()),
    }
    let split = response
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or("incomplete response")?;
    let head = std::str::from_utf8(&response[..split])?;
    let code: u16 = head.split(' ').nth(1).ok_or("bad status line")?.parse()?;
    let payload = &response[split + 4..];
    if code != 200 {
        return Err(format!(
            "{role} service {code}: {}",
            String::from_utf8_lossy(&payload[..payload.len().min(4096)])
        )
        .into());
    }
    serde_json::from_slice(payload).map_err(Into::into)
}
