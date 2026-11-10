//! Owner-side client for the role services (docs/LOCAL-ROLES.md). Only an owner
//! home that contains `service-client.json` sends role commands to services.
//! Callers cannot choose destinations or operations beyond the fixed mapping
//! below. This code is not trusted for any guarantee: the receiver checks every
//! request it is sent (docs/TCB.md).
use openproof_witness::Result;
use serde_json::{json, Value};
use std::{
    io::{Read, Write},
    path::Path,
    time::Duration,
};

/// The owner home and role for a role command whose state is `HOME/ROLE/state`
/// in a home with a service client configuration.
fn target<'a>(a: &[&'a str]) -> Option<(&'a Path, &'static str)> {
    if a.len() < 2 {
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
        _ => return Err("Role administration must be performed by that role's operator".into()),
    };
    post(home, role, op, &body).map(Some)
}

#[cfg(unix)]
fn post(home: &Path, role: &str, op: &str, body: &Value) -> Result<Value> {
    use std::os::unix::net::UnixStream;
    let config = crate::http::strict_json(&std::fs::read(home.join("service-client.json"))?)?;
    let m = crate::http::fields(&config, &["version", "receiver", "witness"], &[])?;
    if m["version"] != "openproof-service-client/2" {
        return Err(
            "This home names role services from an earlier version. Reinstall them (docs/LOCAL-ROLES.md)."
                .into(),
        );
    }
    let t = crate::http::fields(&m[role], &["socket"], &[])?;
    let socket = Path::new(crate::http::text(t, "socket")?);
    if !socket.is_absolute() {
        return Err("The role service socket must be an absolute path".into());
    }
    let mut stream = UnixStream::connect(socket)?;
    stream.set_read_timeout(Some(Duration::from_secs(20)))?;
    stream.set_write_timeout(Some(Duration::from_secs(20)))?;
    let raw = serde_json::to_vec(body)?;
    write!(
        stream,
        "POST /v1/{op} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        raw.len()
    )?;
    stream.write_all(&raw)?;
    stream.flush()?;
    let mut response = Vec::new();
    Read::take(&mut stream, 1_200_000).read_to_end(&mut response)?;
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

#[cfg(not(unix))]
fn post(_: &Path, _: &str, _: &str, _: &Value) -> Result<Value> {
    Err("Role services need Unix sockets".into())
}
