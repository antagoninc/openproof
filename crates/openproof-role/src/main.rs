//! The role service: the receiver or the witness, run under its own account
//! (docs/LOCAL-ROLES.md). It answers one request per connection on a Unix
//! socket, only for the client accounts it was started with, and runs a fixed
//! set of operations. Every change still passes the receiver's own checks: an
//! approval from an active authority and, with an owner passkey in the trust,
//! a valid assertion over exactly that approval.
//!
//! This file, `openproof-receiver` and `openproof-core` are all the code the
//! service runs (docs/TCB.md).
#![deny(unsafe_code)]

#[cfg(unix)]
mod service {
    use openproof_core::{verify_signature, Signed};
    use openproof_receiver::http::{fields, integer, read_request, respond, strict_json, text};
    use openproof_receiver::{files, keys, publish, tlog, *};
    use serde_json::{json, Value};
    use std::os::unix::fs::{FileTypeExt, PermissionsExt};
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    const USAGE: &str = "usage: openproof-role serve --role receiver|witness --state DIR \
        --key FILE --trust FILE --signed-trust FILE --socket PATH --client-uid UID... \
        [--accept-trust-updates] [--publish DIR]";

    struct Role {
        receiver: bool,
        state: PathBuf,
        key: ed25519_dalek::SigningKey,
        trust: PathBuf,
        signed_trust: PathBuf,
        accept_trust_updates: bool,
        /// Protected files (docs/PROTECTED-FILES.md): the receiver's folder for them.
        publish: Option<PathBuf>,
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

    /// The result of an operation. Any failure is reported as unconfirmed.
    fn done<T: serde::Serialize>(r: Result<T>) -> Reply {
        r.and_then(|v| Ok(serde_json::to_value(v)?))
            .map_err(|_| unconfirmed())
    }

    /// A protocol value, parsed as strictly as the receiver's command input.
    fn parse<T: serde::de::DeserializeOwned + serde::Serialize>(v: &Value) -> Result<T> {
        Ok(openproof_core::parse(&serde_json::to_vec(v)?)?)
    }

    /// The account of the process at the other end of the socket.
    #[allow(unsafe_code)]
    fn peer_uid(s: &UnixStream) -> std::io::Result<u32> {
        use std::os::unix::io::AsRawFd;
        let fd = s.as_raw_fd();
        #[cfg(any(target_os = "linux", target_os = "android"))]
        {
            let mut cred = libc::ucred {
                pid: 0,
                uid: 0,
                gid: 0,
            };
            let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
            // SAFETY: `fd` is an open socket owned by `s` for this call, and
            // `cred` and `len` are valid for writes of the size passed.
            let r = unsafe {
                libc::getsockopt(
                    fd,
                    libc::SOL_SOCKET,
                    libc::SO_PEERCRED,
                    (&mut cred as *mut libc::ucred).cast(),
                    &mut len,
                )
            };
            if r != 0 {
                return Err(std::io::Error::last_os_error());
            }
            if len as usize != std::mem::size_of::<libc::ucred>() {
                return Err(std::io::Error::other("peer credentials"));
            }
            Ok(cred.uid)
        }
        #[cfg(not(any(target_os = "linux", target_os = "android")))]
        {
            let (mut uid, mut gid): (libc::uid_t, libc::gid_t) = (0, 0);
            // SAFETY: `fd` is an open socket owned by `s` for this call, and
            // `uid` and `gid` are valid for writes.
            if unsafe { libc::getpeereid(fd, &mut uid, &mut gid) } != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(uid)
        }
    }

    pub fn main(rest: &[String]) -> Result<()> {
        let mut flags = std::collections::BTreeMap::<&str, Vec<&str>>::new();
        let mut accept = false;
        let mut i = 0;
        while i < rest.len() {
            match rest[i].as_str() {
                "--accept-trust-updates" => accept = true,
                name @ ("--role" | "--state" | "--key" | "--trust" | "--signed-trust"
                | "--socket" | "--client-uid" | "--publish") => {
                    i += 1;
                    flags
                        .entry(name)
                        .or_default()
                        .push(rest.get(i).ok_or("missing value")?);
                }
                other => return Err(format!("unknown argument {other}\n{USAGE}").into()),
            }
            i += 1;
        }
        let one = |n: &str| -> Result<&str> {
            match flags.get(n).map(Vec::as_slice) {
                Some([v]) => Ok(v),
                _ => Err(format!("give {n} once\n{USAGE}").into()),
            }
        };
        let role = one("--role")?;
        if !["receiver", "witness"].contains(&role) {
            return Err("role must be receiver or witness".into());
        }
        let mut clients = vec![];
        for c in flags.get("--client-uid").into_iter().flatten() {
            let uid: u32 = c.parse().map_err(|_| "client uid must be a number")?;
            if clients.contains(&uid) {
                return Err("client uid given twice".into());
            }
            clients.push(uid);
        }
        if clients.is_empty() || clients.len() > 8 {
            return Err("give one to eight --client-uid accounts".into());
        }
        let state = PathBuf::from(one("--state")?);
        let publish = match flags.get("--publish").map(Vec::as_slice) {
            None => None,
            Some([dir]) if role == "receiver" => Some(PathBuf::from(dir)),
            Some(_) => return Err(format!("give --publish once, to the receiver\n{USAGE}").into()),
        };
        let s = Role {
            receiver: role == "receiver",
            key: keys::key(one("--key")?)?,
            trust: one("--trust")?.into(),
            signed_trust: one("--signed-trust")?.into(),
            accept_trust_updates: accept,
            state,
            publish,
        };
        // The plain trust this role uses must be exactly the root-authenticated one.
        let root = role_root(&s.state)?.ok_or("Provision a pinned role root before serving")?;
        let signed: Signed<Trust> = openproof_core::parse(&keys::read(&s.signed_trust)?)?;
        verify_signature(&signed, &root)?;
        if strict_json(&keys::read(&s.trust)?)? != serde_json::to_value(&signed.payload)? {
            return Err("Plain trust differs from authenticated trust".into());
        }
        // The protected files are written before a request is served. A folder
        // that fails its check stops the start; a single failed file does not.
        if let Some(dir) = &s.publish {
            publish::all(&s.state, dir)?;
        }
        let socket = PathBuf::from(one("--socket")?);
        let listener = listen(&socket)?;
        println!("{role} service listening on {}", socket.display());
        // Read on a thread per connection, so an idle client cannot stall the
        // service; run operations one at a time under the lock.
        let s = Arc::new(Mutex::new(s));
        let open = Arc::new(AtomicUsize::new(0));
        for stream in listener.incoming() {
            let Ok(stream) = stream else { continue };
            // Any other account is closed on before a byte is read or sent.
            if !peer_uid(&stream).is_ok_and(|u| clients.contains(&u)) {
                continue;
            }
            if open.load(SeqCst) >= 32 {
                continue;
            }
            open.fetch_add(1, SeqCst);
            let (s, open) = (s.clone(), open.clone());
            std::thread::spawn(move || {
                let _ = connection(&s, stream);
                open.fetch_sub(1, SeqCst);
            });
        }
        Ok(())
    }

    /// Bind the socket. A stale socket from an earlier run is replaced; any
    /// other file at the path is refused. The socket is open to every local
    /// account, and the peer check above admits only the listed ones.
    fn listen(socket: &Path) -> Result<UnixListener> {
        match std::fs::symlink_metadata(socket) {
            Ok(m) if m.file_type().is_socket() => std::fs::remove_file(socket)?,
            Ok(_) => return Err("the socket path exists and is not a socket".into()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
        let listener = UnixListener::bind(socket)?;
        std::fs::set_permissions(socket, std::fs::Permissions::from_mode(0o666))?;
        Ok(listener)
    }

    fn connection(s: &Mutex<Role>, mut stream: UnixStream) -> Result<()> {
        stream.set_read_timeout(Some(Duration::from_secs(5)))?;
        stream.set_write_timeout(Some(Duration::from_secs(5)))?;
        // A malformed request gets no reply.
        let request = read_request(&mut stream, 1_048_576)?;
        let s = s.lock().map_err(|_| "lock")?;
        let reply: Reply = if request.method != "POST" {
            Err((405, json!({"error": "post_required"})))
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
        drop(s);
        let (code, body) = match reply {
            Ok(v) => (200, v),
            Err(e) => e,
        };
        respond(
            &mut stream,
            code,
            "application/json",
            &[],
            &serde_json::to_vec(&body)?,
        )
    }

    impl Role {
        fn trust(&self) -> std::result::Result<Trust, (u16, Value)> {
            keys::trust(&self.trust).map_err(|_| unconfirmed())
        }

        fn dispatch(&self, path: &str, v: &Value) -> Reply {
            let st = &self.state;
            let shape = |required: &[&str]| fields(v, required, &[]).map_err(|_| bad());
            let number =
                |m: &serde_json::Map<String, Value>, k: &str| integer(m, k).map_err(|_| bad());
            let time = now();
            match (path, self.receiver) {
                ("/v1/head", _) => {
                    shape(&[])?;
                    done(head(st).map(|count| json!({"count": count})))
                }
                ("/v1/status", _) => {
                    // The trust this role admits under, from its own files: the
                    // check that an owner passkey is in force (docs/LOCAL-ROLES.md).
                    shape(&[])?;
                    let t = self.trust()?;
                    // The protected files are written again here. A document whose
                    // file does not have its content is named; `null` is a refused folder.
                    let published = self.publish.as_ref().map(
                        |dir| json!({"folder": dir, "not_published": publish::all(st, dir).ok()}),
                    );
                    done(role_root(st).map(|root| {
                        json!({"root": root, "epoch": t.epoch, "owner_passkey": t.owner_passkey,
                               "published": published})
                    }))
                }
                ("/v1/install-trust", _) => {
                    let m = shape(&["signed"])?;
                    self.install_trust(&m["signed"])
                }
                ("/v1/document", true) => {
                    let m = shape(&["document"])?;
                    let id = text(m, "document").map_err(|_| bad())?;
                    match document(st, id) {
                        Ok((version, content)) => {
                            Ok(json!({"version": version, "content": content}))
                        }
                        Err(e) if e.to_string().contains("no rows") => {
                            Err((404, json!({"error": "document not found: no rows"})))
                        }
                        Err(_) => Err(unconfirmed()),
                    }
                }
                ("/v1/export", true) => {
                    let m = shape(&["checkpoint"])?;
                    let t = self.trust()?;
                    done(parse(&m["checkpoint"]).and_then(|cp| export_verified(st, &t, cp, time)))
                }
                ("/v1/page", true) => {
                    let m = shape(&["start", "checkpoint"])?;
                    let start = number(m, "start")?;
                    let t = self.trust()?;
                    done(
                        parse(&m["checkpoint"]).and_then(|cp| export_page(st, &t, cp, start, time)),
                    )
                }
                ("/v1/page-historical", true) => {
                    // A client may read history under its historical trust. That
                    // trust is used only for this read and is never installed.
                    let m = shape(&["start", "checkpoint", "trust"])?;
                    let start = number(m, "start")?;
                    done((|| {
                        let t: Trust = parse(&m["trust"])?;
                        let cp: Signed<Checkpoint> = parse(&m["checkpoint"])?;
                        let at = cp.payload.observed_at;
                        export_page(st, &t, cp, start, at)
                    })())
                }
                ("/v1/receive", true) => {
                    let m = shape(&["request"])?;
                    let t = self.trust()?;
                    let r =
                        done(parse(&m["request"]).and_then(|q| apply(st, &q, &t, &self.key, time)));
                    // A change can be committed even when the reply is an error.
                    // A file that could not be written keeps its earlier version;
                    // `/v1/status` reports it and it is written again later.
                    if let Some(dir) = &self.publish {
                        let _ = publish::all(st, dir);
                    }
                    r
                }
                ("/v1/recover", true) => {
                    let m = shape(&["request"])?;
                    done(parse(&m["request"]).and_then(|q| recover(st, &q)))
                }
                ("/v1/receipt", true) => {
                    let m = shape(&["sequence"])?;
                    let seq = number(m, "sequence")?;
                    done(stored_receipt(st, seq))
                }
                ("/v1/witness", false) => {
                    let m = shape(&["receipt"])?;
                    let t = self.trust()?;
                    done(parse(&m["receipt"]).and_then(|r| witness(st, &r, &t, &self.key, time)))
                }
                ("/v1/tlog-request", false) => {
                    let m = shape(&["origin", "old"])?;
                    let origin = text(m, "origin").map_err(|_| bad())?;
                    let old = number(m, "old")?;
                    let t = self.trust()?;
                    done(
                        tlog::add_checkpoint_request(st, &t, &self.key, origin, old, time)
                            .map(|body| json!({"origin": origin, "request": body})),
                    )
                }
                ("/v1/tlog-inclusion", false) => {
                    use base64::{engine::general_purpose::STANDARD, Engine};
                    let m = shape(&["sequence", "size"])?;
                    let (seq, size) = (number(m, "sequence")?, number(m, "size")?);
                    done(tlog::event_inclusion(st, seq, size).map(|proof| {
                        json!({"proof": proof.iter().map(|h| STANDARD.encode(h)).collect::<Vec<_>>()})
                    }))
                }
                ("/v1/checkpoint", false) => {
                    shape(&[])?;
                    let t = self.trust()?;
                    done(current_checkpoint(st, &t, &self.key, time))
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
            let root = role_root(&self.state)
                .ok()
                .flatten()
                .ok_or_else(unconfirmed)?;
            let s: Signed<Trust> = parse(signed).map_err(|_| bad())?;
            verify_signature(&s, &root).map_err(|_| bad())?;
            let new = serde_json::to_value(&s.payload).map_err(|_| unconfirmed())?;
            let old = keys::read(&self.trust)
                .ok()
                .and_then(|b| strict_json(&b).ok())
                .ok_or_else(unconfirmed)?;
            if new["receiver"] != old["receiver"] || new["witness"] != old["witness"] {
                return Err((400, json!({"error": "Role key change refused"})));
            }
            role_install(&self.state, &s, &root, now()).map_err(|_| bad())?;
            for (path, data) in [(&self.signed_trust, signed), (&self.trust, &new)] {
                files::replace(path, &serde_json::to_vec(data).map_err(|_| unconfirmed())?)
                    .map_err(|_| unconfirmed())?;
            }
            Ok(json!({"installed_epoch": new["epoch"]}))
        }
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    #[cfg(unix)]
    let result = match args.split_first() {
        Some((command, rest)) if command == "serve" => service::main(rest),
        _ => Err("usage: openproof-role serve ...".into()),
    };
    #[cfg(not(unix))]
    let result: openproof_receiver::Result<()> = Err("Unix required".into());
    if let Err(e) = result {
        eprintln!("openproof-role: {e}");
        std::process::exit(1);
    }
}
