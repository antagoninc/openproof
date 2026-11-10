#![forbid(unsafe_code)]
//! The owner's binary: the owner app, the agent tools (MCP), the broker and
//! the in-process commands they use. Operator and test commands are in
//! `openproof-tool`; the role service is `openproof-role`. See docs/TCB.md.
use ed25519_dalek::SigningKey;
use openproof_core::parse;
use openproof_witness::keys::{key, read, trust};
use openproof_witness::*;
use rand_core::{OsRng, RngCore};
use serde::Serialize;
use std::{
    fs,
    io::{Read, Write},
    path::Path,
};
use zeroize::Zeroizing;
thread_local! {
    /// Input for an in-process command (role service, broker, owner app).
    /// When unset, commands read standard input as before.
    static INPUT: std::cell::RefCell<Option<Vec<u8>>> = const { std::cell::RefCell::new(None) };
}
fn input_bytes() -> Result<Vec<u8>> {
    if let Some(b) = INPUT.with(|i| i.borrow_mut().take()) {
        return Ok(b);
    }
    let mut b = vec![];
    std::io::stdin().take(1_048_577).read_to_end(&mut b)?;
    Ok(b)
}
fn input<T: serde::de::DeserializeOwned + Serialize>() -> Result<T> {
    Ok(parse(&input_bytes()?)?)
}
/// Run one command in this process, with `value` as its input. Role commands
/// on an owner home that names role services go to those services instead.
pub(crate) fn call(
    args: &[String],
    value: Option<&serde_json::Value>,
) -> Result<serde_json::Value> {
    let a = args.iter().map(String::as_str).collect::<Vec<_>>();
    if let Some(v) = transport::forward(&a, value)? {
        return Ok(v);
    }
    let bytes = match value {
        Some(v) => serde_json::to_vec(v)?,
        None => vec![],
    };
    INPUT.with(|i| *i.borrow_mut() = Some(bytes));
    let result = dispatch(&a);
    INPUT.with(|i| i.borrow_mut().take());
    result
}
/// Path argument helper for `call`.
pub(crate) fn arg(p: impl AsRef<Path>) -> String {
    p.as_ref().to_string_lossy().into_owned()
}
/// Usage text: one command per line.
const USAGE: &str = concat!(
    "usage: openproof-witness COMMAND\n",
    "  owner-app --home HOME [--port PORT] [--open]\n",
    "  mcp HOME\n",
    "  init-home HOME | renew HOME | enable-paging HOME | install-trust HOME TRUST\n",
    "  broker-propose HOME < PROPOSAL | broker-review HOME ID\n",
    "  broker-commit HOME ID | broker-recover HOME ID | export-history HOME DIR\n",
    "  keygen FILE\n",
    "  init DIR\n",
    "  gate-propose HOME < PROPOSAL\n",
    "  gate-review HOME PROPOSAL_ID\n",
    "  gate-approve HOME TRUST PROPOSAL_ID REVIEW_SHA256\n",
    "  gate-approve-terminal HOME TRUST PROPOSAL_ID REVIEW_SHA256\n",
    "  gate-approve-passkey HOME TRUST PROPOSAL_ID APPROVAL_SHA256 < ASSERTION\n",
    "  gate-approved HOME TRUST PROPOSAL_ID\n",
    "  gate-list HOME\n",
    "  receive DIR KEY TRUST < REQUEST\n",
    "  checkpoint DIR KEY TRUST\n",
    "  witness DIR KEY TRUST < RECEIPT\n",
    "  recover DIR < REQUEST\n",
    "  receipt DIR SEQUENCE\n",
    "  head DIR\n",
    "  document DIR ID\n",
    "  tlog-request DIR KEY TRUST ORIGIN OLD_SIZE   (C2SP add-checkpoint body)\n",
    "  tlog-inclusion DIR SEQUENCE TREE_SIZE\n",
    "  export DIR TRUST < CHECKPOINT\n",
    "  role-status DIR\n",
    "  role-pin DIR ROOT\n",
    "  install-signed DIR ROOT < SIGNED_TRUST\n",
    "  signer-init DIR ROOT\n",
    "  sign-trust KEY SIGNER_STATE < TRUST\n",
    "  trust-payload ROOT < SIGNED_TRUST\n",
    "  verifier-init DIR ROOT\n",
    "  verifier-install DIR < SIGNED_TRUST\n",
    "  verify-trusted DIR SIGNED_TRUST PIN < PACKAGE\n",
    "  enable-pages DIR TRUST\n",
    "  export-page DIR TRUST START < CHECKPOINT\n",
    "  export-page-historical DIR TRUST START < CHECKPOINT\n",
    "  verify-page DIR SIGNED_TRUST PIN < PAGE\n",
    "  page-progress DIR\n",
    "Operator and test commands: openproof-tool. Role service: openproof-role.\n",
);
mod broker;
mod mcp;
mod owner_app;
mod transport;
mod zip;
use openproof_witness::http;
fn run() -> Result<serde_json::Value> {
    let a = std::env::args().skip(1).collect::<Vec<_>>();
    let a = a.iter().map(String::as_str).collect::<Vec<_>>();
    // Long-running servers and owner commands that print their own output.
    match a.as_slice() {
        ["mcp", home] => {
            mcp::serve(Path::new(home))?;
            std::process::exit(0)
        }
        ["owner-app", rest @ ..] => {
            owner_app::main(rest)?;
            std::process::exit(0)
        }
        _ => {}
    }
    if let Some(v) = broker::command(&a)? {
        return Ok(v);
    }
    let value = if transport::is_remote(&a) {
        // Read standard input only for commands that take input: a terminal
        // left on standard input must never block a read-only command.
        let v: Option<serde_json::Value> = if transport::takes_input(&a) {
            Some(serde_json::from_slice(&input_bytes()?)?)
        } else {
            None
        };
        transport::forward(&a, v.as_ref())?
    } else {
        None
    };
    if let Some(v) = value {
        return Ok(v);
    }
    dispatch(&a)
}
fn dispatch(a: &[&str]) -> Result<serde_json::Value> {
    Ok(match a {
        ["init", state] => {
            init(Path::new(state))?;
            serde_json::json!({"initialized":true})
        }
        ["keygen", path] => {
            if !cfg!(unix) {
                return Err("Unix key storage required".into());
            }
            let mut seed = Zeroizing::new([0u8; 32]);
            OsRng.fill_bytes(&mut *seed);
            let k = SigningKey::from_bytes(&seed);
            let mut o = fs::OpenOptions::new();
            o.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                o.mode(0o600);
            }
            let mut f = o.open(path)?;
            let encoded = Zeroizing::new(hex::encode(&seed[..]));
            f.write_all(encoded.as_bytes())?;
            f.sync_all()?;
            serde_json::json!({"public_key":hex::encode(k.verifying_key().to_bytes())})
        }
        ["gate-propose", home] => gate_propose(Path::new(home), &input()?, now())?,
        ["gate-review", home, id] => gate_review(Path::new(home), id, now())?,
        [command @ ("gate-approve" | "gate-approve-terminal"), home, configuration, id, reviewed] =>
        {
            let home = Path::new(home);
            gate_approve(
                home,
                &trust(configuration)?,
                &key(home.join("authority/key.secret"))?,
                id,
                reviewed,
                *command == "gate-approve-terminal",
                now(),
            )?
        }
        ["gate-approve-passkey", home, configuration, id, approval] => gate_approve_passkey(
            Path::new(home),
            &trust(configuration)?,
            id,
            approval,
            &input()?,
            now(),
        )?,
        ["gate-approved", home, configuration, id] => {
            gate_approved(Path::new(home), &trust(configuration)?, id, now())?
        }
        ["gate-list", home] => gate_list(Path::new(home), now())?,
        ["receive", state, secret, configuration] => serde_json::to_value(apply(
            Path::new(state),
            &input()?,
            &trust(configuration)?,
            &key(secret)?,
            now(),
        )?)?,
        ["checkpoint", state, secret, configuration] => serde_json::to_value(current_checkpoint(
            Path::new(state),
            &trust(configuration)?,
            &key(secret)?,
            now(),
        )?)?,
        ["witness", state, secret, configuration] => serde_json::to_value(witness(
            Path::new(state),
            &input()?,
            &trust(configuration)?,
            &key(secret)?,
            now(),
        )?)?,
        ["recover", state] => serde_json::to_value(recover(Path::new(state), &input()?)?)?,
        ["receipt", state, sequence] => {
            serde_json::to_value(stored_receipt(Path::new(state), sequence.parse()?)?)?
        }
        ["head", state] => serde_json::json!({"count":head(Path::new(state))?}),
        ["tlog-request", state, secret, configuration, origin, old] => {
            let body = openproof_witness::tlog::add_checkpoint_request(
                Path::new(state),
                &trust(configuration)?,
                &key(secret)?,
                origin,
                old.parse()?,
                now(),
            )?;
            serde_json::json!({"origin": origin, "request": body})
        }
        ["tlog-inclusion", state, sequence, size] => {
            use base64::{engine::general_purpose::STANDARD, Engine};
            let proof = openproof_witness::tlog::event_inclusion(
                Path::new(state),
                sequence.parse()?,
                size.parse()?,
            )?;
            serde_json::json!({"proof": proof.iter().map(|h| STANDARD.encode(h)).collect::<Vec<_>>()})
        }
        ["export", state, configuration] => serde_json::to_value(export_verified(
            Path::new(state),
            &trust(configuration)?,
            input()?,
            now(),
        )?)?,
        ["install-signed", state, root] => {
            let signed: openproof_core::Signed<Trust> = input()?;
            role_install(Path::new(state), &signed, root, now())?;
            serde_json::json!({"installed":true})
        }
        ["role-status", state] => serde_json::json!({"root":role_root(Path::new(state))?}),
        ["role-pin", state, root] => {
            role_pin(Path::new(state), root)?;
            serde_json::json!({"pinned":true})
        }
        ["signer-init", state, root] => {
            signer_init(Path::new(state), root)?;
            serde_json::json!({"initialized":true})
        }
        ["sign-trust", secret, state] => serde_json::to_value(sign_trust_tracked(
            Path::new(state),
            input()?,
            &key(secret)?,
            now(),
        )?)?,
        ["verifier-init", state, root] => {
            verifier_init(Path::new(state), root)?;
            serde_json::json!({"initialized":true})
        }
        ["verifier-install", state] => {
            verifier_install(Path::new(state), &input()?, now())?;
            serde_json::json!({"installed":true})
        }
        ["verify-trusted", state, configuration, pin] => serde_json::to_value(verify_trusted(
            Path::new(state),
            &parse(&read(configuration)?)?,
            &parse(&read(pin)?)?,
            &input()?,
            now(),
        )?)?,
        ["trust-payload", root] => {
            let signed: openproof_core::Signed<Trust> = input()?;
            openproof_core::verify_signature(&signed, root)?;
            serde_json::to_value(signed.payload)?
        }
        ["enable-pages", state, configuration] => {
            enable_pages(Path::new(state), &trust(configuration)?, now())?;
            serde_json::json!({"enabled":true})
        }
        ["export-page-historical", state, configuration, start] => {
            let cp: openproof_core::Signed<Checkpoint> = input()?;
            let at = cp.payload.observed_at;
            serde_json::to_value(export_page(
                Path::new(state),
                &trust(configuration)?,
                cp,
                start.parse()?,
                at,
            )?)?
        }
        ["export-page", state, configuration, start] => serde_json::to_value(export_page(
            Path::new(state),
            &trust(configuration)?,
            input()?,
            start.parse()?,
            now(),
        )?)?,
        ["verify-page", state, configuration, pin] => serde_json::to_value(verify_page(
            Path::new(state),
            &parse(&read(configuration)?)?,
            &parse(&read(pin)?)?,
            &input()?,
            now(),
        )?)?,
        ["page-progress", state] => serde_json::json!({"count":page_progress(Path::new(state))?}),
        ["document", state, id] => {
            let (v, c) = document(Path::new(state), id)?;
            serde_json::json!({"version":v,"content":c})
        }
        _ => return Err(USAGE.into()),
    })
}
fn main() {
    match run() {
        Ok(v) => println!("{}", serde_json::to_string_pretty(&v).unwrap()),
        Err(e) => {
            eprintln!("openproof-witness: {e}");
            std::process::exit(1);
        }
    }
}
