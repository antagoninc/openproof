//! Operator and test commands for OpenProof states and histories. None of
//! this is on the owner's main path, and the role services never run it: it is
//! not trusted for any guarantee (docs/TCB.md). Each command reads its input
//! from standard input and prints JSON.
//!
//! `approve` signs an approval with the authority key directly, without the
//! approval gate's review binding. It exists for tests and for showing that
//! the receiver refuses such a request when an owner passkey is in force.
#![forbid(unsafe_code)]
use openproof_core::{parse, sign};
use openproof_witness::keys::{key, read, trust};
use openproof_witness::*;
use serde::Serialize;
use std::{io::Read, path::Path};

// Planned key handover and the storage pilot: only with `--features experimental`.
#[cfg(feature = "experimental")]
mod experimental;
#[cfg(feature = "experimental")]
use experimental::{experimental, EXPERIMENTAL_USAGE};
#[cfg(not(feature = "experimental"))]
const EXPERIMENTAL_USAGE: &str = "";
#[cfg(not(feature = "experimental"))]
fn experimental(_: &[&str]) -> Result<Option<serde_json::Value>> {
    Ok(None)
}

fn input<T: serde::de::DeserializeOwned + Serialize>() -> Result<T> {
    let mut b = vec![];
    std::io::stdin().take(1_048_577).read_to_end(&mut b)?;
    Ok(parse(&b)?)
}

const USAGE: &str = concat!(
    "usage: openproof-tool COMMAND\n",
    "  approve KEY TRUST < PROPOSAL        (no review binding; tests only)\n",
    "  check-assertion TRUST < REQUEST\n",
    "  verify TRUST PIN < PACKAGE\n",
    "  bench TRUST PIN COUNT < PACKAGE\n",
    "  export-unverified DIR < CHECKPOINT\n",
    "  key-public KEY\n",
    "  install DIR TRUST\n",
    "  revoke DIR NONCE_OR_KEY\n",
    "  gap DIR KEY TRUST < REASON_JSON\n",
    "  role-init DIR ROOT\n",
    "  sign-trust-untracked KEY < TRUST\n",
    "  trust-floor DIR\n",
    "  signer-floor DIR\n",
    "  clock-status DIR\n",
    "  clock-repair DIR TRUST AUTHORITY_KEY\n",
    "  verifier-clock-request DIR\n",
    "  sign-verifier-clock-repair ROOT_KEY < REQUEST\n",
    "  apply-verifier-clock-repair DIR SIGNED_TRUST < TOKEN\n",
    "  verifier-clock-repair DIR SIGNED_TRUST ROOT_KEY\n",
    "  reset-pages DIR\n",
    "  tlog-vkey ORIGIN WITNESS_PUBLIC_KEY_HEX\n",
    "  tlog-verify TRUST ORIGIN COSIGNERS_JSON < CHECKPOINT_AS_JSON_STRING\n",
);

/// A role state of an owner home whose roles run as services
/// (docs/LOCAL-ROLES.md). Only that role's operator may administer it.
fn service_state(a: &[&str]) -> bool {
    let Some(state) = a.get(1).map(Path::new) else {
        return false;
    };
    let role = state.parent().and_then(|p| p.file_name());
    let home = state.parent().and_then(|p| p.parent());
    state.file_name().is_some_and(|n| n == "state")
        && role.is_some_and(|r| r == "receiver" || r == "witness")
        && home.is_some_and(|h| h.join("service-client.json").exists())
}

fn dispatch(a: &[&str]) -> Result<serde_json::Value> {
    if service_state(a) {
        return Err(
            "This state belongs to a role service. Administer it as that role's operator.".into(),
        );
    }
    if let Some(v) = experimental(a)? {
        return Ok(v);
    }
    Ok(match a {
        ["approve", secret, configuration] => {
            let t = trust(configuration)?;
            t.validate(now())?;
            serde_json::to_value(sign_approval(&input()?, &t, &key(secret)?, now())?)?
        }
        ["check-assertion", configuration] => {
            let t = trust(configuration)?;
            t.validate(now())?;
            let q: Request = input()?;
            check_request_assertion(&q, &t)?;
            serde_json::json!({"owner_assertion_verified":true,"approval_sha256":openproof_core::digest(&q.approval.payload)?})
        }
        ["tlog-vkey", origin, public] => {
            if !tlog::valid_origin(origin) {
                return Err("invalid origin".into());
            }
            let k: [u8; 32] = hex::decode(public)?.try_into().map_err(|_| "key length")?;
            serde_json::json!({"vkey": tlog::vkey(origin, 0x01, &k)})
        }
        ["tlog-verify", configuration, origin, cosigners] => {
            // The log's own signature must verify under the trust's witness key;
            // each listed cosigner (a C2SP Ed25519 cosigner vkey) is then checked.
            use tlog;
            let t = trust(configuration)?;
            // The signed checkpoint arrives as one JSON string.
            let text: String = input()?;
            if !tlog::valid_origin(origin) {
                return Err("invalid origin".into());
            }
            let n = tlog::parse_note(&text)?;
            let public: [u8; 32] = hex::decode(&t.witness)?
                .try_into()
                .map_err(|_| "key length")?;
            if n.origin != *origin || !tlog::verify_note(&n, origin, &public) {
                return Err("log signature".into());
            }
            let list: Vec<String> = serde_json::from_slice(&std::fs::read(cosigners)?)?;
            // A cosignature does not commit to the cosigner's name, so one key
            // must never count twice (c2sp.org/tlog-cosignature).
            let mut cosigned = vec![];
            let (mut names, mut keys) = (
                std::collections::HashSet::new(),
                std::collections::HashSet::new(),
            );
            for v in &list {
                let (name, k) = tlog::parse_vkey(v, 0x04)?;
                if !names.insert(name.clone()) || !keys.insert(k) {
                    return Err("cosigner listed twice".into());
                }
                if let Some(time) = tlog::verify_cosignature(&n, &name, &k) {
                    if time > now() + 300 {
                        continue;
                    }
                    cosigned.push(serde_json::json!({"name": name, "time": time}));
                }
            }
            serde_json::json!({"origin": n.origin, "size": n.size,
                "root": hex::encode(n.root), "cosigned_by": cosigned})
        }
        ["export-unverified", state] => serde_json::to_value(export(Path::new(state), input()?)?)?,
        ["key-public", secret] => {
            serde_json::json!({"public_key":hex::encode(key(secret)?.verifying_key().to_bytes())})
        }
        ["role-init", state, root] => {
            openproof_core::public_key(root)?;
            init(Path::new(state))?;
            role_pin(Path::new(state), root)?;
            serde_json::json!({"initialized":true,"trust_mode":"root_pinned"})
        }
        ["sign-trust-untracked", secret] => {
            let t: Trust = input()?;
            t.validate(now())?;
            serde_json::to_value(sign(t, &key(secret)?)?)?
        }
        ["verifier-clock-request", state] => {
            serde_json::to_value(verifier_clock_request(Path::new(state), now())?)?
        }
        ["sign-verifier-clock-repair", secret] => {
            serde_json::to_value(sign(input::<VerifierClockRepair>()?, &key(secret)?)?)?
        }
        ["apply-verifier-clock-repair", state, configuration] => {
            apply_verifier_clock_repair(
                Path::new(state),
                &parse(&read(configuration)?)?,
                &input()?,
                now(),
            )?;
            serde_json::json!({"repaired":true})
        }
        ["trust-floor", state] => serde_json::json!({"epoch":trust_floor(Path::new(state))?}),
        ["signer-floor", state] => serde_json::json!({"epoch":signer_floor(Path::new(state))?}),
        ["verifier-clock-repair", state, configuration, secret] => {
            serde_json::to_value(repair_verifier_clock(
                Path::new(state),
                &parse(&read(configuration)?)?,
                &key(secret)?,
                now(),
            )?)?
        }
        ["clock-status", state] => serde_json::to_value(clock_status(Path::new(state), now())?)?,
        ["clock-repair", state, configuration, secret] => serde_json::to_value(repair_clock(
            Path::new(state),
            &trust(configuration)?,
            &key(secret)?,
            now(),
        )?)?,
        ["reset-pages", state] => {
            reset_pages(Path::new(state))?;
            serde_json::json!({"pending_prefix_reset":true})
        }
        ["bench", configuration, pin, count] => {
            let p: Package = input()?;
            let t = trust(configuration)?;
            let checkpoint = parse(&read(pin)?)?;
            let n: usize = count.parse()?;
            if !(1..=1000).contains(&n) {
                return Err("benchmark bound".into());
            }
            let mut samples = vec![];
            for _ in 0..n {
                let start = std::time::Instant::now();
                std::hint::black_box(assess(&p, &t, &checkpoint, now())?);
                samples.push(start.elapsed().as_nanos() as u64);
            }
            serde_json::json!({"samples_ns":samples,"workload":"full single-document witnessed chain verification; multiple signatures"})
        }
        ["verify", configuration, pin] => serde_json::to_value(assess(
            &input()?,
            &trust(configuration)?,
            &parse(&read(pin)?)?,
            now(),
        )?)?,
        ["install", state, configuration] => {
            install(Path::new(state), &trust(configuration)?, now())?;
            serde_json::json!({"installed":true})
        }
        ["revoke", state, value] => {
            revoke(Path::new(state), value)?;
            serde_json::json!({"revoked":true})
        }
        ["gap", state, secret, configuration] => serde_json::to_value(gap(
            Path::new(state),
            &input::<String>()?,
            &trust(configuration)?,
            &key(secret)?,
            now(),
        )?)?,
        _ => return Err(format!("{USAGE}{EXPERIMENTAL_USAGE}").into()),
    })
}

fn main() {
    let a = std::env::args().skip(1).collect::<Vec<_>>();
    let a = a.iter().map(String::as_str).collect::<Vec<_>>();
    match dispatch(&a) {
        Ok(v) => println!("{}", serde_json::to_string_pretty(&v).unwrap()),
        Err(e) => {
            eprintln!("openproof-tool: {e}");
            std::process::exit(1);
        }
    }
}
