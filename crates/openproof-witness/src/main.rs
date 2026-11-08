#![forbid(unsafe_code)]
use ed25519_dalek::SigningKey;
use openproof_core::{parse, sign};
use openproof_witness::*;
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    io::{Read, Write},
    path::Path,
};
use zeroize::Zeroizing;
fn read(path: &str) -> Result<Vec<u8>> {
    let mut b = vec![];
    fs::File::open(path)?.take(1_048_577).read_to_end(&mut b)?;
    if b.len() > 1_048_576 {
        return Err("input exceeds 1 MiB".into());
    }
    Ok(b)
}
fn input<T: serde::de::DeserializeOwned + Serialize>() -> Result<T> {
    let mut b = vec![];
    std::io::stdin().take(1_048_577).read_to_end(&mut b)?;
    Ok(parse(&b)?)
}
#[cfg(unix)]
fn key(path: &str) -> Result<SigningKey> {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    let f = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    let m = f.metadata()?;
    if !m.is_file() || m.permissions().mode() & 0o077 != 0 {
        return Err("key must be a private regular file".into());
    }
    let mut raw = Zeroizing::new(Vec::new());
    f.take(257).read_to_end(&mut raw)?;
    if raw.len() > 256 {
        return Err("key size".into());
    }
    let encoded = std::str::from_utf8(&raw)?.trim();
    let mut seed = Zeroizing::new([0u8; 32]);
    hex::decode_to_slice(encoded, &mut *seed)?;
    Ok(SigningKey::from_bytes(&seed))
}
#[cfg(not(unix))]
fn key(_: &str) -> Result<SigningKey> {
    Err("Unix key storage required".into())
}
fn trust(path: &str) -> Result<Trust> {
    Ok(parse(&read(path)?)?)
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Proposal {
    document: String,
    expected_version: u64,
    content: String,
}
/// Usage text: one command per line.
const USAGE: &str = concat!(
    "usage: openproof-witness COMMAND\n",
    "  keygen FILE\n",
    "  init DIR\n",
    "  approve KEY TRUST < PROPOSAL\n",
    "  receive DIR KEY TRUST < REQUEST\n",
    "  check-assertion TRUST < REQUEST\n",
    "  witness DIR KEY TRUST < RECEIPT\n",
    "  recover DIR < REQUEST\n",
    "  receipt DIR SEQUENCE\n",
    "  head DIR\n",
    "  export DIR TRUST < CHECKPOINT\n",
    "  export-unverified DIR < CHECKPOINT\n",
    "  key-public KEY\n",
    "  role-init DIR ROOT\n",
    "  role-status DIR\n",
    "  role-pin DIR ROOT\n",
    "  signer-init DIR ROOT\n",
    "  sign-trust KEY SIGNER_STATE < TRUST\n",
    "  sign-trust-untracked KEY < TRUST\n",
    "  install-signed DIR ROOT < SIGNED_TRUST\n",
    "  verifier-init DIR ROOT\n",
    "  verifier-install DIR < SIGNED_TRUST\n",
    "  verify-trusted DIR SIGNED_TRUST PIN < PACKAGE\n",
    "  verify TRUST PIN < PACKAGE\n",
    "  install DIR TRUST\n",
    "  revoke DIR NONCE_OR_KEY\n",
    "  gap DIR KEY TRUST < REASON_JSON\n",
    "  verifier-clock-request DIR\n",
    "  sign-verifier-clock-repair ROOT_KEY < REQUEST\n",
    "  apply-verifier-clock-repair DIR SIGNED_TRUST < TOKEN\n",
    "  trust-payload ROOT < SIGNED_TRUST\n",
    "  trust-floor DIR\n",
    "  signer-floor DIR\n",
    "  verifier-clock-repair DIR SIGNED_TRUST ROOT_KEY\n",
    "  clock-status DIR\n",
    "  clock-repair DIR TRUST AUTHORITY_KEY\n",
    "  enable-pages DIR TRUST\n",
    "  export-page DIR TRUST START < CHECKPOINT\n",
    "  verify-page DIR SIGNED_TRUST PIN < PAGE\n",
    "  page-progress DIR\n",
    "  reset-pages DIR\n",
    "  sign-rotation KEY < ROTATION\n",
    "  check-rotation ROOT OLD_SIGNED_TRUST < HANDOVER\n",
    "  rotate-state DIR OLD_SIGNED_TRUST < HANDOVER\n",
    "  document DIR ID\n",
);
fn run() -> Result<serde_json::Value> {
    let a = std::env::args().skip(1).collect::<Vec<_>>();
    let a = a.iter().map(String::as_str).collect::<Vec<_>>();
    Ok(match a.as_slice() {
        ["storage-authorize", secret] => {
            serde_json::to_value(authorize_upload(input()?, &key(secret)?)?)?
        }
        ["storage-check", authority] => {
            let s: openproof_core::Signed<UploadAuthorization> = input()?;
            serde_json::json!({"authorization_sha256":check_upload(&s,authority,now())?})
        }
        ["storage-check-history", authority] => {
            let s: openproof_core::Signed<UploadAuthorization> = input()?;
            serde_json::json!({"authorization_sha256":check_upload(&s,authority,s.payload.not_before)?,"dispatch_allowed":false})
        }
        ["storage-observe", secret] => {
            let p: StorageObservation = input()?;
            let k = key(secret)?;
            if p.adapter != hex::encode(k.verifying_key().to_bytes()) {
                return Err("wrong adapter".into());
            }
            serde_json::to_value(sign(p, &k)?)?
        }
        ["storage-verify", authority, adapter] => {
            let e: StorageEvidence = input()?;
            verify_storage_evidence(&e, authority, adapter, now())?;
            serde_json::json!({"status":"adapter_statement_verified","kind":e.observation.payload.kind,"independent_storage_proof":false})
        }
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
        ["approve", secret, configuration] => {
            let t = trust(configuration)?;
            t.validate(now())?;
            let k = key(secret)?;
            if hex::encode(k.verifying_key().to_bytes()) != t.authority {
                return Err("wrong authority".into());
            }
            let p: Proposal = input()?;
            if p.content.is_empty() || p.content.len() > 8192 {
                return Err("content bound".into());
            }
            let mut nonce = [0; 32];
            OsRng.fill_bytes(&mut nonce);
            let time = now();
            let a = Approval {
                version: V.into(),
                authority: t.authority.clone(),
                document: p.document,
                expected_version: p.expected_version,
                content_sha256: hash(p.content.as_bytes()),
                nonce: hex::encode(nonce),
                receiver: t.receiver,
                not_before: time,
                expires_at: time + 300,
            };
            serde_json::to_value(Request {
                approval: sign(a, &k)?,
                content: p.content,
                owner_assertion: None,
            })?
        }
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
        ["check-assertion", configuration] => {
            let t = trust(configuration)?;
            t.validate(now())?;
            let q: Request = input()?;
            check_request_assertion(&q, &t)?;
            serde_json::json!({"owner_assertion_verified":true,"approval_sha256":openproof_core::digest(&q.approval.payload)?})
        }
        ["recover", state] => serde_json::to_value(recover(Path::new(state), &input()?)?)?,
        ["receipt", state, sequence] => {
            serde_json::to_value(stored_receipt(Path::new(state), sequence.parse()?)?)?
        }
        ["head", state] => serde_json::json!({"count":head(Path::new(state))?}),
        ["export-unverified", state] => serde_json::to_value(export(Path::new(state), input()?)?)?,
        ["export", state, configuration] => serde_json::to_value(export_verified(
            Path::new(state),
            &trust(configuration)?,
            input()?,
            now(),
        )?)?,
        ["key-public", secret] => {
            serde_json::json!({"public_key":hex::encode(key(secret)?.verifying_key().to_bytes())})
        }
        ["install-signed", state, root] => {
            let signed: openproof_core::Signed<Trust> = input()?;
            role_install(Path::new(state), &signed, root, now())?;
            serde_json::json!({"installed":true})
        }
        ["role-init", state, root] => {
            openproof_core::public_key(root)?;
            init(Path::new(state))?;
            role_pin(Path::new(state), root)?;
            serde_json::json!({"initialized":true,"trust_mode":"root_pinned"})
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
        ["sign-trust-untracked", secret] => {
            let t: Trust = input()?;
            t.validate(now())?;
            serde_json::to_value(sign(t, &key(secret)?)?)?
        }
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
        ["trust-payload", root] => {
            let signed: openproof_core::Signed<Trust> = input()?;
            openproof_core::verify_signature(&signed, root)?;
            serde_json::to_value(signed.payload)?
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
        ["check-rotation", root, old_trust] => {
            validate_handover(&parse(&read(old_trust)?)?, root, &input()?, now())?;
            serde_json::json!({"valid_planned_handover":true})
        }
        ["sign-rotation", secret] => {
            serde_json::to_value(sign(input::<Rotation>()?, &key(secret)?)?)?
        }
        ["rotation-applied", state] => {
            serde_json::json!({"applied":rotation_applied(Path::new(state),&input()?)?})
        }
        ["rotate-state", state, old_trust] => {
            rotate_state(
                Path::new(state),
                &parse(&read(old_trust)?)?,
                &input()?,
                now(),
            )?;
            serde_json::json!({"rotated":true})
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
        ["reset-pages", state] => {
            reset_pages(Path::new(state))?;
            serde_json::json!({"pending_prefix_reset":true})
        }
        ["page-progress", state] => serde_json::json!({"count":page_progress(Path::new(state))?}),
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
#[cfg(all(test, unix))]
mod key_tests {
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt};
    #[test]
    fn descriptor_checks_reject_symlink_fifo_and_public_key_file() {
        let base = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../outputs/key-read-tests");
        fs::create_dir_all(&base).unwrap();
        let d = base.join(format!("{}", std::process::id()));
        fs::create_dir(&d).unwrap();
        let p = d.join("key.secret");
        fs::write(&p, "01".repeat(32)).unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(key(p.to_str().unwrap()).is_ok());
        let link = d.join("link");
        symlink(&p, &link).unwrap();
        assert!(key(link.to_str().unwrap()).is_err());
        fs::set_permissions(&p, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(key(p.to_str().unwrap()).is_err());
        let fifo = d.join("fifo");
        assert!(std::process::Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .unwrap()
            .success());
        assert!(key(fifo.to_str().unwrap()).is_err());
        assert!(key(d.to_str().unwrap()).is_err());
        fs::remove_dir_all(d).unwrap();
    }
}
