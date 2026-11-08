#![forbid(unsafe_code)]
use ed25519_dalek::SigningKey;
use openproof_core::*;
use rand_core::OsRng;
use std::{
    fs::{self, OpenOptions},
    io::{Read, Write},
    path::Path,
};
type AnyResult<T> = std::result::Result<T, Box<dyn std::error::Error>>;
fn read(path: &str) -> AnyResult<Vec<u8>> {
    let mut b = Vec::new();
    fs::File::open(path)?
        .take((MAX_INPUT + 1) as u64)
        .read_to_end(&mut b)?;
    if b.len() > MAX_INPUT {
        return Err("input exceeds 1 MiB".into());
    }
    Ok(b)
}
fn write(path: &str, bytes: &[u8], secret: bool) -> AnyResult<()> {
    let mut opt = OpenOptions::new();
    opt.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opt.mode(if secret { 0o600 } else { 0o644 });
    }
    #[cfg(not(unix))]
    if secret {
        return Err("secret key creation supported only on Unix in v0.1".into());
    }
    let mut f = opt.open(path)?;
    f.write_all(bytes)?;
    f.sync_all()?;
    Ok(())
}
fn json<T: serde::Serialize>(path: &str, v: &T) -> AnyResult<()> {
    write(path, &serde_json::to_vec_pretty(v)?, false)
}
fn key(path: &str) -> AnyResult<SigningKey> {
    let b = read(path)?;
    let s = std::str::from_utf8(&b)?.trim();
    let bytes: [u8; 32] = hex::decode(s)?
        .try_into()
        .map_err(|_| "seed must contain 32 bytes")?;
    Ok(SigningKey::from_bytes(&bytes))
}
fn sign_file<T: Evidence + serde::de::DeserializeOwned>(
    input: &str,
    k: &SigningKey,
    out: &str,
) -> AnyResult<()> {
    json(out, &sign(parse::<T>(&read(input)?)?, k)?)
}
fn run() -> AnyResult<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let a: Vec<&str> = args.iter().map(String::as_str).collect();
    match a.as_slice() {
        ["doctor"] => println!("{}",serde_json::json!({"version":env!("CARGO_PKG_VERSION"),"unix_execution_supported":cfg!(unix),"clock_unix_seconds":openproof_runtime::now()?,"state_checked":false,"security_audit":false,"next":"doctor STATE_DIRECTORY"})),
        ["doctor",state] => {
            let records=openproof_runtime::records(Path::new(state))?;
            println!("{}",serde_json::json!({"state_readable":true,"records":records.len(),"uncertain_operations":records.iter().filter(|r|r.state!="completed").count(),"recovery":"Never delete or retry consumed nonces; inspect uncertain artifacts offline.","backup_rollback_detection":false,"security_audit":false}));
        }
        ["sign-root-transition",input,secret,out] => sign_file::<openproof_trust::RootTransition>(input,&key(secret)?,out)?,
        ["rotate-root",state,old,new,anchor,snapshot] => {
            let next=openproof_runtime::rotate_root(Path::new(state),&parse(&read(old)?)?,&parse(&read(new)?)?,&parse(&read(anchor)?)?,&parse(&read(snapshot)?)?)?;
            println!("{}",serde_json::to_string_pretty(&next)?);
        }
        ["verify-trusted-at",bundle,context,snapshot,anchor,mode,time] => {
            let mode=match *mode {"current"=>openproof_trust::Mode::Current,"historical"=>openproof_trust::Mode::Historical,_=>return Err("invalid mode".into())};
            println!("{}",serde_json::to_string_pretty(&openproof_trust::verify_trusted(&parse(&read(bundle)?)?,&parse(&read(context)?)?,&parse(&read(snapshot)?)?,&parse(&read(anchor)?)?,time.parse()?,mode)?)?);
        }
        ["keygen", secret, public] => {
            let k = SigningKey::generate(&mut OsRng);
            write(secret, hex::encode(k.to_bytes()).as_bytes(), true)?;
            write(public, hex::encode(k.verifying_key().to_bytes()).as_bytes(), false)?;
        }
        ["sign", kind, input, secret, out] => {
            let k=key(secret)?;
            match *kind {
                "authorization"=>sign_file::<Authorization>(input,&k,out)?,
                "action"=>sign_file::<Action>(input,&k,out)?,
                "receipt"=>sign_file::<Receipt>(input,&k,out)?,
                _=>return Err("unknown evidence kind".into()),
            }
        }
        ["install-trust",state,snapshot,anchor]=>{
            openproof_runtime::install_trust(Path::new(state),&parse(&read(snapshot)?)?,&parse(&read(anchor)?)?)?;
        }
        ["sign-trust",input,secret,out]=>sign_file::<openproof_trust::TrustBundle>(input,&key(secret)?,out)?,
        ["verify-trusted",bundle,context,snapshot,anchor,mode]=>{
            let mode=match *mode {"current"=>openproof_trust::Mode::Current,"historical"=>openproof_trust::Mode::Historical,_=>return Err("mode must be current or historical".into())};
            let b=parse(&read(bundle)?)?;let c=parse(&read(context)?)?;let t=parse(&read(snapshot)?)?;let a=parse(&read(anchor)?)?;
            println!("{}",serde_json::to_string_pretty(&openproof_trust::verify_trusted(&b,&c,&t,&a,openproof_runtime::now()?,mode)?)?);
        }
        ["execute-trusted",bundle,context,policy,arguments,secret,state,snapshot,anchor]=>{
            let b=parse(&read(bundle)?)?;let c=parse(&read(context)?)?;let t=parse(&read(snapshot)?)?;let a=parse(&read(anchor)?)?;
            let result=openproof_runtime::execute_trusted(Path::new(state),&b,&c,&read(policy)?,&read(arguments)?,&key(secret)?,openproof_runtime::TrustInput{snapshot:&t,anchor:&a})?;
            println!("{}",serde_json::to_string_pretty(&result)?);
        }
        ["verify", bundle, context] => {
            let b:Bundle=parse(&read(bundle)?)?;let c:Context=parse(&read(context)?)?;
            println!("{}",serde_json::to_string_pretty(&verify(&b,&c)?)?);
        }
        ["verify-artifact",bundle,context,output] => {
            let b:Bundle=parse(&read(bundle)?)?;let c:Context=parse(&read(context)?)?;
            println!("{}",serde_json::to_string_pretty(&openproof_runtime::verify_artifact(&b,&c,&read(output)?)?)?);
        }
        ["canonical",kind,input,out] => {
            let b=read(input)?;
            let bytes=match *kind {
                "authorization"=>signing_bytes(&parse::<Authorization>(&b)?)?,
                "action"=>signing_bytes(&parse::<Action>(&b)?)?,
                "receipt"=>signing_bytes(&parse::<Receipt>(&b)?)?,
                _=>return Err("unknown evidence kind".into()),
            };write(out,&bytes,false)?;
        }
        ["digest",kind,input] => {
            let b=read(input)?;
            let d=match *kind {
                "authorization"=>digest(&parse::<Authorization>(&b)?)?,
                "action"=>digest(&parse::<Action>(&b)?)?,
                "receipt"=>digest(&parse::<Receipt>(&b)?)?,
                _=>return Err("unknown evidence kind".into()),
            };println!("{d}");
        }
        ["init-state",dir]=>openproof_runtime::init_state(Path::new(dir))?,
        ["state",dir]=>println!("{}",serde_json::to_string_pretty(&openproof_runtime::records(Path::new(dir))?)?),
        ["execute",bundle,context,policy,arguments,secret,state]=>{
            let b:Bundle=parse(&read(bundle)?)?;let c:Context=parse(&read(context)?)?;
            let policy=read(policy)?;let arguments=read(arguments)?;let executor=key(secret)?;
            let result=openproof_runtime::execute(Path::new(state),&b,&c,&policy,&arguments,&executor)?;
            println!("{}",serde_json::to_string_pretty(&result)?);
        }
        ["execution-demo",dir]|["assurance-demo",dir]=>execution_demo(dir)?,
        ["demo",dir]=>demo(dir)?,
        ["--help"]|["help"]|[]=>println!("OpenProof {} (experimental)\ndoctor [STATE_DIRECTORY]\nassurance-demo NEW_DIRECTORY\nsign-root-transition INPUT SECRET OUTPUT\nrotate-root STATE OLD_SIGNED NEW_SIGNED OLD_ANCHOR NEW_SNAPSHOT\nverify-trusted-at BUNDLE CONTEXT SNAPSHOT ANCHOR current|historical TRUSTED_UNIX_TIME\nkeygen SECRET PUBLIC\nsign-trust INPUT ROOT_SECRET OUTPUT\ninstall-trust STATE SNAPSHOT ANCHOR\nverify-trusted BUNDLE CONTEXT SNAPSHOT ANCHOR current|historical\nexecute-trusted BUNDLE CONTEXT POLICY ARGUMENTS EXECUTOR_SECRET STATE SNAPSHOT ANCHOR\nsign authorization|action|receipt INPUT SECRET OUTPUT\ncanonical authorization|action|receipt INPUT OUTPUT\ndigest authorization|action|receipt INPUT\nverify BUNDLE TRUSTED_CONTEXT\nverify-artifact BUNDLE TRUSTED_CONTEXT OUTPUT\ninit-state NEW_DIRECTORY\nstate STATE_DIRECTORY\nexecute BUNDLE TRUSTED_CONTEXT POLICY ARGUMENTS EXECUTOR_SECRET STATE_DIRECTORY\nexecution-demo NEW_DIRECTORY\ndemo NEW_DIRECTORY\nOutput files must be new. Verification is offline. Execution supports only local artifact.write and artifact.sha256.",env!("CARGO_PKG_VERSION")),
        _=>return Err("invalid arguments; use --help".into()),
    }
    Ok(())
}
fn execution_demo(dir: &str) -> AnyResult<()> {
    use openproof_runtime::{sha256, Grant, Policy, POLICY_VERSION, RESOURCE};
    fs::create_dir(dir)?;
    let root = Path::new(dir);
    let authority = SigningKey::generate(&mut OsRng);
    let actor = SigningKey::generate(&mut OsRng);
    let executor = SigningKey::generate(&mut OsRng);
    let pk = |k: &SigningKey| hex::encode(k.verifying_key().to_bytes());
    let policy = Policy {
        version: POLICY_VERSION.into(),
        audience: "local-artifact-demo".into(),
        executor_key: pk(&executor),
        max_validity_seconds: 300,
        allow: vec![Grant {
            tool: "artifact.write".into(),
            resource: RESOURCE.into(),
            max_argument_bytes: 4096,
        }],
    };
    let policy_bytes = serde_json::to_vec_pretty(&policy)?;
    let arguments = b"OpenProof wrote these exact authorized bytes.\n";
    let time = openproof_runtime::now()?;
    let action = ActionSpec {
        tool: "artifact.write".into(),
        resource: RESOURCE.into(),
        arguments_sha256: sha256(arguments),
    };
    use rand_core::RngCore;
    let mut random = [0u8; 32];
    OsRng.fill_bytes(&mut random);
    let context = Context {
        authority_key: pk(&authority),
        actor_key: pk(&actor),
        executor_key: pk(&executor),
        run_id: "local-artifact-run".into(),
        nonce: hex::encode(random),
        audience: policy.audience,
        policy_sha256: sha256(&policy_bytes),
        expected_action: action.clone(),
        now: time,
    };
    let auth = Authorization {
        version: VERSION.into(),
        run_id: context.run_id.clone(),
        nonce: context.nonce.clone(),
        audience: context.audience.clone(),
        actor_key: context.actor_key.clone(),
        policy_sha256: context.policy_sha256.clone(),
        action: action.clone(),
        not_before: time.saturating_sub(1),
        expires_at: time + 120,
    };
    let claim = Action {
        version: VERSION.into(),
        authorization_sha256: digest(&auth)?,
        action,
        claimed_at: time,
    };
    let request = Bundle {
        authorization: sign(auth, &authority)?,
        action: sign(claim, &actor)?,
        receipt: None,
    };
    let dest = |name: &str| root.join(name).to_string_lossy().into_owned();
    json(&dest("request.json"), &request)?;
    json(&dest("context.json"), &context)?;
    write(&dest("policy.json"), &policy_bytes, false)?;
    write(&dest("arguments.bin"), arguments, false)?;
    let state = root.join("state");
    openproof_runtime::init_state(&state)?;
    let result = openproof_runtime::execute(
        &state,
        &request,
        &context,
        &policy_bytes,
        arguments,
        &executor,
    )?;
    json(&dest("execution.json"), &result)?;
    let output = fs::read(result.artifact_directory.join("output.bin"))?;
    json(
        &dest("artifact-report.json"),
        &openproof_runtime::verify_artifact(&result.bundle, &result.context, &output)?,
    )?;
    let replay = openproof_runtime::execute(
        &state,
        &request,
        &context,
        &policy_bytes,
        arguments,
        &executor,
    )
    .expect_err("duplicate execution must be rejected");
    if replay.code != openproof_runtime::Code::Replay {
        return Err(replay.into());
    }
    json(
        &dest("replay-report.json"),
        &serde_json::json!({"code":replay.code,"message":replay.message}),
    )?;
    let mut tampered = output.clone();
    tampered.push(0);
    let tamper = openproof_runtime::verify_artifact(&result.bundle, &result.context, &tampered)
        .expect_err("tampered output must fail");
    json(
        &dest("tamper-report.json"),
        &serde_json::json!({"code":tamper.code,"message":tamper.message}),
    )?;
    println!(
        "{}",
        serde_json::to_string_pretty(
            &serde_json::json!({"artifact_directory":result.artifact_directory,"replay_attempt":"rejected","tamper_attempt":"rejected","receipt_verified":true,"operation":"artifact.write","private_keys_saved":false})
        )?
    );
    Ok(())
}
fn demo(dir: &str) -> AnyResult<()> {
    fs::create_dir(dir)?;
    let auth = SigningKey::generate(&mut OsRng);
    let actor = SigningKey::generate(&mut OsRng);
    let executor = SigningKey::generate(&mut OsRng);
    let pk = |k: &SigningKey| hex::encode(k.verifying_key().to_bytes());
    let action = ActionSpec {
        tool: "synthetic.echo".into(),
        resource: "urn:openproof:synthetic".into(),
        arguments_sha256: "00".repeat(32),
    };
    let c = Context {
        authority_key: pk(&auth),
        actor_key: pk(&actor),
        executor_key: pk(&executor),
        run_id: "synthetic-run-1".into(),
        nonce: "synthetic-single-use-id".into(),
        audience: "local-demo".into(),
        policy_sha256: "11".repeat(32),
        expected_action: action.clone(),
        now: 100,
    };
    let au = Authorization {
        version: VERSION.into(),
        run_id: c.run_id.clone(),
        nonce: c.nonce.clone(),
        audience: c.audience.clone(),
        actor_key: c.actor_key.clone(),
        policy_sha256: c.policy_sha256.clone(),
        action: action.clone(),
        not_before: 90,
        expires_at: 110,
    };
    let ac = Action {
        version: VERSION.into(),
        authorization_sha256: digest(&au)?,
        action,
        claimed_at: 95,
    };
    let re = Receipt {
        version: VERSION.into(),
        action_sha256: digest(&ac)?,
        observed_at: 99,
        outcome: Outcome::Succeeded,
        output_sha256: "22".repeat(32),
    };
    let b = Bundle {
        authorization: sign(au, &auth)?,
        action: sign(ac, &actor)?,
        receipt: Some(sign(re, &executor)?),
    };
    let dest = |s: &str| Path::new(dir).join(s).to_string_lossy().into_owned();
    json(&dest("bundle.json"), &b)?;
    json(&dest("context.json"), &c)?;
    json(&dest("report.json"), &verify(&b, &c)?)?;
    println!("Synthetic demo created. Keys discarded; no tool was executed. Context is for this demo only.");
    Ok(())
}
fn main() {
    if let Err(e) = run() {
        eprintln!("openproof: {e}");
        std::process::exit(1)
    }
}
