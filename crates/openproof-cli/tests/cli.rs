use std::{fs, path::PathBuf, process::Command};
fn cli(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_openproof"))
        .args(args)
        .output()
        .unwrap()
}
fn dir(name: &str) -> PathBuf {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../outputs/tests")
        .join(format!("{name}-{}", std::process::id()));
    fs::create_dir_all(&p).unwrap();
    p
}
#[test]
fn demo_verifies_and_tampering_fails() {
    let root = dir("demo");
    let demo = root.join("fixture");
    let d = demo.to_str().unwrap();
    assert!(cli(&["demo", d]).status.success());
    let b = demo.join("bundle.json");
    let c = demo.join("context.json");
    let args = ["verify", b.to_str().unwrap(), c.to_str().unwrap()];
    let result = cli(&args);
    assert!(result.status.success());
    assert!(String::from_utf8_lossy(&result.stdout).contains("executor_reported_success"));
    let data = fs::read_to_string(&b)
        .unwrap()
        .replace("synthetic.echo", "synthetic.evil");
    fs::write(&b, data).unwrap();
    assert!(!cli(&args).status.success());
    assert!(!cli(&["demo", d]).status.success());
}
#[test]
fn keygen_refuses_overwrite_and_is_private() {
    let root = dir("keys");
    let s = root.join("test.secret");
    let p = root.join("test.public");
    let args = ["keygen", s.to_str().unwrap(), p.to_str().unwrap()];
    assert!(cli(&args).status.success());
    let original = fs::read(&s).unwrap();
    assert!(!cli(&args).status.success());
    assert_eq!(original, fs::read(&s).unwrap());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(&s).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    fs::remove_file(s).unwrap();
}
#[test]
fn help_and_error_exit_codes() {
    assert!(cli(&["--help"]).status.success());
    assert!(!cli(&["unknown"]).status.success());
    assert!(!cli(&["verify", "missing", "missing"]).status.success());
}

#[test]
fn signing_digest_and_canonical_commands_agree() {
    let root = dir("sign");
    let seed = root.join("test.secret");
    let public = root.join("public");
    assert!(
        cli(&["keygen", seed.to_str().unwrap(), public.to_str().unwrap()])
            .status
            .success()
    );
    let input = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../examples/authorization.json");
    let signed = root.join("signed.json");
    let bytes = root.join("canonical.bin");
    assert!(cli(&[
        "sign",
        "authorization",
        input.to_str().unwrap(),
        seed.to_str().unwrap(),
        signed.to_str().unwrap()
    ])
    .status
    .success());
    let value: openproof_core::Signed<openproof_core::Authorization> =
        openproof_core::parse(&fs::read(&signed).unwrap()).unwrap();
    openproof_core::verify_signature(&value, &fs::read_to_string(&public).unwrap()).unwrap();
    assert!(cli(&[
        "canonical",
        "authorization",
        input.to_str().unwrap(),
        bytes.to_str().unwrap()
    ])
    .status
    .success());
    assert_eq!(
        fs::read(bytes).unwrap(),
        openproof_core::signing_bytes(&value.payload).unwrap()
    );
    let output = cli(&["digest", "authorization", input.to_str().unwrap()]);
    assert!(output.status.success());
    assert_eq!(
        String::from_utf8(output.stdout).unwrap().trim(),
        openproof_core::digest(&value.payload).unwrap()
    );
    fs::remove_file(seed).unwrap();
}

#[test]
fn real_execution_demo_verifies_artifact_and_blocks_second_dispatch() {
    let root = dir("execution");
    let demo = root.join("run");
    let result = cli(&["execution-demo", demo.to_str().unwrap()]);
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let info: serde_json::Value =
        serde_json::from_slice(&fs::read(demo.join("execution.json")).unwrap()).unwrap();
    let job = PathBuf::from(info["artifact_directory"].as_str().unwrap());
    let b = job.join("bundle.json");
    let c = job.join("context.json");
    let o = job.join("output.bin");
    let args = [
        "verify-artifact",
        b.to_str().unwrap(),
        c.to_str().unwrap(),
        o.to_str().unwrap(),
    ];
    assert!(cli(&args).status.success());
    let replay: serde_json::Value =
        serde_json::from_slice(&fs::read(demo.join("replay-report.json")).unwrap()).unwrap();
    assert_eq!(replay["code"], "replay");
    fs::write(&o, b"tampered").unwrap();
    assert!(!cli(&args).status.success());
}
#[test]
fn state_initialization_is_explicit_and_never_overwrites() {
    let root = dir("state");
    let state = root.join("state");
    let path = state.to_str().unwrap();
    assert!(!cli(&["state", path]).status.success());
    assert!(cli(&["init-state", path]).status.success());
    assert!(!cli(&["init-state", path]).status.success());
    let out = cli(&["state", path]);
    assert!(out.status.success());
    assert_eq!(String::from_utf8(out.stdout).unwrap().trim(), "[]");
}

#[test]
fn doctor_and_assurance_demo_report_limits_and_tampering() {
    assert!(cli(&["doctor"]).status.success());
    assert!(!cli(&["doctor", "/nonexistent-openproof-state"])
        .status
        .success());
    let d = dir("assurance").join("run");
    let out = cli(&["assurance-demo", d.to_str().unwrap()]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let info: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(info["tamper_attempt"], "rejected");
    assert!(d.join("tamper-report.json").exists());
    let out = cli(&["doctor", d.join("state").to_str().unwrap()]);
    assert!(out.status.success());
    let info: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(info["uncertain_operations"], 0);
    assert_eq!(info["backup_rollback_detection"], false);
}
