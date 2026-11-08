use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Barrier};
static SEQ: AtomicUsize = AtomicUsize::new(0);
struct Fixture {
    root: PathBuf,
    bundle: Bundle,
    context: Context,
    policy: Vec<u8>,
    args: Vec<u8>,
    key: SigningKey,
}
fn fixture() -> Fixture {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../outputs/runtime-tests")
        .join(format!(
            "{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::SeqCst)
        ));
    fs::create_dir_all(root.parent().unwrap()).unwrap();
    init_state(&root).unwrap();
    let authority = SigningKey::from_bytes(&[1; 32]);
    let actor = SigningKey::from_bytes(&[2; 32]);
    let key = SigningKey::from_bytes(&[3; 32]);
    let pk = |k: &SigningKey| hex::encode(k.verifying_key().to_bytes());
    let policy = serde_json::to_vec(&Policy {
        version: POLICY_VERSION.into(),
        audience: "test".into(),
        executor_key: pk(&key),
        max_validity_seconds: 300,
        allow: vec![
            Grant {
                tool: "artifact.write".into(),
                resource: RESOURCE.into(),
                max_argument_bytes: 4096,
            },
            Grant {
                tool: "artifact.sha256".into(),
                resource: RESOURCE.into(),
                max_argument_bytes: 4096,
            },
        ],
    })
    .unwrap();
    let args = b"captured bytes\0\xff\n".to_vec();
    let t = now().unwrap();
    let spec = openproof_core::ActionSpec {
        tool: "artifact.write".into(),
        resource: RESOURCE.into(),
        arguments_sha256: sha256(&args),
    };
    let context = Context {
        authority_key: pk(&authority),
        actor_key: pk(&actor),
        executor_key: pk(&key),
        run_id: "run".into(),
        nonce: "nonce".into(),
        audience: "test".into(),
        policy_sha256: sha256(&policy),
        expected_action: spec.clone(),
        now: t,
    };
    let auth = openproof_core::Authorization {
        version: VERSION.into(),
        run_id: context.run_id.clone(),
        nonce: context.nonce.clone(),
        audience: context.audience.clone(),
        actor_key: context.actor_key.clone(),
        policy_sha256: context.policy_sha256.clone(),
        action: spec.clone(),
        not_before: t - 1,
        expires_at: t + 120,
    };
    let action = openproof_core::Action {
        version: VERSION.into(),
        authorization_sha256: digest(&auth).unwrap(),
        action: spec,
        claimed_at: t,
    };
    Fixture {
        root,
        bundle: Bundle {
            authorization: sign(auth, &authority).unwrap(),
            action: sign(action, &actor).unwrap(),
            receipt: None,
        },
        context,
        policy,
        args,
        key,
    }
}
fn run(f: &Fixture) -> Result<Execution> {
    execute(&f.root, &f.bundle, &f.context, &f.policy, &f.args, &f.key)
}
fn resign(f: &mut Fixture) {
    f.bundle.authorization = sign(
        f.bundle.authorization.payload.clone(),
        &SigningKey::from_bytes(&[1; 32]),
    )
    .unwrap();
    f.bundle.action.payload.authorization_sha256 = digest(&f.bundle.authorization.payload).unwrap();
    f.bundle.action = sign(
        f.bundle.action.payload.clone(),
        &SigningKey::from_bytes(&[2; 32]),
    )
    .unwrap();
}
#[test]
fn writes_actual_artifact_and_rejects_replay_after_reopen() {
    let f = fixture();
    let result = run(&f).unwrap();
    let output = fs::read(result.artifact_directory.join("output.bin")).unwrap();
    assert_eq!(output, f.args);
    verify_artifact(&result.bundle, &result.context, &output).unwrap();
    assert_eq!(run(&f).unwrap_err().code, Code::Replay);
    let rows = records(&f.root).unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].state, "completed");
}
#[test]
fn hash_adapter_produces_real_digest() {
    let mut f = fixture();
    f.context.expected_action.tool = "artifact.sha256".into();
    f.bundle.authorization.payload.action = f.context.expected_action.clone();
    f.bundle.action.payload.action = f.context.expected_action.clone();
    resign(&mut f);
    let r = run(&f).unwrap();
    assert_eq!(
        fs::read(r.artifact_directory.join("output.bin")).unwrap(),
        format!("{}\n", sha256(&f.args)).as_bytes()
    );
}
#[test]
fn changed_arguments_do_not_consume_nonce() {
    let mut f = fixture();
    f.args.push(0);
    assert_eq!(run(&f).unwrap_err().code, Code::InvalidEvidence);
    assert!(records(&f.root).unwrap().is_empty());
}
#[test]
fn altered_policy_or_denied_scope_rejected() {
    let mut f = fixture();
    f.policy.push(b' ');
    assert_eq!(run(&f).unwrap_err().code, Code::PolicyDenied);
    assert!(records(&f.root).unwrap().is_empty());
}
#[test]
fn policy_limit_is_enforced() {
    let mut f = fixture();
    let mut p: Policy = parse(&f.policy).unwrap();
    p.allow[0].max_argument_bytes = 1;
    f.policy = serde_json::to_vec(&p).unwrap();
    f.context.policy_sha256 = sha256(&f.policy);
    f.bundle.authorization.payload.policy_sha256 = f.context.policy_sha256.clone();
    resign(&mut f);
    assert_eq!(run(&f).unwrap_err().code, Code::PolicyDenied);
}
#[test]
fn unsupported_tool_and_path_traversal_denied() {
    for (tool, resource) in [
        ("shell", "urn:openproof:artifact"),
        ("artifact.write", "../../outside"),
    ] {
        let mut f = fixture();
        f.context.expected_action.tool = tool.into();
        f.context.expected_action.resource = resource.into();
        f.bundle.authorization.payload.action = f.context.expected_action.clone();
        f.bundle.action.payload.action = f.context.expected_action.clone();
        resign(&mut f);
        assert_eq!(run(&f).unwrap_err().code, Code::PolicyDenied);
        assert!(records(&f.root).unwrap().is_empty());
    }
}
#[test]
fn wrong_executor_rejected() {
    let mut f = fixture();
    f.key = SigningKey::from_bytes(&[4; 32]);
    assert_eq!(run(&f).unwrap_err().code, Code::PolicyDenied);
}
#[test]
fn caller_cannot_freeze_execution_clock() {
    let mut f = fixture();
    f.context.now = 10;
    f.bundle.authorization.payload.not_before = 1;
    f.bundle.authorization.payload.expires_at = 20;
    f.bundle.action.payload.claimed_at = 2;
    resign(&mut f);
    assert_eq!(run(&f).unwrap_err().code, Code::InvalidEvidence);
}
#[test]
fn future_claim_rejected() {
    let mut f = fixture();
    f.bundle.action.payload.claimed_at = now().unwrap() + 60;
    resign(&mut f);
    assert_eq!(run(&f).unwrap_err().code, Code::InvalidEvidence);
}
#[test]
fn artifact_tamper_rejected() {
    let f = fixture();
    let r = run(&f).unwrap();
    assert_eq!(
        verify_artifact(&r.bundle, &r.context, b"different")
            .unwrap_err()
            .code,
        Code::InvalidEvidence
    );
}
#[test]
fn concurrent_threads_dispatch_once() {
    let f = Arc::new(fixture());
    let barrier = Arc::new(Barrier::new(8));
    let threads: Vec<_> = (0..8)
        .map(|_| {
            let f = f.clone();
            let b = barrier.clone();
            std::thread::spawn(move || {
                b.wait();
                run(&f).map(|_| ()).map_err(|e| e.code)
            })
        })
        .collect();
    let results: Vec<_> = threads.into_iter().map(|t| t.join().unwrap()).collect();
    assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 1);
    assert_eq!(
        results.iter().filter(|r| **r == Err(Code::Replay)).count(),
        7
    );
}
#[test]
fn nonce_reuse_across_runs_and_new_authorizations_is_rejected() {
    let mut f = fixture();
    run(&f).unwrap();
    f.context.run_id = "another-run".into();
    f.bundle.authorization.payload.run_id = f.context.run_id.clone();
    f.bundle.action.payload.claimed_at = now().unwrap();
    resign(&mut f);
    assert_eq!(run(&f).unwrap_err().code, Code::Replay);
}
#[test]
fn missing_corrupt_or_reset_database_fails_closed() {
    let f = fixture();
    fs::remove_file(f.root.join("replay.sqlite3")).unwrap();
    assert_eq!(run(&f).unwrap_err().code, Code::Storage);
    assert!(init_state(&f.root).is_err());
    fs::write(f.root.join("replay.sqlite3"), b"bad database").unwrap();
    assert_eq!(run(&f).unwrap_err().code, Code::Storage);
}
#[test]
fn post_reservation_io_error_keeps_nonce_consumed() {
    let f = fixture();
    create_private_dir(&f.root.join("jobs").join(token(&f.context).unwrap())).unwrap();
    assert_eq!(run(&f).unwrap_err().code, Code::Indeterminate);
    assert_eq!(records(&f.root).unwrap()[0].state, "indeterminate");
    assert_eq!(run(&f).unwrap_err().code, Code::Replay);
}
#[cfg(unix)]
#[test]
fn public_or_symlinked_state_is_rejected() {
    use std::os::unix::fs::{symlink, PermissionsExt};
    let f = fixture();
    let alias = f.root.with_extension("alias");
    symlink(&f.root, &alias).unwrap();
    assert!(connect(&alias).is_err());
    fs::set_permissions(&f.root, fs::Permissions::from_mode(0o755)).unwrap();
    assert!(run(&f).is_err());
}
fn worker_inputs(f: &Fixture) {
    json_new(&f.root.join("test-request.json"), &f.bundle).unwrap();
    json_new(&f.root.join("test-context.json"), &f.context).unwrap();
    write_new(&f.root.join("test-policy.json"), &f.policy).unwrap();
    write_new(&f.root.join("test-args.bin"), &f.args).unwrap();
}
fn child(f: &Fixture, stage: &str) -> std::process::Child {
    std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "tests::process_worker", "--nocapture"])
        .env("OPENPROOF_TEST_ROOT", &f.root)
        .env("OPENPROOF_TEST_STAGE", stage)
        .stdout(std::process::Stdio::null())
        .spawn()
        .unwrap()
}
#[test]
fn process_worker() {
    let Ok(root) = std::env::var("OPENPROOF_TEST_ROOT") else {
        return;
    };
    let root = PathBuf::from(root);
    let bundle: Bundle = parse(&fs::read(root.join("test-request.json")).unwrap()).unwrap();
    let ctx: Context = parse(&fs::read(root.join("test-context.json")).unwrap()).unwrap();
    let policy = fs::read(root.join("test-policy.json")).unwrap();
    let args = fs::read(root.join("test-args.bin")).unwrap();
    let stage = std::env::var("OPENPROOF_TEST_STAGE").unwrap();
    let result = execute_inner(
        &root,
        &bundle,
        &ctx,
        &policy,
        &args,
        &SigningKey::from_bytes(&[3; 32]),
        |checkpoint| {
            if (stage == "before-reservation" && checkpoint == Checkpoint::BeforeReservation)
                || (stage == "before-artifact" && checkpoint == Checkpoint::BeforeArtifact)
                || (stage == "before-completion" && checkpoint == Checkpoint::BeforeCompletion)
                || (stage == "completed" && checkpoint == Checkpoint::Completed)
                || (stage == "reserved" && checkpoint == Checkpoint::Reserved)
                || (stage == "artifact" && checkpoint == Checkpoint::ArtifactWritten)
            {
                std::process::exit(77)
            }
        },
    );
    std::process::exit(match result {
        Ok(_) => 0,
        Err(e) if e.code == Code::Replay => 23,
        Err(_) => 24,
    });
}
#[test]
fn abrupt_process_exit_after_commit_or_artifact_never_retries() {
    for stage in ["reserved", "artifact"] {
        let f = fixture();
        worker_inputs(&f);
        assert_eq!(child(&f, stage).wait().unwrap().code(), Some(77));
        assert_eq!(records(&f.root).unwrap()[0].state, "reserved");
        assert_eq!(run(&f).unwrap_err().code, Code::Replay);
        let file = f
            .root
            .join("jobs")
            .join(token(&f.context).unwrap())
            .join("output.bin");
        assert_eq!(file.exists(), stage == "artifact");
    }
}
#[test]
fn independent_processes_dispatch_once() {
    let f = fixture();
    worker_inputs(&f);
    let mut a = child(&f, "none");
    let mut b = child(&f, "none");
    let mut codes = vec![
        a.wait().unwrap().code().unwrap(),
        b.wait().unwrap().code().unwrap(),
    ];
    codes.sort();
    assert_eq!(codes, vec![0, 23]);
}

fn trust(
    f: &Fixture,
    revision: u64,
) -> (
    openproof_core::Signed<openproof_trust::TrustBundle>,
    openproof_trust::Anchor,
) {
    use openproof_trust::{Anchor, Key, Role, TrustBundle};
    let root = SigningKey::from_bytes(&[9; 32]);
    let t = now().unwrap();
    let keys = [
        (&f.context.authority_key, Role::Authority),
        (&f.context.actor_key, Role::Actor),
        (&f.context.executor_key, Role::Executor),
    ]
    .into_iter()
    .map(|(pk, role)| Key {
        public_key: pk.clone(),
        role,
        not_before: t - 10,
        expires_at: t + 1000,
        revoked_at: None,
    })
    .collect();
    (
        sign(
            TrustBundle {
                version: "openproof-trust/1".into(),
                audience: f.context.audience.clone(),
                revision,
                issued_at: t - 1,
                expires_at: t + 1000,
                keys,
            },
            &root,
        )
        .unwrap(),
        Anchor {
            root_key: hex::encode(root.verifying_key().to_bytes()),
            audience: f.context.audience.clone(),
            minimum_revision: 1,
        },
    )
}
#[test]
fn trusted_gate_pins_revision_and_rejects_equivocation() {
    let mut f = fixture();
    let (mut t, a) = trust(&f, 2);
    execute_trusted(
        &f.root,
        &f.bundle,
        &f.context,
        &f.policy,
        &f.args,
        &f.key,
        TrustInput {
            snapshot: &t,
            anchor: &a,
        },
    )
    .unwrap();
    f.context.nonce = "new-nonce".into();
    f.bundle.authorization.payload.nonce = f.context.nonce.clone();
    resign(&mut f);
    t.payload.revision = 1;
    t = sign(t.payload, &SigningKey::from_bytes(&[9; 32])).unwrap();
    assert!(execute_trusted(
        &f.root,
        &f.bundle,
        &f.context,
        &f.policy,
        &f.args,
        &f.key,
        TrustInput {
            snapshot: &t,
            anchor: &a
        }
    )
    .is_err());
    t.payload.revision = 2;
    t.payload.expires_at += 1;
    t = sign(t.payload, &SigningKey::from_bytes(&[9; 32])).unwrap();
    assert!(execute_trusted(
        &f.root,
        &f.bundle,
        &f.context,
        &f.policy,
        &f.args,
        &f.key,
        TrustInput {
            snapshot: &t,
            anchor: &a
        }
    )
    .is_err());
    assert_eq!(records(&f.root).unwrap().len(), 1);
}
#[test]
fn trusted_gate_revocation_prevents_consumption() {
    let f = fixture();
    let (mut t, a) = trust(&f, 1);
    t.payload.keys[1].revoked_at = Some(now().unwrap());
    t = sign(t.payload, &SigningKey::from_bytes(&[9; 32])).unwrap();
    assert!(execute_trusted(
        &f.root,
        &f.bundle,
        &f.context,
        &f.policy,
        &f.args,
        &f.key,
        TrustInput {
            snapshot: &t,
            anchor: &a
        }
    )
    .is_err());
    assert!(records(&f.root).unwrap().is_empty());
}
#[test]
fn rotating_authority_does_not_reset_trusted_nonce_namespace() {
    let mut f = fixture();
    let (mut t, a) = trust(&f, 1);
    execute_trusted(
        &f.root,
        &f.bundle,
        &f.context,
        &f.policy,
        &f.args,
        &f.key,
        TrustInput {
            snapshot: &t,
            anchor: &a,
        },
    )
    .unwrap();
    let new = SigningKey::from_bytes(&[4; 32]);
    f.context.authority_key = hex::encode(new.verifying_key().to_bytes());
    f.bundle.authorization = sign(f.bundle.authorization.payload, &new).unwrap();
    f.bundle.action.payload.authorization_sha256 = digest(&f.bundle.authorization.payload).unwrap();
    f.bundle.action = sign(f.bundle.action.payload, &SigningKey::from_bytes(&[2; 32])).unwrap();
    let mut rotated = t.payload.keys[0].clone();
    rotated.public_key = f.context.authority_key.clone();
    t.payload.keys.push(rotated);
    t.payload.revision = 2;
    t = sign(t.payload, &SigningKey::from_bytes(&[9; 32])).unwrap();
    assert_eq!(
        execute_trusted(
            &f.root,
            &f.bundle,
            &f.context,
            &f.policy,
            &f.args,
            &f.key,
            TrustInput {
                snapshot: &t,
                anchor: &a
            }
        )
        .unwrap_err()
        .code,
        Code::Replay
    );
}
#[test]
fn installing_revocation_snapshot_blocks_old_snapshots_without_dispatch() {
    let f = fixture();
    let (old, a) = trust(&f, 1);
    let mut revoked = old.clone();
    revoked.payload.revision = 2;
    revoked.payload.keys[1].revoked_at = Some(now().unwrap());
    revoked = sign(revoked.payload, &SigningKey::from_bytes(&[9; 32])).unwrap();
    install_trust(&f.root, &revoked, &a).unwrap();
    assert!(records(&f.root).unwrap().is_empty());
    assert!(execute_trusted(
        &f.root,
        &f.bundle,
        &f.context,
        &f.policy,
        &f.args,
        &f.key,
        TrustInput {
            snapshot: &old,
            anchor: &a
        }
    )
    .is_err());
    assert!(install_trust(&f.root, &old, &a).is_err());
}

#[test]
fn process_crashes_cover_transaction_and_file_boundaries() {
    for stage in [
        "before-reservation",
        "before-artifact",
        "before-completion",
        "completed",
    ] {
        let f = fixture();
        worker_inputs(&f);
        assert_eq!(child(&f, stage).wait().unwrap().code(), Some(77));
        let rows = records(&f.root).unwrap();
        if stage == "before-reservation" {
            assert!(rows.is_empty());
            run(&f).unwrap();
        } else {
            assert_eq!(
                rows[0].state,
                if stage == "completed" {
                    "completed"
                } else {
                    "reserved"
                }
            );
            let file = f
                .root
                .join("jobs")
                .join(token(&f.context).unwrap())
                .join("output.bin");
            assert_eq!(file.exists(), stage != "before-artifact");
            let before = fs::read(&file).ok();
            assert_eq!(run(&f).unwrap_err().code, Code::Replay);
            assert_eq!(before, fs::read(file).ok());
        }
    }
}
#[test]
fn clock_watermark_rejects_regression_transactionally() {
    let f = fixture();
    let mut c = connect(&f.root).unwrap();
    {
        let tx = c.transaction().unwrap();
        clock_floor(&tx, "test", 200).unwrap();
        tx.commit().unwrap();
    }
    {
        let tx = c.transaction().unwrap();
        assert!(clock_floor(&tx, "test", 199).is_err());
    }
    let tx = c.transaction().unwrap();
    clock_floor(&tx, "test", 200).unwrap();
    clock_floor(&tx, "test", 201).unwrap();
}
#[test]
fn restored_old_floor_requires_independent_minimum_revision() {
    let f = fixture();
    let (old, mut a) = trust(&f, 1);
    // Models a backup that lacks subsequent pins. An independently stored floor is essential.
    a.minimum_revision = 2;
    assert!(install_trust(&f.root, &old, &a).is_err());
    assert!(records(&f.root).unwrap().is_empty());
}
#[test]
fn root_handover_preserves_replay_and_retires_old_root() {
    use openproof_trust::RootTransition;
    let mut f = fixture();
    let (t, a) = trust(&f, 1);
    execute_trusted(
        &f.root,
        &f.bundle,
        &f.context,
        &f.policy,
        &f.args,
        &f.key,
        TrustInput {
            snapshot: &t,
            anchor: &a,
        },
    )
    .unwrap();
    let new_key = SigningKey::from_bytes(&[10; 32]);
    let transition = RootTransition {
        version: "openproof-root-transition/1".into(),
        audience: a.audience.clone(),
        old_root: a.root_key.clone(),
        new_root: hex::encode(new_key.verifying_key().to_bytes()),
        next_revision: 2,
        not_before: now().unwrap() - 1,
        expires_at: now().unwrap() + 100,
    };
    let old = sign(transition.clone(), &SigningKey::from_bytes(&[9; 32])).unwrap();
    let new = sign(transition, &new_key).unwrap();
    let mut payload = t.payload.clone();
    payload.revision = 2;
    let snapshot = sign(payload, &new_key).unwrap();
    let bad = sign(new.payload.clone(), &SigningKey::from_bytes(&[11; 32])).unwrap();
    assert!(rotate_root(&f.root, &old, &bad, &a, &snapshot).is_err());
    let next = rotate_root(&f.root, &old, &new, &a, &snapshot).unwrap();
    assert_eq!(
        execute_trusted(
            &f.root,
            &f.bundle,
            &f.context,
            &f.policy,
            &f.args,
            &f.key,
            TrustInput {
                snapshot: &snapshot,
                anchor: &next
            }
        )
        .unwrap_err()
        .code,
        Code::Replay
    );
    assert!(install_trust(&f.root, &t, &a).is_err());
    assert!(rotate_root(&f.root, &old, &new, &a, &snapshot).is_err());
    f.context.nonce = "after-rotation".into();
    f.bundle.authorization.payload.nonce = f.context.nonce.clone();
    resign(&mut f);
    execute_trusted(
        &f.root,
        &f.bundle,
        &f.context,
        &f.policy,
        &f.args,
        &f.key,
        TrustInput {
            snapshot: &snapshot,
            anchor: &next,
        },
    )
    .unwrap();
    assert_eq!(records(&f.root).unwrap().len(), 2);
}

#[test]
fn actual_backup_restore_loses_local_history_but_external_floor_rejects_stale_trust() {
    let f = fixture();
    let (old, anchor) = trust(&f, 1);
    install_trust(&f.root, &old, &anchor).unwrap();
    // All connections are closed: SQLite checkpoints/removes WAL on last connection close.
    let backup = f.root.join("backup.sqlite3");
    fs::copy(f.root.join("replay.sqlite3"), &backup).unwrap();
    let (new, _) = trust(&f, 2);
    execute_trusted(
        &f.root,
        &f.bundle,
        &f.context,
        &f.policy,
        &f.args,
        &f.key,
        TrustInput {
            snapshot: &new,
            anchor: &anchor,
        },
    )
    .unwrap();
    assert_eq!(records(&f.root).unwrap().len(), 1);
    fs::copy(backup, f.root.join("replay.sqlite3")).unwrap();
    // Honest limitation: the restored database no longer remembers consumption.
    assert!(records(&f.root).unwrap().is_empty());
    let external = Anchor {
        minimum_revision: 2,
        ..anchor
    };
    assert!(install_trust(&f.root, &old, &external).is_err());
    install_trust(&f.root, &new, &external).unwrap();
    // A fresh snapshot cannot reconstruct the lost operation ledger.
    assert!(records(&f.root).unwrap().is_empty());
}

#[test]
fn trusted_gate_rejects_clock_regression_before_consumption() {
    let f = fixture();
    let (t, a) = trust(&f, 1);
    install_trust(&f.root, &t, &a).unwrap();
    let namespace = sha256(&canonical(&(&a.root_key, &a.audience)).unwrap());
    let mut c = connect(&f.root).unwrap();
    {
        let tx = c.transaction().unwrap();
        clock_floor(&tx, &namespace, now().unwrap() + 600).unwrap();
        tx.commit().unwrap();
    }
    assert!(install_trust(&f.root, &t, &a).is_err());
    assert_eq!(
        execute_trusted(
            &f.root,
            &f.bundle,
            &f.context,
            &f.policy,
            &f.args,
            &f.key,
            TrustInput {
                snapshot: &t,
                anchor: &a
            }
        )
        .unwrap_err()
        .code,
        Code::InvalidEvidence
    );
    assert!(records(&f.root).unwrap().is_empty());
}
