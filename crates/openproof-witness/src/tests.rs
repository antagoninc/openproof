use super::*;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
static N: AtomicU64 = AtomicU64::new(0);
struct Setup {
    dir: PathBuf,
    t: Trust,
    a: SigningKey,
    r: SigningKey,
    w: SigningKey,
}
impl Drop for Setup {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}
fn setup() -> Setup {
    let base = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../outputs/witness-test-temp");
    fs::create_dir_all(&base).unwrap();
    let d = base.join(format!(
        "openproof-witness-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::SeqCst)
    ));
    fs::create_dir(&d).unwrap();
    init(&d.join("receiver")).unwrap();
    init(&d.join("witness")).unwrap();
    let a = SigningKey::from_bytes(&[1; 32]);
    let r = SigningKey::from_bytes(&[2; 32]);
    let w = SigningKey::from_bytes(&[3; 32]);
    let t = Trust {
        version: V.into(),
        epoch: 1,
        expires_at: 1000,
        authority: hex::encode(a.verifying_key().to_bytes()),
        previous_authorities: vec![],
        revoked_authorities: vec![],
        receiver: hex::encode(r.verifying_key().to_bytes()),
        witness: hex::encode(w.verifying_key().to_bytes()),
    };
    Setup { dir: d, t, a, r, w }
}
fn request(s: &Setup, nonce: u8, version: u64) -> Request {
    let content = format!("document-{nonce}");
    Request {
        approval: sign(
            Approval {
                version: V.into(),
                authority: s.t.authority.clone(),
                document: "report".into(),
                expected_version: version,
                content_sha256: hash(content.as_bytes()),
                nonce: hex::encode([nonce; 32]),
                receiver: s.t.receiver.clone(),
                not_before: 90,
                expires_at: 200,
            },
            &s.a,
        )
        .unwrap(),
        content,
    }
}
fn receive(s: &Setup, q: &Request) -> Signed<Receipt> {
    apply(&s.dir.join("receiver"), q, &s.t, &s.r, 100).unwrap()
}
fn checkpoint(s: &Setup, r: &Signed<Receipt>) -> Signed<Checkpoint> {
    witness(&s.dir.join("witness"), r, &s.t, &s.w, 100).unwrap()
}
#[test]
fn observed_outcome_and_durable_idempotency() {
    let s = setup();
    let q = request(&s, 1, 0);
    let r = receive(&s, &q);
    let again = receive(&s, &q);
    assert_eq!(canonical(&r).unwrap(), canonical(&again).unwrap());
    assert_eq!(
        document(&s.dir.join("receiver"), "report").unwrap(),
        (1, q.content)
    );
    let c = checkpoint(&s, &r);
    let p = export(&s.dir.join("receiver"), c.clone()).unwrap();
    assert!(assess(&p, &s.t, &c, 100).unwrap().complete_history);
}
#[test]
fn tampered_content_scope_expiry_and_forgery_denied() {
    let s = setup();
    let q = request(&s, 1, 0);
    let mut bad = q.clone();
    bad.content.push('x');
    assert!(apply(&s.dir.join("receiver"), &bad, &s.t, &s.r, 100).is_err());
    bad = q.clone();
    bad.approval.payload.document = "elsewhere".into();
    assert!(apply(&s.dir.join("receiver"), &bad, &s.t, &s.r, 100).is_err());
    assert!(apply(&s.dir.join("receiver"), &q, &s.t, &s.r, 201).is_err());
    bad = q;
    bad.approval = sign(bad.approval.payload, &s.w).unwrap();
    assert!(apply(&s.dir.join("receiver"), &bad, &s.t, &s.r, 100).is_err());
}
#[test]
fn conflicting_version_and_nonce_rejected() {
    let s = setup();
    receive(&s, &request(&s, 1, 0));
    assert!(apply(&s.dir.join("receiver"), &request(&s, 2, 0), &s.t, &s.r, 100).is_err());
    assert!(apply(&s.dir.join("receiver"), &request(&s, 1, 1), &s.t, &s.r, 100).is_err());
}
#[test]
fn missing_reordered_truncated_and_equivocating_history() {
    let s = setup();
    let r1 = receive(&s, &request(&s, 1, 0));
    let c1 = checkpoint(&s, &r1);
    let r2 = receive(&s, &request(&s, 2, 1));
    let c2 = checkpoint(&s, &r2);
    let p = export(&s.dir.join("receiver"), c2.clone()).unwrap();
    let mut bad = p.clone();
    bad.receipts.remove(0);
    assert!(assess(&bad, &s.t, &c2, 100).is_err());
    bad = p.clone();
    bad.receipts.swap(0, 1);
    assert!(assess(&bad, &s.t, &c2, 100).is_err());
    bad = p.clone();
    bad.receipts.pop();
    bad.requests.pop();
    bad.checkpoint = c1;
    assert!(assess(&bad, &s.t, &c2, 100).is_err());
    let mut x = r2.payload;
    x.content_sha256 = ZERO.into();
    assert!(witness(
        &s.dir.join("witness"),
        &sign(x, &s.r).unwrap(),
        &s.t,
        &s.w,
        100
    )
    .is_err());
}
#[test]
fn witness_requires_receiver_signature_and_continuity() {
    let s = setup();
    let _ = receive(&s, &request(&s, 1, 0));
    let r = receive(&s, &request(&s, 2, 1));
    assert!(witness(&s.dir.join("witness"), &r, &s.t, &s.w, 100).is_err());
    assert!(witness(
        &s.dir.join("witness"),
        &sign(r.payload, &s.a).unwrap(),
        &s.t,
        &s.w,
        100
    )
    .is_err());
}
#[test]
fn explicit_gap_is_unknown_not_complete() {
    let s = setup();
    let r = gap(
        &s.dir.join("receiver"),
        "receiver records unavailable",
        &s.t,
        &s.r,
        100,
    )
    .unwrap();
    let c = checkpoint(&s, &r);
    let p = export(&s.dir.join("receiver"), c.clone()).unwrap();
    let a = assess(&p, &s.t, &c, 100).unwrap();
    assert!(!a.complete_history);
    assert_eq!(a.status, "unknown_due_to_disclosed_gap");
}
#[test]
fn rollback_revocation_and_expired_trust() {
    let s = setup();
    let q = request(&s, 1, 0);
    revoke(&s.dir.join("receiver"), &q.approval.payload.nonce).unwrap();
    assert!(apply(&s.dir.join("receiver"), &q, &s.t, &s.r, 100).is_err());
    let mut t = s.t.clone();
    t.epoch = 2;
    install(&s.dir.join("receiver"), &t, 100).unwrap();
    assert!(install(&s.dir.join("receiver"), &s.t, 100).is_err());
    assert!(install(&s.dir.join("receiver"), &t, 99).is_err());
    assert!(install(&s.dir.join("receiver"), &t, 1001).is_err());
}
#[test]
fn transaction_failure_rolls_back_document_and_nonce() {
    let s = setup();
    let q = request(&s, 1, 0);
    assert!(
        apply_inner(&s.dir.join("receiver"), &q, &s.t, &s.r, 100, || Err(
            "simulated crash before commit".into()
        ))
        .is_err()
    );
    assert!(document(&s.dir.join("receiver"), "report").is_err());
    assert_eq!(receive(&s, &q).payload.document_version, 1);
}
#[test]
fn process_exit_before_commit_rolls_back() {
    if let Ok(dir) = std::env::var("OPENPROOF_CRASH_TEST_DIR") {
        let mut s = setup();
        fs::remove_dir_all(&s.dir).unwrap();
        s.dir = PathBuf::from(dir);
        let _ = apply_inner(
            &s.dir.join("receiver"),
            &request(&s, 1, 0),
            &s.t,
            &s.r,
            100,
            || std::process::exit(19),
        );
        panic!("exit missing");
    }
    let s = setup();
    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "tests::process_exit_before_commit_rolls_back"])
        .env("OPENPROOF_CRASH_TEST_DIR", &s.dir)
        .status()
        .unwrap();
    assert_eq!(status.code(), Some(19));
    assert!(document(&s.dir.join("receiver"), "report").is_err());
    assert_eq!(receive(&s, &request(&s, 1, 0)).payload.document_version, 1);
}
#[test]
fn concurrent_duplicate_has_one_effect() {
    let s = setup();
    std::thread::scope(|scope| {
        let mut hs = vec![];
        for _ in 0..4 {
            hs.push(scope.spawn(|| receive(&s, &request(&s, 1, 0))));
        }
        for h in hs {
            assert_eq!(h.join().unwrap().payload.sequence, 1);
        }
    });
    assert_eq!(document(&s.dir.join("receiver"), "report").unwrap().0, 1);
}
#[test]
fn executor_claim_without_receiver_cannot_verify() {
    let s = setup();
    let r = receive(&s, &request(&s, 1, 0));
    let c = checkpoint(&s, &r);
    let mut p = export(&s.dir.join("receiver"), c.clone()).unwrap();
    p.receipts[0] = sign(p.receipts[0].payload.clone(), &s.a).unwrap();
    assert!(assess(&p, &s.t, &c, 100).is_err());
}
#[test]
fn strict_parse_duplicate_unknown_version() {
    assert!(openproof_core::parse::<Request>(b"{\"content\":\"x\",\"content\":\"y\"}").is_err());
    let s = setup();
    let mut q = request(&s, 1, 0);
    q.approval.payload.version = "unknown".into();
    assert!(sign(q.approval.payload, &s.a).is_err());
}
#[test]
fn process_exit_after_commit_reuses_receipt() {
    if let Ok(dir) = std::env::var("OPENPROOF_AFTER_COMMIT_TEST_DIR") {
        let mut s = setup();
        fs::remove_dir_all(&s.dir).unwrap();
        s.dir = PathBuf::from(dir);
        receive(&s, &request(&s, 1, 0));
        std::process::exit(23);
    }
    let s = setup();
    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "tests::process_exit_after_commit_reuses_receipt"])
        .env("OPENPROOF_AFTER_COMMIT_TEST_DIR", &s.dir)
        .status()
        .unwrap();
    assert_eq!(status.code(), Some(23));
    assert_eq!(receive(&s, &request(&s, 1, 0)).payload.sequence, 1);
    assert_eq!(document(&s.dir.join("receiver"), "report").unwrap().0, 1);
}
#[test]
fn authority_rotation_keeps_document_and_nonce_state() {
    let s = setup();
    let q = request(&s, 1, 0);
    receive(&s, &q);
    let new = SigningKey::from_bytes(&[7; 32]);
    let mut t = s.t.clone();
    t.epoch = 2;
    t.previous_authorities.push(t.authority.clone());
    t.authority = hex::encode(new.verifying_key().to_bytes());
    install(&s.dir.join("receiver"), &t, 100).unwrap();
    assert!(apply(&s.dir.join("receiver"), &q, &t, &s.r, 100).is_err());
    let mut next = request(&s, 2, 1);
    next.approval.payload.authority = t.authority.clone();
    next.approval = sign(next.approval.payload, &new).unwrap();
    assert_eq!(
        apply(&s.dir.join("receiver"), &next, &t, &s.r, 100)
            .unwrap()
            .payload
            .document_version,
        2
    );
}
#[test]
fn empty_signed_history_is_not_an_observed_document() {
    let s = setup();
    let c = sign(
        Checkpoint {
            version: V.into(),
            count: 0,
            head: ZERO.into(),
            observed_at: 100,
            receiver: s.t.receiver.clone(),
        },
        &s.w,
    )
    .unwrap();
    let p = Package {
        version: V.into(),
        requests: vec![],
        receipts: vec![],
        checkpoint: c.clone(),
    };
    assert!(assess(&p, &s.t, &c, 100).is_err());
}
#[test]
fn retired_authority_history_valid_until_explicit_revocation() {
    let s = setup();
    let r = receive(&s, &request(&s, 1, 0));
    checkpoint(&s, &r);
    let k = SigningKey::from_bytes(&[7; 32]);
    let mut t = s.t.clone();
    t.epoch = 2;
    t.previous_authorities.push(t.authority.clone());
    t.authority = hex::encode(k.verifying_key().to_bytes());
    let mut q = request(&s, 2, 1);
    q.approval.payload.authority = t.authority.clone();
    q.approval = sign(q.approval.payload, &k).unwrap();
    let r2 = apply(&s.dir.join("receiver"), &q, &t, &s.r, 100).unwrap();
    let cp = witness(&s.dir.join("witness"), &r2, &t, &s.w, 100).unwrap();
    let p = export(&s.dir.join("receiver"), cp.clone()).unwrap();
    assert!(assess(&p, &t, &cp, 100).unwrap().complete_history);
    t.revoked_authorities.push(s.t.authority.clone());
    assert!(assess(&p, &t, &cp, 100).is_err());
}
#[test]
fn bounded_history_rejects_before_effect_and_preserves_retry() {
    let s = setup();
    let mut last = None;
    let mut rejected = false;
    for i in 0..180u64 {
        let mut q = request(&s, (i + 1) as u8, i);
        q.content = "\"\\\n\u{1b}é".repeat(1000);
        q.approval.payload.content_sha256 = hash(q.content.as_bytes());
        q.approval = sign(q.approval.payload, &s.a).unwrap();
        match apply(&s.dir.join("receiver"), &q, &s.t, &s.r, 100) {
            Ok(r) => last = Some((q, r)),
            Err(e) => {
                assert!(e.to_string().contains("capacity") || e.to_string().contains("large"));
                assert_eq!(document(&s.dir.join("receiver"), "report").unwrap().0, i);
                assert_eq!(head(&s.dir.join("receiver")).unwrap(), i);
                assert!(recover(&s.dir.join("receiver"), &q).unwrap().is_none());
                rejected = true;
                break;
            }
        }
    }
    assert!(rejected);
    let (q, r) = last.unwrap();
    assert_eq!(receive(&s, &q).payload.sequence, r.payload.sequence);
    let cp = sign(
        Checkpoint {
            version: V.into(),
            count: r.payload.sequence,
            head: digest(&r.payload).unwrap(),
            observed_at: 100,
            receiver: s.t.receiver.clone(),
        },
        &s.w,
    )
    .unwrap();
    let p = export(&s.dir.join("receiver"), cp.clone()).unwrap();
    assert!(serde_json::to_vec_pretty(&p).unwrap().len() < 1_048_576);
    assert!(assess(&p, &s.t, &cp, 100).is_ok());
    // Gap insertion shares the same admission budget and must roll back on exhaustion.
    let mut gap_rejected = false;
    for _ in 0..30 {
        let before = head(&s.dir.join("receiver")).unwrap();
        if gap(&s.dir.join("receiver"), &"x".repeat(512), &s.t, &s.r, 100).is_err() {
            assert_eq!(head(&s.dir.join("receiver")).unwrap(), before);
            gap_rejected = true;
            break;
        }
    }
    assert!(gap_rejected);
}
#[test]
fn recover_expired_retired_and_revoked_receipt_without_dispatch() {
    let s = setup();
    let q = request(&s, 1, 0);
    let r = receive(&s, &q);
    assert!(apply(&s.dir.join("receiver"), &q, &s.t, &s.r, 201).is_err());
    let saved = recover(&s.dir.join("receiver"), &q).unwrap().unwrap();
    let fresh = witness(&s.dir.join("witness"), &saved, &s.t, &s.w, 201).unwrap();
    let expired_history = export(&s.dir.join("receiver"), fresh.clone()).unwrap();
    assert!(assess(&expired_history, &s.t, &fresh, 201).is_ok());
    let mut t = s.t.clone();
    t.epoch = 2;
    t.revoked_authorities.push(t.authority.clone());
    t.previous_authorities.push(t.authority.clone());
    t.authority = hex::encode(SigningKey::from_bytes(&[7; 32]).verifying_key().to_bytes());
    install(&s.dir.join("receiver"), &t, 201).unwrap();
    assert!(apply(&s.dir.join("receiver"), &q, &t, &s.r, 201).is_err());
    let saved = recover(&s.dir.join("receiver"), &q).unwrap().unwrap();
    assert_eq!(canonical(&saved).unwrap(), canonical(&r).unwrap());
    assert_eq!(head(&s.dir.join("receiver")).unwrap(), 1);
    let cp = witness(&s.dir.join("witness"), &saved, &t, &s.w, 201).unwrap();
    let p = export(&s.dir.join("receiver"), cp.clone()).unwrap();
    assert!(assess(&p, &t, &cp, 201).is_err()); // Recovery cannot bypass historical revocation.
    let mut bad = q.clone();
    bad.content.push('x');
    assert!(recover(&s.dir.join("receiver"), &bad).is_err());
    bad = q.clone();
    bad.approval.payload.document = "other".into();
    bad.approval = sign(bad.approval.payload, &s.a).unwrap();
    assert!(recover(&s.dir.join("receiver"), &bad).is_err());
    let missing = request(&s, 2, 1);
    assert!(recover(&s.dir.join("receiver"), &missing)
        .unwrap()
        .is_none());
    assert!(apply(&s.dir.join("receiver"), &missing, &s.t, &s.r, 201).is_err());
}
#[test]
fn older_checkpoint_exports_exact_prefix_despite_later_commit() {
    let s = setup();
    let r = receive(&s, &request(&s, 1, 0));
    let cp = checkpoint(&s, &r);
    receive(&s, &request(&s, 2, 1));
    let p = export(&s.dir.join("receiver"), cp.clone()).unwrap();
    assert_eq!(p.receipts.len(), 1);
    assert!(assess(&p, &s.t, &cp, 100).is_ok());
    let mut bad = cp.clone();
    bad.payload.head = ZERO.into();
    assert!(export(&s.dir.join("receiver"), bad).is_err());
    bad = cp;
    bad.payload.count = 3;
    assert!(export(&s.dir.join("receiver"), bad).is_err());
}
#[test]
fn indexed_requests_preserve_duplicate_and_unrelated_rejection() {
    let s = setup();
    let r = receive(&s, &request(&s, 1, 0));
    let cp = checkpoint(&s, &r);
    let p = export(&s.dir.join("receiver"), cp.clone()).unwrap();
    let mut bad = p.clone();
    bad.requests.push(bad.requests[0].clone());
    assert!(assess(&bad, &s.t, &cp, 100).is_err());
    bad = p;
    bad.requests.push(request(&s, 2, 1));
    assert!(assess(&bad, &s.t, &cp, 100).is_err());
}
fn verifier_setup(s: &Setup) -> (PathBuf, SigningKey, Signed<Trust>) {
    let path = s.dir.join("verifier");
    let root = SigningKey::from_bytes(&[9; 32]);
    verifier_init(&path, &hex::encode(root.verifying_key().to_bytes())).unwrap();
    let signed = sign(s.t.clone(), &root).unwrap();
    (path, root, signed)
}
#[test]
fn signed_trust_rejects_forgery_rollback_and_same_epoch_change() {
    let s = setup();
    let (v, root, t) = verifier_setup(&s);
    verifier_install(&v, &t, 100).unwrap();
    let mut changed = s.t.clone();
    changed.expires_at += 1;
    assert!(verifier_install(&v, &sign(changed.clone(), &root).unwrap(), 100).is_err());
    changed.epoch = 2;
    assert!(verifier_install(&v, &sign(changed.clone(), &s.a).unwrap(), 100).is_err());
    verifier_install(&v, &sign(changed, &root).unwrap(), 100).unwrap();
    assert!(verifier_install(&v, &t, 100).is_err());
    assert!(verifier_init(&v, &hex::encode(s.a.verifying_key().to_bytes())).is_err());
}
#[test]
fn rejected_revoked_package_still_advances_verifier_trust_floor() {
    let s = setup();
    let (v, root, t) = verifier_setup(&s);
    let r = receive(&s, &request(&s, 1, 0));
    let cp = checkpoint(&s, &r);
    let p = export(&s.dir.join("receiver"), cp.clone()).unwrap();
    verify_trusted(&v, &t, &cp, &p, 100).unwrap();
    let mut revoked = s.t.clone();
    revoked.epoch = 2;
    revoked.previous_authorities.push(revoked.authority.clone());
    revoked.revoked_authorities.push(revoked.authority.clone());
    revoked.authority = hex::encode(SigningKey::from_bytes(&[7; 32]).verifying_key().to_bytes());
    assert!(verify_trusted(&v, &sign(revoked, &root).unwrap(), &cp, &p, 100).is_err());
    assert!(verify_trusted(&v, &t, &cp, &p, 100).is_err());
}
#[test]
fn verifier_rejects_old_checkpoint_and_signed_fork() {
    let s = setup();
    let (v, _root, t) = verifier_setup(&s);
    let r1 = receive(&s, &request(&s, 1, 0));
    let cp1 = checkpoint(&s, &r1);
    let p1 = export(&s.dir.join("receiver"), cp1.clone()).unwrap();
    verify_trusted(&v, &t, &cp1, &p1, 100).unwrap();
    let r2 = receive(&s, &request(&s, 2, 1));
    let cp2 = checkpoint(&s, &r2);
    let p2 = export(&s.dir.join("receiver"), cp2.clone()).unwrap();
    verify_trusted(&v, &t, &cp2, &p2, 100).unwrap();
    assert!(verify_trusted(&v, &t, &cp1, &p1, 100).is_err());
    // A separately signed, internally valid alternative history must not replace prefix.
    let mut fork = p2.clone();
    fork.requests[0].content = "fork".into();
    fork.requests[0].approval.payload.content_sha256 = hash(b"fork");
    fork.requests[0].approval = sign(fork.requests[0].approval.payload.clone(), &s.a).unwrap();
    fork.receipts[0].payload.content_sha256 = hash(b"fork");
    fork.receipts[0].payload.approval_sha256 = digest(&fork.requests[0].approval.payload).unwrap();
    fork.receipts[0] = sign(fork.receipts[0].payload.clone(), &s.r).unwrap();
    fork.receipts[1].payload.previous = digest(&fork.receipts[0].payload).unwrap();
    fork.receipts[1] = sign(fork.receipts[1].payload.clone(), &s.r).unwrap();
    fork.checkpoint.payload.head = digest(&fork.receipts[1].payload).unwrap();
    fork.checkpoint = sign(fork.checkpoint.payload.clone(), &s.w).unwrap();
    assert!(assess(&fork, &s.t, &fork.checkpoint, 100).is_ok());
    assert!(verify_trusted(&v, &t, &fork.checkpoint, &fork, 100).is_err());
    assert!(verify_trusted(&v, &t, &cp2, &p2, 401).is_err());
}
#[test]
fn verified_export_requires_actual_witness_signature() {
    let s = setup();
    let r = receive(&s, &request(&s, 1, 0));
    let cp = checkpoint(&s, &r);
    assert!(export_verified(&s.dir.join("receiver"), &s.t, cp.clone(), 100).is_ok());
    let wrong = sign(cp.payload, &s.a).unwrap();
    assert!(export_verified(&s.dir.join("receiver"), &s.t, wrong, 100).is_err());
}
#[test]
fn trust_lists_are_unambiguous_and_gaps_have_no_version_continuity_claim() {
    let s = setup();
    let mut t = s.t.clone();
    t.previous_authorities.push(t.authority.clone());
    assert!(t.validate(100).is_err());
    t = s.t.clone();
    let old = hex::encode(SigningKey::from_bytes(&[7; 32]).verifying_key().to_bytes());
    t.previous_authorities = vec![old.clone(), old.clone()];
    assert!(t.validate(100).is_err());
    t.previous_authorities.pop();
    t.revoked_authorities.push(old);
    assert!(t.validate(100).is_ok());
    let r = gap(&s.dir.join("receiver"), "unknown", &s.t, &s.r, 100).unwrap();
    let cp = checkpoint(&s, &r);
    let p = export(&s.dir.join("receiver"), cp.clone()).unwrap();
    assert!(
        !assess(&p, &s.t, &cp, 100)
            .unwrap()
            .document_version_continuity_verified
    );
}
#[test]
fn clock_repair_preserves_history_and_refuses_signed_future() {
    let s = setup();
    let q = request(&s, 1, 0);
    let r = receive(&s, &q);
    checkpoint(&s, &r);
    install(&s.dir.join("receiver"), &s.t, 900).unwrap();
    let repaired = repair_clock(&s.dir.join("receiver"), &s.t, &s.a, 110).unwrap();
    verify_signature(&repaired, &s.t.authority).unwrap();
    assert_eq!(repaired.payload.signed_floor, 100);
    assert_eq!(head(&s.dir.join("receiver")).unwrap(), 1);
    assert!(recover(&s.dir.join("receiver"), &q).unwrap().is_some());
    assert_eq!(
        apply(&s.dir.join("receiver"), &q, &s.t, &s.r, 110)
            .unwrap()
            .payload
            .sequence,
        1
    );
}
#[test]
fn clock_repair_never_rewinds_emitted_checkpoint_or_verifier() {
    let s = setup();
    let r = receive(&s, &request(&s, 1, 0));
    witness(&s.dir.join("witness"), &r, &s.t, &s.w, 500).unwrap();
    assert!(repair_clock(&s.dir.join("witness"), &s.t, &s.a, 110).is_err());
    assert_eq!(
        clock_status(&s.dir.join("witness"), 110)
            .unwrap()
            .signed_floor,
        500
    );
    let (v, _, t) = verifier_setup(&s);
    verifier_install(&v, &t, 500).unwrap();
    assert!(repair_clock(&v, &s.t, &s.a, 110).is_err());
}
#[test]
fn anchored_role_denies_unsigned_epoch_poisoning_and_fake_authority() {
    let s = setup();
    let root = SigningKey::from_bytes(&[9; 32]);
    let pubkey = hex::encode(root.verifying_key().to_bytes());
    let path = s.dir.join("receiver");
    role_pin(&path, &pubkey).unwrap();
    assert!(install(&path, &s.t, 100).is_err());
    role_install(&path, &sign(s.t.clone(), &root).unwrap(), &pubkey, 100).unwrap();
    let attacker = SigningKey::from_bytes(&[7; 32]);
    let mut bad = s.t.clone();
    bad.epoch = i64::MAX as u64;
    bad.authority = hex::encode(attacker.verifying_key().to_bytes());
    let mut q = request(&s, 1, 0);
    q.approval.payload.authority = bad.authority.clone();
    q.approval = sign(q.approval.payload, &attacker).unwrap();
    assert!(apply(&path, &q, &bad, &s.r, 100).is_err());
    assert!(install(&path, &bad, 100).is_err());
    assert_eq!(head(&path).unwrap(), 0);
    assert!(role_install(&path, &sign(bad, &attacker).unwrap(), &pubkey, 100).is_err());
    assert!(role_pin(&path, &hex::encode(attacker.verifying_key().to_bytes())).is_err());
    receive(&s, &request(&s, 2, 0));
}
#[test]
fn verifier_root_clock_repair_preserves_pins_and_revocation_floor() {
    let s = setup();
    let (v, root, t) = verifier_setup(&s);
    let r = receive(&s, &request(&s, 1, 0));
    let cp = checkpoint(&s, &r);
    let p = export(&s.dir.join("receiver"), cp.clone()).unwrap();
    verify_trusted(&v, &t, &cp, &p, 100).unwrap();
    verifier_install(&v, &t, 900).unwrap();
    assert!(verify_trusted(&v, &t, &cp, &p, 110).is_err());
    assert!(repair_verifier_clock(&v, &t, &s.a, 110).is_err());
    let audit = repair_verifier_clock(&v, &t, &root, 110).unwrap();
    verify_signature(&audit, &hex::encode(root.verifying_key().to_bytes())).unwrap();
    assert_eq!(audit.payload.count, 1);
    verify_trusted(&v, &t, &cp, &p, 110).unwrap();
    verifier_install(&v, &t, 900).unwrap();
    assert!(repair_verifier_clock(&v, &t, &root, 99).is_err());
}
#[test]
fn read_only_legacy_inspection_does_not_install_schema() {
    let s = setup();
    let q = request(&s, 1, 0);
    receive(&s, &q);
    let path = s.dir.join("receiver");
    let c = Connection::open(path.join("state.db")).unwrap();
    c.execute_batch("DROP TABLE signing_clock; DROP TABLE clock_repairs;")
        .unwrap();
    drop(c);
    assert!(recover(&path, &q).unwrap().is_some());
    assert_eq!(head(&path).unwrap(), 1);
    assert_eq!(document(&path, "report").unwrap().0, 1);
    clock_status(&path, 100).unwrap();
    stored_receipt(&path, 1).unwrap();
    let c = Connection::open_with_flags(
        path.join("state.db"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .unwrap();
    let n: u64 = c
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE name IN ('signing_clock','clock_repairs')",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(n, 0);
}
#[test]
fn signing_ledger_refuses_conflicting_or_older_trust() {
    let s = setup();
    let root = SigningKey::from_bytes(&[9; 32]);
    let path = s.dir.join("signer");
    signer_init(&path, &hex::encode(root.verifying_key().to_bytes())).unwrap();
    let first = sign_trust_tracked(&path, s.t.clone(), &root, 100).unwrap();
    assert_eq!(
        canonical(&first).unwrap(),
        canonical(&sign_trust_tracked(&path, s.t.clone(), &root, 100).unwrap()).unwrap()
    );
    let mut conflict = s.t.clone();
    conflict.expires_at += 1;
    assert!(sign_trust_tracked(&path, conflict.clone(), &root, 100).is_err());
    conflict.epoch = 2;
    sign_trust_tracked(&path, conflict, &root, 100).unwrap();
    let mut older = s.t.clone();
    older.expires_at += 2;
    assert!(sign_trust_tracked(&path, older, &root, 100).is_err());
}
#[test]
fn offline_root_repair_token_is_bound_fresh_and_single_use() {
    let s = setup();
    let (v, root, t) = verifier_setup(&s);
    let r = receive(&s, &request(&s, 1, 0));
    let cp = checkpoint(&s, &r);
    let p = export(&s.dir.join("receiver"), cp.clone()).unwrap();
    verify_trusted(&v, &t, &cp, &p, 100).unwrap();
    verifier_install(&v, &t, 900).unwrap();
    let request = verifier_clock_request(&v, 110).unwrap();
    let token = sign(request, &root).unwrap();
    let fake = sign(verifier_clock_request(&v, 110).unwrap(), &s.a).unwrap();
    assert!(apply_verifier_clock_repair(&v, &t, &fake, 110).is_err());
    assert!(apply_verifier_clock_repair(&v, &t, &token, 109).is_err());
    assert!(apply_verifier_clock_repair(&v, &t, &token, 711).is_err());
    apply_verifier_clock_repair(&v, &t, &token, 110).unwrap();
    assert!(apply_verifier_clock_repair(&v, &t, &token, 110).is_err());
    verify_trusted(&v, &t, &cp, &p, 110).unwrap();
}
#[test]
fn pages_cross_legacy_limit_and_reject_order_tamper_replay() {
    let s = setup();
    let (v, _root, t) = verifier_setup(&s);
    let receiver = s.dir.join("receiver");
    enable_pages(&receiver, &s.t, 100).unwrap();
    let mut cp = None;
    for i in 0..150 {
        let mut q = request(&s, (i + 1) as u8, i);
        q.content = "é\\\n\"".repeat(1200);
        q.approval.payload.content_sha256 = hash(q.content.as_bytes());
        q.approval = sign(q.approval.payload, &s.a).unwrap();
        let r = receive(&s, &q);
        cp = Some(checkpoint(&s, &r));
    }
    let cp = cp.unwrap();
    let first = export_page(&receiver, &s.t, cp.clone(), 1, 100).unwrap();
    let mut bad = first.clone();
    bad.receipts[0].payload.content_sha256 = ZERO.into();
    assert!(verify_page(&v, &t, &cp, &bad, 100).is_err());
    assert_eq!(page_progress(&v).unwrap(), 0);
    let later = export_page(
        &receiver,
        &s.t,
        cp.clone(),
        first.receipts.len() as u64 + 1,
        100,
    )
    .unwrap();
    assert!(verify_page(&v, &t, &cp, &later, 100).is_err());
    let result = verify_page(&v, &t, &cp, &first, 100).unwrap();
    assert!(!result.checkpoint_complete);
    assert!(!result.complete_history);
    assert!(verify_page(&v, &t, &cp, &first, 100).is_err());
    reset_pages(&v).unwrap();
    assert_eq!(page_progress(&v).unwrap(), 0);
    while page_progress(&v).unwrap() < cp.payload.count {
        let page = export_page(
            &receiver,
            &s.t,
            cp.clone(),
            page_progress(&v).unwrap() + 1,
            100,
        )
        .unwrap();
        assert!(serde_json::to_vec_pretty(&page).unwrap().len() <= 512 * 1024);
        verify_page(&v, &t, &cp, &page, 100).unwrap();
    }
    assert_eq!(page_progress(&v).unwrap(), 150);
    reset_pages(&v).unwrap();
    assert_eq!(page_progress(&v).unwrap(), 150);
    let empty = HistoryPage {
        version: PAGE_VERSION.into(),
        start: 151,
        requests: vec![],
        receipts: vec![],
        checkpoint: cp.clone(),
    };
    assert!(
        verify_page(&v, &t, &cp, &empty, 100)
            .unwrap()
            .checkpoint_complete
    );
}
#[test]
fn planned_rotation_keeps_history_nonces_and_retires_old_root() {
    let s = setup();
    let (v, root, old) = verifier_setup(&s);
    let receiver = s.dir.join("receiver");
    let witness_path = s.dir.join("witness");
    let roothex = hex::encode(root.verifying_key().to_bytes());
    for path in [&receiver, &witness_path] {
        role_pin(path, &roothex).unwrap();
        role_install(path, &old, &roothex, 100).unwrap();
    }
    enable_pages(&receiver, &s.t, 100).unwrap();
    let q = request(&s, 1, 0);
    let r = receive(&s, &q);
    let cp = checkpoint(&s, &r);
    let page = export_page(&receiver, &s.t, cp.clone(), 1, 100).unwrap();
    verify_page(&v, &old, &cp, &page, 100).unwrap();
    let newroot = SigningKey::from_bytes(&[10; 32]);
    let newreceiver = SigningKey::from_bytes(&[11; 32]);
    let newwitness = SigningKey::from_bytes(&[12; 32]);
    let mut nt = s.t.clone();
    nt.epoch = 2;
    nt.receiver = hex::encode(newreceiver.verifying_key().to_bytes());
    nt.witness = hex::encode(newwitness.verifying_key().to_bytes());
    let proposal = Rotation {
        version: "openproof-rotation/1".into(),
        old_root: roothex.clone(),
        new_root: hex::encode(newroot.verifying_key().to_bytes()),
        old_trust_sha256: hash(&canonical(&s.t).unwrap()),
        new_trust: nt.clone(),
        checkpoint: cp.clone(),
        not_before: 100,
        expires_at: 200,
    };
    let handover = Handover {
        old_root: sign(proposal.clone(), &root).unwrap(),
        new_root: sign(proposal.clone(), &newroot).unwrap(),
        old_receiver: sign(proposal.clone(), &s.r).unwrap(),
        new_receiver: sign(proposal.clone(), &newreceiver).unwrap(),
        old_witness: sign(proposal.clone(), &s.w).unwrap(),
        new_witness: sign(proposal, &newwitness).unwrap(),
    };
    let mut bad = handover.clone();
    bad.new_witness = sign(bad.new_witness.payload, &s.a).unwrap();
    assert!(rotate_state(&v, &old, &bad, 100).is_err());
    assert!(rotate_state(&v, &old, &handover, 201).is_err());
    for path in [&receiver, &witness_path, &v] {
        assert!(!rotation_applied(path, &handover).unwrap());
        rotate_state(path, &old, &handover, 100).unwrap();
        assert!(rotation_applied(path, &handover).unwrap());
        assert!(rotation_applied(path, &bad).is_err());
        assert!(rotate_state(path, &old, &handover, 100).is_err());
    }
    assert!(role_install(&receiver, &old, &roothex, 100).is_err());
    assert!(recover(&receiver, &q).unwrap().is_some());
    let mut next = request(&s, 2, 1);
    next.approval.payload.receiver = nt.receiver.clone();
    next.approval = sign(next.approval.payload, &s.a).unwrap();
    assert!(apply(&receiver, &next, &nt, &s.r, 100).is_err());
    let r2 = apply(&receiver, &next, &nt, &newreceiver, 100).unwrap();
    assert_eq!(r2.payload.sequence, 2);
    let cp2 = witness(&witness_path, &r2, &nt, &newwitness, 100).unwrap();
    let page2 = export_page(&receiver, &nt, cp2.clone(), 2, 100).unwrap();
    let signednew = sign(nt, &newroot).unwrap();
    assert!(
        verify_page(&v, &signednew, &cp2, &page2, 100)
            .unwrap()
            .checkpoint_complete
    );
    assert_eq!(document(&receiver, "report").unwrap().0, 2);
}

#[test]
fn pages_reject_signed_cross_page_nonce_version_and_revocation() {
    let s = setup();
    let (v, root, t) = verifier_setup(&s);
    let r1 = receive(&s, &request(&s, 1, 0));
    checkpoint(&s, &r1);
    let r2 = receive(&s, &request(&s, 2, 1));
    let cp = checkpoint(&s, &r2);
    let mut first = export_page(&s.dir.join("receiver"), &s.t, cp.clone(), 1, 100).unwrap();
    first.receipts.truncate(1);
    first.requests.truncate(1);
    verify_page(&v, &t, &cp, &first, 100).unwrap();
    let second = export_page(&s.dir.join("receiver"), &s.t, cp.clone(), 2, 100).unwrap();
    for duplicate_nonce in [true, false] {
        let mut bad = second.clone();
        let a = &mut bad.requests[0].approval.payload;
        if duplicate_nonce {
            a.nonce = first.requests[0].approval.payload.nonce.clone();
        } else {
            a.expected_version = 99;
        }
        bad.requests[0].approval = sign(a.clone(), &s.a).unwrap();
        bad.receipts[0].payload.approval_sha256 =
            digest(&bad.requests[0].approval.payload).unwrap();
        bad.receipts[0].payload.document_version =
            bad.requests[0].approval.payload.expected_version + 1;
        bad.receipts[0] = sign(bad.receipts[0].payload.clone(), &s.r).unwrap();
        bad.checkpoint.payload.head = digest(&bad.receipts[0].payload).unwrap();
        bad.checkpoint = sign(bad.checkpoint.payload.clone(), &s.w).unwrap();
        assert!(verify_page(&v, &t, &bad.checkpoint, &bad, 100).is_err());
        assert_eq!(page_progress(&v).unwrap(), 1);
    }
    let mut revoked = s.t.clone();
    revoked.epoch = 2;
    revoked.authority = hex::encode(SigningKey::from_bytes(&[40; 32]).verifying_key().to_bytes());
    revoked.revoked_authorities.push(s.t.authority.clone());
    let revoked = sign(revoked, &root).unwrap();
    assert!(verify_page(&v, &revoked, &cp, &second, 100).is_err());
    assert_eq!(trust_floor(&v).unwrap(), 2);
    assert!(verify_page(&v, &t, &cp, &second, 100).is_err());
}

#[test]
fn refreshed_checkpoint_preserves_count_and_rejects_wrong_key_or_clock() {
    let s = setup();
    let r = receive(&s, &request(&s, 1, 0));
    let old = checkpoint(&s, &r);
    let refreshed = current_checkpoint(&s.dir.join("witness"), &s.t, &s.w, 110).unwrap();
    assert_eq!(refreshed.payload.count, old.payload.count);
    assert_eq!(refreshed.payload.head, old.payload.head);
    assert_eq!(refreshed.payload.observed_at, 110);
    assert!(current_checkpoint(&s.dir.join("witness"), &s.t, &s.r, 111).is_err());
    assert!(current_checkpoint(&s.dir.join("witness"), &s.t, &s.w, 109).is_err());
}
