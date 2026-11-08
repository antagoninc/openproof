//! Accelerated logical-time tests, not six weeks of elapsed operation or power-loss testing.
use ed25519_dalek::SigningKey;
use openproof_core::sign;
use openproof_witness::*;
use std::{
    fs,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};
struct Cleanup(PathBuf);
impl Drop for Cleanup {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn copy_tree(a: &Path, b: &Path) {
    fs::create_dir(b).unwrap();
    fs::set_permissions(b, fs::metadata(a).unwrap().permissions()).unwrap();
    for e in fs::read_dir(a).unwrap() {
        let e = e.unwrap();
        if e.file_type().unwrap().is_dir() {
            copy_tree(&e.path(), &b.join(e.file_name()));
        } else {
            fs::copy(e.path(), b.join(e.file_name())).unwrap();
        }
    }
}
#[test]
fn six_weeks_of_renewals_replay_and_restored_backup_reconciliation() {
    let base = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../outputs")
        .join(format!(
            "retention-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
    fs::create_dir_all(&base).unwrap();
    let _cleanup = Cleanup(base.clone());
    let receiver = base.join("receiver");
    let witness_state = base.join("witness");
    let verifier = base.join("verifier");
    init(&receiver).unwrap();
    init(&witness_state).unwrap();
    let authority = SigningKey::from_bytes(&[21; 32]);
    let rk = SigningKey::from_bytes(&[22; 32]);
    let wk = SigningKey::from_bytes(&[23; 32]);
    let root = SigningKey::from_bytes(&[24; 32]);
    let pk = |k: &SigningKey| hex::encode(k.verifying_key().to_bytes());
    let root_public = pk(&root);
    role_pin(&receiver, &root_public).unwrap();
    role_pin(&witness_state, &root_public).unwrap();
    verifier_init(&verifier, &root_public).unwrap();
    let mut t = Trust {
        version: V.into(),
        epoch: 1,
        expires_at: 1_800_086_399,
        authority: pk(&authority),
        receiver: pk(&rk),
        witness: pk(&wk),
        previous_authorities: vec![],
        revoked_authorities: vec![],
        owner_passkey: None,
    };
    let mut count = 0;
    let mut last = None;
    let mut old = None;
    for day in 0..42u64 {
        let time = 1_800_000_000 + day * 86400;
        t.epoch = day + 1;
        t.expires_at = time + 86399;
        let signed = sign(t.clone(), &root).unwrap();
        role_install(&receiver, &signed, &root_public, time).unwrap();
        role_install(&witness_state, &signed, &root_public, time).unwrap();
        verifier_install(&verifier, &signed, time).unwrap();
        if day == 0 {
            enable_pages(&receiver, &t, time).unwrap();
        }
        for n in 0..4 {
            let at = time + n;
            let content = format!("Public logical-day {day} update {n}");
            let request = Request {
                approval: sign(
                    Approval {
                        version: V.into(),
                        authority: t.authority.clone(),
                        document: "report".into(),
                        expected_version: count,
                        content_sha256: hash(content.as_bytes()),
                        nonce: format!("{count:064x}"),
                        receiver: t.receiver.clone(),
                        not_before: at,
                        expires_at: at + 300,
                    },
                    &authority,
                )
                .unwrap(),
                content,
                owner_assertion: None,
            };
            let receipt = apply(&receiver, &request, &t, &rk, at).unwrap();
            assert_eq!(
                apply(&receiver, &request, &t, &rk, at)
                    .unwrap()
                    .payload
                    .sequence,
                receipt.payload.sequence
            );
            count += 1;
            last = Some(witness(&witness_state, &receipt, &t, &wk, at).unwrap());
        }
        let cp = last.as_ref().unwrap();
        let page = export_page(
            &receiver,
            &t,
            cp.clone(),
            page_progress(&verifier).unwrap() + 1,
            time + 3,
        )
        .unwrap();
        assert!(
            verify_page(&verifier, &signed, cp, &page, time + 3)
                .unwrap()
                .checkpoint_complete
        );
        if day == 13 {
            copy_tree(&receiver, &base.join("restored-backup"));
            old = Some((signed.clone(), cp.clone(), page));
        }
        assert!(current_checkpoint(&witness_state, &t, &wk, time + 86400).is_err());
        // renewal is required next day
    }
    let at = 1_800_000_000 + 41 * 86400 + 3;
    let cp = last.unwrap();
    assert_eq!(count, 168);
    assert_eq!(head(&receiver).unwrap(), 168);
    assert_eq!(head(&base.join("restored-backup")).unwrap(), 56);
    assert!(export_page(&base.join("restored-backup"), &t, cp.clone(), 1, at).is_err());
    let (old_trust, old_cp, old_page) = old.unwrap();
    assert!(verify_page(&verifier, &old_trust, &old_cp, &old_page, at).is_err());
    assert_eq!(page_progress(&verifier).unwrap(), 168);
    let clean = base.join("fresh-offline-verifier");
    verifier_init(&clean, &root_public).unwrap();
    let signed = sign(t.clone(), &root).unwrap();
    loop {
        let start = page_progress(&clean).unwrap() + 1;
        let page = export_page(&receiver, &t, cp.clone(), start, at).unwrap();
        let result = verify_page(&clean, &signed, &cp, &page, at).unwrap();
        if result.checkpoint_complete {
            assert!(result.complete_history);
            break;
        }
    }
    assert_eq!(page_progress(&clean).unwrap(), 168);
}
