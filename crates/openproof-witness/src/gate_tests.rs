use super::*;
use p256::ecdsa::{signature::Signer, Signature, SigningKey as P256Key};
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

static N: AtomicU64 = AtomicU64::new(0);
const ORIGIN: &str = "http://localhost:8765";
const T: u64 = 100;

struct Home {
    dir: PathBuf,
    t: Trust,
    a: SigningKey,
}
impl Drop for Home {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

fn mkdir(path: &Path) {
    fs::create_dir(path).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
}

fn home(owner_passkey: Option<OwnerPasskey>) -> Home {
    let base = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../outputs/witness-test-temp");
    fs::create_dir_all(&base).unwrap();
    let dir = base.join(format!(
        "gate-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::SeqCst)
    ));
    mkdir(&dir);
    mkdir(&dir.join("authority"));
    mkdir(&dir.join("receiver"));
    init(&dir.join("receiver/state")).unwrap();
    let a = SigningKey::from_bytes(&[1; 32]);
    let public = |k: &SigningKey| hex::encode(k.verifying_key().to_bytes());
    let t = Trust {
        version: V.into(),
        epoch: 1,
        expires_at: 1000,
        authority: public(&a),
        previous_authorities: vec![],
        revoked_authorities: vec![],
        receiver: public(&SigningKey::from_bytes(&[2; 32])),
        witness: public(&SigningKey::from_bytes(&[3; 32])),
        owner_passkey,
    };
    Home { dir, t, a }
}

fn owner_key() -> P256Key {
    P256Key::from_slice(&[7u8; 32]).unwrap()
}

fn passkey() -> OwnerPasskey {
    let point = owner_key().verifying_key().to_sec1_point(false);
    OwnerPasskey {
        public_key: hex::encode(point.as_bytes()),
        rp_id: "localhost".into(),
        origin: ORIGIN.into(),
        from_sequence: 1,
    }
}

/// A software passkey assertion over `approval` (hex digest).
fn assertion(approval: &str, flags: u8) -> PasskeyAssertion {
    let challenge = URL_SAFE_NO_PAD.encode(hex::decode(approval).unwrap());
    let client = format!(
        "{{\"type\":\"webauthn.get\",\"challenge\":\"{challenge}\",\"origin\":\"{ORIGIN}\"}}"
    );
    let mut auth = Sha256::digest(b"localhost").to_vec();
    auth.push(flags);
    auth.extend_from_slice(&[0, 0, 0, 0]);
    let mut signed = auth.clone();
    signed.extend_from_slice(&Sha256::digest(client.as_bytes()));
    let signature: Signature = owner_key().sign(&signed);
    PasskeyAssertion {
        authenticator_data: URL_SAFE_NO_PAD.encode(auth),
        client_data_json: URL_SAFE_NO_PAD.encode(client),
        signature: URL_SAFE_NO_PAD.encode(signature.to_der().as_bytes()),
    }
}

fn proposal(content: &str) -> Proposal {
    Proposal {
        document: "report".into(),
        expected_version: 0,
        content: content.into(),
    }
}

fn propose(h: &Home, content: &str) -> String {
    gate_propose(&h.dir, &proposal(content), T).unwrap()["proposal_id"]
        .as_str()
        .unwrap()
        .to_string()
}

fn review(h: &Home, id: &str) -> String {
    gate_review(&h.dir, id, T).unwrap()["review_sha256"]
        .as_str()
        .unwrap()
        .to_string()
}

fn approve(h: &Home, id: &str) -> Result<Value> {
    gate_approve(&h.dir, &h.t, &h.a, id, &review(h, id), false, T)
}

fn state(h: &Home, id: &str) -> String {
    gate_approved(&h.dir, &h.t, id, T).unwrap()["state"]
        .as_str()
        .unwrap()
        .to_string()
}

fn stored(h: &Home, id: &str) -> Request {
    serde_json::from_value(gate_approved(&h.dir, &h.t, id, T).unwrap()["request"].clone()).unwrap()
}

fn db(h: &Home) -> Connection {
    Connection::open(h.dir.join("authority/gate/gate.db")).unwrap()
}

fn err(r: Result<Value>, needle: &str) {
    let e = r.unwrap_err().to_string();
    assert!(e.contains(needle), "{e} does not mention {needle}");
}

#[test]
fn approval_without_passkey_is_stored_once_and_executes() {
    let h = home(None);
    let id = propose(&h, "approved text");
    assert_eq!(state(&h, &id), "proposed");
    let review = gate_review(&h.dir, &id, T).unwrap();
    assert_eq!(review["proposal"]["content"], "approved text");
    assert_eq!(review["content_sha256"], hash(b"approved text"));
    assert_eq!(approve(&h, &id).unwrap()["state"], "approved");
    let q = stored(&h, &id);
    assert_eq!(q.content, "approved text");
    assert!(q.owner_assertion.is_none());
    let reviewed = proposal("approved text").review_sha256().unwrap();
    err(
        gate_approve(&h.dir, &h.t, &h.a, &id, &reviewed, false, T),
        "unavailable",
    );
    let list = gate_list(&h.dir, T).unwrap();
    assert_eq!(list["proposals"].as_array().unwrap().len(), 0);
    assert_eq!(list["approved"][0]["id"], id.as_str());
    let rk = SigningKey::from_bytes(&[2; 32]);
    apply(&h.dir.join("receiver/state"), &q, &h.t, &rk, T).unwrap();
}

#[test]
fn proposal_rules_and_unique_ids() {
    let h = home(None);
    for bad in [
        Proposal {
            document: "../outside".into(),
            ..proposal("x")
        },
        proposal(""),
        proposal(&"x".repeat(8193)),
        Proposal {
            expected_version: i64::MAX as u64,
            ..proposal("x")
        },
    ] {
        assert!(gate_propose(&h.dir, &bad, T).is_err());
    }
    assert_ne!(propose(&h, "same"), propose(&h, "same"));
    err(gate_review(&h.dir, "../authority/key.secret", T), "invalid");
    err(gate_review(&h.dir, &"0".repeat(64), T), "unavailable");
}

#[test]
fn wrong_reviewed_hash_is_refused() {
    let h = home(None);
    let id = propose(&h, "reviewed bytes");
    for reviewed in [
        hash(b"reviewed bytes"),
        proposal("other bytes").review_sha256().unwrap(),
        Proposal {
            expected_version: 1,
            ..proposal("reviewed bytes")
        }
        .review_sha256()
        .unwrap(),
    ] {
        err(
            gate_approve(&h.dir, &h.t, &h.a, &id, &reviewed, false, T),
            "changed",
        );
    }
    assert_eq!(state(&h, &id), "proposed");
}

#[test]
fn tampered_stored_proposal_is_refused() {
    let h = home(None);
    let id = propose(&h, "reviewed bytes");
    let reviewed = review(&h, &id);
    let changed = serde_json::to_string(&proposal("changed bytes")).unwrap();
    db(&h)
        .execute("UPDATE proposals SET proposal=?1", [&changed])
        .unwrap();
    err(gate_review(&h.dir, &id, T), "does not match");
    err(
        gate_approve(&h.dir, &h.t, &h.a, &id, &reviewed, false, T),
        "does not match",
    );
    assert_eq!(state(&h, &id), "proposed");
}

#[test]
fn approved_entries_not_written_by_the_gate_are_not_returned() {
    let h = home(None);
    let id = propose(&h, "genuine");
    approve(&h, &id).unwrap();
    let genuine = stored(&h, &id);
    // A file in the legacy folder is never read once the gate store exists.
    let other = propose(&h, "forged");
    mkdir(&h.dir.join("approved"));
    let mut forged = genuine.clone();
    forged.content = "forged".into();
    forged.approval.payload.content_sha256 = hash(b"forged");
    forged.approval = sign(forged.approval.payload, &SigningKey::from_bytes(&[9; 32])).unwrap();
    fs::write(
        h.dir.join("approved").join(format!("{other}.json")),
        serde_json::to_string(&genuine).unwrap(),
    )
    .unwrap();
    assert_eq!(state(&h, &other), "proposed");
    // Rows written straight into the store are checked when read.
    let insert = |q: &Request, salt: Option<&str>| {
        let c = db(&h);
        c.execute("DELETE FROM approved WHERE id=?1", [&other])
            .unwrap();
        c.execute(
            "INSERT INTO approved VALUES(?1,?2,?3)",
            params![other, serde_json::to_string(q).unwrap(), salt],
        )
        .unwrap();
    };
    insert(&forged, None);
    err(gate_approved(&h.dir, &h.t, &other, T), "signature");
    let attacker = SigningKey::from_bytes(&[9; 32]);
    forged.approval.payload.authority = hex::encode(attacker.verifying_key().to_bytes());
    forged.approval = sign(forged.approval.payload, &attacker).unwrap();
    insert(&forged, None);
    err(gate_approved(&h.dir, &h.t, &other, T), "trusted authority");
    let mut changed = genuine.clone();
    changed.content = "changed".into();
    insert(&changed, None);
    err(gate_approved(&h.dir, &h.t, &other, T), "content");
    let salt: String = db(&h)
        .query_row("SELECT salt FROM proposals WHERE id=?1", [&other], |r| {
            r.get(0)
        })
        .unwrap();
    insert(&genuine, Some(&salt));
    err(
        gate_approved(&h.dir, &h.t, &other, T),
        "does not match its proposal",
    );
    let mut asserted = genuine.clone();
    asserted.owner_assertion = Some(assertion(&digest(&genuine.approval.payload).unwrap(), 5));
    insert(&asserted, None);
    err(gate_approved(&h.dir, &h.t, &other, T), "unexpected");
}

#[test]
fn passkey_approval_is_pending_until_a_valid_assertion() {
    let h = home(Some(passkey()));
    let id = propose(&h, "passkey text");
    let r = approve(&h, &id).unwrap();
    assert_eq!(r["state"], "passkey_required");
    let digest = r["approval_sha256"].as_str().unwrap().to_string();
    assert_eq!(
        r["challenge"],
        URL_SAFE_NO_PAD.encode(hex::decode(&digest).unwrap())
    );
    // Pending is not executable and not listed as approved.
    assert_eq!(state(&h, &id), "awaiting_passkey");
    let list = gate_list(&h.dir, T).unwrap();
    assert_eq!(list["approved"].as_array().unwrap().len(), 0);
    assert_eq!(
        list["awaiting_passkey"][0]["approval_sha256"],
        digest.as_str()
    );
    // The terminal path refuses outright.
    err(
        gate_approve(&h.dir, &h.t, &h.a, &id, &review(&h, &id), true, T),
        "passkey required",
    );
    // A user-verification flag is required; a failed attempt changes nothing.
    err(
        gate_approve_passkey(&h.dir, &h.t, &id, &digest, &assertion(&digest, 1), T),
        "verification",
    );
    let ok = assertion(&digest, 5);
    gate_approve_passkey(&h.dir, &h.t, &id, &digest, &ok, T).unwrap();
    let q = stored(&h, &id);
    assert_eq!(q.owner_assertion, Some(ok.clone()));
    let rk = SigningKey::from_bytes(&[2; 32]);
    apply(&h.dir.join("receiver/state"), &q, &h.t, &rk, T).unwrap();
    // Replaying the same assertion finds no pending approval.
    err(
        gate_approve_passkey(&h.dir, &h.t, &id, &digest, &ok, T),
        "no pending approval",
    );
}

#[test]
fn assertion_for_another_digest_or_proposal_is_refused() {
    let h = home(Some(passkey()));
    let first = propose(&h, "first");
    let second = propose(&h, "second");
    let d1 = approve(&h, &first).unwrap()["approval_sha256"]
        .as_str()
        .unwrap()
        .to_string();
    let d2 = approve(&h, &second).unwrap()["approval_sha256"]
        .as_str()
        .unwrap()
        .to_string();
    err(
        gate_approve_passkey(&h.dir, &h.t, &first, &d1, &assertion(&d2, 5), T),
        "challenge",
    );
    err(
        gate_approve_passkey(&h.dir, &h.t, &second, &d1, &assertion(&d1, 5), T),
        "another proposal",
    );
    err(
        gate_approve_passkey(&h.dir, &h.t, &first, &hash(b"x"), &assertion(&d1, 5), T),
        "no pending approval",
    );
    let plain = Trust {
        owner_passkey: None,
        ..h.t.clone()
    };
    err(
        gate_approve_passkey(&h.dir, &plain, &first, &d1, &assertion(&d1, 5), T),
        "no owner passkey",
    );
    assert_eq!(state(&h, &first), "awaiting_passkey");
    gate_approve_passkey(&h.dir, &h.t, &first, &d1, &assertion(&d1, 5), T).unwrap();
    assert_eq!(state(&h, &first), "approved");
    assert_eq!(state(&h, &second), "awaiting_passkey");
}

#[test]
fn expired_pending_approval_is_refused() {
    let h = home(Some(passkey()));
    let id = propose(&h, "late");
    let digest = approve(&h, &id).unwrap()["approval_sha256"]
        .as_str()
        .unwrap()
        .to_string();
    let late = T + APPROVAL_WINDOW + 1;
    err(
        gate_approve_passkey(&h.dir, &h.t, &id, &digest, &assertion(&digest, 5), late),
        "expired",
    );
    assert_eq!(
        gate_approved(&h.dir, &h.t, &id, late).unwrap()["state"],
        "proposed"
    );
}

#[test]
fn passkey_cannot_be_dropped_from_the_trust() {
    let h = home(Some(passkey()));
    let id = propose(&h, "pinned");
    approve(&h, &id).unwrap();
    let plain = Trust {
        owner_passkey: None,
        ..h.t.clone()
    };
    err(
        gate_approve(&h.dir, &plain, &h.a, &id, &review(&h, &id), false, T),
        "removal",
    );
    // A fresh gate store still follows the receiver's pin.
    let fresh = home(None);
    install(&fresh.dir.join("receiver/state"), &h.t, T).unwrap();
    let id = propose(&fresh, "pinned");
    err(approve(&fresh, &id), "receiver's pinned passkey");
}

#[test]
fn links_and_open_permissions_are_refused() {
    let h = home(None);
    let id = propose(&h, "x");
    let gate = h.dir.join("authority/gate");
    fs::set_permissions(&gate, fs::Permissions::from_mode(0o755)).unwrap();
    err(gate_review(&h.dir, &id, T), "private");
    fs::set_permissions(&gate, fs::Permissions::from_mode(0o700)).unwrap();
    let db = gate.join("gate.db");
    fs::set_permissions(&db, fs::Permissions::from_mode(0o644)).unwrap();
    err(gate_review(&h.dir, &id, T), "private");
    fs::set_permissions(&db, fs::Permissions::from_mode(0o600)).unwrap();
    fs::rename(&db, gate.join("real.db")).unwrap();
    symlink(gate.join("real.db"), &db).unwrap();
    err(gate_review(&h.dir, &id, T), "regular file");
    fs::remove_file(&db).unwrap();
    fs::rename(gate.join("real.db"), &db).unwrap();
    fs::rename(&gate, h.dir.join("authority/elsewhere")).unwrap();
    symlink(h.dir.join("authority/elsewhere"), &gate).unwrap();
    err(gate_review(&h.dir, &id, T), "real directory");
    fs::set_permissions(h.dir.join("authority"), fs::Permissions::from_mode(0o755)).unwrap();
    err(gate_list(&h.dir, T), "private");
}

#[test]
fn earlier_homes_are_imported_once() {
    let h = home(None);
    for folder in ["proposals", "approved"] {
        mkdir(&h.dir.join(folder));
    }
    let p = proposal("legacy approved");
    let q = sign_approval(&p, &h.t, &h.a, T).unwrap();
    let approved_id = hash(b"legacy approved id");
    let pending_id = hash(b"legacy pending id");
    let write = |folder: &str, id: &str, value: String| {
        fs::write(h.dir.join(folder).join(format!("{id}.json")), value).unwrap()
    };
    write("approved", &approved_id, serde_json::to_string(&q).unwrap());
    write(
        "proposals",
        &pending_id,
        serde_json::to_string(&proposal("legacy pending")).unwrap(),
    );
    write("proposals", &hash(b"bad"), "{\"document\":\"../x\"}".into());
    symlink(
        h.dir.join("approved").join(format!("{approved_id}.json")),
        h.dir
            .join("approved")
            .join(format!("{}.json", hash(b"link"))),
    )
    .unwrap();
    assert_eq!(stored(&h, &approved_id).content, "legacy approved");
    let list = gate_list(&h.dir, T).unwrap();
    assert_eq!(list["proposals"].as_array().unwrap().len(), 1);
    assert_eq!(list["approved"].as_array().unwrap().len(), 1);
    assert_eq!(
        gate_review(&h.dir, &pending_id, T).unwrap()["proposal"]["content"],
        "legacy pending"
    );
    approve(&h, &pending_id).unwrap();
    assert_eq!(stored(&h, &pending_id).content, "legacy pending");
    // Files added after the import are ignored.
    let late = hash(b"late");
    write("approved", &late, serde_json::to_string(&q).unwrap());
    assert_eq!(state(&h, &late), "unknown");
}
