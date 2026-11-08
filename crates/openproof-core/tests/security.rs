use ed25519_dalek::{Signer, SigningKey};
use openproof_core::*;
fn keys() -> [SigningKey; 3] {
    [
        SigningKey::from_bytes(&[1; 32]),
        SigningKey::from_bytes(&[2; 32]),
        SigningKey::from_bytes(&[3; 32]),
    ]
}
fn fixture() -> (Bundle, Context) {
    let [authority, actor, executor] = keys();
    let pk = |k: &SigningKey| hex::encode(k.verifying_key().to_bytes());
    let spec = ActionSpec {
        tool: "echo".into(),
        resource: "urn:test".into(),
        arguments_sha256: "aa".repeat(32),
    };
    let c = Context {
        authority_key: pk(&authority),
        actor_key: pk(&actor),
        executor_key: pk(&executor),
        run_id: "run".into(),
        nonce: "unique".into(),
        audience: "test".into(),
        policy_sha256: "bb".repeat(32),
        expected_action: spec.clone(),
        now: 100,
    };
    let a = Authorization {
        version: VERSION.into(),
        run_id: c.run_id.clone(),
        nonce: c.nonce.clone(),
        audience: c.audience.clone(),
        actor_key: c.actor_key.clone(),
        policy_sha256: c.policy_sha256.clone(),
        action: spec.clone(),
        not_before: 90,
        expires_at: 110,
    };
    let x = Action {
        version: VERSION.into(),
        authorization_sha256: digest(&a).unwrap(),
        action: spec,
        claimed_at: 95,
    };
    let r = Receipt {
        version: VERSION.into(),
        action_sha256: digest(&x).unwrap(),
        observed_at: 99,
        outcome: Outcome::Succeeded,
        output_sha256: "cc".repeat(32),
    };
    (
        Bundle {
            authorization: sign(a, &authority).unwrap(),
            action: sign(x, &actor).unwrap(),
            receipt: Some(sign(r, &executor).unwrap()),
        },
        c,
    )
}
fn resign(b: &mut Bundle) {
    let [a, x, r] = keys();
    b.authorization = sign(b.authorization.payload.clone(), &a).unwrap();
    b.action = sign(b.action.payload.clone(), &x).unwrap();
    if let Some(s) = &mut b.receipt {
        *s = sign(s.payload.clone(), &r).unwrap();
    }
}
#[test]
fn valid_receipt_is_only_an_executor_report() {
    let (b, c) = fixture();
    let r = verify(&b, &c).unwrap();
    assert_eq!(r.assurance, Assurance::ExecutorReportedSuccess);
    assert!(!r.external_effects_proven && !r.replay_protection_enforced);
}
#[test]
fn no_receipt_does_not_prove_execution() {
    let (mut b, c) = fixture();
    b.receipt = None;
    assert_eq!(
        verify(&b, &c).unwrap().assurance,
        Assurance::AuthorizedClaimOnly
    );
}
#[test]
fn failed_receipt_is_not_success() {
    let (mut b, c) = fixture();
    b.receipt.as_mut().unwrap().payload.outcome = Outcome::Failed;
    resign(&mut b);
    assert_eq!(
        verify(&b, &c).unwrap().assurance,
        Assurance::ExecutorReportedFailure
    );
}
#[test]
fn every_signed_payload_byte_is_authenticated() {
    let (b, c) = fixture();
    for which in 0..3 {
        let mut x = b.clone();
        match which {
            0 => x.authorization.payload.audience.push('x'),
            1 => x.action.payload.action.resource.push('x'),
            _ => x.receipt.as_mut().unwrap().payload.output_sha256 = "dd".repeat(32),
        }
        assert!(verify(&x, &c).is_err());
    }
}
#[test]
fn every_signature_byte_is_authenticated() {
    let (b, c) = fixture();
    for kind in 0..3 {
        for i in 0..64 {
            let mut x = b.clone();
            let s = match kind {
                0 => &mut x.authorization.signature,
                1 => &mut x.action.signature,
                _ => &mut x.receipt.as_mut().unwrap().signature,
            };
            let mut bytes = hex::decode(&*s).unwrap();
            bytes[i] ^= 1;
            *s = hex::encode(bytes);
            assert!(verify(&x, &c).is_err(), "kind {kind} byte {i}");
        }
    }
}
#[test]
fn trusted_key_substitution_rejected() {
    let (b, c) = fixture();
    for i in 0..3 {
        let mut x = c.clone();
        let bad = hex::encode(SigningKey::from_bytes(&[4; 32]).verifying_key().to_bytes());
        match i {
            0 => x.authority_key = bad,
            1 => x.actor_key = bad,
            _ => x.executor_key = bad,
        }
        assert!(verify(&b, &x).is_err());
    }
}
#[test]
fn cross_context_replay_rejected() {
    let (b, c) = fixture();
    for i in 0..4 {
        let mut x = c.clone();
        match i {
            0 => x.run_id.push('x'),
            1 => x.nonce.push('x'),
            2 => x.audience.push('x'),
            _ => x.policy_sha256 = "ff".repeat(32),
        }
        assert!(verify(&b, &x).is_err());
    }
}
#[test]
fn exact_action_scope_required() {
    let (b, c) = fixture();
    for i in 0..3 {
        let mut x = c.clone();
        match i {
            0 => x.expected_action.tool.push('x'),
            1 => x.expected_action.resource.push('x'),
            _ => x.expected_action.arguments_sha256 = "ff".repeat(32),
        }
        assert!(verify(&b, &x).is_err());
    }
}
#[test]
fn legitimately_signed_different_action_rejected() {
    let (mut b, c) = fixture();
    b.action.payload.action.resource = "urn:other".into();
    resign(&mut b);
    assert!(verify(&b, &c).is_err());
}
#[test]
fn authorization_splicing_rejected() {
    let (mut b, c) = fixture();
    b.action.payload.authorization_sha256 = "00".repeat(32);
    resign(&mut b);
    assert!(verify(&b, &c).is_err());
}
#[test]
fn receipt_splicing_rejected() {
    let (mut b, c) = fixture();
    b.receipt.as_mut().unwrap().payload.action_sha256 = "00".repeat(32);
    resign(&mut b);
    assert!(verify(&b, &c).is_err());
}
#[test]
fn time_window_boundaries() {
    let (b, mut c) = fixture();
    for t in [0, 89, 111, u64::MAX] {
        c.now = t;
        assert!(verify(&b, &c).is_err());
    }
    c.now = 110;
    assert!(verify(&b, &c).is_ok());
}
#[test]
fn false_event_order_rejected() {
    let (b, c) = fixture();
    for i in 0..4 {
        let mut x = b.clone();
        match i {
            0 => x.action.payload.claimed_at = 89,
            1 => x.action.payload.claimed_at = 101,
            2 => x.receipt.as_mut().unwrap().payload.observed_at = 94,
            _ => x.receipt.as_mut().unwrap().payload.observed_at = 101,
        }
        resign(&mut x);
        assert!(verify(&x, &c).is_err());
    }
}
#[test]
fn invalid_window_cannot_be_signed() {
    let (b, _) = fixture();
    let mut a = b.authorization.payload;
    a.not_before = 111;
    assert!(sign(a, &keys()[0]).is_err());
}
#[test]
fn self_signed_receipt_not_independent() {
    let (mut b, mut c) = fixture();
    c.executor_key = c.actor_key.clone();
    b.receipt = Some(sign(b.receipt.unwrap().payload, &keys()[1]).unwrap());
    assert!(verify(&b, &c).is_err());
}
#[test]
fn weak_and_malformed_keys_rejected() {
    for k in [
        "00".repeat(32),
        format!("01{}", "00".repeat(31)),
        "ff".repeat(31),
        "GG".repeat(32),
    ] {
        assert!(public_key(&k).is_err());
    }
}
#[test]
fn unknown_versions_rejected() {
    let (b, _) = fixture();
    let mut a = b.authorization.payload;
    a.version = "openproof/2".into();
    assert!(sign(a, &keys()[0]).is_err());
}
#[test]
fn strict_json_boundary() {
    let (b, _) = fixture();
    let good = serde_json::to_string(&b.authorization.payload).unwrap();
    for s in [
        good.replacen("{", "{\"version\":\"openproof/1\",", 1),
        good.replacen("{", "{\"extra\":0,", 1),
        format!("{good} null"),
        good.replace("90", "90.0"),
        good.replace("90", "-1"),
        good.replace("90", "18446744073709551616"),
    ] {
        assert!(parse::<Authorization>(s.as_bytes()).is_err(), "{s}");
    }
}
#[test]
fn nested_unknown_and_duplicate_fields_rejected() {
    let (b, _) = fixture();
    let s = serde_json::to_string(&b).unwrap();
    for x in [
        s.replacen("\"tool\":", "\"tool\":\"duplicate\",\"tool\":", 1),
        s.replacen("\"tool\":", "\"surprise\":true,\"tool\":", 1),
    ] {
        assert!(parse::<Bundle>(x.as_bytes()).is_err());
    }
}
#[test]
fn malformed_hex_signatures_rejected() {
    let (b, c) = fixture();
    for sig in [
        "00".repeat(63),
        "00".repeat(65),
        "FF".repeat(64),
        "zz".repeat(64),
    ] {
        let mut x = b.clone();
        x.action.signature = sig;
        assert!(verify(&x, &c).is_err());
    }
}
#[test]
fn empty_or_control_text_rejected() {
    let (b, _) = fixture();
    for s in ["".into(), "bad\ntext".into(), "x".repeat(1025)] {
        let mut a = b.authorization.payload.clone();
        a.run_id = s;
        assert!(sign(a, &keys()[0]).is_err());
    }
}
#[test]
fn oversized_input_rejected() {
    assert!(parse::<Bundle>(&vec![b' '; MAX_INPUT + 1]).is_err());
}
#[test]
fn canonical_known_vectors() {
    assert_eq!(
        hex::encode(canonical(&serde_json::Value::Null).unwrap()),
        "4f5045430100"
    );
    assert_eq!(
        hex::encode(canonical(&"a").unwrap()),
        "4f5045430104000000000000000161"
    );
    assert_eq!(
        hex::encode(canonical(&1u64).unwrap()),
        "4f50454301030000000000000001"
    );
    assert_eq!(
        hex::encode(canonical(&serde_json::json!({"b":true,"a":null})).unwrap()),
        "4f5045430106000000000000000204000000000000000161000400000000000000016202"
    );
}
#[test]
fn canonical_reordering_and_whitespace() {
    let (b, _) = fixture();
    let p = &b.authorization.payload;
    let pretty = serde_json::to_vec_pretty(p).unwrap();
    let q: Authorization = parse(&pretty).unwrap();
    assert_eq!(canonical(p).unwrap(), canonical(&q).unwrap());
    let a: serde_json::Value = serde_json::from_str(r#"{"b":1,"a":"é"}"#).unwrap();
    let b: serde_json::Value = serde_json::from_str(r#"{ "a":"\u00e9", "b":1 }"#).unwrap();
    assert_eq!(canonical(&a).unwrap(), canonical(&b).unwrap());
    assert_ne!(canonical(&"é").unwrap(), canonical(&"e\u{301}").unwrap());
}
#[test]
fn floats_and_negative_numbers_not_canonical() {
    assert!(canonical(&-1).is_err());
    assert!(canonical(&1.0).is_err());
}
#[test]
fn framing_is_unambiguous() {
    assert_ne!(
        canonical(&vec!["ab", "c"]).unwrap(),
        canonical(&vec!["a", "bc"]).unwrap()
    );
}
#[test]
fn signature_domain_separation() {
    let (b, c) = fixture();
    let mut x = b.action;
    let bytes = canonical(&x.payload).unwrap();
    x.signature = hex::encode(keys()[1].sign(&bytes).to_bytes());
    assert!(verify_signature(&x, &c.actor_key).is_err());
}
#[test]
fn rfc8032_test_vector_1() {
    let seed: [u8; 32] =
        hex::decode("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
            .unwrap()
            .try_into()
            .unwrap();
    let k = SigningKey::from_bytes(&seed);
    assert_eq!(
        hex::encode(k.verifying_key().to_bytes()),
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
    );
    assert_eq!(hex::encode(k.sign(b"").to_bytes()),"e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b");
}
#[test]
fn same_context_replay_is_explicitly_not_prevented() {
    let (b, c) = fixture();
    assert!(verify(&b, &c).is_ok());
    assert!(!verify(&b, &c).unwrap().replay_protection_enforced);
}

#[test]
fn struct_sequence_encodings_rejected() {
    let (b, _) = fixture();
    let p = &b.action.payload;
    let array = serde_json::json!([p.version, p.authorization_sha256, p.action, p.claimed_at]);
    assert!(parse::<Action>(&serde_json::to_vec(&array).unwrap()).is_err());
    let mut nested = serde_json::to_value(p).unwrap();
    nested["action"] =
        serde_json::json!([p.action.tool, p.action.resource, p.action.arguments_sha256]);
    assert!(parse::<Action>(&serde_json::to_vec(&nested).unwrap()).is_err());
}
#[test]
fn omitted_receipt_and_null_both_mean_claim_only() {
    let (b, c) = fixture();
    let mut value = serde_json::to_value(b).unwrap();
    value.as_object_mut().unwrap().remove("receipt");
    let parsed: Bundle = parse(&serde_json::to_vec(&value).unwrap()).unwrap();
    assert_eq!(
        verify(&parsed, &c).unwrap().assurance,
        Assurance::AuthorizedClaimOnly
    );
    value["receipt"] = serde_json::Value::Null;
    assert!(parse::<Bundle>(&serde_json::to_vec(&value).unwrap()).is_ok());
}
