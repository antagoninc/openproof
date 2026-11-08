use ed25519_dalek::SigningKey;
use openproof_core::*;
use proptest::prelude::*;
proptest! {
 #![proptest_config(ProptestConfig::with_cases(256))]
 #[test]
 fn canonical_unicode_roundtrip(chars in prop::collection::vec(any::<char>(),0..128)) {
  let s:String=chars.into_iter().collect();let raw=serde_json::to_vec(&s).unwrap();let decoded:String=serde_json::from_slice(&raw).unwrap();
  prop_assert_eq!(canonical(&s).unwrap(),canonical(&decoded).unwrap());
 }
 #[test]
 fn canonical_map_order_is_irrelevant(entries in prop::collection::vec(("[a-z]{1,12}",any::<u64>()),0..32)) {
  let mut a=serde_json::Map::new();for(k,v)in entries {a.insert(k,serde_json::json!(v));}
  let mut b=serde_json::Map::new();for(k,v)in a.iter().rev(){b.insert(k.clone(),v.clone());}
  prop_assert_eq!(canonical(&a).unwrap(),canonical(&b).unwrap());
 }
 #[test]
 fn signing_is_deterministic_and_mutations_fail(seed in any::<[u8;32]>(),name in "[a-zA-Z0-9]{1,128}",time in 0u64..1_000_000) {
  let key=SigningKey::from_bytes(&seed);let pk=hex::encode(key.verifying_key().to_bytes());
  let p=Authorization{version:VERSION.into(),run_id:name,nonce:"nonce".into(),audience:"aud".into(),actor_key:pk.clone(),policy_sha256:"aa".repeat(32),action:ActionSpec{tool:"test".into(),resource:"urn:test".into(),arguments_sha256:"bb".repeat(32)},not_before:time,expires_at:time+100};
  let mut a=sign(p.clone(),&key).unwrap();let b=sign(p,&key).unwrap();prop_assert_eq!(&a.signature,&b.signature);prop_assert!(verify_signature(&a,&pk).is_ok());
  let parsed:Signed<Authorization>=parse(&serde_json::to_vec_pretty(&a).unwrap()).unwrap();prop_assert_eq!(a.clone(),parsed);
  a.payload.audience.push('x');prop_assert!(verify_signature(&a,&pk).is_err());
 }
 #[test]
 fn malformed_bytes_do_not_panic(bytes in prop::collection::vec(any::<u8>(),0..4096)) {
  let _=parse::<Bundle>(&bytes);let _=parse::<Context>(&bytes);let _=parse::<Authorization>(&bytes);
 }
}
#[test]
fn python_generated_golden_vectors_match_rust() {
    let bundle: Bundle = parse(include_bytes!("../../../fixtures/v1/bundle.json")).unwrap();
    let context: Context = parse(include_bytes!("../../../fixtures/v1/context.json")).unwrap();
    let vectors: serde_json::Value =
        serde_json::from_slice(include_bytes!("../../../fixtures/v1/vectors.json")).unwrap();
    verify(&bundle, &context).unwrap();
    macro_rules! check {
        ($kind:literal,$payload:expr,$seed:expr) => {{
            let p = $payload;
            assert_eq!(
                hex::encode(signing_bytes(&p).unwrap()),
                vectors[$kind]["signing_bytes_hex"]
            );
            assert_eq!(digest(&p).unwrap(), vectors[$kind]["sha256"]);
            assert_eq!(
                sign(p, &SigningKey::from_bytes(&[$seed; 32]))
                    .unwrap()
                    .signature,
                vectors[$kind]["signature"]
            );
        }};
    }
    check!("authorization", bundle.authorization.payload, 1);
    check!("action", bundle.action.payload, 2);
    check!("receipt", bundle.receipt.unwrap().payload, 3);
}
