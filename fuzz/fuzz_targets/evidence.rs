#![no_main]
use libfuzzer_sys::fuzz_target;
use openproof_core::*;
fuzz_target!(|data:&[u8]|{
 let context:Context=parse(include_bytes!("../../fixtures/v1/context.json")).unwrap();
 if let Ok(mut b)=parse::<Bundle>(data){
  if verify(&b,&context).is_ok(){b.action.signature="00".repeat(64);assert!(verify(&b,&context).is_err());}
  let _=signing_bytes(&b.authorization.payload);let _=signing_bytes(&b.action.payload);
 }
 let _=parse::<Authorization>(data);let _=parse::<Context>(data);
 if let Ok(v)=serde_json::from_slice::<serde_json::Value>(data){let _=canonical(&v);}
});
