#![no_main]
use libfuzzer_sys::fuzz_target;
use openproof_core::{parse,Evidence,Signed,verify_signature};
use openproof_witness::{Approval,Receipt,Checkpoint,Package,Trust,assess,HistoryPage,Handover,Rotation,validate_handover};
fuzz_target!(|data:&[u8]|{
 if let Ok(v)=parse::<HistoryPage>(data){let _=openproof_core::canonical(&v);}
 if let Ok(v)=parse::<Rotation>(data){let _=v.validate();}
 if let Ok(v)=parse::<Handover>(data){
  let t:Signed<Trust>=parse(include_bytes!("../../fixtures/witness-trust-v1/trust-signed.json")).unwrap();
  let root:serde_json::Value=serde_json::from_slice(include_bytes!("../../fixtures/witness-trust-v1/root-public.json")).unwrap();
  let _=validate_handover(&t,root["public_key"].as_str().unwrap(),&v,t.payload.expires_at);
 }

 if let Ok(v)=parse::<Signed<Trust>>(data){
  let root:serde_json::Value=serde_json::from_slice(include_bytes!("../../fixtures/witness-trust-v1/root-public.json")).unwrap();
  let _=verify_signature(&v,root["public_key"].as_str().unwrap());
 }

 if let Ok(v)=parse::<Approval>(data){let _=v.validate();}
 if let Ok(v)=parse::<Receipt>(data){let _=v.validate();}
 if let Ok(v)=parse::<Checkpoint>(data){let _=v.validate();}
 if let Ok(v)=parse::<Package>(data){
  let t:Trust=parse(include_bytes!("../../fixtures/witness-v1/trust.json")).unwrap();
  let c=parse(include_bytes!("../../fixtures/witness-v1/checkpoint.json")).unwrap();
  let _=assess(&v,&t,&c,t.expires_at);
 }
});
