#![no_main]
use libfuzzer_sys::fuzz_target;
use openproof_core::{parse,Signed,Evidence};
use openproof_trust::{TrustBundle,Anchor,validate_snapshot};
fuzz_target!(|data:&[u8]|{
 if let Ok(t)=parse::<Signed<TrustBundle>>(data){
  let _=t.payload.validate();
  let a:Anchor=parse(include_bytes!("../../fixtures/trust-v1/anchor.json")).unwrap();
  let _=validate_snapshot(&t,&a,100);
 }
 if let Ok(t)=parse::<openproof_trust::RootTransition>(data){let _=t.validate();}
 let _=parse::<Anchor>(data);
});
