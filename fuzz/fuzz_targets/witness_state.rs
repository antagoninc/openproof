#![no_main]
use ed25519_dalek::SigningKey;
use libfuzzer_sys::fuzz_target;
use openproof_core::sign;
use openproof_witness::*;
use std::{fs,path::PathBuf,time::{SystemTime,UNIX_EPOCH}};
struct Cleanup(PathBuf);
impl Drop for Cleanup { fn drop(&mut self) { let _=fs::remove_dir_all(&self.0); } }
fuzz_target!(|data:&[u8]| {
 if data.is_empty(){return;}
 let base=PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../outputs/fuzz-state");fs::create_dir_all(&base).unwrap();
 let path=base.join(format!("{}-{}",std::process::id(),SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()));fs::create_dir(&path).unwrap();let _cleanup=Cleanup(path.clone());
 let receiver=path.join("receiver");let witness_path=path.join("witness");let verifier=path.join("verifier");init(&receiver).unwrap();init(&witness_path).unwrap();
 let authority=SigningKey::from_bytes(&[1;32]);let rk=SigningKey::from_bytes(&[2;32]);let wk=SigningKey::from_bytes(&[3;32]);let root=SigningKey::from_bytes(&[4;32]);
 let public=|k:&SigningKey| k.verifying_key().to_bytes().iter().map(|b|format!("{b:02x}")).collect::<String>();
 let t=Trust{version:V.into(),epoch:1,expires_at:1000,authority:public(&authority),receiver:public(&rk),witness:public(&wk),previous_authorities:vec![],revoked_authorities:vec![]};
 verifier_init(&verifier,&public(&root)).unwrap();let signed=sign(t.clone(),&root).unwrap();enable_pages(&receiver,&t,100).unwrap();let mut count=0u64;let mut latest=None;let mut last_request:Option<Request>=None;
 for byte in data.iter().take(32) {
  match byte%8 {
   0|1=>{
    let content=format!("fixture-{count}");let q=Request{approval:sign(Approval{version:V.into(),authority:t.authority.clone(),document:"doc".into(),expected_version:count,content_sha256:hash(content.as_bytes()),nonce:format!("{count:064x}"),receiver:t.receiver.clone(),not_before:90,expires_at:200},&authority).unwrap(),content};
    let r=apply(&receiver,&q,&t,&rk,100).unwrap();assert_eq!(apply(&receiver,&q,&t,&rk,100).unwrap().payload.sequence,r.payload.sequence);count+=1;last_request=Some(q);latest=Some(witness(&witness_path,&r,&t,&wk,100).unwrap());
   },
   2|3=>{if let Some(ref cp)=latest {let progress=page_progress(&verifier).unwrap();if progress<count {let mut page=export_page(&receiver,&t,cp.clone(),progress+1,100).unwrap();if byte%8==3 {page.requests[0].content.push('!');assert!(verify_page(&verifier,&signed,cp,&page,100).is_err());assert_eq!(page_progress(&verifier).unwrap(),progress);}else{verify_page(&verifier,&signed,cp,&page,100).unwrap();}}}},
   4=>{if let Some(ref q)=last_request {let mut bad=q.clone();bad.content.push('!');assert!(apply(&receiver,&bad,&t,&rk,100).is_err());}},
   5=>{if let Some(ref cp)=latest {let progress=page_progress(&verifier).unwrap();if progress<count {let page=export_page(&receiver,&t,cp.clone(),progress+1,100).unwrap();assert!(verify_page(&verifier,&signed,cp,&page,99).is_err());assert_eq!(page_progress(&verifier).unwrap(),progress);}}},
   6=>{let content="expired fixture".to_string();let q=Request{approval:sign(Approval{version:V.into(),authority:t.authority.clone(),document:"doc".into(),expected_version:count,content_sha256:hash(content.as_bytes()),nonce:format!("{count:064x}"),receiver:t.receiver.clone(),not_before:90,expires_at:99},&authority).unwrap(),content};assert!(apply(&receiver,&q,&t,&rk,100).is_err());},
   _=>{reset_pages(&verifier).unwrap();}
  }
  assert_eq!(head(&receiver).unwrap(),count);assert_eq!(head(&witness_path).unwrap(),count);
 }
});
