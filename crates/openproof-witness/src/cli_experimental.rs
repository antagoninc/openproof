//! Command-line entry points for the experimental planned key handover and storage
//! pilot. Built only with `--features experimental`; not part of the trusted code.
use super::*;
/// Experimental commands, present only with `--features experimental`.
pub const EXPERIMENTAL_USAGE: &str = concat!(
    "experimental:\n",
    "  sign-rotation KEY < ROTATION\n",
    "  check-rotation ROOT OLD_SIGNED_TRUST < HANDOVER\n",
    "  rotation-applied DIR < HANDOVER\n",
    "  rotate-state DIR OLD_SIGNED_TRUST < HANDOVER\n",
    "  storage-authorize KEY < UPLOAD\n",
    "  storage-check AUTHORITY < SIGNED_UPLOAD\n",
    "  storage-check-history AUTHORITY < SIGNED_UPLOAD\n",
    "  storage-observe KEY < OBSERVATION\n",
    "  storage-verify AUTHORITY ADAPTER < EVIDENCE\n",
);
/// Experimental storage and rotation commands. `None` means not one of them.
pub fn experimental(a: &[&str]) -> Result<Option<serde_json::Value>> {
    Ok(Some(match a {
        ["storage-authorize", secret] => {
            serde_json::to_value(authorize_upload(input()?, &key(secret)?)?)?
        }
        ["storage-check", authority] => {
            let s: openproof_core::Signed<UploadAuthorization> = input()?;
            serde_json::json!({"authorization_sha256":check_upload(&s,authority,now())?})
        }
        ["storage-check-history", authority] => {
            let s: openproof_core::Signed<UploadAuthorization> = input()?;
            serde_json::json!({"authorization_sha256":check_upload(&s,authority,s.payload.not_before)?,"dispatch_allowed":false})
        }
        ["storage-observe", secret] => {
            let p: StorageObservation = input()?;
            let k = key(secret)?;
            if p.adapter != hex::encode(k.verifying_key().to_bytes()) {
                return Err("wrong adapter".into());
            }
            serde_json::to_value(sign(p, &k)?)?
        }
        ["storage-verify", authority, adapter] => {
            let e: StorageEvidence = input()?;
            verify_storage_evidence(&e, authority, adapter, now())?;
            serde_json::json!({"status":"adapter_statement_verified","kind":e.observation.payload.kind,"independent_storage_proof":false})
        }
        ["check-rotation", root, old_trust] => {
            validate_handover(&parse(&read(old_trust)?)?, root, &input()?, now())?;
            serde_json::json!({"valid_planned_handover":true})
        }
        ["sign-rotation", secret] => {
            serde_json::to_value(sign(input::<Rotation>()?, &key(secret)?)?)?
        }
        ["rotation-applied", state] => {
            serde_json::json!({"applied":rotation_applied(Path::new(state),&input()?)?})
        }
        ["rotate-state", state, old_trust] => {
            rotate_state(
                Path::new(state),
                &parse(&read(old_trust)?)?,
                &input()?,
                now(),
            )?;
            serde_json::json!({"rotated":true})
        }
        _ => return Ok(None),
    }))
}
