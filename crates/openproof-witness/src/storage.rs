//! Bounded upload authorization and adapter observations; no independent provider proof.
use crate::{check, valid_hash, Result};
use ed25519_dalek::SigningKey;
use openproof_core::{digest, public_key, sign, verify_signature, Evidence, Signed};
use serde::{Deserialize, Serialize};
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UploadAuthorization {
    pub version: String,
    pub authority: String,
    pub endpoint: String,
    pub bucket: String,
    pub object_key: String,
    pub content_sha256: String,
    pub content_bytes: u64,
    pub nonce: String,
    pub not_before: u64,
    pub expires_at: u64,
}
impl Evidence for UploadAuthorization {
    const DOMAIN: &'static str = "storage-upload-authorization/1";
    fn validate(&self) -> openproof_core::Result<()> {
        let valid = || -> Result<()> {
            check(
                self.version == "openproof-storage-upload/1",
                "storage version",
            )?;
            public_key(&self.authority)?;
            let origin = self
                .endpoint
                .strip_prefix("https://")
                .ok_or("HTTPS required")?;
            let parts: Vec<_> = origin.split(':').collect();
            check(
                parts.len() <= 2
                    && !parts[0].is_empty()
                    && parts[0].len() <= 253
                    && parts[0].bytes().all(|b| {
                        b.is_ascii_lowercase() || b.is_ascii_digit() || b".-".contains(&b)
                    }),
                "endpoint origin",
            )?;
            if parts.len() == 2 {
                check(parts[1].parse::<u16>()? > 0, "port")?;
            }
            check(
                (3..=63).contains(&self.bucket.len())
                    && self
                        .bucket
                        .bytes()
                        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
                    && self.bucket.as_bytes()[0].is_ascii_alphanumeric()
                    && self.bucket.as_bytes()[self.bucket.len() - 1].is_ascii_alphanumeric(),
                "bucket",
            )?;
            check(
                !self.object_key.is_empty()
                    && self.object_key.len() <= 160
                    && self
                        .object_key
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"-_/.".contains(&b))
                    && self
                        .object_key
                        .split('/')
                        .all(|p| !p.is_empty() && p != "." && p != ".."),
                "object key",
            )?;
            check(
                valid_hash(&self.content_sha256)
                    && valid_hash(&self.nonce)
                    && (1..=65536).contains(&self.content_bytes),
                "content bounds",
            )?;
            check(
                self.expires_at >= self.not_before && self.expires_at - self.not_before <= 300,
                "approval window",
            )
        };
        valid().map_err(|_| openproof_core::Error("invalid storage authorization".into()))
    }
}
pub fn authorize_upload(
    p: UploadAuthorization,
    key: &SigningKey,
) -> Result<Signed<UploadAuthorization>> {
    check(
        hex::encode(key.verifying_key().to_bytes()) == p.authority,
        "wrong authority",
    )?;
    Ok(sign(p, key)?)
}
pub fn check_upload(s: &Signed<UploadAuthorization>, authority: &str, time: u64) -> Result<String> {
    verify_signature(s, authority)?;
    check(
        s.payload.authority == authority
            && s.payload.not_before <= time
            && time <= s.payload.expires_at,
        "approval not current",
    )?;
    Ok(digest(&s.payload)?)
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum StorageObservationKind {
    ProviderAcknowledgment,
    ReadBackMatch,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StorageObservation {
    pub version: String,
    pub adapter: String,
    pub authorization_sha256: String,
    pub kind: StorageObservationKind,
    pub request_started_at: u64,
    pub observed_at: u64,
}
impl Evidence for StorageObservation {
    const DOMAIN: &'static str = "storage-adapter-observation/1";
    fn validate(&self) -> openproof_core::Result<()> {
        public_key(&self.adapter)?;
        if self.version != "openproof-storage-observation/1"
            || !valid_hash(&self.authorization_sha256)
            || self.observed_at < self.request_started_at
        {
            return Err(openproof_core::Error("invalid storage observation".into()));
        }
        Ok(())
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StorageEvidence {
    pub authorization: Signed<UploadAuthorization>,
    pub observation: Signed<StorageObservation>,
}
pub fn verify_storage_evidence(
    e: &StorageEvidence,
    authority: &str,
    adapter: &str,
    time: u64,
) -> Result<()> {
    check_upload(
        &e.authorization,
        authority,
        e.authorization.payload.not_before,
    )?;
    check(authority != adapter, "storage role keys must differ")?;
    verify_signature(&e.observation, adapter)?;
    let o = &e.observation.payload;
    let a = &e.authorization.payload;
    check(
        o.adapter == adapter
            && o.authorization_sha256 == digest(a)?
            && o.observed_at <= time
            && o.request_started_at >= a.not_before,
        "observation binding",
    )?;
    if o.kind == StorageObservationKind::ProviderAcknowledgment {
        check(o.request_started_at <= a.expires_at, "late dispatch")?;
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> (SigningKey, UploadAuthorization) {
        let k = SigningKey::from_bytes(&[31; 32]);
        let p = UploadAuthorization {
            version: "openproof-storage-upload/1".into(),
            authority: hex::encode(k.verifying_key().to_bytes()),
            endpoint: "https://127.0.0.1:8443".into(),
            bucket: "test-bucket".into(),
            object_key: "reports/test.txt".into(),
            content_sha256: "ab".repeat(32),
            content_bytes: 12,
            nonce: "cd".repeat(32),
            not_before: 100,
            expires_at: 200,
        };
        (k, p)
    }
    #[test]
    fn approval_binds_destination_bytes_and_time() {
        let (k, p) = fixture();
        let s = authorize_upload(p.clone(), &k).unwrap();
        assert!(check_upload(&s, &p.authority, 100).is_ok());
        assert!(check_upload(&s, &p.authority, 99).is_err());
        assert!(check_upload(&s, &p.authority, 201).is_err());
        for field in [
            "endpoint",
            "bucket",
            "object_key",
            "content_sha256",
            "content_bytes",
            "nonce",
        ] {
            let mut v = serde_json::to_value(&s).unwrap();
            v["payload"][field] = if field == "content_bytes" {
                serde_json::json!(13)
            } else {
                serde_json::json!("changed")
            };
            let altered = serde_json::from_value(v).unwrap();
            assert!(check_upload(&altered, &p.authority, 100).is_err());
        }
    }
    #[test]
    fn path_escape_and_cross_domain_rejected() {
        let (k, mut p) = fixture();
        for path in ["../key", "a//b", "a/%2e", "a?token=x", "/a"] {
            p.object_key = path.into();
            assert!(authorize_upload(p.clone(), &k).is_err());
        }
        p.object_key = "report.txt".into();
        p.endpoint = "http://127.0.0.1".into();
        assert!(authorize_upload(p, &k).is_err());
    }
    #[test]
    fn observations_are_bound_and_typed() {
        let (k, p) = fixture();
        let adapter = SigningKey::from_bytes(&[32; 32]);
        let pubkey = hex::encode(adapter.verifying_key().to_bytes());
        let authorization = authorize_upload(p.clone(), &k).unwrap();
        let o = StorageObservation {
            version: "openproof-storage-observation/1".into(),
            adapter: pubkey.clone(),
            authorization_sha256: digest(&p).unwrap(),
            kind: StorageObservationKind::ReadBackMatch,
            request_started_at: 250,
            observed_at: 251,
        };
        let mut e = StorageEvidence {
            authorization,
            observation: sign(o, &adapter).unwrap(),
        };
        assert!(verify_storage_evidence(&e, &p.authority, &pubkey, 251).is_ok());
        assert!(verify_storage_evidence(&e, &p.authority, &pubkey, 250).is_err());
        e.observation.payload.kind = StorageObservationKind::ProviderAcknowledgment;
        assert!(verify_storage_evidence(&e, &p.authority, &pubkey, 251).is_err());
        e.observation = sign(e.observation.payload, &adapter).unwrap();
        assert!(verify_storage_evidence(&e, &p.authority, &pubkey, 251).is_err());
    }
}
