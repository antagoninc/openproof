//! Passkey owner approvals. A WebAuthn assertion binds a user-verified gesture on a
//! platform authenticator to the exact signed approval. See docs/PASSKEY.md.
use super::*;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};

pub const MAX_AUTHENTICATOR_DATA: usize = 1024;
pub const MAX_CLIENT_DATA_JSON: usize = 2048;
pub const MAX_ASSERTION_SIGNATURE: usize = 80;
const FLAG_USER_PRESENT: u8 = 0x01;
const FLAG_USER_VERIFIED: u8 = 0x04;

/// The owner's passkey, set by the trust root. Requests whose receipt sequence is at
/// least `from_sequence` must carry an assertion from this key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwnerPasskey {
    /// Lowercase hex of the SEC1 uncompressed P-256 point (65 bytes).
    pub public_key: String,
    pub rp_id: String,
    pub origin: String,
    /// First receipt sequence that requires an assertion. Earlier history was
    /// approved before the passkey existed and must not carry one.
    pub from_sequence: u64,
}

/// What the browser returns from `navigator.credentials.get`, base64url without padding.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PasskeyAssertion {
    pub authenticator_data: String,
    pub client_data_json: String,
    /// DER-encoded ECDSA signature, exactly as the browser returns it.
    pub signature: String,
}

fn dns_name(s: &str) -> bool {
    let labels: Vec<&str> = s.split('.').collect();
    let last_is_numeric = labels
        .last()
        .is_some_and(|l| l.bytes().all(|b| b.is_ascii_digit()));
    !s.is_empty()
        && s.len() <= 253
        && !last_is_numeric
        && labels.iter().all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && !l.starts_with('-')
                && !l.ends_with('-')
                && l.bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
}

fn port(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 5
        && !s.starts_with('0')
        && s.bytes().all(|b| b.is_ascii_digit())
        && s.parse::<u32>().is_ok_and(|p| (1..=65535).contains(&p))
}

/// Host of an exact origin string: `http://localhost:PORT` or `https://HOST[:PORT]`.
fn origin_host(origin: &str) -> Option<&str> {
    if let Some(rest) = origin.strip_prefix("http://") {
        let (host, p) = rest.split_once(':')?;
        if host == "localhost" && port(p) {
            return Some(host);
        }
        return None;
    }
    let rest = origin.strip_prefix("https://")?;
    let (host, p) = match rest.split_once(':') {
        Some((host, p)) => (host, Some(p)),
        None => (rest, None),
    };
    if !dns_name(host) || p.is_some_and(|p| !port(p)) {
        return None;
    }
    Some(host)
}

impl OwnerPasskey {
    pub fn validate(&self) -> Result<()> {
        check(
            self.public_key.len() == 130
                && self.public_key.starts_with("04")
                && self
                    .public_key
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
            "owner passkey must be a lowercase hex uncompressed P-256 point",
        )?;
        VerifyingKey::from_sec1_bytes(&hex::decode(&self.public_key)?)
            .map_err(|_| "owner passkey is not a P-256 point")?;
        check(
            dns_name(&self.rp_id),
            "owner passkey rp_id must be localhost or a lowercase DNS name",
        )?;
        let host = origin_host(&self.origin).ok_or("owner passkey origin is not exact")?;
        check(
            host == self.rp_id || host.ends_with(&format!(".{}", self.rp_id)),
            "owner passkey origin is outside its rp_id",
        )?;
        check(
            self.from_sequence > 0 && self.from_sequence <= i64::MAX as u64,
            "owner passkey sequence range",
        )
    }
}

fn decode(field: &str, max: usize, what: &str) -> Result<Vec<u8>> {
    let raw = URL_SAFE_NO_PAD
        .decode(field)
        .map_err(|_| format!("{what} is not base64url without padding"))?;
    check(!raw.is_empty() && raw.len() <= max, &format!("{what} size"))?;
    Ok(raw)
}

/// Top-level keys of a JSON object, so that duplicate keys can be rejected.
struct Keys(Vec<String>);
impl<'de> Deserialize<'de> for Keys {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        struct Visit;
        impl<'de> serde::de::Visitor<'de> for Visit {
            type Value = Keys;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("a JSON object")
            }
            fn visit_map<M: serde::de::MapAccess<'de>>(
                self,
                mut map: M,
            ) -> std::result::Result<Keys, M::Error> {
                let mut keys = vec![];
                while let Some((k, _)) = map.next_entry::<String, serde::de::IgnoredAny>()? {
                    keys.push(k);
                }
                Ok(Keys(keys))
            }
        }
        d.deserialize_map(Visit)
    }
}

/// Check one assertion against the trusted passkey and the approval digest (hex).
pub fn verify_assertion(
    a: &PasskeyAssertion,
    k: &OwnerPasskey,
    approval_digest: &str,
) -> Result<()> {
    let auth = decode(
        &a.authenticator_data,
        MAX_AUTHENTICATOR_DATA,
        "authenticator data",
    )?;
    let client = decode(&a.client_data_json, MAX_CLIENT_DATA_JSON, "client data")?;
    let der = decode(&a.signature, MAX_ASSERTION_SIGNATURE, "assertion signature")?;
    let keys: Keys =
        serde_json::from_slice(&client).map_err(|_| "client data is not a JSON object")?;
    let unique: std::collections::HashSet<_> = keys.0.iter().collect();
    check(unique.len() == keys.0.len(), "duplicate client data field")?;
    let data: serde_json::Value = serde_json::from_slice(&client)?;
    let challenge = URL_SAFE_NO_PAD.encode(hex::decode(approval_digest)?);
    check(
        data.get("type").and_then(|v| v.as_str()) == Some("webauthn.get"),
        "client data type must be webauthn.get",
    )?;
    check(
        data.get("challenge").and_then(|v| v.as_str()) == Some(challenge.as_str()),
        "passkey challenge does not match the approval",
    )?;
    check(
        data.get("origin").and_then(|v| v.as_str()) == Some(k.origin.as_str()),
        "passkey origin mismatch",
    )?;
    let cross_origin = data.get("crossOrigin");
    check(
        cross_origin.is_none() || cross_origin == Some(&serde_json::Value::Bool(false)),
        "cross-origin passkey assertion",
    )?;
    check(auth.len() >= 37, "authenticator data too short")?;
    check(
        auth[..32] == Sha256::digest(k.rp_id.as_bytes())[..],
        "passkey rp_id mismatch",
    )?;
    check(
        auth[32] & FLAG_USER_PRESENT != 0,
        "passkey user presence missing",
    )?;
    check(
        auth[32] & FLAG_USER_VERIFIED != 0,
        "passkey user verification missing",
    )?;
    let key = VerifyingKey::from_sec1_bytes(&hex::decode(&k.public_key)?)
        .map_err(|_| "owner passkey is not a P-256 point")?;
    let signature = Signature::from_der(&der).map_err(|_| "assertion signature is not DER")?;
    let mut signed = auth;
    signed.extend_from_slice(&Sha256::digest(&client));
    key.verify(&signed, &signature)
        .map_err(|_| "passkey signature verification failed")?;
    Ok(())
}

/// History rule: a request needs an assertion exactly when the trust has a passkey
/// and the receipt sequence is at or after `from_sequence`.
pub fn check_owner_assertion(q: &Request, t: &Trust, sequence: u64) -> Result<()> {
    let required = t
        .owner_passkey
        .as_ref()
        .filter(|k| sequence >= k.from_sequence);
    match (required, &q.owner_assertion) {
        (Some(k), Some(a)) => verify_assertion(a, k, &digest(&q.approval.payload)?),
        (Some(_), None) => Err("owner passkey assertion required".into()),
        (None, Some(_)) => Err("unexpected owner passkey assertion".into()),
        (None, None) => Ok(()),
    }
}

/// Receiver rule: with a passkey in force every new admission needs an assertion.
pub(crate) fn admit_owner_assertion(q: &Request, t: &Trust, next_sequence: u64) -> Result<()> {
    if let Some(k) = &t.owner_passkey {
        check(
            next_sequence >= k.from_sequence,
            "owner passkey requirement starts at a later sequence; refusing admission",
        )?;
    }
    check_owner_assertion(q, t, next_sequence)
}

/// Owner-app pre-check before an approval is stored: the trust must have a passkey
/// and the request must carry a valid assertion for it.
pub fn check_request_assertion(q: &Request, t: &Trust) -> Result<()> {
    let k = t
        .owner_passkey
        .as_ref()
        .ok_or("trust has no owner passkey")?;
    let a = q
        .owner_assertion
        .as_ref()
        .ok_or("owner passkey assertion required")?;
    verify_assertion(a, k, &digest(&q.approval.payload)?)
}

/// Once a state has installed a trust with an owner passkey, every later trust must
/// keep the identical passkey. A stolen root key cannot silently remove or replace it.
pub(crate) fn pin_owner_passkey(tx: &rusqlite::Transaction<'_>, t: &Trust) -> Result<()> {
    tx.execute_batch(
        "CREATE TABLE IF NOT EXISTS owner_passkey_pin(id INTEGER PRIMARY KEY,record TEXT NOT NULL);",
    )?;
    let pinned: Option<String> = tx
        .query_row("SELECT record FROM owner_passkey_pin WHERE id=1", [], |r| {
            r.get(0)
        })
        .optional()?;
    let current = match &t.owner_passkey {
        Some(k) => Some(serde_json::to_string(k)?),
        None => None,
    };
    match (pinned, current) {
        (None, None) => Ok(()),
        (None, Some(record)) => {
            tx.execute("INSERT INTO owner_passkey_pin VALUES(1,?1)", [record])?;
            Ok(())
        }
        (Some(old), Some(new)) => check(old == new, "owner passkey replacement forbidden"),
        (Some(_), None) => Err("owner passkey removal forbidden".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::{signature::Signer, SigningKey as P256Key};

    const ORIGIN: &str = "http://localhost:8765";

    fn owner_key() -> P256Key {
        P256Key::from_slice(&[7u8; 32]).unwrap()
    }

    fn passkey(from_sequence: u64) -> OwnerPasskey {
        let point = owner_key().verifying_key().to_encoded_point(false);
        OwnerPasskey {
            public_key: hex::encode(point.as_bytes()),
            rp_id: "localhost".into(),
            origin: ORIGIN.into(),
            from_sequence,
        }
    }

    fn trust(owner_passkey: Option<OwnerPasskey>) -> Trust {
        let key = |n: u8| hex::encode(SigningKey::from_bytes(&[n; 32]).verifying_key().to_bytes());
        Trust {
            version: V.into(),
            epoch: 1,
            expires_at: 1000,
            authority: key(1),
            previous_authorities: vec![],
            revoked_authorities: vec![],
            receiver: key(2),
            witness: key(3),
            owner_passkey,
        }
    }

    fn request(t: &Trust) -> Request {
        numbered(t, 9, 0)
    }

    fn numbered(t: &Trust, nonce: u8, expected_version: u64) -> Request {
        let content = format!("passkey document {nonce}");
        Request {
            approval: sign(
                Approval {
                    version: V.into(),
                    authority: t.authority.clone(),
                    document: "report".into(),
                    expected_version,
                    content_sha256: hash(content.as_bytes()),
                    nonce: hex::encode([nonce; 32]),
                    receiver: t.receiver.clone(),
                    not_before: 90,
                    expires_at: 200,
                },
                &SigningKey::from_bytes(&[1; 32]),
            )
            .unwrap(),
            content,
            owner_assertion: None,
        }
    }

    struct Parts {
        rp_id: String,
        flags: u8,
        kind: String,
        origin: String,
        challenge: Option<String>,
        extra: String,
    }

    fn parts() -> Parts {
        Parts {
            rp_id: "localhost".into(),
            flags: FLAG_USER_PRESENT | FLAG_USER_VERIFIED,
            kind: "webauthn.get".into(),
            origin: ORIGIN.into(),
            challenge: None,
            extra: String::new(),
        }
    }

    fn assertion(q: &Request, p: Parts) -> PasskeyAssertion {
        let digest = digest(&q.approval.payload).unwrap();
        let challenge = p
            .challenge
            .unwrap_or_else(|| URL_SAFE_NO_PAD.encode(hex::decode(digest).unwrap()));
        let client = format!(
            "{{\"type\":\"{}\",\"challenge\":\"{}\",\"origin\":\"{}\"{}}}",
            p.kind, challenge, p.origin, p.extra
        );
        let mut auth = Sha256::digest(p.rp_id.as_bytes()).to_vec();
        auth.push(p.flags);
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

    fn with(q: &Request, a: PasskeyAssertion) -> Request {
        let mut q = q.clone();
        q.owner_assertion = Some(a);
        q
    }

    fn rejected(q: &Request, t: &Trust, needle: &str) {
        let e = check_owner_assertion(q, t, 1).unwrap_err().to_string();
        assert!(e.contains(needle), "{e} does not mention {needle}");
    }

    #[test]
    fn valid_assertion_accepted() {
        let t = trust(Some(passkey(1)));
        let q = request(&t);
        let q = with(&q, assertion(&q, parts()));
        check_owner_assertion(&q, &t, 1).unwrap();
        check_request_assertion(&q, &t).unwrap();
        admit_owner_assertion(&q, &t, 1).unwrap();
    }

    #[test]
    fn high_s_signature_accepted() {
        let t = trust(Some(passkey(1)));
        let q = request(&t);
        let mut a = assertion(&q, parts());
        let der = URL_SAFE_NO_PAD.decode(&a.signature).unwrap();
        let s = Signature::from_der(&der).unwrap();
        let (r, low) = s.split_scalars();
        let high = Signature::from_scalars(r, -*low).unwrap();
        a.signature = URL_SAFE_NO_PAD.encode(high.to_der().as_bytes());
        check_owner_assertion(&with(&q, a), &t, 1).unwrap();
    }

    #[test]
    fn wrong_challenge_rejected() {
        let t = trust(Some(passkey(1)));
        let q = request(&t);
        let mut p = parts();
        p.challenge = Some(URL_SAFE_NO_PAD.encode([0u8; 32]));
        rejected(&with(&q, assertion(&q, p)), &t, "challenge");
        let mut other = request(&t);
        other.approval.payload.nonce = hex::encode([8u8; 32]);
        other.approval = sign(other.approval.payload, &SigningKey::from_bytes(&[1; 32])).unwrap();
        rejected(&with(&q, assertion(&other, parts())), &t, "challenge");
    }

    #[test]
    fn wrong_rp_id_hash_rejected() {
        let t = trust(Some(passkey(1)));
        let q = request(&t);
        let mut p = parts();
        p.rp_id = "attacker.example".into();
        rejected(&with(&q, assertion(&q, p)), &t, "rp_id");
    }

    #[test]
    fn missing_user_verification_or_presence_rejected() {
        let t = trust(Some(passkey(1)));
        let q = request(&t);
        let mut p = parts();
        p.flags = FLAG_USER_PRESENT;
        rejected(&with(&q, assertion(&q, p)), &t, "verification");
        let mut p = parts();
        p.flags = FLAG_USER_VERIFIED;
        rejected(&with(&q, assertion(&q, p)), &t, "presence");
    }

    #[test]
    fn wrong_type_origin_and_cross_origin_rejected() {
        let t = trust(Some(passkey(1)));
        let q = request(&t);
        let mut p = parts();
        p.kind = "webauthn.create".into();
        rejected(&with(&q, assertion(&q, p)), &t, "type");
        let mut p = parts();
        p.origin = "http://localhost:8766".into();
        rejected(&with(&q, assertion(&q, p)), &t, "origin");
        let mut p = parts();
        p.extra = ",\"crossOrigin\":true".into();
        rejected(&with(&q, assertion(&q, p)), &t, "cross-origin");
        let mut p = parts();
        p.extra = ",\"crossOrigin\":false".into();
        check_owner_assertion(&with(&q, assertion(&q, p)), &t, 1).unwrap();
        let mut p = parts();
        p.extra = ",\"type\":\"webauthn.get\"".into();
        rejected(&with(&q, assertion(&q, p)), &t, "duplicate");
    }

    #[test]
    fn bad_or_garbled_signature_rejected() {
        let t = trust(Some(passkey(1)));
        let q = request(&t);
        let good = assertion(&q, parts());
        let mut der = URL_SAFE_NO_PAD.decode(&good.signature).unwrap();
        let last = der.len() - 1;
        der[last] ^= 1;
        let mut a = good.clone();
        a.signature = URL_SAFE_NO_PAD.encode(&der);
        rejected(&with(&q, a), &t, "signature");
        let mut a = good.clone();
        a.signature = URL_SAFE_NO_PAD.encode([0x30, 0x02, 0x01, 0x01]);
        rejected(&with(&q, a), &t, "DER");
        let mut a = good.clone();
        a.signature = "not base64!".into();
        rejected(&with(&q, a), &t, "base64url");
        let mut a = good.clone();
        a.signature.push('=');
        rejected(&with(&q, a), &t, "base64url");
        let mut auth = URL_SAFE_NO_PAD.decode(&good.authenticator_data).unwrap();
        auth[36] = 1;
        let mut a = good;
        a.authenticator_data = URL_SAFE_NO_PAD.encode(auth);
        rejected(&with(&q, a), &t, "signature");
    }

    #[test]
    fn missing_when_required_and_present_when_not_configured() {
        let t = trust(Some(passkey(1)));
        let q = request(&t);
        rejected(&q, &t, "required");
        assert!(check_request_assertion(&q, &t).is_err());
        assert!(admit_owner_assertion(&q, &t, 5).is_err());
        let plain = trust(None);
        let signed = with(&q, assertion(&q, parts()));
        rejected(&signed, &plain, "unexpected");
        assert!(check_request_assertion(&signed, &plain).is_err());
        check_owner_assertion(&q, &plain, 1).unwrap();
    }

    #[test]
    fn sequence_boundary_separates_old_history() {
        let t = trust(Some(passkey(3)));
        let q = request(&t);
        let signed = with(&q, assertion(&q, parts()));
        check_owner_assertion(&q, &t, 2).unwrap();
        assert!(check_owner_assertion(&signed, &t, 2).is_err());
        assert!(check_owner_assertion(&q, &t, 3).is_err());
        check_owner_assertion(&signed, &t, 3).unwrap();
        assert!(admit_owner_assertion(&signed, &t, 2).is_err());
        admit_owner_assertion(&signed, &t, 3).unwrap();
    }

    #[test]
    fn oversize_fields_rejected() {
        let t = trust(Some(passkey(1)));
        let q = request(&t);
        let good = assertion(&q, parts());
        let mut a = good.clone();
        a.authenticator_data = URL_SAFE_NO_PAD.encode(vec![0u8; MAX_AUTHENTICATOR_DATA + 1]);
        rejected(&with(&q, a), &t, "size");
        let mut a = good.clone();
        a.client_data_json = URL_SAFE_NO_PAD.encode(vec![b' '; MAX_CLIENT_DATA_JSON + 1]);
        rejected(&with(&q, a), &t, "size");
        let mut a = good.clone();
        a.signature = URL_SAFE_NO_PAD.encode(vec![0u8; MAX_ASSERTION_SIGNATURE + 1]);
        rejected(&with(&q, a), &t, "size");
        let mut a = good;
        a.authenticator_data = URL_SAFE_NO_PAD.encode([0u8; 36]);
        rejected(&with(&q, a), &t, "short");
    }

    #[test]
    fn passkey_configuration_validated() {
        passkey(1).validate().unwrap();
        let mut https = passkey(1);
        https.rp_id = "owner.example".into();
        https.origin = "https://app.owner.example".into();
        https.validate().unwrap();
        https.origin = "https://app.owner.example:8443".into();
        https.validate().unwrap();
        let bad: Vec<fn(&mut OwnerPasskey)> = vec![
            |k| k.public_key = k.public_key.to_uppercase(),
            |k| k.public_key = format!("02{}", &k.public_key[2..66]),
            |k| k.public_key = format!("04{}", "11".repeat(64)),
            |k| k.rp_id = "127.0.0.1".into(),
            |k| k.rp_id = "LocalHost".into(),
            |k| k.rp_id = "-bad.example".into(),
            |k| k.rp_id = String::new(),
            |k| k.origin = "http://127.0.0.1:8765".into(),
            |k| k.origin = "http://localhost".into(),
            |k| k.origin = "http://localhost:08765".into(),
            |k| k.origin = "http://localhost:70000".into(),
            |k| k.origin = "http://localhost:8765/".into(),
            |k| k.origin = "http://example.com:80".into(),
            |k| k.origin = "https://elsewhere.example".into(),
            |k| k.from_sequence = 0,
        ];
        for change in bad {
            let mut k = passkey(1);
            change(&mut k);
            assert!(k.validate().is_err(), "{k:?}");
            assert!(trust(Some(k)).validate(0).is_err());
        }
    }

    #[test]
    fn trust_round_trip_and_old_canonical_bytes_unchanged() {
        let fixture = include_bytes!("../../../fixtures/witness-trust-v1/trust-signed.json");
        let root: serde_json::Value = serde_json::from_slice(include_bytes!(
            "../../../fixtures/witness-trust-v1/root-public.json"
        ))
        .unwrap();
        let signed: Signed<Trust> = openproof_core::parse(fixture).unwrap();
        assert!(signed.payload.owner_passkey.is_none());
        verify_signature(&signed, root["public_key"].as_str().unwrap()).unwrap();
        let source: serde_json::Value = serde_json::from_slice(fixture).unwrap();
        let reserialized = serde_json::to_value(&signed).unwrap();
        assert_eq!(source, reserialized);
        assert_eq!(
            canonical(&source["payload"]).unwrap(),
            canonical(&signed.payload).unwrap()
        );
        let package: Package =
            openproof_core::parse(include_bytes!("../../../fixtures/witness-v1/package.json"))
                .unwrap();
        assert!(package.requests.iter().all(|q| q.owner_assertion.is_none()));
        let raw: serde_json::Value =
            serde_json::from_slice(include_bytes!("../../../fixtures/witness-v1/package.json"))
                .unwrap();
        assert_eq!(raw, serde_json::to_value(&package).unwrap());

        let with_key = trust(Some(passkey(4)));
        with_key.validate(0).unwrap();
        let text = serde_json::to_vec(&with_key).unwrap();
        let back: Trust = openproof_core::parse(&text).unwrap();
        assert_eq!(back.owner_passkey, Some(passkey(4)));
        assert_ne!(canonical(&back).unwrap(), canonical(&trust(None)).unwrap());
        let mut value = serde_json::to_value(&with_key).unwrap();
        value["owner_passkey"]["extra"] = serde_json::json!(1);
        assert!(openproof_core::parse::<Trust>(&serde_json::to_vec(&value).unwrap()).is_err());
        let mut value = serde_json::to_value(trust(None)).unwrap();
        value["owner_passkey"] = serde_json::Value::Null;
        assert!(openproof_core::parse::<Trust>(&serde_json::to_vec(&value).unwrap()).is_err());
        let q = request(&with_key);
        let mut value = serde_json::to_value(with(&q, assertion(&q, parts()))).unwrap();
        value["owner_assertion"]["extra"] = serde_json::json!("x");
        assert!(openproof_core::parse::<Request>(&serde_json::to_vec(&value).unwrap()).is_err());
    }

    #[test]
    fn receiver_admission_history_and_passkey_pin() {
        let base = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../outputs/witness-test-temp");
        fs::create_dir_all(&base).unwrap();
        let d = base.join(format!("passkey-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir(&d).unwrap();
        let receiver = d.join("receiver");
        let witness_state = d.join("witness");
        init(&receiver).unwrap();
        init(&witness_state).unwrap();
        let rk = SigningKey::from_bytes(&[2; 32]);
        let wk = SigningKey::from_bytes(&[3; 32]);
        let plain = trust(None);
        let first = numbered(&plain, 1, 0);
        let r1 = apply(&receiver, &first, &plain, &rk, 100).unwrap();
        witness(&witness_state, &r1, &plain, &wk, 100).unwrap();

        let mut keyed = trust(Some(passkey(2)));
        keyed.epoch = 2;
        let bare = numbered(&keyed, 2, 1);
        let e = apply(&receiver, &bare, &keyed, &rk, 100).unwrap_err();
        assert!(e.to_string().contains("required"), "{e}");
        let signed = with(&bare, assertion(&bare, parts()));
        assert!(apply(&receiver, &signed, &plain, &rk, 100).is_err());
        let mut late = trust(Some(passkey(5)));
        late.epoch = 2;
        assert!(apply(&receiver, &signed, &late, &rk, 100).is_err());
        let r2 = apply(&receiver, &signed, &keyed, &rk, 100).unwrap();
        let cp = witness(&witness_state, &r2, &keyed, &wk, 100).unwrap();
        let p = export(&receiver, cp.clone()).unwrap();
        assert!(p.requests[0].owner_assertion.is_none());
        assess(&p, &keyed, &cp, 100).unwrap();
        let mut stripped = p.clone();
        stripped.requests[1].owner_assertion = None;
        assert!(assess(&stripped, &keyed, &cp, 100).is_err());
        let mut moved = p.clone();
        moved.requests[0].owner_assertion = moved.requests[1].owner_assertion.clone();
        assert!(assess(&moved, &keyed, &cp, 100).is_err());
        assert!(assess(&p, &plain, &cp, 100).is_err());

        let mut dropped = trust(None);
        dropped.epoch = 3;
        let e = install(&receiver, &dropped, 100).unwrap_err();
        assert!(e.to_string().contains("removal"), "{e}");
        let mut other = trust(Some(passkey(2)));
        other.epoch = 3;
        other.owner_passkey.as_mut().unwrap().origin = "http://localhost:9999".into();
        let e = install(&receiver, &other, 100).unwrap_err();
        assert!(e.to_string().contains("replacement"), "{e}");
        let mut renewed = keyed.clone();
        renewed.epoch = 3;
        install(&receiver, &renewed, 100).unwrap();
        fs::remove_dir_all(&d).unwrap();
    }
}
