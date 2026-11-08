//! Original OpenProof v1 evidence protocol. Signatures authenticate statements, not reality.
#![forbid(unsafe_code)]
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;

pub const VERSION: &str = "openproof/1";
pub const MAX_INPUT: usize = 1_048_576;
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error(pub String);
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for Error {}
pub type Result<T> = std::result::Result<T, Error>;
fn require(ok: bool, msg: &str) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(Error(msg.into()))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActionSpec {
    pub tool: String,
    pub resource: String,
    pub arguments_sha256: String,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Authorization {
    pub version: String,
    pub run_id: String,
    pub nonce: String,
    pub audience: String,
    pub actor_key: String,
    pub policy_sha256: String,
    pub action: ActionSpec,
    pub not_before: u64,
    pub expires_at: u64,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Action {
    pub version: String,
    pub authorization_sha256: String,
    pub action: ActionSpec,
    pub claimed_at: u64,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    Succeeded,
    Failed,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Receipt {
    pub version: String,
    pub action_sha256: String,
    pub observed_at: u64,
    pub outcome: Outcome,
    pub output_sha256: String,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Signed<T> {
    pub payload: T,
    pub signature: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Bundle {
    pub authorization: Signed<Authorization>,
    pub action: Signed<Action>,
    pub receipt: Option<Signed<Receipt>>,
}
/// Trusted inputs must come from the verifier, never from the evidence producer.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Context {
    pub authority_key: String,
    pub actor_key: String,
    pub executor_key: String,
    pub run_id: String,
    pub nonce: String,
    pub audience: String,
    pub policy_sha256: String,
    pub expected_action: ActionSpec,
    pub now: u64,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Assurance {
    AuthorizedClaimOnly,
    ExecutorReportedSuccess,
    ExecutorReportedFailure,
}
#[derive(Debug, Clone, Serialize)]
pub struct Report {
    pub assurance: Assurance,
    pub external_effects_proven: bool,
    pub replay_protection_enforced: bool,
}

/// Parse typed JSON without accepting Serde's alternate array representation of structs.
pub fn parse<T: serde::de::DeserializeOwned + Serialize>(bytes: &[u8]) -> Result<T> {
    require(bytes.len() <= MAX_INPUT, "input exceeds 1 MiB")?;
    // Deserialize typed first so duplicate fields cannot be erased by a Value parser.
    let typed: T = serde_json::from_slice(bytes).map_err(|e| Error(e.to_string()))?;
    let source: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|e| Error(e.to_string()))?;
    let normalized = serde_json::to_value(&typed).map_err(|e| Error(e.to_string()))?;
    require(
        same_shape(&source, &normalized),
        "JSON object shape required",
    )?;
    Ok(typed)
}
fn same_shape(source: &serde_json::Value, normalized: &serde_json::Value) -> bool {
    use serde_json::Value;
    match (source, normalized) {
        (Value::Object(a), Value::Object(b)) => a
            .iter()
            .all(|(k, v)| b.get(k).is_some_and(|n| same_shape(v, n))),
        (Value::Array(a), Value::Array(b)) => {
            a.len() == b.len() && a.iter().zip(b).all(|(v, n)| same_shape(v, n))
        }
        (Value::Object(_) | Value::Array(_), _) | (_, Value::Object(_) | Value::Array(_)) => false,
        _ => true,
    }
}
/// OPEC-1: typed binary canonicalization, deliberately not RFC 8785/JCS.
pub fn canonical<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    let v = serde_json::to_value(value).map_err(|e| Error(e.to_string()))?;
    let mut out = b"OPEC\x01".to_vec();
    encode(&v, &mut out)?;
    require(out.len() <= MAX_INPUT, "canonical value exceeds 1 MiB")?;
    Ok(out)
}
fn count(n: usize, out: &mut Vec<u8>) {
    out.extend_from_slice(&(n as u64).to_be_bytes());
}
fn encode(v: &serde_json::Value, out: &mut Vec<u8>) -> Result<()> {
    use serde_json::Value::*;
    match v {
        Null => out.push(0),
        Bool(false) => out.push(1),
        Bool(true) => out.push(2),
        Number(n) => {
            out.push(3);
            out.extend_from_slice(
                &n.as_u64()
                    .ok_or_else(|| Error("only u64 integers supported".into()))?
                    .to_be_bytes(),
            );
        }
        String(s) => {
            out.push(4);
            count(s.len(), out);
            out.extend_from_slice(s.as_bytes());
        }
        Array(a) => {
            out.push(5);
            count(a.len(), out);
            for x in a {
                encode(x, out)?;
            }
        }
        Object(m) => {
            out.push(6);
            count(m.len(), out);
            let mut keys: Vec<_> = m.keys().collect();
            keys.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
            for k in keys {
                encode(&String(k.clone()), out)?;
                encode(&m[k], out)?;
            }
        }
    }
    Ok(())
}
pub trait Evidence: Serialize {
    const DOMAIN: &'static str;
    fn validate(&self) -> Result<()>;
}
fn text(s: &str) -> Result<()> {
    require(
        !s.is_empty() && s.len() <= 1024 && !s.chars().any(char::is_control),
        "invalid text field",
    )
}
fn hex_bytes<const N: usize>(s: &str) -> Result<[u8; N]> {
    require(
        s.len() == N * 2
            && s.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "noncanonical hex",
    )?;
    hex::decode(s)
        .map_err(|e| Error(e.to_string()))?
        .try_into()
        .map_err(|_| Error("invalid hex length".into()))
}
pub fn public_key(s: &str) -> Result<VerifyingKey> {
    let k = VerifyingKey::from_bytes(&hex_bytes::<32>(s)?).map_err(|e| Error(e.to_string()))?;
    require(!k.is_weak(), "weak public key")?;
    Ok(k)
}
fn spec(a: &ActionSpec) -> Result<()> {
    text(&a.tool)?;
    text(&a.resource)?;
    hex_bytes::<32>(&a.arguments_sha256)?;
    Ok(())
}
impl Evidence for Authorization {
    const DOMAIN: &'static str = "authorization";
    fn validate(&self) -> Result<()> {
        require(self.version == VERSION, "unsupported version")?;
        text(&self.run_id)?;
        text(&self.nonce)?;
        text(&self.audience)?;
        public_key(&self.actor_key)?;
        hex_bytes::<32>(&self.policy_sha256)?;
        spec(&self.action)?;
        require(self.not_before <= self.expires_at, "invalid time window")
    }
}
impl Evidence for Action {
    const DOMAIN: &'static str = "action";
    fn validate(&self) -> Result<()> {
        require(self.version == VERSION, "unsupported version")?;
        hex_bytes::<32>(&self.authorization_sha256)?;
        spec(&self.action)
    }
}
impl Evidence for Receipt {
    const DOMAIN: &'static str = "receipt";
    fn validate(&self) -> Result<()> {
        require(self.version == VERSION, "unsupported version")?;
        hex_bytes::<32>(&self.action_sha256)?;
        hex_bytes::<32>(&self.output_sha256)?;
        Ok(())
    }
}
pub fn signing_bytes<T: Evidence>(p: &T) -> Result<Vec<u8>> {
    p.validate()?;
    let mut out = format!("OpenProof/v1/{}\0", T::DOMAIN).into_bytes();
    out.extend(canonical(p)?);
    Ok(out)
}
pub fn digest<T: Evidence>(p: &T) -> Result<String> {
    Ok(hex::encode(Sha256::digest(signing_bytes(p)?)))
}
pub fn sign<T: Evidence>(payload: T, key: &SigningKey) -> Result<Signed<T>> {
    let signature = hex::encode(key.sign(&signing_bytes(&payload)?).to_bytes());
    Ok(Signed { payload, signature })
}
pub fn verify_signature<T: Evidence>(s: &Signed<T>, trusted_key: &str) -> Result<()> {
    let sig = Signature::from_bytes(&hex_bytes::<64>(&s.signature)?);
    public_key(trusted_key)?
        .verify_strict(&signing_bytes(&s.payload)?, &sig)
        .map_err(|_| Error("signature verification failed".into()))
}
pub fn verify(bundle: &Bundle, ctx: &Context) -> Result<Report> {
    let a = &bundle.authorization.payload;
    let x = &bundle.action.payload;
    verify_signature(&bundle.authorization, &ctx.authority_key)?;
    require(a.actor_key == ctx.actor_key, "actor mismatch")?;
    verify_signature(&bundle.action, &ctx.actor_key)?;
    require(
        a.run_id == ctx.run_id && a.nonce == ctx.nonce && a.audience == ctx.audience,
        "context mismatch",
    )?;
    require(a.policy_sha256 == ctx.policy_sha256, "policy mismatch")?;
    require(
        a.action == ctx.expected_action && x.action == a.action,
        "action mismatch",
    )?;
    require(
        x.authorization_sha256 == digest(a)?,
        "authorization binding mismatch",
    )?;
    require(
        a.not_before <= ctx.now && ctx.now <= a.expires_at,
        "authorization not currently valid",
    )?;
    require(
        a.not_before <= x.claimed_at && x.claimed_at <= ctx.now,
        "invalid claim time",
    )?;
    let assurance = if let Some(r) = &bundle.receipt {
        require(
            ctx.executor_key != ctx.actor_key && ctx.executor_key != ctx.authority_key,
            "executor key must be independent",
        )?;
        verify_signature(r, &ctx.executor_key)?;
        require(
            r.payload.action_sha256 == digest(x)?,
            "receipt binding mismatch",
        )?;
        require(
            x.claimed_at <= r.payload.observed_at && r.payload.observed_at <= ctx.now,
            "invalid receipt time",
        )?;
        match r.payload.outcome {
            Outcome::Succeeded => Assurance::ExecutorReportedSuccess,
            Outcome::Failed => Assurance::ExecutorReportedFailure,
        }
    } else {
        Assurance::AuthorizedClaimOnly
    };
    Ok(Report {
        assurance,
        external_effects_proven: false,
        replay_protection_enforced: false,
    })
}
