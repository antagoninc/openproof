//! Root-signed offline trust snapshots. Freshness and minimum revision come from the operator.
#![forbid(unsafe_code)]
use openproof_core::{
    public_key, verify, verify_signature, Bundle, Context, Error, Evidence, Report, Result, Signed,
};
use serde::{Deserialize, Serialize};
fn require(ok: bool, msg: &str) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(Error(msg.into()))
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    Authority,
    Actor,
    Executor,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Key {
    pub public_key: String,
    pub role: Role,
    pub not_before: u64,
    pub expires_at: u64,
    pub revoked_at: Option<u64>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustBundle {
    pub version: String,
    pub audience: String,
    pub revision: u64,
    pub issued_at: u64,
    pub expires_at: u64,
    pub keys: Vec<Key>,
}
/// This anchor must be provisioned independently of evidence and trust-bundle producers.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Anchor {
    pub root_key: String,
    pub audience: String,
    pub minimum_revision: u64,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    Current,
    Historical,
}
impl Evidence for TrustBundle {
    const DOMAIN: &'static str = "trust-bundle";
    fn validate(&self) -> Result<()> {
        require(
            self.version == "openproof-trust/1",
            "unsupported trust version",
        )?;
        require(
            !self.audience.is_empty()
                && self.audience.len() <= 1024
                && !self.audience.chars().any(char::is_control),
            "invalid trust audience",
        )?;
        require(
            self.revision > 0
                && self.revision <= i64::MAX as u64
                && self.issued_at <= self.expires_at,
            "invalid trust revision/window",
        )?;
        require(
            !self.keys.is_empty() && self.keys.len() <= 1024,
            "trust bundle must contain 1..1024 keys",
        )?;
        let mut seen = std::collections::HashSet::new();
        for k in &self.keys {
            public_key(&k.public_key)?;
            require(k.not_before <= k.expires_at, "invalid key window")?;
            require(
                seen.insert((&k.public_key, k.role)),
                "duplicate key/role entry",
            )?;
        }
        Ok(())
    }
}
pub fn validate_snapshot(trust: &Signed<TrustBundle>, anchor: &Anchor, now: u64) -> Result<()> {
    verify_signature(trust, &anchor.root_key)?;
    let t = &trust.payload;
    require(t.audience == anchor.audience, "trust audience mismatch")?;
    require(
        t.revision >= anchor.minimum_revision,
        "trust revision below pinned minimum",
    )?;
    require(
        t.issued_at <= now && now <= t.expires_at,
        "trust snapshot stale or not yet valid",
    )
}
fn allowed(t: &TrustBundle, key: &str, role: Role, event: u64, now: u64, mode: Mode) -> Result<()> {
    let k = t
        .keys
        .iter()
        .find(|k| k.public_key == key && k.role == role)
        .ok_or_else(|| Error("key/role absent from trust snapshot".into()))?;
    require(
        k.revoked_at.is_none_or(|r| now < r),
        "key revoked: historical acceptance is also denied",
    )?;
    require(
        k.not_before <= event && event <= k.expires_at,
        "key not valid at claimed event time",
    )?;
    if mode == Mode::Current {
        require(
            k.not_before <= now && now <= k.expires_at,
            "key not currently valid",
        )?;
    }
    Ok(())
}
/// Historical mode authenticates assertions at a supplied time; it cannot prove when they were signed.
pub fn verify_trusted(
    bundle: &Bundle,
    context: &Context,
    trust: &Signed<TrustBundle>,
    anchor: &Anchor,
    now: u64,
    mode: Mode,
) -> Result<Report> {
    validate_snapshot(trust, anchor, now)?;
    require(
        context.audience == anchor.audience,
        "evidence audience differs from anchor",
    )?;
    require(
        context.now <= now,
        "historical evaluation time is in the future",
    )?;
    let mut effective = context.clone();
    if mode == Mode::Current {
        effective.now = now;
    }
    let report = verify(bundle, &effective)?;
    let t = &trust.payload;
    let a = &bundle.authorization.payload;
    // Authorization has no issuance timestamp: require its entire validity interval to fit the authority key's window.
    allowed(
        t,
        &context.authority_key,
        Role::Authority,
        a.not_before,
        now,
        mode,
    )?;
    allowed(
        t,
        &context.authority_key,
        Role::Authority,
        a.expires_at,
        now,
        mode,
    )?;
    allowed(
        t,
        &context.actor_key,
        Role::Actor,
        bundle.action.payload.claimed_at,
        now,
        mode,
    )?;
    if let Some(r) = &bundle.receipt {
        allowed(
            t,
            &context.executor_key,
            Role::Executor,
            r.payload.observed_at,
            now,
            mode,
        )?;
    } else {
        allowed(
            t,
            &context.executor_key,
            Role::Executor,
            effective.now,
            now,
            mode,
        )?;
    }
    Ok(report)
}
/// A planned handover, signed identically by both roots. Not compromise recovery.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RootTransition {
    pub version: String,
    pub audience: String,
    pub old_root: String,
    pub new_root: String,
    pub next_revision: u64,
    pub not_before: u64,
    pub expires_at: u64,
}
impl Evidence for RootTransition {
    const DOMAIN: &'static str = "root-transition";
    fn validate(&self) -> Result<()> {
        require(
            self.version == "openproof-root-transition/1",
            "unsupported root transition",
        )?;
        public_key(&self.old_root)?;
        public_key(&self.new_root)?;
        require(self.old_root != self.new_root, "roots must differ")?;
        require(
            !self.audience.is_empty()
                && self.audience.len() <= 1024
                && !self.audience.chars().any(char::is_control),
            "invalid audience",
        )?;
        require(
            self.next_revision > 0
                && self.next_revision <= i64::MAX as u64
                && self.not_before <= self.expires_at,
            "invalid transition window/revision",
        )
    }
}
pub fn verify_transition(
    old: &Signed<RootTransition>,
    new: &Signed<RootTransition>,
    anchor: &Anchor,
    now: u64,
) -> Result<Anchor> {
    verify_signature(old, &anchor.root_key)?;
    let t = &old.payload;
    verify_signature(new, &t.new_root)?;
    require(
        openproof_core::digest(&old.payload)? == openproof_core::digest(&new.payload)?,
        "transition payload mismatch",
    )?;
    require(
        t.old_root == anchor.root_key && t.audience == anchor.audience,
        "transition anchor mismatch",
    )?;
    require(
        t.not_before <= now && now <= t.expires_at,
        "transition outside validity window",
    )?;
    require(
        t.next_revision > anchor.minimum_revision,
        "transition must advance revision",
    )?;
    Ok(Anchor {
        root_key: t.new_root.clone(),
        audience: t.audience.clone(),
        minimum_revision: t.next_revision,
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use openproof_core::{parse, sign};
    fn fixture() -> (Bundle, Context, Signed<TrustBundle>, Anchor) {
        let b = parse(include_bytes!("../../../fixtures/v1/bundle.json")).unwrap();
        let c: Context = parse(include_bytes!("../../../fixtures/v1/context.json")).unwrap();
        let root = SigningKey::from_bytes(&[9; 32]);
        let a = Anchor {
            root_key: hex::encode(root.verifying_key().to_bytes()),
            audience: c.audience.clone(),
            minimum_revision: 2,
        };
        let keys = [
            (&c.authority_key, Role::Authority),
            (&c.actor_key, Role::Actor),
            (&c.executor_key, Role::Executor),
        ]
        .into_iter()
        .map(|(s, role)| Key {
            public_key: s.clone(),
            role,
            not_before: 80,
            expires_at: 120,
            revoked_at: None,
        })
        .collect();
        let t = sign(
            TrustBundle {
                version: "openproof-trust/1".into(),
                audience: c.audience.clone(),
                revision: 2,
                issued_at: 80,
                expires_at: 1000,
                keys,
            },
            &root,
        )
        .unwrap();
        (b, c, t, a)
    }
    fn resign(t: &mut Signed<TrustBundle>) {
        *t = sign(t.payload.clone(), &SigningKey::from_bytes(&[9; 32])).unwrap();
    }
    #[test]
    fn accepts_pinned_snapshot() {
        let (b, c, t, a) = fixture();
        verify_trusted(&b, &c, &t, &a, 100, Mode::Current).unwrap();
    }
    #[test]
    fn rejects_untrusted_root_and_rollback() {
        let (b, c, t, mut a) = fixture();
        a.minimum_revision = 3;
        assert!(verify_trusted(&b, &c, &t, &a, 100, Mode::Current).is_err());
        a.minimum_revision = 2;
        a.root_key = c.actor_key.clone();
        assert!(verify_trusted(&b, &c, &t, &a, 100, Mode::Current).is_err());
    }
    #[test]
    fn stale_future_or_wrong_audience_rejected() {
        let (b, c, t, mut a) = fixture();
        for now in [79, 1001] {
            assert!(verify_trusted(&b, &c, &t, &a, now, Mode::Current).is_err());
        }
        a.audience = "other".into();
        assert!(verify_trusted(&b, &c, &t, &a, 100, Mode::Current).is_err());
    }
    #[test]
    fn revocation_rejects_historical_backdating() {
        let (b, c, mut t, a) = fixture();
        t.payload.keys[1].revoked_at = Some(150);
        resign(&mut t);
        assert!(verify_trusted(&b, &c, &t, &a, 200, Mode::Historical).is_err());
        assert!(verify_trusted(&b, &c, &t, &a, 100, Mode::Current).is_ok());
    }
    #[test]
    fn historical_mode_explicitly_allows_expired_unrevoked_keys() {
        let (b, c, t, a) = fixture();
        assert!(verify_trusted(&b, &c, &t, &a, 200, Mode::Current).is_err());
        assert!(verify_trusted(&b, &c, &t, &a, 200, Mode::Historical).is_ok());
    }
    #[test]
    fn key_role_and_full_authority_interval_checked() {
        let (b, c, mut t, a) = fixture();
        t.payload.keys[0].expires_at = 100;
        resign(&mut t);
        assert!(verify_trusted(&b, &c, &t, &a, 100, Mode::Current).is_err());
        t.payload.keys[0].expires_at = 120;
        t.payload.keys[0].role = Role::Executor;
        resign(&mut t);
        assert!(verify_trusted(&b, &c, &t, &a, 100, Mode::Current).is_err());
    }
    #[test]
    fn rotation_keeps_old_unrevoked_keys_for_history() {
        let (b, c, mut t, a) = fixture();
        let key = SigningKey::from_bytes(&[10; 32]);
        t.payload.keys.push(Key {
            public_key: hex::encode(key.verifying_key().to_bytes()),
            role: Role::Actor,
            not_before: 120,
            expires_at: 500,
            revoked_at: None,
        });
        t.payload.revision = 3;
        resign(&mut t);
        verify_trusted(&b, &c, &t, &a, 200, Mode::Historical).unwrap();
    }
    #[test]
    fn tampering_duplicate_and_unknown_version_rejected() {
        let (_, _, mut t, a) = fixture();
        t.payload.revision = 10;
        assert!(validate_snapshot(&t, &a, 100).is_err());
        t.payload.keys.push(t.payload.keys[0].clone());
        assert!(t.payload.validate().is_err());
        t.payload.keys.pop();
        t.payload.version = "other".into();
        assert!(t.payload.validate().is_err());
    }
}

#[cfg(test)]
mod transition_tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use openproof_core::sign;
    #[test]
    fn transitions_bind_both_roots_payload_revision_audience_and_time() {
        let old_key = SigningKey::from_bytes(&[9; 32]);
        let new_key = SigningKey::from_bytes(&[10; 32]);
        let anchor = Anchor {
            root_key: hex::encode(old_key.verifying_key().to_bytes()),
            audience: "test".into(),
            minimum_revision: 1,
        };
        let p = RootTransition {
            version: "openproof-root-transition/1".into(),
            audience: "test".into(),
            old_root: anchor.root_key.clone(),
            new_root: hex::encode(new_key.verifying_key().to_bytes()),
            next_revision: 2,
            not_before: 90,
            expires_at: 110,
        };
        let old = sign(p.clone(), &old_key).unwrap();
        let new = sign(p.clone(), &new_key).unwrap();
        assert!(verify_transition(&old, &new, &anchor, 100).is_ok());
        for now in [89, 111] {
            assert!(verify_transition(&old, &new, &anchor, now).is_err());
        }
        for change in 0..6 {
            let mut q = p.clone();
            match change {
                0 => q.audience = "wrong".into(),
                1 => q.old_root = p.new_root.clone(),
                2 => q.next_revision = 1,
                3 => q.version = "unknown".into(),
                4 => q.next_revision = 1u64 << 63,
                _ => q.expires_at = 89,
            }
            let result = sign(q, &old_key).and_then(|s| verify_transition(&s, &new, &anchor, 100));
            assert!(result.is_err());
        }
        let mut changed = p;
        changed.expires_at += 1;
        let other = sign(changed, &new_key).unwrap();
        assert!(verify_transition(&old, &other, &anchor, 100).is_err());
        assert!(verify_transition(&new, &old, &anchor, 100).is_err());
    }
}
