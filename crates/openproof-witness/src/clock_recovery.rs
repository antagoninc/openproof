//! Privileged recovery of an installation-only clock jump; never rewrite signed time.
use super::*;
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClockRepair {
    pub version: String,
    pub old_floor: u64,
    pub new_floor: u64,
    pub signed_floor: u64,
    pub trust_epoch: u64,
    pub trust_sha256: String,
}
impl Evidence for ClockRepair {
    const DOMAIN: &'static str = "witness-clock-repair/1";
    fn validate(&self) -> openproof_core::Result<()> {
        if self.version != V
            || self.old_floor <= self.new_floor
            || self.new_floor < self.signed_floor
            || !valid_hash(&self.trust_sha256)
        {
            return Err(openproof_core::Error("invalid clock repair".into()));
        }
        Ok(())
    }
}
#[derive(Serialize)]
pub struct ClockStatus {
    pub clock_floor: u64,
    pub signed_floor: u64,
    pub now: u64,
    pub wait_until: u64,
}
pub fn clock_status(path: &Path, time: u64) -> Result<ClockStatus> {
    let c = connect_read(path)?;
    let floor: u64 = c.query_row("SELECT COALESCE(MAX(clock),0) FROM control", [], |r| {
        r.get(0)
    })?;
    let is_verifier: bool = c.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE name='verifier')",
        [],
        |r| r.get(0),
    )?;
    let has_floor: bool = c.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE name='signing_clock')",
        [],
        |r| r.get(0),
    )?;
    let signed: u64 = if is_verifier {
        c.query_row("SELECT observed FROM verifier WHERE id=1", [], |r| r.get(0))?
    } else if has_floor {
        c.query_row("SELECT floor FROM signing_clock WHERE id=1", [], |r| {
            r.get(0)
        })?
    } else {
        floor
    };
    Ok(ClockStatus {
        clock_floor: floor,
        signed_floor: signed,
        now: time,
        wait_until: signed,
    })
}
pub fn repair_clock(
    path: &Path,
    t: &Trust,
    key: &SigningKey,
    time: u64,
) -> Result<Signed<ClockRepair>> {
    t.validate(time)?;
    check(time <= i64::MAX as u64, "clock range")?;
    check(
        hex::encode(key.verifying_key().to_bytes()) == t.authority,
        "wrong repair authority",
    )?;
    let mut c = connect(path)?;
    let tx = c.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let verifier: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE name='verifier')",
        [],
        |r| r.get(0),
    )?;
    check(
        !verifier,
        "verifier floors cannot be repaired through role clock recovery",
    )?;
    let (epoch, hash, old): (u64, String, u64) = tx.query_row(
        "SELECT epoch,trust_hash,clock FROM control WHERE id=1",
        [],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
    )?;
    check(
        epoch == t.epoch && hash == super::hash(&canonical(t)?),
        "repair requires installed trust",
    )?;
    let signed: u64 = tx.query_row("SELECT floor FROM signing_clock WHERE id=1", [], |r| {
        r.get(0)
    })?;
    check(
        time < old && time >= signed,
        "cannot lower below signed-time floor; wait for clock to catch up",
    )?;
    let count: u64 = tx.query_row("SELECT COUNT(*) FROM clock_repairs", [], |r| r.get(0))?;
    check(count < 64, "clock repair audit capacity")?;
    let audit = sign(
        ClockRepair {
            version: V.into(),
            old_floor: old,
            new_floor: time,
            signed_floor: signed,
            trust_epoch: epoch,
            trust_sha256: hash,
        },
        key,
    )?;
    tx.execute(
        "INSERT INTO clock_repairs(record) VALUES(?1)",
        [serde_json::to_string(&audit)?],
    )?;
    tx.execute("UPDATE control SET clock=?1 WHERE id=1", [time])?;
    tx.commit()?;
    Ok(audit)
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifierClockRepair {
    pub version: String,
    pub old_floor: u64,
    pub new_floor: u64,
    pub trust_epoch: u64,
    pub trust_sha256: String,
    pub count: u64,
    pub head: String,
    pub observed: u64,
}
impl Evidence for VerifierClockRepair {
    const DOMAIN: &'static str = "verifier-clock-repair/1";
    fn validate(&self) -> openproof_core::Result<()> {
        if self.version != V
            || self.new_floor >= self.old_floor
            || self.new_floor < self.observed
            || !valid_hash(&self.head)
            || !valid_hash(&self.trust_sha256)
        {
            return Err(openproof_core::Error(
                "invalid verifier clock repair".into(),
            ));
        }
        Ok(())
    }
}
/// Prepare a bounded request on the verifier host; no private root is needed here.
pub fn verifier_clock_request(path: &Path, time: u64) -> Result<VerifierClockRepair> {
    let c = connect_read(path)?;
    let (count, head, observed): (u64, String, u64) = c.query_row(
        "SELECT count,head,observed FROM verifier WHERE id=1",
        [],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
    )?;
    let (epoch, h, old): (u64, String, u64) = c.query_row(
        "SELECT epoch,trust_hash,clock FROM control WHERE id=1",
        [],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
    )?;
    let request = VerifierClockRepair {
        version: V.into(),
        old_floor: old,
        new_floor: time,
        trust_epoch: epoch,
        trust_sha256: h,
        count,
        head,
        observed,
    };
    request.validate()?;
    Ok(request)
}
pub fn apply_verifier_clock_repair(
    path: &Path,
    trust: &Signed<Trust>,
    token: &Signed<VerifierClockRepair>,
    time: u64,
) -> Result<()> {
    let mut c = connect(path)?;
    let tx = c.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let (root, count, head, observed): (String, u64, String, u64) = tx.query_row(
        "SELECT root,count,head,observed FROM verifier WHERE id=1",
        [],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
    )?;
    verify_signature(trust, &root)?;
    verify_signature(token, &root)?;
    let q = &token.payload;
    check(
        time <= i64::MAX as u64 && q.new_floor <= time && time - q.new_floor <= 600,
        "clock repair token outside ten-minute window",
    )?;
    let (epoch, h, old): (u64, String, u64) = tx.query_row(
        "SELECT epoch,trust_hash,clock FROM control WHERE id=1",
        [],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
    )?;
    check(
        epoch == trust.payload.epoch
            && h == hash(&canonical(&trust.payload)?)
            && q.trust_epoch == epoch
            && q.trust_sha256 == h
            && q.old_floor == old
            && q.count == count
            && q.head == head
            && q.observed == observed,
        "clock repair state changed or token replayed",
    )?;
    let repairs: u64 = tx.query_row("SELECT COUNT(*) FROM clock_repairs", [], |r| r.get(0))?;
    check(repairs < 64, "clock repair audit capacity")?;
    tx.execute(
        "INSERT INTO clock_repairs(record) VALUES(?1)",
        [serde_json::to_string(token)?],
    )?;
    tx.execute("UPDATE control SET clock=?1 WHERE id=1", [q.new_floor])?;
    tx.commit()?;
    Ok(())
}
/// Local convenience for tests/single-owner homes; independent operators use tokens.
pub fn repair_verifier_clock(
    path: &Path,
    trust: &Signed<Trust>,
    key: &SigningKey,
    time: u64,
) -> Result<Signed<VerifierClockRepair>> {
    let token = sign(verifier_clock_request(path, time)?, key)?;
    apply_verifier_clock_repair(path, trust, &token, time)?;
    Ok(token)
}
