//! The signing clock floor: never lowered by a signature.
use super::*;
pub fn signed_time(tx: &rusqlite::Transaction<'_>, time: u64) -> Result<()> {
    tx.execute(
        "UPDATE signing_clock SET floor=MAX(floor,?1) WHERE id=1",
        [time],
    )?;
    Ok(())
}
