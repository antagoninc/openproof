//! Private files: created new, or replaced atomically and durably.
use crate::Result;
use std::{io::Write, path::Path};

/// 128 random bits, hex.
pub fn random_hex() -> String {
    use rand_core::{OsRng, RngCore};
    let mut b = [0u8; 16];
    OsRng.fill_bytes(&mut b);
    hex::encode(b)
}

/// Create a new private file; refuse to replace one.
pub fn write_new(path: &Path, data: &[u8]) -> Result<()> {
    let mut o = std::fs::OpenOptions::new();
    o.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600);
    }
    let mut f = o.open(path)?;
    f.write_all(data)?;
    f.sync_all()?;
    Ok(())
}

/// Replace a file atomically and make the rename durable.
pub fn replace(path: &Path, data: &[u8]) -> Result<()> {
    let name = path.file_name().ok_or("file name")?.to_string_lossy();
    let pending = path.with_file_name(format!(".{name}-{}", random_hex()));
    write_new(&pending, data)?;
    std::fs::rename(&pending, path)?;
    if let Some(parent) = path.parent() {
        std::fs::File::open(parent)?.sync_all()?;
    }
    Ok(())
}
