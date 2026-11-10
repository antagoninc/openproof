//! Reading private keys and bounded input files.
use crate::{Result, Trust};
use ed25519_dalek::SigningKey;
use std::{fs, io::Read, path::Path};
use zeroize::Zeroizing;

/// A file of at most 1 MiB.
pub fn read(path: impl AsRef<Path>) -> Result<Vec<u8>> {
    let mut b = vec![];
    fs::File::open(path)?.take(1_048_577).read_to_end(&mut b)?;
    if b.len() > 1_048_576 {
        return Err("input exceeds 1 MiB".into());
    }
    Ok(b)
}

/// A trust configuration file, strictly parsed.
pub fn trust(path: impl AsRef<Path>) -> Result<Trust> {
    Ok(openproof_core::parse(&read(path)?)?)
}

/// A hex Ed25519 seed in a private regular file: not a link, a FIFO or a
/// directory, and readable by its owner only.
#[cfg(unix)]
pub fn key(path: impl AsRef<Path>) -> Result<SigningKey> {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    let f = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    let m = f.metadata()?;
    if !m.is_file() || m.permissions().mode() & 0o077 != 0 {
        return Err("key must be a private regular file".into());
    }
    let mut raw = Zeroizing::new(Vec::new());
    f.take(257).read_to_end(&mut raw)?;
    if raw.len() > 256 {
        return Err("key size".into());
    }
    let encoded = std::str::from_utf8(&raw)?.trim();
    let mut seed = Zeroizing::new([0u8; 32]);
    hex::decode_to_slice(encoded, &mut *seed)?;
    Ok(SigningKey::from_bytes(&seed))
}
#[cfg(not(unix))]
pub fn key(_: impl AsRef<Path>) -> Result<SigningKey> {
    Err("Unix key storage required".into())
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt};
    #[test]
    fn descriptor_checks_reject_symlink_fifo_and_public_key_file() {
        let base = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../outputs/key-read-tests");
        fs::create_dir_all(&base).unwrap();
        let d = base.join(format!("{}", std::process::id()));
        fs::create_dir(&d).unwrap();
        let p = d.join("key.secret");
        fs::write(&p, "01".repeat(32)).unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(key(&p).is_ok());
        let link = d.join("link");
        symlink(&p, &link).unwrap();
        assert!(key(&link).is_err());
        fs::set_permissions(&p, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(key(&p).is_err());
        let fifo = d.join("fifo");
        assert!(std::process::Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .unwrap()
            .success());
        assert!(key(&fifo).is_err());
        assert!(key(&d).is_err());
        fs::remove_dir_all(d).unwrap();
    }
}
