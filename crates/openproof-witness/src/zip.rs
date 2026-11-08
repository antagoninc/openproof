//! Write a ZIP archive of flat files with the STORE method (no compression).
//! Enough for the owner app's evidence download; no reader is included.
use openproof_witness::Result;

fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &b in data {
        crc ^= u32::from(b);
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0xEDB8_8320 & (crc & 1).wrapping_neg());
        }
    }
    !crc
}

/// `files` are (name, bytes). Names must be plain ASCII file names.
pub fn store(files: &[(String, Vec<u8>)]) -> Result<Vec<u8>> {
    if files.len() > 65_000 {
        return Err("too many files".into());
    }
    let mut out = Vec::new();
    let mut central = Vec::new();
    for (name, data) in files {
        if name.is_empty()
            || !name.bytes().all(|b| b.is_ascii_graphic())
            || name.contains(['/', '\\'])
        {
            return Err("archive names must be plain file names".into());
        }
        let size = u32::try_from(data.len())?;
        let offset = u32::try_from(out.len())?;
        let crc = crc32(data);
        let fixed = |sig: u32, central_entry: bool| {
            let mut h = Vec::new();
            h.extend_from_slice(&sig.to_le_bytes());
            if central_entry {
                h.extend_from_slice(&20u16.to_le_bytes()); // made by
            }
            h.extend_from_slice(&20u16.to_le_bytes()); // version needed
            h.extend_from_slice(&0u16.to_le_bytes()); // flags
            h.extend_from_slice(&0u16.to_le_bytes()); // method: store
            h.extend_from_slice(&0u16.to_le_bytes()); // time
            h.extend_from_slice(&0x21u16.to_le_bytes()); // date: 1980-01-01
            h.extend_from_slice(&crc.to_le_bytes());
            h.extend_from_slice(&size.to_le_bytes());
            h.extend_from_slice(&size.to_le_bytes());
            h.extend_from_slice(&(name.len() as u16).to_le_bytes());
            h.extend_from_slice(&0u16.to_le_bytes()); // extra length
            h
        };
        out.extend(fixed(0x0403_4b50, false));
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(data);
        let mut c = fixed(0x0201_4b50, true);
        c.extend_from_slice(&0u16.to_le_bytes()); // comment length
        c.extend_from_slice(&0u16.to_le_bytes()); // disk
        c.extend_from_slice(&0u16.to_le_bytes()); // internal attributes
        c.extend_from_slice(&0u32.to_le_bytes()); // external attributes
        c.extend_from_slice(&offset.to_le_bytes());
        c.extend_from_slice(name.as_bytes());
        central.extend(c);
    }
    let start = u32::try_from(out.len())?;
    let count = files.len() as u16;
    out.extend_from_slice(&central);
    out.extend_from_slice(&0x0605_4b50u32.to_le_bytes());
    out.extend_from_slice(&[0, 0, 0, 0]);
    out.extend_from_slice(&count.to_le_bytes());
    out.extend_from_slice(&count.to_le_bytes());
    out.extend_from_slice(&u32::try_from(central.len())?.to_le_bytes());
    out.extend_from_slice(&start.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    Ok(out)
}

#[cfg(test)]
mod tests {
    #[test]
    fn crc_matches_reference() {
        assert_eq!(super::crc32(b"123456789"), 0xCBF4_3926);
    }
}
