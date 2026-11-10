//! Checks of the witness's C2SP checkpoints and of cosignatures on them
//! (c2sp.org/signed-note, c2sp.org/tlog-cosignature, Ed25519 type 0x04), and
//! RFC 6962 proof verification. The tree, the proofs and the log's own
//! signature are in `openproof_receiver::tlog`, re-exported here.
use crate::{check, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
pub use openproof_receiver::tlog::*;
/// RFC 9162 section 2.1.3.2.
pub fn verify_inclusion(
    index: u64,
    size: u64,
    leaf: &Hash,
    proof: &[Hash],
    root_hash: &Hash,
) -> bool {
    if index >= size {
        return false;
    }
    let (mut f_n, mut s_n) = (index, size - 1);
    let mut r = *leaf;
    for p in proof {
        if s_n == 0 {
            return false;
        }
        if f_n & 1 == 1 || f_n == s_n {
            r = node(p, &r);
            if f_n & 1 == 0 {
                while f_n & 1 == 0 && f_n != 0 {
                    f_n >>= 1;
                    s_n >>= 1;
                }
            }
        } else {
            r = node(&r, p);
        }
        f_n >>= 1;
        s_n >>= 1;
    }
    s_n == 0 && &r == root_hash
}
/// RFC 9162 section 2.1.4.2.
pub fn verify_consistency(
    old: u64,
    new: u64,
    old_root: &Hash,
    new_root: &Hash,
    proof: &[Hash],
) -> bool {
    if old > new {
        return false;
    }
    if old == new {
        return proof.is_empty() && old_root == new_root;
    }
    if old == 0 {
        return proof.is_empty();
    }
    let mut path: Vec<Hash> = proof.to_vec();
    if old.is_power_of_two() {
        path.insert(0, *old_root);
    }
    let Some((first, rest)) = path.split_first() else {
        return false;
    };
    let (mut f_n, mut s_n) = (old - 1, new - 1);
    while f_n & 1 == 1 {
        f_n >>= 1;
        s_n >>= 1;
    }
    let (mut f_r, mut s_r) = (*first, *first);
    for c in rest {
        if s_n == 0 {
            return false;
        }
        if f_n & 1 == 1 || f_n == s_n {
            f_r = node(c, &f_r);
            s_r = node(c, &s_r);
            if f_n & 1 == 0 {
                while f_n & 1 == 0 && f_n != 0 {
                    f_n >>= 1;
                    s_n >>= 1;
                }
            }
        } else {
            s_r = node(&s_r, c);
        }
        f_n >>= 1;
        s_n >>= 1;
    }
    &f_r == old_root && &s_r == new_root && s_n == 0
}

// ---------------------------------------------------------------- signed notes
/// The C2SP vkey of a signer: name+hex key ID+base64(type || key).
pub fn vkey(name: &str, kind: u8, public: &[u8; 32]) -> String {
    let mut raw = vec![kind];
    raw.extend_from_slice(public);
    format!(
        "{name}+{}+{}",
        hex::encode(key_id(name, kind, public)),
        B64.encode(raw)
    )
}
/// Parse a vkey of the given type into its name and key.
pub fn parse_vkey(v: &str, kind: u8) -> Result<(String, [u8; 32])> {
    let mut parts = v.splitn(3, '+');
    let (Some(name), Some(id), Some(key)) = (parts.next(), parts.next(), parts.next()) else {
        return Err("malformed vkey".into());
    };
    let raw = B64.decode(key)?;
    check(raw.len() == 33 && raw[0] == kind, "unsupported vkey type")?;
    let public: [u8; 32] = raw[1..].try_into()?;
    check(
        hex::encode(key_id(name, kind, &public)) == id && !name.is_empty(),
        "vkey key ID mismatch",
    )?;
    // Refuse small-order keys: with one, a fixed signature verifies on any note.
    openproof_core::public_key(&hex::encode(public)).map_err(|_| "weak vkey")?;
    Ok((name.to_string(), public))
}
/// A parsed signed checkpoint: the body, its fields and its signature lines.
#[derive(Debug, Clone)]
pub struct Note {
    pub body: String,
    pub origin: String,
    pub size: u64,
    pub root: Hash,
    pub signatures: Vec<(String, Vec<u8>)>,
}
pub fn parse_note(text: &str) -> Result<Note> {
    check(text.len() <= 1 << 16, "note too large")?;
    check(
        !text.contains('\r') && !text.chars().any(|c| c.is_control() && c != '\n'),
        "control characters in note",
    )?;
    // The signatures follow the last empty line (c2sp.org/signed-note).
    let (body, sigs) = text.rsplit_once("\n\n").ok_or("note without signatures")?;
    let body = format!("{body}\n");
    let mut lines = body.split('\n');
    let origin = lines.next().ok_or("no origin")?.to_string();
    let size_text = lines.next().ok_or("no size")?;
    check(
        !size_text.is_empty()
            && size_text.bytes().all(|b| b.is_ascii_digit())
            && (size_text == "0" || !size_text.starts_with('0')),
        "noncanonical tree size",
    )?;
    let size: u64 = size_text.parse()?;
    let root: Hash = B64
        .decode(lines.next().ok_or("no root")?)?
        .try_into()
        .map_err(|_| "root hash length")?;
    let mut signatures = vec![];
    check(sigs.ends_with('\n'), "note must end in a newline")?;
    for line in sigs[..sigs.len() - 1].split('\n') {
        let rest = line
            .strip_prefix("\u{2014} ")
            .ok_or("malformed signature line")?;
        let (name, sig) = rest.split_once(' ').ok_or("malformed signature line")?;
        let raw = B64.decode(sig)?;
        check(raw.len() >= 4, "short signature")?;
        signatures.push((name.to_string(), raw));
    }
    Ok(Note {
        body,
        origin,
        size,
        root,
        signatures,
    })
}
/// The log's own signature on a note, by its Ed25519 key.
pub fn verify_note(n: &Note, name: &str, public: &[u8; 32]) -> bool {
    let id = key_id(name, 0x01, public);
    let Ok(k) = VerifyingKey::from_bytes(public) else {
        return false;
    };
    if k.is_weak() {
        return false;
    }
    n.signatures.iter().any(|(sname, raw)| {
        sname == name
            && raw.len() == 68
            && raw[..4] == id
            && <[u8; 64]>::try_from(&raw[4..])
                .map(|s| {
                    k.verify_strict(n.body.as_bytes(), &ed25519_dalek::Signature::from_bytes(&s))
                })
                .is_ok_and(|r| r.is_ok())
    })
}
/// The message an Ed25519 checkpoint cosigner (type 0x04) signs.
pub fn cosigned_message(n: &Note, time: u64) -> String {
    format!("cosignature/v1\ntime {time}\n{}", n.body)
}
/// A valid cosignature on the note by this cosigner: Some(timestamp), else None.
pub fn verify_cosignature(n: &Note, name: &str, public: &[u8; 32]) -> Option<u64> {
    let id = key_id(name, 0x04, public);
    let k = VerifyingKey::from_bytes(public)
        .ok()
        .filter(|k| !k.is_weak())?;
    n.signatures.iter().find_map(|(sname, raw)| {
        if sname != name || raw.len() != 76 || raw[..4] != id {
            return None;
        }
        let time = u64::from_be_bytes(raw[4..12].try_into().ok()?);
        let sig = ed25519_dalek::Signature::from_bytes(&raw[12..76].try_into().ok()?);
        k.verify_strict(cosigned_message(n, time).as_bytes(), &sig)
            .ok()
            .map(|_| time)
    })
}
/// Cosign a note (type 0x04). Used by tests and by an owner-run test witness.
pub fn cosign(n: &Note, name: &str, key: &SigningKey, time: u64) -> String {
    let public = key.verifying_key().to_bytes();
    let mut raw = key_id(name, 0x04, &public).to_vec();
    raw.extend_from_slice(&time.to_be_bytes());
    raw.extend_from_slice(&key.sign(cosigned_message(n, time).as_bytes()).to_bytes());
    format!("\u{2014} {name} {}\n", B64.encode(raw))
}

// ---------------------------------------------------------------- the witness state
#[cfg(test)]
mod tests {
    use super::*;

    fn tree(n: usize) -> Vec<Hash> {
        (0..n).map(|i| leaf_hash(&[i as u8])).collect()
    }

    #[test]
    fn rfc6962_empty_and_known_roots() {
        // RFC 6962 test vectors (certificate-transparency-go merkle tests): the empty
        // root, and the root over the 8 leaves "", 00, 10, 2021, 3031, 40414243,
        // 5051525354555657, 606162636465666768696a6b6c6d6e6f.
        assert_eq!(
            hex::encode(root(&[])),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        let data: [&[u8]; 8] = [
            b"",
            b"\x00",
            b"\x10",
            b"\x20\x21",
            b"\x30\x31",
            b"\x40\x41\x42\x43",
            b"\x50\x51\x52\x53\x54\x55\x56\x57",
            b"\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f",
        ];
        let leaves: Vec<Hash> = data.iter().map(|d| leaf_hash(d)).collect();
        assert_eq!(
            hex::encode(root(&leaves)),
            "5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328"
        );
        assert_eq!(
            hex::encode(root(&leaves[..1])),
            "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d"
        );
    }

    #[test]
    fn every_inclusion_and_consistency_proof_verifies_and_breaks() {
        for n in 1..=40usize {
            let d = tree(n);
            let r = root(&d);
            for i in 0..n {
                let p = inclusion_proof(i, &d).unwrap();
                assert!(
                    verify_inclusion(i as u64, n as u64, &d[i], &p, &r),
                    "{i}/{n}"
                );
                // A proof does not commit to the size on its own; the signed checkpoint
                // binds size and root, so check a wrong root and a wrong leaf instead.
                assert!(!verify_inclusion(
                    i as u64,
                    n as u64,
                    &d[i],
                    &p,
                    &leaf_hash(b"x")
                ));
                assert!(!verify_inclusion(
                    i as u64,
                    n as u64,
                    &leaf_hash(b"x"),
                    &p,
                    &r
                ));
                if let Some(first) = p.first() {
                    let mut bad = p.clone();
                    bad[0] = leaf_hash(first);
                    assert!(!verify_inclusion(i as u64, n as u64, &d[i], &bad, &r));
                }
            }
            for m in 0..=n {
                let p = consistency_proof(m, &d).unwrap();
                let old = root(&d[..m]);
                assert!(
                    verify_consistency(m as u64, n as u64, &old, &r, &p),
                    "{m}->{n}"
                );
                if m > 0 && m < n {
                    let other = root(&tree(m + 1)[1..]);
                    assert!(!verify_consistency(m as u64, n as u64, &other, &r, &p));
                    let mut bad = p.clone();
                    bad.pop();
                    assert!(!verify_consistency(m as u64, n as u64, &old, &r, &bad));
                }
            }
        }
    }

    #[test]
    fn notes_sign_verify_and_cosign() {
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let witness = SigningKey::from_bytes(&[9u8; 32]);
        let d = tree(5);
        let body = checkpoint_body("example.org/log", 5, &root(&d));
        let signed = sign_note(&body, "example.org/log", &key);
        let n = parse_note(&signed).unwrap();
        assert_eq!((n.origin.as_str(), n.size), ("example.org/log", 5));
        let public = key.verifying_key().to_bytes();
        assert!(verify_note(&n, "example.org/log", &public));
        assert!(!verify_note(&n, "example.org/other", &public));
        let wpub = witness.verifying_key().to_bytes();
        let cosigned = format!(
            "{signed}{}",
            cosign(&n, "witness.example", &witness, 1_700_000_000)
        );
        let c = parse_note(&cosigned).unwrap();
        assert_eq!(
            verify_cosignature(&c, "witness.example", &wpub),
            Some(1_700_000_000)
        );
        assert_eq!(verify_cosignature(&c, "witness.other", &wpub), None);
        // A cosignature does not carry over to another tree head.
        let moved = cosigned.replacen("\n5\n", "\n6\n", 1);
        assert_eq!(
            verify_cosignature(&parse_note(&moved).unwrap(), "witness.example", &wpub),
            None
        );
        let v = vkey("witness.example", 0x04, &wpub);
        assert_eq!(
            parse_vkey(&v, 0x04).unwrap(),
            ("witness.example".into(), wpub)
        );
        assert!(parse_vkey(&v, 0x01).is_err());
    }

    #[test]
    fn small_order_keys_and_loose_notes_are_refused() {
        // The identity point: with it, R = identity and S = 0 verifies on anything.
        let mut identity = [0u8; 32];
        identity[0] = 1;
        assert!(parse_vkey(&vkey("w.example", 0x04, &identity), 0x04).is_err());
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let signed = sign_note(
            &checkpoint_body("example.org/log", 0, &root(&[])),
            "example.org/log",
            &key,
        );
        assert!(parse_note(&signed).is_ok());
        assert!(parse_note(&signed.replace('\n', "\r\n")).is_err());
        assert!(parse_note(&signed.replacen("\n0\n", "\n00\n", 1)).is_err());
    }

    #[test]
    fn origins_exclude_openproof_domains_and_odd_bytes() {
        assert!(valid_origin("openproof.antagon.ai/log/abc"));
        for bad in [
            "",
            "OpenProof/v1/witness-trust/1",
            "cosignature/v1",
            "a b",
            "a\nb",
            "é",
        ] {
            assert!(!valid_origin(bad), "{bad:?}");
        }
    }
}
