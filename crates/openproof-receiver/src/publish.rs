//! Protected files (docs/PROTECTED-FILES.md): every approved document, also
//! written as a file that only the receiver's account can change.
use crate::{check, connect_read, files, name, Result};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::{fs, path::Path};

/// Write each document in `state` to `dir/<document>`, unless the file has
/// that content already. `dir` must be a directory of the state's account
/// whose mode lets no other account write it. Returns the documents whose
/// files do not have the current content: a name with a capital letter (file
/// names can ignore case) has no file, and after a failed write the file is
/// absent or has an earlier version.
pub fn all(state: &Path, dir: &Path) -> Result<Vec<String>> {
    let m = fs::symlink_metadata(dir)?;
    check(
        m.is_dir() && m.uid() == fs::metadata(state)?.uid() && m.mode() & 0o022 == 0,
        "the publish folder must be a directory that only this account can write",
    )?;
    // What an interrupted write left. A document name cannot start with a dot.
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        if entry.file_name().to_string_lossy().starts_with('.') {
            let _ = fs::remove_file(entry.path());
        }
    }
    let c = connect_read(state)?;
    let mut q = c.prepare("SELECT id,content FROM docs ORDER BY id")?;
    let docs = q.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?;
    let mut missing = vec![];
    for doc in docs {
        let (id, content): (String, String) = doc?;
        let plain = name(&id) && !id.bytes().any(|b| b.is_ascii_uppercase());
        if !plain || write(&dir.join(&id), content.as_bytes()).is_err() {
            missing.push(id);
        }
    }
    Ok(missing)
}

/// A file every account can read. It is replaced whole, never written in
/// place, so a reader sees all of the old content or all of the new. The
/// rename is not made durable here: after a crash the old file can be back,
/// and the service writes every file again when it starts.
fn write(path: &Path, content: &[u8]) -> Result<()> {
    let current = fs::symlink_metadata(path).is_ok_and(|m| {
        m.is_file() && m.mode() & 0o7777 == 0o644 && m.len() == content.len() as u64
    }) && fs::read(path).is_ok_and(|old| old == content);
    if current {
        return Ok(());
    }
    let pending = path.with_file_name(format!(".{}", files::random_hex()));
    files::write_new(&pending, content)?;
    fs::set_permissions(&pending, fs::Permissions::from_mode(0o644))?;
    fs::rename(&pending, path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    fn fixture(tag: &str) -> (std::path::PathBuf, std::path::PathBuf) {
        let base = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../outputs/publish-tests");
        fs::create_dir_all(&base).unwrap();
        let d = base.join(format!("{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir(&d).unwrap();
        let (state, dir) = (d.join("state"), d.join("published"));
        crate::init(&state).unwrap();
        fs::create_dir(&dir).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();
        (state, dir)
    }

    fn put(state: &Path, id: &str, content: &str) {
        crate::connect(state)
            .unwrap()
            .execute(
                "INSERT INTO docs VALUES(?1,1,?2) ON CONFLICT(id) DO UPDATE SET content=excluded.content",
                [id, content],
            )
            .unwrap();
    }

    #[test]
    fn documents_become_files_and_are_repaired() {
        let (state, dir) = fixture("repair");
        assert!(all(&state, &dir).unwrap().is_empty());
        put(&state, "agent-rules", "rule one\n");
        put(&state, "Notes", "capital");
        assert_eq!(all(&state, &dir).unwrap(), ["Notes"]);
        let file = dir.join("agent-rules");
        assert_eq!(fs::read(&file).unwrap(), b"rule one\n");
        assert_eq!(fs::metadata(&file).unwrap().mode() & 0o7777, 0o644);
        assert!(!dir.join("Notes").exists() && !dir.join("notes").exists());
        // An unchanged file is left as it is.
        let before = fs::metadata(&file).unwrap().ino();
        all(&state, &dir).unwrap();
        assert_eq!(fs::metadata(&file).unwrap().ino(), before);
        // Changed content, a wrong mode, a deleted file and a link are repaired.
        fs::write(&file, "rule two\n").unwrap();
        all(&state, &dir).unwrap();
        assert_eq!(fs::read(&file).unwrap(), b"rule one\n");
        fs::set_permissions(&file, fs::Permissions::from_mode(0o666)).unwrap();
        all(&state, &dir).unwrap();
        assert_eq!(fs::metadata(&file).unwrap().mode() & 0o7777, 0o644);
        fs::remove_file(&file).unwrap();
        let other = dir.parent().unwrap().join("other");
        fs::write(&other, "rule one\n").unwrap();
        symlink(&other, &file).unwrap();
        all(&state, &dir).unwrap();
        assert!(fs::symlink_metadata(&file).unwrap().is_file());
        assert_eq!(fs::read(&other).unwrap(), b"rule one\n");
        // A new version replaces the file, and leftovers are removed.
        put(&state, "agent-rules", "rule three\n");
        fs::write(dir.join(".leftover"), "x").unwrap();
        assert_eq!(all(&state, &dir).unwrap(), ["Notes"]);
        assert_eq!(fs::read(&file).unwrap(), b"rule three\n");
        let names: Vec<_> = fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(names, ["agent-rules"]);
        // A name that cannot be replaced is reported, and the rest is written.
        // Each try leaves at most one unfinished file.
        put(&state, "blocked", "b");
        fs::create_dir(dir.join("blocked")).unwrap();
        put(&state, "zeta", "z");
        for _ in 0..3 {
            assert_eq!(all(&state, &dir).unwrap(), ["Notes", "blocked"]);
            assert_eq!(fs::read(dir.join("zeta")).unwrap(), b"z");
            assert_eq!(fs::read_dir(&dir).unwrap().count(), 4);
        }
        // Only a document name becomes a file name, whatever the state holds.
        for id in ["../escaped", ".hidden", "a/b", ""] {
            put(&state, id, "x");
        }
        let missing = all(&state, &dir).unwrap();
        assert_eq!(
            missing,
            ["", "../escaped", ".hidden", "Notes", "a/b", "blocked"]
        );
        assert!(!dir.parent().unwrap().join("escaped").exists());
        assert!(!dir.join(".hidden").exists() && !dir.join("a").exists());
        fs::remove_dir_all(dir.parent().unwrap()).unwrap();
    }

    #[test]
    fn folder_must_be_a_directory_only_this_account_can_write() {
        let (state, dir) = fixture("folder");
        put(&state, "agent-rules", "rule one\n");
        for mode in [0o775, 0o757, 0o777] {
            fs::set_permissions(&dir, fs::Permissions::from_mode(mode)).unwrap();
            assert!(all(&state, &dir).is_err(), "{mode:o}");
        }
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();
        let link = dir.parent().unwrap().join("link");
        symlink(&dir, &link).unwrap();
        assert!(all(&state, &link).is_err());
        assert!(all(&state, &dir.join("absent")).is_err());
        assert!(fs::read_dir(&dir).unwrap().next().is_none());
        assert!(all(&state, &dir).unwrap().is_empty());
        fs::remove_dir_all(dir.parent().unwrap()).unwrap();
    }
}
