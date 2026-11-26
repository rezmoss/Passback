//! Crash-safe, owner-only file writes.

use std::{
    fs,
    io::{self, Read, Write},
    path::{Path, PathBuf},
};

#[cfg(test)]
thread_local! {
    /// Test-only fault seam: fail after the temp file is written, before the rename.
    pub static FAIL_BEFORE_RENAME: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    /// Test-only seam: use this temp-file name instead of a random one.
    pub static FORCE_TEMP_NAME: std::cell::RefCell<Option<String>> = const { std::cell::RefCell::new(None) };
}

/// A path's directory; `.` for a bare relative file name.
fn dir_of(path: &Path) -> &Path {
    match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    }
}

fn sync_dir(dir: &Path) -> io::Result<()> {
    #[cfg(unix)]
    fs::File::open(dir)?.sync_all()?;
    let _ = dir;
    Ok(())
}

/// Ensure `dir` exists. Directories that already exist are left exactly as they are;
/// each directory we create is owner-only from creation, and its parent is fsynced
/// so the new entry survives a crash.
pub fn create_private_dir(dir: &Path) -> io::Result<()> {
    if dir.as_os_str().is_empty() || dir.is_dir() {
        return Ok(());
    }
    let mut missing: Vec<&Path> = Vec::new();
    let mut p = dir;
    loop {
        if p.as_os_str().is_empty() || p.exists() {
            break;
        }
        missing.push(p);
        match p.parent() {
            Some(parent) => p = parent,
            None => break,
        }
    }
    for d in missing.into_iter().rev() {
        match passback_harden::fs::create_dir_private(d) {
            Ok(()) => sync_dir(dir_of(d))?,
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists && d.is_dir() => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

fn temp_name(path: &Path) -> io::Result<PathBuf> {
    let name = path
        .file_name()
        .ok_or_else(|| io::Error::other("path has no file name"))?
        .to_string_lossy();
    #[cfg(test)]
    if let Some(forced) = FORCE_TEMP_NAME.with(|f| f.borrow().clone()) {
        return Ok(path.with_file_name(forced));
    }
    let rand: [u8; 8] = passback_crypto::rand::array().map_err(io::Error::other)?;
    Ok(path.with_file_name(format!(".{name}.{}.tmp", hex::encode(rand))))
}

/// Create a fresh, uniquely named, owner-only temp file next to `path`. Retries a few
/// times on a name collision (never touching the existing file).
fn create_temp(path: &Path) -> io::Result<(PathBuf, fs::File)> {
    let mut last = None;
    for _ in 0..4 {
        let tmp = temp_name(path)?;
        match passback_harden::fs::create_file_private(&tmp) {
            Ok(f) => return Ok((tmp, f)),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => last = Some(e),
            Err(e) => return Err(e),
        }
    }
    Err(last.unwrap_or_else(|| io::Error::other("could not create a temp file")))
}

/// Replace `path` with `bytes` atomically and durably: write a new, uniquely named,
/// owner-only temp file next to it, fsync it, rename it over `path` (write-through
/// on Windows), then fsync the directory. After a crash `path` holds either the old
/// or the new contents. On failure only a temp file this call created is removed.
pub fn write_atomic(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let dir = dir_of(path);
    create_private_dir(dir)?;
    let (tmp, mut f) = create_temp(path)?;
    let result = (|| {
        f.write_all(bytes)?;
        f.sync_all()?;
        drop(f);
        #[cfg(test)]
        if FAIL_BEFORE_RENAME.with(|c| c.get()) {
            return Err(io::Error::other("simulated crash before rename"));
        }
        passback_harden::fs::replace(&tmp, path)?;
        sync_dir(dir)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result
}

/// Read a whole file, refusing anything larger than `limit` bytes. Uses one open
/// handle, so the file can't be swapped or grown between the size check and the read.
/// `Ok(None)` if the file doesn't exist. The buffer is allocated once at the file's
/// size and zeroized on drop (device state holds Secret Keys).
pub fn read_bounded(path: &Path, limit: u64) -> io::Result<Option<zeroize::Zeroizing<Vec<u8>>>> {
    let f = match fs::File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    let meta = f.metadata()?;
    if !meta.is_file() {
        return Err(io::Error::other("not a regular file"));
    }
    if meta.len() > limit {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "file too large"));
    }
    let mut buf = zeroize::Zeroizing::new(Vec::with_capacity(meta.len() as usize));
    f.take(limit + 1).read_to_end(&mut buf)?;
    if buf.len() as u64 > limit {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "file too large"));
    }
    Ok(Some(buf))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn atomic_write_replaces_contents_and_is_owner_only() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("sub/deeper/state.json");
        write_atomic(&p, b"one").unwrap();
        write_atomic(&p, b"two").unwrap();
        assert_eq!(fs::read(&p).unwrap(), b"two");
        for owner_only in [&p, &p.parent().unwrap().to_path_buf(), &d.path().join("sub")] {
            assert!(
                passback_harden::fs::is_owner_only(owner_only).unwrap(),
                "{}",
                owner_only.display()
            );
        }
        let leftovers: Vec<_> = fs::read_dir(p.parent().unwrap())
            .unwrap()
            .filter_map(|e| e.ok())
            .collect();
        assert_eq!(leftovers.len(), 1, "temp files left behind: {leftovers:?}");
    }

    #[test]
    fn a_relative_path_is_written_in_the_current_directory() {
        assert_eq!(dir_of(Path::new("vault.pbv")), Path::new("."));
        assert_eq!(dir_of(Path::new("a/vault.pbv")), Path::new("a"));
    }

    #[cfg(unix)]
    #[test]
    fn existing_directories_keep_their_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let d = tempfile::tempdir().unwrap();
        let mine = d.path().join("user-dir");
        fs::create_dir(&mine).unwrap();
        fs::set_permissions(&mine, fs::Permissions::from_mode(0o755)).unwrap();
        write_atomic(&mine.join("vault.pbv"), b"x").unwrap();
        assert_eq!(fs::metadata(&mine).unwrap().permissions().mode() & 0o777, 0o755);
    }

    #[cfg(unix)]
    #[test]
    fn a_planted_symlink_at_a_predictable_name_is_not_used() {
        let d = tempfile::tempdir().unwrap();
        let target = d.path().join("vault.pbv");
        let elsewhere = d.path().join("attacker-file");
        fs::write(&elsewhere, b"untouched").unwrap();
        for name in ["vault.tmp", ".vault.pbv.tmp", "vault.pbv.tmp"] {
            std::os::unix::fs::symlink(&elsewhere, d.path().join(name)).unwrap();
        }
        write_atomic(&target, b"secret").unwrap();
        assert_eq!(fs::read(&elsewhere).unwrap(), b"untouched");
        assert_eq!(fs::read(&target).unwrap(), b"secret");
    }

    #[test]
    fn a_temp_name_collision_never_deletes_the_existing_file() {
        let d = tempfile::tempdir().unwrap();
        let target = d.path().join("vault.pbv");
        let existing = d.path().join(".collision.tmp");
        fs::write(&existing, b"someone else's file").unwrap();
        FORCE_TEMP_NAME.with(|f| *f.borrow_mut() = Some(".collision.tmp".into()));
        let r = write_atomic(&target, b"new");
        FORCE_TEMP_NAME.with(|f| *f.borrow_mut() = None);
        assert!(r.is_err(), "every retry collides with the forced name");
        assert_eq!(fs::read(&existing).unwrap(), b"someone else's file");
        assert!(!target.exists());
    }

    #[test]
    fn failure_before_rename_keeps_old_contents_and_removes_the_temp_file() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("vault.pbv");
        write_atomic(&p, b"old").unwrap();
        FAIL_BEFORE_RENAME.with(|c| c.set(true));
        assert!(write_atomic(&p, b"new").is_err());
        FAIL_BEFORE_RENAME.with(|c| c.set(false));
        assert_eq!(fs::read(&p).unwrap(), b"old");
        assert_eq!(fs::read_dir(d.path()).unwrap().count(), 1, "temp file left behind");
    }

    #[test]
    fn bounded_read_refuses_oversized_files() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("f");
        fs::write(&p, vec![0u8; 11]).unwrap();
        assert!(read_bounded(&p, 10).is_err());
        assert_eq!(read_bounded(&p, 11).unwrap().unwrap().len(), 11);
        assert!(read_bounded(&d.path().join("missing"), 10).unwrap().is_none());
    }
}
