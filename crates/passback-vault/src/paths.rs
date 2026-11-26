//! Where the vault, device state and backups live.

use std::path::{Path, PathBuf};

/// File locations for one vault.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Paths {
    /// The vault file (`.pbv`). Encrypted and signed; fine to copy or back up.
    pub vault: PathBuf,
    /// Device state: checkpoints and Secret Key. Must stay local, never synced.
    pub device: PathBuf,
    /// Automatic backups.
    pub backups: PathBuf,
    /// Portable mode: vault and device state sit next to the binary, so rollback
    /// protection is weaker (whoever has the folder has both).
    pub portable: bool,
}

/// Name of the marker file that enables portable mode when placed next to the binary.
pub const PORTABLE_MARKER: &str = "passback.portable";

/// Environment the resolver reads. A struct so tests can pass a fake environment.
#[derive(Clone, Debug, Default)]
pub struct Env {
    /// `PASSBACK_VAULT`.
    pub vault: Option<PathBuf>,
    /// `HOME` (Unix) or `USERPROFILE` (Windows).
    pub home: Option<PathBuf>,
    /// `XDG_DATA_HOME`.
    pub xdg_data: Option<PathBuf>,
    /// `XDG_STATE_HOME`.
    pub xdg_state: Option<PathBuf>,
    /// `APPDATA`.
    pub appdata: Option<PathBuf>,
    /// `LOCALAPPDATA`.
    pub local_appdata: Option<PathBuf>,
    /// Directory of the running executable.
    pub exe_dir: Option<PathBuf>,
}

impl Env {
    /// Read the real process environment.
    pub fn from_process() -> Self {
        let var = |k: &str| std::env::var_os(k).filter(|v| !v.is_empty()).map(PathBuf::from);
        Self {
            vault: var("PASSBACK_VAULT"),
            home: var("HOME").or_else(|| var("USERPROFILE")),
            xdg_data: var("XDG_DATA_HOME"),
            xdg_state: var("XDG_STATE_HOME"),
            appdata: var("APPDATA"),
            local_appdata: var("LOCALAPPDATA"),
            exe_dir: std::env::current_exe()
                .ok()
                .and_then(|p| p.parent().map(Path::to_path_buf)),
        }
    }
}

/// Error when no location can be determined.
#[derive(Debug, thiserror::Error)]
#[error("cannot determine where to store data: set HOME (or USERPROFILE on Windows), or pass --vault")]
pub struct NoHome;

impl Paths {
    /// Everything under one directory (portable mode and tests).
    pub fn under(dir: &Path, portable: bool) -> Self {
        Self {
            vault: dir.join("vault.pbv"),
            device: dir.join("device").join("device.json"),
            backups: dir.join("backups"),
            portable,
        }
    }

    /// Resolve locations. Precedence: `--vault` (`explicit`), then `PASSBACK_VAULT`, then
    /// portable mode, then the platform default. Device state always uses the
    /// platform's local (non-roaming) state directory unless portable.
    pub fn resolve(explicit: Option<&Path>, env: &Env) -> Result<Self, NoHome> {
        if explicit.is_none()
            && env.vault.is_none()
            && let Some(exe) = &env.exe_dir
            && exe.join(PORTABLE_MARKER).exists()
        {
            return Ok(Self::under(&exe.join("data"), true));
        }
        let device = Self::device_dir(env)?.join("device.json");
        let vault = match explicit.map(Path::to_path_buf).or_else(|| env.vault.clone()) {
            Some(v) => v,
            None => Self::data_dir(env)?.join("vault.pbv"),
        };
        let backups = vault.parent().unwrap_or(Path::new(".")).join("backups");
        Ok(Self {
            vault,
            device,
            backups,
            portable: false,
        })
    }

    /// Reject locations that would make one file overwrite another: the vault at the
    /// device-state path (or its lock), or, outside portable mode, device state in the
    /// vault's own directory (it would be copied or synced along with the vault).
    /// Paths are compared by real location (absolute, symlinks and `..` resolved,
    /// case-insensitive on macOS and Windows), not by spelling.
    pub fn validate(&self) -> Result<(), crate::VaultError> {
        if self.vault.file_name().is_none() {
            return Err(crate::VaultError::BadPaths("the vault path has no file name"));
        }
        let lock_of = |p: &Path| {
            let mut s = p.as_os_str().to_owned();
            s.push(".lock");
            PathBuf::from(s)
        };
        let (vault, device) = (real_location(&self.vault), real_location(&self.device));
        if same(&vault, &device)
            || same(&vault, &real_location(&lock_of(&self.device)))
            || same(&device, &real_location(&lock_of(&self.vault)))
        {
            return Err(crate::VaultError::BadPaths(
                "the vault and the device state use the same file",
            ));
        }
        if !self.portable && same(&dir(&vault), &dir(&device)) {
            return Err(crate::VaultError::BadPaths(
                "device state must not live in the vault's directory (it would be synced or backed up with it)",
            ));
        }
        Ok(())
    }

    fn data_dir(env: &Env) -> Result<PathBuf, NoHome> {
        if cfg!(windows) {
            return env.appdata.as_ref().map(|d| d.join("Passback")).ok_or(NoHome);
        }
        let home = env.home.as_ref().ok_or(NoHome);
        if cfg!(target_os = "macos") {
            return Ok(home?.join("Library/Application Support/Passback"));
        }
        Ok(match &env.xdg_data {
            Some(d) => d.join("passback"),
            None => home?.join(".local/share/passback"),
        })
    }

    fn device_dir(env: &Env) -> Result<PathBuf, NoHome> {
        // Always a dedicated `Device`/`device` directory, so it can't coincide with the
        // vault's directory even if the data and state roots are set to the same place.
        if cfg!(windows) {
            return env
                .local_appdata
                .as_ref()
                .map(|d| d.join("Passback").join("Device"))
                .ok_or(NoHome);
        }
        let home = env.home.as_ref().ok_or(NoHome);
        if cfg!(target_os = "macos") {
            return Ok(home?.join("Library/Application Support/Passback/Device"));
        }
        Ok(match &env.xdg_state {
            Some(d) => d.join("passback").join("device"),
            None => home?.join(".local/state/passback/device"),
        })
    }
}

fn dir(p: &Path) -> PathBuf {
    p.parent().map(Path::to_path_buf).unwrap_or_default()
}

/// Absolute path with the longest existing prefix canonicalized (symlinks and `..`
/// resolved by the OS) and the rest normalized lexically.
fn real_location(p: &Path) -> PathBuf {
    use std::path::Component;
    let abs = if p.is_absolute() {
        p.to_path_buf()
    } else {
        std::env::current_dir().unwrap_or_default().join(p)
    };
    // Walk component by component, resolving symlinks as soon as a prefix exists, so
    // a `..` after a symlink goes to the symlink target's parent (as the OS does),
    // and a `..` after a missing directory is resolved by text.
    let mut out = PathBuf::new();
    for c in abs.components() {
        match c {
            Component::Prefix(_) | Component::RootDir => out.push(c),
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            Component::Normal(name) => {
                out.push(name);
                if let Ok(real) = std::fs::canonicalize(&out) {
                    out = real;
                }
            }
        }
    }
    out
}

fn same(a: &Path, b: &Path) -> bool {
    if cfg!(any(windows, target_os = "macos")) {
        a.to_string_lossy().to_lowercase() == b.to_string_lossy().to_lowercase()
    } else {
        a == b
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn precedence_and_device_state_stays_local() {
        let d = tempfile::tempdir().unwrap();
        let env = Env {
            home: Some(d.path().join("home")),
            xdg_data: Some(d.path().join("data")),
            xdg_state: Some(d.path().join("state")),
            appdata: Some(d.path().join("appdata")),
            local_appdata: Some(d.path().join("local")),
            exe_dir: Some(d.path().join("bin")),
            ..Env::default()
        };
        let default = Paths::resolve(None, &env).unwrap();
        assert!(!default.portable);
        assert_ne!(
            default.vault.parent(),
            default.device.parent(),
            "device state must not sit next to the vault"
        );

        let explicit = d.path().join("synced/vault.pbv");
        let p = Paths::resolve(Some(&explicit), &env).unwrap();
        assert_eq!(p.vault, explicit);
        assert_eq!(
            p.device, default.device,
            "a custom vault path doesn't move device state"
        );

        let p = Paths::resolve(
            None,
            &Env {
                vault: Some(explicit.clone()),
                ..env.clone()
            },
        )
        .unwrap();
        assert_eq!(p.vault, explicit);

        std::fs::create_dir_all(d.path().join("bin")).unwrap();
        std::fs::write(d.path().join("bin").join(PORTABLE_MARKER), b"").unwrap();
        let p = Paths::resolve(None, &env).unwrap();
        assert!(p.portable);
        assert!(p.vault.starts_with(d.path().join("bin/data")));
        // An explicit vault path wins over portable mode.
        assert!(!Paths::resolve(Some(&explicit), &env).unwrap().portable);

        assert!(Paths::resolve(None, &Env::default()).is_err());
    }

    #[test]
    fn same_data_and_state_roots_still_separate_device_state() {
        let d = tempfile::tempdir().unwrap();
        let root = d.path().join("same");
        let env = Env {
            home: Some(d.path().join("home")),
            xdg_data: Some(root.clone()),
            xdg_state: Some(root.clone()),
            appdata: Some(root.clone()),
            local_appdata: Some(root),
            ..Env::default()
        };
        let p = Paths::resolve(None, &env).unwrap();
        assert_ne!(p.vault.parent(), p.device.parent());
        p.validate().unwrap();
    }

    #[test]
    fn colliding_paths_are_rejected() {
        let d = tempfile::tempdir().unwrap();
        let ok = Paths::under(d.path(), false);
        ok.validate().unwrap();
        for bad in [
            Paths {
                vault: ok.device.clone(),
                ..ok.clone()
            },
            Paths {
                vault: PathBuf::from(format!("{}.lock", ok.device.display())),
                ..ok.clone()
            },
            Paths {
                device: ok.vault.with_file_name("device.json"),
                ..ok.clone()
            },
        ] {
            assert!(bad.validate().is_err(), "{bad:?}");
        }
        // Different spellings of the same place are still caught.
        std::fs::create_dir_all(d.path().join("v")).unwrap();
        let alias = Paths {
            vault: d.path().join("x/../v/vault.pbv"),
            device: d.path().join("v/device.json"),
            backups: d.path().join("b"),
            portable: false,
        };
        assert!(alias.validate().is_err(), "`..` alias accepted");
        #[cfg(unix)]
        {
            // `link/../x` is in the parent of link's *target*, not next to `link`.
            std::fs::create_dir_all(d.path().join("synced/sub")).unwrap();
            std::os::unix::fs::symlink(d.path().join("synced/sub"), d.path().join("hop")).unwrap();
            let hop = Paths {
                vault: d.path().join("synced/vault.pbv"),
                device: d.path().join("hop/../device.json"),
                backups: d.path().join("b"),
                portable: false,
            };
            assert!(hop.validate().is_err(), "symlink + `..` alias accepted");

            std::os::unix::fs::symlink(d.path().join("v"), d.path().join("link")).unwrap();
            let linked = Paths {
                device: d.path().join("link/device.json"),
                ..alias.clone()
            };
            let linked = Paths {
                vault: d.path().join("v/vault.pbv"),
                ..linked
            };
            assert!(linked.validate().is_err(), "symlinked directory alias accepted");
        }
        if cfg!(any(windows, target_os = "macos")) {
            let cased = Paths {
                vault: d.path().join("V/vault.pbv"),
                ..alias.clone()
            };
            assert!(cased.validate().is_err(), "case alias accepted");
        }

        // Portable mode keeps both under one folder by design.
        Paths {
            device: ok.vault.with_file_name("device.json"),
            portable: true,
            ..ok
        }
        .validate()
        .unwrap();
    }
}
