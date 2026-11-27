//! Owner-only files and durable replacement, for files that hold secrets or
//! integrity state.
//!
//! Everything is owner-only **from the moment it exists**: on Unix through the
//! creation mode (0600 files, 0700 directories); on Windows through a protected
//! security descriptor passed to `CreateFileW`/`CreateDirectoryW`, granting access
//! to the current user only, with no inherited entries. There is no window in which
//! a freshly created file carries its parent's (possibly permissive) permissions.

use std::{fs::File, io, path::Path};

/// Create one new directory (its parent must exist), owner-only from creation.
pub fn create_dir_private(path: &Path) -> io::Result<()> {
    imp::create_dir_private(path)
}

/// Create a new file exclusively (fails if anything, including a symlink, already
/// exists at `path`), owner-only from creation, opened for writing.
pub fn create_file_private(path: &Path) -> io::Result<File> {
    imp::create_file_private(path)
}

/// Open or create a lock file, owner-only. Refuses symlinks and reparse points, and
/// re-restricts a pre-existing lock file.
pub fn open_lock_private(path: &Path) -> io::Result<File> {
    imp::open_lock_private(path)
}

/// Replace `dst` with `src` (same directory). On Windows uses `MoveFileExW` with
/// `MOVEFILE_WRITE_THROUGH`, so the rename is durable when this returns. On Unix a
/// plain `rename`; the caller fsyncs the directory.
pub fn replace(src: &Path, dst: &Path) -> io::Result<()> {
    imp::replace(src, dst)
}

/// Whether only the current user can access `path`. Unix: owned by the effective
/// user, no group or other permission bits. Windows: a protected DACL with exactly
/// one access-allowed entry, for the current user's SID.
pub fn is_owner_only(path: &Path) -> io::Result<bool> {
    imp::is_owner_only(path)
}

#[cfg(unix)]
mod imp {
    use std::{
        fs::{self, File},
        io,
        os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
        path::Path,
    };

    pub fn create_dir_private(path: &Path) -> io::Result<()> {
        fs::DirBuilder::new().mode(0o700).create(path)
    }

    pub fn create_file_private(path: &Path) -> io::Result<File> {
        fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)
    }

    pub fn open_lock_private(path: &Path) -> io::Result<File> {
        let f = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)?;
        // SAFETY: geteuid has no preconditions.
        if f.metadata()?.uid() != unsafe { libc::geteuid() } {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "lock file is owned by another user",
            ));
        }
        f.set_permissions(fs::Permissions::from_mode(0o600))?;
        Ok(f)
    }

    pub fn replace(src: &Path, dst: &Path) -> io::Result<()> {
        fs::rename(src, dst)
    }

    pub fn is_owner_only(path: &Path) -> io::Result<bool> {
        let m = fs::symlink_metadata(path)?;
        // SAFETY: geteuid has no preconditions.
        Ok(m.permissions().mode() & 0o077 == 0 && m.uid() == unsafe { libc::geteuid() })
    }
}

#[cfg(windows)]
mod imp {
    use std::{
        fs::File,
        io,
        os::windows::{ffi::OsStrExt, io::FromRawHandle},
        path::Path,
        ptr::{null, null_mut},
    };

    use windows_sys::Win32::{
        Foundation::{
            CloseHandle, GENERIC_ALL, GENERIC_READ, GENERIC_WRITE, HANDLE, HLOCAL, INVALID_HANDLE_VALUE, LocalFree,
        },
        Security::{
            ACCESS_ALLOWED_ACE, ACL, ACL_SIZE_INFORMATION, AclSizeInformation, Authorization::*,
            DACL_SECURITY_INFORMATION, EqualSid, GetAce, GetAclInformation, GetSecurityDescriptorControl,
            GetTokenInformation, InitializeSecurityDescriptor, NO_INHERITANCE, PROTECTED_DACL_SECURITY_INFORMATION,
            PSECURITY_DESCRIPTOR, PSID, SE_DACL_PROTECTED, SECURITY_ATTRIBUTES, SECURITY_DESCRIPTOR,
            SUB_CONTAINERS_AND_OBJECTS_INHERIT, SetSecurityDescriptorControl, SetSecurityDescriptorDacl, TOKEN_QUERY,
            TOKEN_USER, TokenUser,
        },
        Storage::FileSystem::{
            BY_HANDLE_FILE_INFORMATION, CREATE_NEW, CreateDirectoryW, CreateFileW, FILE_ATTRIBUTE_NORMAL,
            FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_DELETE, FILE_SHARE_READ,
            FILE_SHARE_WRITE, GetFileInformationByHandle, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH,
            MoveFileExW, OPEN_ALWAYS, READ_CONTROL, WRITE_DAC,
        },
        System::Threading::{GetCurrentProcess, OpenProcessToken},
    };

    /// `ACCESS_ALLOWED_ACE_TYPE` (winnt.h).
    const ACCESS_ALLOWED_ACE_TYPE: u8 = 0;
    /// `SECURITY_DESCRIPTOR_REVISION` (winnt.h).
    const SECURITY_DESCRIPTOR_REVISION: u32 = 1;

    fn wide(p: &Path) -> Vec<u16> {
        p.as_os_str().encode_wide().chain(std::iter::once(0)).collect()
    }

    fn win32(rc: u32) -> io::Result<()> {
        if rc == 0 {
            Ok(())
        } else {
            Err(io::Error::from_raw_os_error(rc as i32))
        }
    }

    /// The current user's TOKEN_USER, in a u64-aligned buffer (it holds pointers).
    struct TokenUserBuf(Vec<u64>);

    impl TokenUserBuf {
        fn current() -> io::Result<Self> {
            let mut token: HANDLE = null_mut();
            // SAFETY: valid out-pointer; GetCurrentProcess returns a pseudo-handle.
            if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
                return Err(io::Error::last_os_error());
            }
            let mut len = 0u32;
            // SAFETY: size query with a null buffer; `len` receives the required size.
            unsafe { GetTokenInformation(token, TokenUser, null_mut(), 0, &mut len) };
            let mut buf = vec![0u64; (len as usize).div_ceil(8).max(1)];
            // SAFETY: `buf` is at least `len` bytes and 8-byte aligned.
            let ok = unsafe { GetTokenInformation(token, TokenUser, buf.as_mut_ptr().cast(), len, &mut len) };
            // SAFETY: `token` came from OpenProcessToken above.
            unsafe { CloseHandle(token) };
            if ok == 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(Self(buf))
        }

        fn sid(&self) -> PSID {
            // SAFETY: GetTokenInformation(TokenUser) wrote a TOKEN_USER at the start of the buffer.
            unsafe { (*(self.0.as_ptr() as *const TOKEN_USER)).User.Sid }
        }
    }

    /// A DACL with one full-access entry for a SID. Freed on drop.
    struct Dacl(*mut ACL);

    impl Dacl {
        fn single(sid: PSID, inherit: bool) -> io::Result<Self> {
            let ea = EXPLICIT_ACCESS_W {
                grfAccessPermissions: GENERIC_ALL,
                grfAccessMode: SET_ACCESS,
                grfInheritance: if inherit {
                    SUB_CONTAINERS_AND_OBJECTS_INHERIT
                } else {
                    NO_INHERITANCE
                },
                Trustee: TRUSTEE_W {
                    pMultipleTrustee: null_mut(),
                    MultipleTrusteeOperation: NO_MULTIPLE_TRUSTEE,
                    TrusteeForm: TRUSTEE_IS_SID,
                    TrusteeType: TRUSTEE_IS_USER,
                    ptstrName: sid.cast(),
                },
            };
            let mut acl: *mut ACL = null_mut();
            // SAFETY: one valid EXPLICIT_ACCESS_W; `sid` outlives this call.
            win32(unsafe { SetEntriesInAclW(1, &ea, null(), &mut acl) })?;
            Ok(Self(acl))
        }
    }

    impl Drop for Dacl {
        fn drop(&mut self) {
            // SAFETY: freeing the ACL allocated by SetEntriesInAclW.
            unsafe { LocalFree(self.0 as HLOCAL) };
        }
    }

    /// Owner-only security attributes for creating a file or directory.
    struct OwnerOnly {
        _user: TokenUserBuf,
        _dacl: Dacl,
        sd: Box<SECURITY_DESCRIPTOR>,
    }

    impl OwnerOnly {
        fn new(inherit: bool) -> io::Result<Self> {
            let user = TokenUserBuf::current()?;
            let dacl = Dacl::single(user.sid(), inherit)?;
            let mut sd = Box::new(SECURITY_DESCRIPTOR::default());
            let psd: PSECURITY_DESCRIPTOR = (&mut *sd as *mut SECURITY_DESCRIPTOR).cast();
            // SAFETY: `psd` points to a SECURITY_DESCRIPTOR we own; `dacl` outlives it (same struct).
            let ok = unsafe {
                InitializeSecurityDescriptor(psd, SECURITY_DESCRIPTOR_REVISION) != 0
                    && SetSecurityDescriptorDacl(psd, 1, dacl.0, 0) != 0
                    && SetSecurityDescriptorControl(psd, SE_DACL_PROTECTED, SE_DACL_PROTECTED) != 0
            };
            if !ok {
                return Err(io::Error::last_os_error());
            }
            Ok(Self {
                _user: user,
                _dacl: dacl,
                sd,
            })
        }

        fn attributes(&mut self) -> SECURITY_ATTRIBUTES {
            SECURITY_ATTRIBUTES {
                nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
                lpSecurityDescriptor: (&mut *self.sd as *mut SECURITY_DESCRIPTOR).cast(),
                bInheritHandle: 0,
            }
        }
    }

    pub fn create_dir_private(path: &Path) -> io::Result<()> {
        let mut owner = OwnerOnly::new(true)?;
        let sa = owner.attributes();
        let name = wide(path);
        // SAFETY: NUL-terminated path; `sa` and its descriptor live until the call returns.
        if unsafe { CreateDirectoryW(name.as_ptr(), &sa) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    fn create(path: &Path, access: u32, disposition: u32, flags: u32) -> io::Result<HANDLE> {
        let mut owner = OwnerOnly::new(false)?;
        let sa = owner.attributes();
        let name = wide(path);
        // SAFETY: NUL-terminated path; `sa` and its descriptor live until the call returns.
        let h = unsafe {
            CreateFileW(
                name.as_ptr(),
                access,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                &sa,
                disposition,
                flags,
                null_mut(),
            )
        };
        if h == INVALID_HANDLE_VALUE {
            return Err(io::Error::last_os_error());
        }
        Ok(h)
    }

    pub fn create_file_private(path: &Path) -> io::Result<File> {
        let h = create(path, GENERIC_READ | GENERIC_WRITE, CREATE_NEW, FILE_ATTRIBUTE_NORMAL)?;
        // SAFETY: `h` is a valid, owned file handle from CreateFileW.
        Ok(unsafe { File::from_raw_handle(h) })
    }

    pub fn open_lock_private(path: &Path) -> io::Result<File> {
        // WRITE_DAC (and READ_CONTROL) are needed to replace the DACL of a lock file
        // that already existed, via SetSecurityInfo on this handle.
        let h = create(
            path,
            GENERIC_READ | GENERIC_WRITE | READ_CONTROL | WRITE_DAC,
            OPEN_ALWAYS,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
        )?;
        // SAFETY: `h` is a valid, owned file handle; `File` closes it on every path below.
        let f = unsafe { File::from_raw_handle(h) };
        let mut info = BY_HANDLE_FILE_INFORMATION::default();
        // SAFETY: valid handle and out-pointer.
        if unsafe { GetFileInformationByHandle(h, &mut info) } == 0 {
            return Err(io::Error::last_os_error());
        }
        if info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "lock file is a reparse point",
            ));
        }
        // A lock file that already existed keeps its old DACL; replace it through the handle.
        let user = TokenUserBuf::current()?;
        let dacl = Dacl::single(user.sid(), false)?;
        // SAFETY: valid handle; `dacl` lives until the call returns.
        win32(unsafe {
            SetSecurityInfo(
                h,
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                null_mut(),
                null_mut(),
                dacl.0,
                null(),
            )
        })?;
        Ok(f)
    }

    pub fn replace(src: &Path, dst: &Path) -> io::Result<()> {
        let (s, d) = (wide(src), wide(dst));
        // SAFETY: NUL-terminated paths.
        if unsafe {
            MoveFileExW(
                s.as_ptr(),
                d.as_ptr(),
                MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    pub fn is_owner_only(path: &Path) -> io::Result<bool> {
        let user = TokenUserBuf::current()?;
        let name = wide(path);
        let mut dacl: *mut ACL = null_mut();
        let mut sd: PSECURITY_DESCRIPTOR = null_mut();
        // SAFETY: NUL-terminated path; valid out-pointers.
        win32(unsafe {
            GetNamedSecurityInfoW(
                name.as_ptr(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                null_mut(),
                null_mut(),
                &mut dacl,
                null_mut(),
                &mut sd,
            )
        })?;
        // SAFETY: `sd` and `dacl` were returned by GetNamedSecurityInfoW and stay valid until LocalFree.
        let ok = unsafe {
            let mut control = 0u16;
            let mut rev = 0u32;
            let mut info = ACL_SIZE_INFORMATION::default();
            let mut ace: *mut core::ffi::c_void = null_mut();
            GetSecurityDescriptorControl(sd, &mut control, &mut rev) != 0
                && control & SE_DACL_PROTECTED != 0
                && !dacl.is_null()
                && GetAclInformation(
                    dacl,
                    (&mut info as *mut ACL_SIZE_INFORMATION).cast(),
                    size_of::<ACL_SIZE_INFORMATION>() as u32,
                    AclSizeInformation,
                ) != 0
                && info.AceCount == 1
                && GetAce(dacl, 0, &mut ace) != 0
                && {
                    let allowed = &*(ace as *const ACCESS_ALLOWED_ACE);
                    allowed.Header.AceType == ACCESS_ALLOWED_ACE_TYPE
                        && EqualSid((&allowed.SidStart as *const u32).cast_mut().cast(), user.sid()) != 0
                }
        };
        // SAFETY: freeing the descriptor returned by GetNamedSecurityInfoW.
        unsafe { LocalFree(sd as HLOCAL) };
        Ok(ok)
    }

    /// Test helper: give `path` a protected DACL with one full-access entry for
    /// Everyone, to prove `is_owner_only` rejects it.
    #[cfg(test)]
    pub fn grant_everyone(path: &Path) -> io::Result<()> {
        use windows_sys::Win32::Security::Authorization::ConvertStringSidToSidW;
        let everyone: Vec<u16> = "S-1-1-0".encode_utf16().chain(std::iter::once(0)).collect();
        let mut sid: PSID = null_mut();
        // SAFETY: NUL-terminated SID string; valid out-pointer.
        if unsafe { ConvertStringSidToSidW(everyone.as_ptr(), &mut sid) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let result = Dacl::single(sid, false).and_then(|dacl| {
            let name = wide(path);
            // SAFETY: NUL-terminated path; `dacl` lives until the call returns.
            win32(unsafe {
                SetNamedSecurityInfoW(
                    name.as_ptr(),
                    SE_FILE_OBJECT,
                    DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                    null_mut(),
                    null_mut(),
                    dacl.0,
                    null(),
                )
            })
        });
        // SAFETY: freeing the SID allocated by ConvertStringSidToSidW.
        unsafe { LocalFree(sid as HLOCAL) };
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn created_files_dirs_and_locks_are_owner_only_and_replace_works() {
        let d = tempfile::tempdir().unwrap();
        let dir = d.path().join("private");
        create_dir_private(&dir).unwrap();
        assert!(is_owner_only(&dir).unwrap());

        let a = dir.join("a");
        create_file_private(&a).unwrap().write_all(b"new").unwrap();
        assert!(is_owner_only(&a).unwrap());
        assert!(
            create_file_private(&a).is_err(),
            "exclusive create must refuse an existing file"
        );

        let lock = dir.join("x.lock");
        drop(open_lock_private(&lock).unwrap());
        drop(open_lock_private(&lock).unwrap()); // reopening an existing lock file works
        assert!(is_owner_only(&lock).unwrap());

        let b = dir.join("b");
        create_file_private(&b).unwrap().write_all(b"old").unwrap();
        replace(&a, &b).unwrap();
        assert_eq!(std::fs::read(&b).unwrap(), b"new");
        assert!(!a.exists());
        assert!(is_owner_only(&b).unwrap());
    }

    #[test]
    fn a_file_others_can_access_is_not_owner_only() {
        let d = tempfile::tempdir().unwrap();
        let f = d.path().join("shared");
        create_file_private(&f).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o640)).unwrap();
        }
        #[cfg(windows)]
        imp::grant_everyone(&f).unwrap();
        assert!(!is_owner_only(&f).unwrap());
    }

    #[cfg(unix)]
    #[test]
    fn lock_files_refuse_symlinks_and_tighten_existing_modes() {
        use std::os::unix::fs::PermissionsExt;
        let d = tempfile::tempdir().unwrap();
        let target = d.path().join("elsewhere");
        std::fs::write(&target, b"").unwrap();
        let link = d.path().join("v.lock");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(open_lock_private(&link).is_err());

        let loose = d.path().join("loose.lock");
        std::fs::write(&loose, b"").unwrap();
        std::fs::set_permissions(&loose, std::fs::Permissions::from_mode(0o666)).unwrap();
        drop(open_lock_private(&loose).unwrap());
        assert!(is_owner_only(&loose).unwrap());
    }
}
