//! Process and memory hardening.
//!
//! [`harden_process`] runs first thing in `main`, before any secret exists:
//!
//! | Platform | Measure |
//! |---|---|
//! | Unix | `RLIMIT_CORE = 0` (no core dumps) |
//! | Linux/Android | `PR_SET_DUMPABLE = 0`: no core dumps, no ptrace attach or `/proc/<pid>/mem` reads by other same-user processes |
//! | macOS | `PT_DENY_ATTACH` in release builds: debuggers can't attach |
//! | FreeBSD | `PROC_TRACE_CTL_DISABLE`: no ptrace, no core dumps |
//! | Windows | `SetErrorMode` to stop crash dialogs/WER from capturing memory |
//!
//! [`SecureBuf`] holds long-lived secrets in memory that is page-aligned, surrounded
//! by inaccessible guard pages (so overflows fault instead of reading neighbours),
//! locked into RAM (`mlock` / `VirtualLock`, never swapped), excluded from core dumps
//! (`MADV_DONTDUMP` on Linux), and zeroed before release.

#![deny(missing_docs)]

use core::fmt;

pub mod fs;

/// What [`harden_process`] managed to apply.
#[derive(Debug, Default, Clone)]
pub struct Report {
    /// Measures applied.
    pub applied: Vec<&'static str>,
    /// Measures that failed or are unavailable on this platform.
    pub missing: Vec<&'static str>,
}

impl Report {
    fn ok(&mut self, ok: bool, what: &'static str) {
        if ok {
            self.applied.push(what)
        } else {
            self.missing.push(what)
        }
    }
}

/// Apply process-level hardening. Safe to call more than once.
pub fn harden_process() -> Report {
    let mut r = Report::default();
    imp::harden(&mut r);
    r
}

/// Locked, guarded, zero-on-drop memory for secrets.
pub struct SecureBuf {
    inner: imp::Region,
    len: usize,
}

impl SecureBuf {
    /// Allocate `len` zeroed bytes. Fails if memory can't be allocated; if it can't
    /// be locked, [`SecureBuf::locked`] reports false but the buffer is still usable.
    pub fn new(len: usize) -> std::io::Result<Self> {
        Ok(Self {
            inner: imp::Region::alloc(len.max(1))?,
            len,
        })
    }

    /// Copy `data` into a new buffer.
    pub fn from_slice(data: &[u8]) -> std::io::Result<Self> {
        let mut b = Self::new(data.len())?;
        b.as_mut().copy_from_slice(data);
        Ok(b)
    }

    /// Whether the pages are locked in RAM.
    pub fn locked(&self) -> bool {
        self.inner.locked
    }

    /// Length in bytes.
    pub fn len(&self) -> usize {
        self.len
    }

    /// True if empty.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

impl AsRef<[u8]> for SecureBuf {
    fn as_ref(&self) -> &[u8] {
        &self.inner.slice()[..self.len]
    }
}

impl AsMut<[u8]> for SecureBuf {
    fn as_mut(&mut self) -> &mut [u8] {
        let len = self.len;
        &mut self.inner.slice_mut()[..len]
    }
}

impl fmt::Debug for SecureBuf {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecureBuf({} bytes, <redacted>)", self.len)
    }
}

#[cfg(unix)]
mod imp {
    use super::Report;
    use zeroize::Zeroize;

    pub fn harden(r: &mut Report) {
        let lim = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // SAFETY: setrlimit with a valid pointer to an initialized rlimit.
        r.ok(
            unsafe { libc::setrlimit(libc::RLIMIT_CORE, &lim) } == 0,
            "core dumps disabled (RLIMIT_CORE=0)",
        );

        #[cfg(any(target_os = "linux", target_os = "android"))]
        {
            // SAFETY: prctl with integer arguments only.
            r.ok(
                unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } == 0,
                "non-dumpable (blocks ptrace and /proc/pid/mem)",
            );
        }

        #[cfg(target_os = "macos")]
        {
            if cfg!(debug_assertions) {
                r.missing.push("debugger attach allowed (debug build)");
            } else {
                const PT_DENY_ATTACH: libc::c_int = 31;
                // SAFETY: PT_DENY_ATTACH takes no address/data arguments.
                r.ok(
                    unsafe { libc::ptrace(PT_DENY_ATTACH, 0, core::ptr::null_mut(), 0) } == 0,
                    "debugger attach denied (PT_DENY_ATTACH)",
                );
            }
        }

        #[cfg(target_os = "freebsd")]
        {
            let mut arg: libc::c_int = libc::PROC_TRACE_CTL_DISABLE;
            // SAFETY: procctl on our own pid with a valid pointer to an int.
            let rc = unsafe {
                libc::procctl(
                    libc::P_PID,
                    0,
                    libc::PROC_TRACE_CTL,
                    &mut arg as *mut _ as *mut libc::c_void,
                )
            };
            r.ok(rc == 0, "tracing disabled (PROC_TRACE_CTL)");
        }
    }

    fn page() -> usize {
        // SAFETY: sysconf has no preconditions.
        let p = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        if p > 0 { p as usize } else { 4096 }
    }

    pub struct Region {
        base: *mut u8,
        total: usize,
        data: *mut u8,
        cap: usize,
        pub locked: bool,
    }

    // SAFETY: Region exclusively owns its mapping; no interior sharing.
    unsafe impl Send for Region {}
    // SAFETY: shared access only hands out `&[u8]`.
    unsafe impl Sync for Region {}

    impl Region {
        pub fn alloc(len: usize) -> std::io::Result<Self> {
            let pg = page();
            let cap = len.div_ceil(pg) * pg;
            let total = cap + 2 * pg;
            // SAFETY: anonymous private mapping, no fd; result checked below.
            let base = unsafe {
                libc::mmap(
                    core::ptr::null_mut(),
                    total,
                    libc::PROT_NONE,
                    libc::MAP_PRIVATE | libc::MAP_ANON,
                    -1,
                    0,
                )
            };
            if base == libc::MAP_FAILED {
                return Err(std::io::Error::last_os_error());
            }
            let base = base as *mut u8;
            // SAFETY: `pg..pg+cap` lies inside the mapping just created.
            let data = unsafe { base.add(pg) };
            // SAFETY: making the inner pages readable/writable; guards stay PROT_NONE.
            if unsafe { libc::mprotect(data as *mut _, cap, libc::PROT_READ | libc::PROT_WRITE) } != 0 {
                let e = std::io::Error::last_os_error();
                // SAFETY: unmapping the mapping we own.
                unsafe { libc::munmap(base as *mut _, total) };
                return Err(e);
            }
            #[cfg(any(target_os = "linux", target_os = "android"))]
            // SAFETY: advisory call on our own mapping.
            unsafe {
                libc::madvise(data as *mut _, cap, libc::MADV_DONTDUMP);
            }
            // SAFETY: locking pages of our own mapping; failure is reported, not fatal.
            let locked = unsafe { libc::mlock(data as *const _, cap) } == 0;
            Ok(Self {
                base,
                total,
                data,
                cap,
                locked,
            })
        }

        #[cfg(test)]
        pub fn bounds(&self) -> (*mut u8, usize) {
            (self.data, self.cap)
        }

        pub fn slice(&self) -> &[u8] {
            // SAFETY: `data..data+cap` is mapped RW for the life of `self`.
            unsafe { core::slice::from_raw_parts(self.data, self.cap) }
        }

        pub fn slice_mut(&mut self) -> &mut [u8] {
            // SAFETY: as above, and `&mut self` guarantees exclusivity.
            unsafe { core::slice::from_raw_parts_mut(self.data, self.cap) }
        }
    }

    impl Drop for Region {
        fn drop(&mut self) {
            self.slice_mut().zeroize();
            // SAFETY: unlocking/unmapping exactly what `alloc` mapped.
            unsafe {
                if self.locked {
                    libc::munlock(self.data as *const _, self.cap);
                }
                libc::munmap(self.base as *mut _, self.total);
            }
        }
    }
}

#[cfg(windows)]
mod imp {
    use super::Report;
    use windows_sys::Win32::System::{
        Diagnostics::Debug::{SEM_FAILCRITICALERRORS, SEM_NOGPFAULTERRORBOX, SetErrorMode},
        Memory::{
            MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_NOACCESS, PAGE_READWRITE, VirtualAlloc, VirtualFree,
            VirtualLock, VirtualProtect, VirtualUnlock,
        },
        SystemInformation::{GetSystemInfo, SYSTEM_INFO},
    };
    use zeroize::Zeroize;

    pub fn harden(r: &mut Report) {
        // SAFETY: SetErrorMode takes flags only.
        unsafe { SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX) };
        // SetErrorMode returns the previous mode and cannot fail.
        r.ok(true, "crash dialogs/WER capture suppressed (SetErrorMode)");
        r.missing
            .push("debugger attach blocking (not yet implemented on Windows)");
    }

    fn page() -> usize {
        // SAFETY: GetSystemInfo fills the struct we pass.
        let mut si: SYSTEM_INFO = unsafe { core::mem::zeroed() };
        // SAFETY: `si` is a valid, writable SYSTEM_INFO.
        unsafe { GetSystemInfo(&mut si) };
        si.dwPageSize as usize
    }

    pub struct Region {
        base: *mut u8,
        data: *mut u8,
        cap: usize,
        pub locked: bool,
    }
    // SAFETY: exclusive ownership of the allocation.
    unsafe impl Send for Region {}
    // SAFETY: shared access only hands out `&[u8]`.
    unsafe impl Sync for Region {}

    impl Region {
        pub fn alloc(len: usize) -> std::io::Result<Self> {
            let pg = page();
            let cap = len.div_ceil(pg) * pg;
            let total = cap + 2 * pg;
            // SAFETY: fresh reservation; result checked.
            let base =
                unsafe { VirtualAlloc(core::ptr::null(), total, MEM_COMMIT | MEM_RESERVE, PAGE_NOACCESS) } as *mut u8;
            if base.is_null() {
                return Err(std::io::Error::last_os_error());
            }
            // SAFETY: inner range is within the allocation.
            let data = unsafe { base.add(pg) };
            let mut old = 0u32;
            // SAFETY: changing protection of our own pages.
            if unsafe { VirtualProtect(data as *const _, cap, PAGE_READWRITE, &mut old) } == 0 {
                let e = std::io::Error::last_os_error();
                unsafe { VirtualFree(base as *mut _, 0, MEM_RELEASE) };
                return Err(e);
            }
            // SAFETY: locking our own committed pages.
            let locked = unsafe { VirtualLock(data as *const _, cap) } != 0;
            Ok(Self {
                base,
                data,
                cap,
                locked,
            })
        }
        #[cfg(test)]
        pub fn bounds(&self) -> (*mut u8, usize) {
            (self.data, self.cap)
        }
        pub fn slice(&self) -> &[u8] {
            // SAFETY: inner pages are RW for the life of `self`.
            unsafe { core::slice::from_raw_parts(self.data, self.cap) }
        }
        pub fn slice_mut(&mut self) -> &mut [u8] {
            // SAFETY: as above, exclusive via `&mut self`.
            unsafe { core::slice::from_raw_parts_mut(self.data, self.cap) }
        }
    }

    impl Drop for Region {
        fn drop(&mut self) {
            self.slice_mut().zeroize();
            // SAFETY: releasing exactly what `alloc` reserved.
            unsafe {
                if self.locked {
                    VirtualUnlock(self.data as *const _, self.cap);
                }
                VirtualFree(self.base as *mut _, 0, MEM_RELEASE);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secure_buf_roundtrip() {
        let mut b = SecureBuf::from_slice(b"secret").unwrap();
        assert_eq!(b.as_ref(), b"secret");
        b.as_mut()[0] = b'S';
        assert_eq!(b.as_ref(), b"Secret");
        assert_eq!(format!("{b:?}"), "SecureBuf(6 bytes, <redacted>)");
        let big = SecureBuf::new(10_000).unwrap();
        assert_eq!(big.len(), 10_000);
        assert!(big.as_ref().iter().all(|&x| x == 0));
    }
}

/// Behaviour checks. Each runs in a child process (this test binary re-executed),
/// because they change process state or are expected to crash.
#[cfg(test)]
mod behaviour {
    use super::*;
    use std::process::{Command, ExitStatus, Stdio};

    const MODE: &str = "PASSBACK_HARDEN_CHILD";

    fn run_child(mode: &str) -> ExitStatus {
        Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "behaviour::child_entry", "--ignored", "--test-threads=1"])
            .env(MODE, mode)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap()
    }

    /// Entry point for the child. Does nothing unless started by `run_child`.
    #[test]
    #[ignore]
    fn child_entry() {
        let Ok(mode) = std::env::var(MODE) else { return };
        let code = match mode.as_str() {
            "guard-before" | "guard-after" => {
                let b = SecureBuf::new(16).unwrap();
                let (data, cap) = b.inner.bounds();
                let target = if mode == "guard-before" {
                    data.wrapping_sub(1)
                } else {
                    data.wrapping_add(cap)
                };
                // SAFETY: deliberately invalid: `target` is inside a PROT_NONE guard page and
                // this read must fault. Reaching the next line means the guard page is missing.
                let _ = unsafe { core::ptr::read_volatile(target) };
                10
            }
            "harden" => harden_effect(),
            _ => 11,
        };
        std::process::exit(code);
    }

    /// Exit codes: 0 = measure was off before and on after; 3x = precondition could
    /// not be established (the check would be vacuous); 2x = measure not in effect.
    #[cfg(unix)]
    fn harden_effect() -> i32 {
        let mut lim = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // SAFETY: getrlimit writes into a valid rlimit.
        if unsafe { libc::getrlimit(libc::RLIMIT_CORE, &mut lim) } != 0 || lim.rlim_max == 0 {
            return 30; // hard limit already 0: can't show that hardening changes anything
        }
        lim.rlim_cur = lim.rlim_max.min(1 << 20);
        // SAFETY: setrlimit with a valid rlimit, soft limit within the hard limit.
        if unsafe { libc::setrlimit(libc::RLIMIT_CORE, &lim) } != 0 {
            return 31;
        }
        #[cfg(any(target_os = "linux", target_os = "android"))]
        // SAFETY: prctl query with integer arguments.
        if unsafe { libc::prctl(libc::PR_GET_DUMPABLE, 0, 0, 0, 0) } != 1 {
            return 32;
        }

        harden_process();

        // SAFETY: getrlimit writes into a valid rlimit.
        if unsafe { libc::getrlimit(libc::RLIMIT_CORE, &mut lim) } != 0 || lim.rlim_cur != 0 || lim.rlim_max != 0 {
            return 20;
        }
        #[cfg(any(target_os = "linux", target_os = "android"))]
        // SAFETY: prctl query with integer arguments.
        if unsafe { libc::prctl(libc::PR_GET_DUMPABLE, 0, 0, 0, 0) } != 0 {
            return 21;
        }
        0
    }

    #[cfg(windows)]
    fn harden_effect() -> i32 {
        use windows_sys::Win32::System::Diagnostics::Debug::{
            GetErrorMode, SEM_FAILCRITICALERRORS, SEM_NOGPFAULTERRORBOX, SetErrorMode,
        };
        let flags = SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX;
        // SAFETY: SetErrorMode/GetErrorMode take flags only. Clear any inherited mode first.
        unsafe { SetErrorMode(0) };
        // SAFETY: as above.
        if unsafe { GetErrorMode() } & flags != 0 {
            return 30;
        }

        harden_process();

        // SAFETY: as above.
        if unsafe { GetErrorMode() } & flags != flags {
            return 22;
        }
        0
    }

    fn died_from_memory_fault(st: ExitStatus) -> bool {
        #[cfg(unix)]
        {
            use std::os::unix::process::ExitStatusExt;
            matches!(st.signal(), Some(libc::SIGSEGV) | Some(libc::SIGBUS))
        }
        #[cfg(windows)]
        {
            st.code() == Some(0xC000_0005_u32 as i32) // STATUS_ACCESS_VIOLATION
        }
    }

    #[test]
    fn reading_the_page_before_a_secure_buf_faults() {
        let st = run_child("guard-before");
        assert!(died_from_memory_fault(st), "no fault before the buffer: {st:?}");
    }

    #[test]
    fn reading_the_page_after_a_secure_buf_faults() {
        let st = run_child("guard-after");
        assert!(died_from_memory_fault(st), "no fault after the buffer: {st:?}");
    }

    #[test]
    fn hardening_takes_effect() {
        let st = run_child("harden");
        assert_eq!(st.code(), Some(0), "hardening not in effect: {st:?}");
    }
}
