//! This module's two fixed read-only calls: flavor18 and the boot-session sysctl.
//! Other explicitly scoped wrappers live in sibling modules; each unsafe block states its obligations.
use super::{Error, ProcessInfo, layout};
use std::mem::{offset_of, size_of};

// Public half checked against the locked libc SDK mirror. The real SDK assertion/row is
// also required on Mac before parity is claimed; the private SPI tail fails closed by size.
const _: () = assert!(size_of::<libc::proc_bsdinfo>() == 136);
const _: () = assert!(offset_of!(libc::proc_bsdinfo, pbi_status) == 4);
const _: () = assert!(offset_of!(libc::proc_bsdinfo, pbi_pid) == 12);
const _: () = assert!(offset_of!(libc::proc_bsdinfo, pbi_ppid) == 16);
const _: () = assert!(offset_of!(libc::proc_bsdinfo, pbi_uid) == 20);
const _: () = assert!(offset_of!(libc::proc_bsdinfo, pbi_gid) == 24);
const _: () = assert!(offset_of!(libc::proc_bsdinfo, pbi_ruid) == 28);
const _: () = assert!(offset_of!(libc::proc_bsdinfo, pbi_rgid) == 32);
const _: () = assert!(offset_of!(libc::proc_bsdinfo, pbi_pgid) == 100);

/// Fixed flavor18, arg0 (zombies excluded). Never accepts partial or oversized replies.
#[allow(unsafe_code)]
pub fn process_info(pid: u32) -> Result<ProcessInfo, Error> {
    let pid_t = i32::try_from(pid).ok().filter(|p| *p > 0).ok_or(Error::InvalidPid)?;
    // u64 storage guarantees the alignment of both SDK structs; zeroed before the call.
    let mut buffer = [0u64; layout::SIZE / 8];
    // SAFETY: positive pid; fixed read-only flavor/arg; initialized writable aligned buffer
    // of exactly the advertised capacity. libproc neither retains nor frees the pointer.
    let got = unsafe { libc::proc_pidinfo(pid_t, 18, 0, buffer.as_mut_ptr().cast(), layout::SIZE as i32) };
    if got <= 0 {
        return Err(Error::Unavailable);
    }
    if got != layout::SIZE as i32 {
        return Err(Error::ShortRead);
    }
    // No reinterpreted struct or reference is formed, even after a successful call.
    let mut bytes = [0u8; layout::SIZE];
    for (word, chunk) in buffer.iter().zip(bytes.chunks_exact_mut(8)) {
        chunk.copy_from_slice(&word.to_ne_bytes());
    }
    layout::parse(pid, &bytes)
}

/// Read-only, bounded, fixed kern.bootsessionuuid. No caller-supplied key or write value.
#[allow(unsafe_code)]
pub fn boot_session() -> Result<String, Error> {
    let mut buffer = [0u8; 128];
    let mut len = buffer.len();
    // SAFETY: fixed NUL-terminated key; buffer and length are writable for the call,
    // capacity is correct; null newp/newlen0 is a read. No pointers escape or are retained.
    let rc = unsafe {
        libc::sysctlbyname(
            c"kern.bootsessionuuid".as_ptr(),
            buffer.as_mut_ptr().cast(),
            &mut len,
            std::ptr::null_mut(),
            0,
        )
    };
    if rc != 0 {
        return Err(Error::Unavailable);
    }
    if len == 0 || len > buffer.len() {
        return Err(Error::InvalidBootSession);
    }
    super::decode_boot_session(&buffer[..len])
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    #[test]
    fn real_f18_returns_exact_layout_and_fresh_self_identity() {
        let first = super::process_info(std::process::id()).unwrap();
        let again = super::process_info(std::process::id()).unwrap();
        assert_eq!(first.pid, std::process::id());
        assert_eq!(
            (first.unique_id, first.pid_version),
            (again.unique_id, again.pid_version)
        );
        assert!(first.live());
        assert_eq!(super::boot_session().unwrap(), super::boot_session().unwrap());
        assert!(super::process_info(0).is_err());
    }
}
