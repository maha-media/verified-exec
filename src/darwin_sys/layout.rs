//! Fixed flavor-18 byte contract, tested on every host. No pointer casts.
use super::Error;

pub(crate) const SIZE: usize = 192;

/// Kernel observations, not authority. Only socket-origin proof can create a peer hold.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProcessInfo {
    pub pid: u32,
    pub ppid: u32,
    pub pgid: u32,
    pub status: u32,
    pub uid: u32,
    pub gid: u32,
    pub ruid: u32,
    pub rgid: u32,
    pub unique_id: u64,
    pub parent_unique_id: u64,
    pub pid_version: u32,
}
impl ProcessInfo {
    pub fn live(&self) -> bool {
        matches!(self.status, 1..=4)
    }
}

// Public SDK proc_bsdinfo is 136 bytes. The private uniqidentifierinfo tail is 56:
// uuid[16], uniqueid u64, puniqueid u64, idversion u32, original-parent-version u32,
// two reserved u64. native probe sizeof asserted 136+56=192 on macOS26.3.1 arm64.
#[cfg_attr(not(any(test, target_os = "macos")), allow(dead_code))]
pub(crate) fn parse(pid: u32, bytes: &[u8]) -> Result<ProcessInfo, Error> {
    let b: &[u8; SIZE] = bytes.try_into().map_err(|_| Error::ShortRead)?;
    let u32_at = |n| {
        let mut v = [0; 4];
        v.copy_from_slice(&b[n..n + 4]);
        u32::from_ne_bytes(v)
    };
    let u64_at = |n| {
        let mut v = [0; 8];
        v.copy_from_slice(&b[n..n + 8]);
        u64::from_ne_bytes(v)
    };
    if pid == 0 || pid > i32::MAX as u32 || u32_at(12) != pid {
        return Err(Error::InvalidPid);
    }
    let info = ProcessInfo {
        pid,
        ppid: u32_at(16),
        pgid: u32_at(100),
        status: u32_at(4),
        uid: u32_at(20),
        gid: u32_at(24),
        ruid: u32_at(28),
        rgid: u32_at(32),
        unique_id: u64_at(152),
        parent_unique_id: u64_at(160),
        pid_version: u32_at(168),
    };
    if !matches!(info.status, 1..=5) || info.unique_id == 0 || info.pid_version == 0 {
        return Err(Error::InvalidIdentity);
    }
    Ok(info)
}

/// Exactly one nonempty UUID, allowing the kernel's surrounding whitespace before NUL.
/// Unknown formats never become a boot key; no truncation or lossily decoded strings.
pub fn decode_boot_session(bytes: &[u8]) -> Result<String, Error> {
    let nul = bytes.iter().position(|b| *b == 0).ok_or(Error::InvalidBootSession)?;
    if bytes[nul..].iter().any(|b| *b != 0) {
        return Err(Error::InvalidBootSession);
    }
    let s = std::str::from_utf8(&bytes[..nul])
        .map_err(|_| Error::InvalidBootSession)?
        .trim();
    if s.len() != 36
        || !s.bytes().enumerate().all(|(i, b)| {
            if matches!(i, 8 | 13 | 18 | 23) {
                b == b'-'
            } else {
                b.is_ascii_hexdigit()
            }
        })
    {
        return Err(Error::InvalidBootSession);
    }
    Ok(s.to_owned())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    fn fixture() -> [u8; SIZE] {
        let mut b = [0; SIZE];
        for (offset, value) in [
            (4, 2u32),
            (12, 4242),
            (16, 4000),
            (20, 502),
            (24, 20),
            (28, 502),
            (32, 20),
            (100, 4242),
            (168, 77),
        ] {
            b[offset..offset + 4].copy_from_slice(&value.to_ne_bytes());
        }
        b[152..160].copy_from_slice(&4_000_000_123u64.to_ne_bytes());
        b[160..168].copy_from_slice(&4_000_000_001u64.to_ne_bytes());
        b
    }
    #[test]
    fn exact_f18_layout_includes_pidversion_not_start_time() {
        let info = parse(4242, &fixture()).unwrap();
        assert_eq!(
            info,
            ProcessInfo {
                pid: 4242,
                ppid: 4000,
                pgid: 4242,
                status: 2,
                uid: 502,
                gid: 20,
                ruid: 502,
                rgid: 20,
                unique_id: 4_000_000_123,
                parent_unique_id: 4_000_000_001,
                pid_version: 77
            }
        );
    }
    #[test]
    fn every_nonexact_size_is_refused() {
        for len in 0..=256 {
            if len != SIZE {
                assert_eq!(parse(4242, &vec![0; len]), Err(Error::ShortRead));
            }
        }
    }
    #[test]
    fn wrong_pid_unknown_state_and_missing_keys_are_refused() {
        assert_eq!(parse(4243, &fixture()), Err(Error::InvalidPid));
        for (offset, value) in [(4, 0u32), (4, 6), (168, 0)] {
            let mut b = fixture();
            b[offset..offset + 4].copy_from_slice(&value.to_ne_bytes());
            assert_eq!(parse(4242, &b), Err(Error::InvalidIdentity));
        }
        let mut b = fixture();
        b[152..160].fill(0);
        assert_eq!(parse(4242, &b), Err(Error::InvalidIdentity));
        b = fixture();
        b[4..8].copy_from_slice(&5u32.to_ne_bytes());
        assert!(!parse(4242, &b).unwrap().live());
    }
    #[test]
    fn boot_session_is_nonempty_bounded_uuid() {
        let good = b"12345678-1234-1234-1234-123456789ABC\0";
        assert_eq!(
            decode_boot_session(good).unwrap(),
            "12345678-1234-1234-1234-123456789ABC"
        );
        for bad in [&b"\0"[..], &b" \0"[..], &good[..36], &b"not-a-key\0"[..]] {
            assert_eq!(decode_boot_session(bad), Err(Error::InvalidBootSession));
        }
        let mut bad = good.to_vec();
        bad.push(b'x');
        assert_eq!(decode_boot_session(&bad), Err(Error::InvalidBootSession));
    }
}
