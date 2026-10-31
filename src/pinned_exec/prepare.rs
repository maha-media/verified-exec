//! SHA256 is a pre-spawn candidate check, NOT a measurement of the loaded image.
//! The loaded-image authority remains token-guest cdhash verification before resume.
use sha2::{Digest, Sha256};
use std::{
    ffi::{CStr, CString},
    fs::{File, Metadata, OpenOptions},
    io,
    os::unix::{
        ffi::OsStrExt,
        fs::{FileExt, MetadataExt, OpenOptionsExt},
    },
    path::{Path, PathBuf},
    sync::Arc,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Refusal {
    InvalidInput,
    Environment,
    Candidate,
    ShaMismatch,
    Changed,
    Io(io::ErrorKind),
}
impl From<io::Error> for Refusal {
    fn from(error: io::Error) -> Self {
        Self::Io(error.kind())
    }
}

#[derive(Clone, PartialEq, Eq)]
struct Facts {
    dev: u64,
    ino: u64,
    len: u64,
    mode: u32,
    uid: u32,
    gid: u32,
    mtime: (i64, i64),
    ctime: (i64, i64),
}
impl Facts {
    fn of(m: &Metadata) -> Result<Self, Refusal> {
        if !m.is_file() || m.mode() & 0o111 == 0 || m.mode() & 0o6000 != 0 {
            return Err(Refusal::Candidate);
        }
        Ok(Self {
            dev: m.dev(),
            ino: m.ino(),
            len: m.len(),
            mode: m.mode(),
            uid: m.uid(),
            gid: m.gid(),
            mtime: (m.mtime(), m.mtime_nsec()),
            ctime: (m.ctime(), m.ctime_nsec()),
        })
    }
}

/// Caller selects trusted expected bytes from the baked manifest, never from this file.
/// The caller separately validates its private directory ancestry and placement policy.
pub(super) struct Candidate {
    file: Arc<File>,
    path: PathBuf,
    facts: Facts,
    expected_sha: [u8; 32],
}
impl Candidate {
    #[cfg(target_os = "macos")]
    pub fn retained_image(&self) -> (Arc<File>, (u64, u64)) {
        (Arc::clone(&self.file), (self.facts.dev, self.facts.ino))
    }
    pub fn open(path: &Path, expected_sha: [u8; 32]) -> Result<Self, Refusal> {
        if !path.is_absolute() || expected_sha == [0; 32] {
            return Err(Refusal::InvalidInput);
        }
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(
                (rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC | rustix::fs::OFlags::NONBLOCK).bits()
                    as i32,
            )
            .open(path)?;
        let facts = Facts::of(&file.metadata()?)?;
        let candidate = Self {
            file: Arc::new(file),
            path: path.into(),
            facts,
            expected_sha,
        };
        candidate.recheck()?;
        Ok(candidate)
    }
    /// Called immediately before suspended spawn while the same descriptor is retained.
    /// A path replacement refuses rather than substituting the new candidate's hash.
    pub fn recheck(&self) -> Result<(), Refusal> {
        if Facts::of(&self.file.metadata()?)? != self.facts
            || Facts::of(&std::fs::symlink_metadata(&self.path)?)? != self.facts
        {
            return Err(Refusal::Changed);
        }
        let mut hash = Sha256::new();
        let mut offset = 0;
        let mut bytes = [0u8; 65536];
        while offset < self.facts.len {
            let size = (self.facts.len - offset).min(bytes.len() as u64) as usize;
            let n = match self.file.read_at(&mut bytes[..size], offset) {
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                other => other?,
            };
            if n == 0 {
                return Err(Refusal::Changed);
            }
            hash.update(&bytes[..n]);
            offset += n as u64;
        }
        if <[u8; 32]>::from(hash.finalize()) != self.expected_sha {
            return Err(Refusal::ShaMismatch);
        }
        if Facts::of(&self.file.metadata()?)? != self.facts
            || Facts::of(&std::fs::symlink_metadata(&self.path)?)? != self.facts
        {
            return Err(Refusal::Changed);
        }
        Ok(())
    }
    pub fn executable(&self) -> Result<CString, Refusal> {
        CString::new(self.path.as_os_str().as_bytes()).map_err(|_| Refusal::InvalidInput)
    }
}

/// Exact explicit environment only; no process-environment fallback or expansion.
/// Allowlist is caller policy; even an explicitly allowed DYLD_* key always refuses.
pub(super) fn environment(entries: &[&CStr], allowed: &[&[u8]]) -> Result<(), Refusal> {
    let mut seen = std::collections::HashSet::new();
    for entry in entries {
        let bytes = entry.to_bytes();
        let eq = bytes.iter().position(|b| *b == b'=').ok_or(Refusal::Environment)?;
        let key = &bytes[..eq];
        if key.is_empty() || key.starts_with(b"DYLD_") || !allowed.contains(&key) || !seen.insert(key) {
            return Err(Refusal::Environment);
        }
    }
    Ok(())
}

pub(super) fn cwd(path: Option<&Path>) -> Result<Option<CString>, Refusal> {
    path.map(|p| {
        if !p.is_absolute() {
            return Err(Refusal::InvalidInput);
        }
        CString::new(p.as_os_str().as_bytes()).map_err(|_| Refusal::InvalidInput)
    })
    .transpose()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};

    fn fixture() -> io::Result<(tempfile::TempDir, PathBuf, [u8; 32])> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("helper");
        std::fs::write(&path, b"approved helper")?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))?;
        Ok((dir, path, Sha256::digest(b"approved helper").into()))
    }
    #[test]
    fn candidate_sha_is_expected_not_observed_and_replacement_refuses() -> io::Result<()> {
        let (_dir, path, sha) = fixture()?;
        assert!(matches!(Candidate::open(&path, [1; 32]), Err(Refusal::ShaMismatch)));
        let candidate = Candidate::open(&path, sha).map_err(|e| io::Error::other(format!("{e:?}")))?;
        assert_eq!(candidate.recheck(), Ok(()));
        assert_eq!(
            candidate.executable().map(|p| p.as_bytes().to_vec()),
            Ok(path.as_os_str().as_bytes().to_vec())
        );
        let old = path.with_extension("old");
        std::fs::rename(&path, &old)?;
        std::fs::write(&path, b"approved helper")?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))?;
        assert_eq!(candidate.recheck(), Err(Refusal::Changed));
        let link = path.with_extension("link");
        symlink(&old, &link)?;
        assert!(Candidate::open(&link, sha).is_err());
        assert!(Candidate::open(path.parent().unwrap_or(Path::new("/")), sha).is_err());
        let candidate = Candidate::open(&path, sha).map_err(|e| io::Error::other(format!("{e:?}")))?;
        std::fs::write(&path, b"changed helper!")?;
        assert!(candidate.recheck().is_err());
        Ok(())
    }
    #[test]
    fn env_and_cwd_are_explicit_and_dyld_never_allowed() {
        assert_eq!(environment(&[c"HOME=/x", c"LANG=C"], &[b"HOME", b"LANG"]), Ok(()));
        assert_eq!(environment(&[], &[]), Ok(()));
        for entries in [
            vec![c"DYLD_INSERT_LIBRARIES=/x"],
            vec![c"HOME=/x", c"HOME=/y"],
            vec![c"OTHER=x"],
            vec![c"HOME"],
            vec![c"=x"],
        ] {
            assert_eq!(
                environment(&entries, &[b"HOME", b"DYLD_INSERT_LIBRARIES"]),
                Err(Refusal::Environment)
            );
        }
        assert_eq!(cwd(None), Ok(None));
        assert_eq!(cwd(Some(Path::new("relative"))), Err(Refusal::InvalidInput));
        assert_eq!(cwd(Some(Path::new("/absolute"))), Ok(Some(c"/absolute".to_owned())));
    }
}
