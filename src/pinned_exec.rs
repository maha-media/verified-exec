//! Execution of an already-open image. This is not a socket/process authority constructor.
//! The caller retains its existing selection policy; no PID/DTO is promoted into ProcessHold.
use std::{fs::File, path::PathBuf, sync::Arc};

#[cfg(target_os = "linux")]
#[path = "pinned_exec/linux.rs"]
mod backend;
#[cfg(not(target_os = "linux"))]
#[path = "pinned_exec/unavailable.rs"]
mod backend;

/// An open executable retained through spawn and the post-spawn image check.
/// Construction preserves the existing file/expected-inode contract of the Linux PTY API.
/// It confers no peer identity, process lifetime hold, or authorization to attach a session.
#[derive(Debug, Clone)]
pub struct PinnedExec {
    file: Arc<File>,
    identity: (u64, u64),
    #[cfg(target_os = "macos")]
    verified: Option<Arc<verified::Prepared>>,
}
impl PartialEq for PinnedExec {
    fn eq(&self, other: &Self) -> bool {
        let same_image = Arc::ptr_eq(&self.file, &other.file) && self.identity == other.identity;
        #[cfg(target_os = "macos")]
        {
            same_image
                && match (&self.verified, &other.verified) {
                    (None, None) => true,
                    (Some(a), Some(b)) => Arc::ptr_eq(a, b),
                    _ => false,
                }
        }
        #[cfg(not(target_os = "macos"))]
        {
            same_image
        }
    }
}
impl Eq for PinnedExec {}

impl PinnedExec {
    /// Retain the same open file and expected identity the caller already checked.
    /// This is a file handle, not proof that execution is available: exec_path returns None
    /// on unsupported hosts, and consumers must refuse rather than substitute a pathname.
    pub fn from_open_image(file: Arc<File>, identity: (u64, u64)) -> Self {
        Self {
            file,
            identity,
            #[cfg(target_os = "macos")]
            verified: None,
        }
    }

    pub fn file(&self) -> &Arc<File> {
        &self.file
    }

    pub fn identity(&self) -> (u64, u64) {
        self.identity
    }

    /// Names the parent's descriptor, not a descriptor the child might have closed.
    pub fn exec_path(&self) -> Option<PathBuf> {
        backend::exec_path(&self.file)
    }

    /// Observe the child's image after exec, using the existing bounded Linux wait.
    /// A returned identity is an observation to compare, never a ProcessHold.
    pub fn exec_identity(&self, pid: u32) -> Option<(u64, u64)> {
        backend::exec_identity(pid)
    }
}

// One facade; strong spawn is Darwin-only. Existing Linux retained-fd behavior is unchanged.
#[cfg(target_os = "macos")]
mod darwin;
#[cfg(any(test, target_os = "macos"))]
mod lifecycle;
#[cfg(any(all(test, unix), target_os = "macos"))]
mod prepare;
#[cfg(any(test, target_os = "macos"))]
mod sequence;
#[cfg(unix)]
mod verified;
#[cfg(unix)]
pub use verified::{ChildExit, ChildState, ExpectedImage, Reason, Refusal, SpawnInputs, Stage, VerifiedChild};

#[cfg(test)]
mod tests;
