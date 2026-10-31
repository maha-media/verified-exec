//! owned-exec owned children, distinct from socket-origin process capabilities.
//! Callers own pin policy and the S0/verify/S1 sequence. No PID-to-owner constructor.
use super::ProcessInfo;
use std::{ffi::CStr, os::fd::BorrowedFd};

#[cfg(target_os = "macos")]
#[allow(unsafe_code)]
mod darwin;
#[cfg(target_os = "macos")]
#[allow(unsafe_code)]
mod signature;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecError {
    // Constructed only by the non-macOS stub backend; retained for exhaustive facade mapping.
    #[cfg_attr(target_os = "macos", allow(dead_code))]
    Unsupported,
    InvalidSpec,
    DyldEnvironment,
    Identity,
    Credentials,
    Allocation,
    Os(i32),
    Security(i32),
    Cleanup(i32),
}
/// Consuming resume failure: cleanup already attempted; caller must NEVER reap again.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResumeError {
    pub primary: ExecError,
    pub cleanup: Option<ExecError>,
}
/// Exactly three caller-owned streams and explicit argv/environment. child-only cwd permits
/// only a fixed child-only absolute cwd; no arbitrary file actions or parent chdir.
pub struct SpawnSpec<'a> {
    pub executable: &'a CStr,
    pub cwd: Option<&'a CStr>,
    pub argv: &'a [&'a CStr],
    /// Each entry is KEY=VALUE; duplicates and DYLD_* keys refuse before spawn.
    pub environment: &'a [&'a CStr],
    pub stdio: [BorrowedFd<'a>; 3],
}
/// Trusted final-artifact expectation supplied by policy, not derived from the child.
pub struct ExpectedCdHash([u8; 20]);
impl ExpectedCdHash {
    pub fn new(bytes: [u8; 20]) -> Result<Self, ExecError> {
        if bytes == [0; 20] {
            return Err(ExecError::InvalidSpec);
        }
        Ok(Self(bytes))
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChildExit {
    Code(i32),
    Signal(i32),
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WaitState {
    Running,
    Stopped(i32),
    Exited(ChildExit),
}

/// Sole reaper. No Clone, raw PID handoff, or constructor from observed identity.
pub struct SuspendedChild {
    owner: Owner,
}
pub struct RunningChild {
    owner: Owner,
}
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
struct Owner {
    pid: u32,
    exit: Option<ChildExit>,
    reaped: bool,
    resumed: bool,
    #[cfg(target_os = "macos")]
    kill_attempted: bool,
    #[cfg(target_os = "macos")]
    cleanup_error: Option<i32>,
}
impl SuspendedChild {
    pub fn pid(&self) -> u32 {
        self.owner.pid
    }
    /// Observation only: a stopped report is never an exit. Verification still needs f18.
    #[cfg(test)]
    pub fn try_wait(&mut self) -> Result<WaitState, ExecError> {
        self.owner.wait(false)
    }
    pub fn kill_and_reap(mut self) -> Result<ChildExit, ExecError> {
        self.owner.cleanup()
    }
    pub fn resume(mut self) -> Result<RunningChild, ResumeError> {
        if self.owner.reaped {
            return Err(ResumeError {
                primary: ExecError::Identity,
                cleanup: None,
            });
        }
        if let Err(primary) = self.owner.signal(false, Signal::Continue) {
            let cleanup = self.owner.cleanup().err();
            return Err(ResumeError { primary, cleanup });
        }
        self.owner.resumed = true;
        Ok(RunningChild { owner: self.owner })
    }
}
impl RunningChild {
    pub fn pid(&self) -> u32 {
        self.owner.pid
    }
    pub fn try_wait(&mut self) -> Result<WaitState, ExecError> {
        self.owner.wait(false)
    }
    /// Lifecycle termination targets the child's SETSID process group, never arbitrary PIDs.
    pub fn terminate_group(&mut self) -> Result<(), ExecError> {
        self.owner.signal(true, Signal::Terminate)
    }
    pub fn kill_and_reap(mut self) -> Result<ChildExit, ExecError> {
        self.owner.cleanup()
    }
}
#[derive(Clone, Copy)]
enum Signal {
    Continue,
    Terminate,
    Kill,
}
impl Drop for Owner {
    fn drop(&mut self) {
        if !self.reaped {
            let _ = self.cleanup();
        }
    }
}

pub fn spawn_suspended(spec: &SpawnSpec<'_>) -> Result<SuspendedChild, ExecError> {
    validate(spec)?;
    #[cfg(target_os = "macos")]
    {
        darwin::spawn(spec).map(|owner| SuspendedChild { owner })
    }
    #[cfg(not(target_os = "macos"))]
    {
        Err(ExecError::Unsupported)
    }
}
/// Borrows only; failure NEVER reaps. Caller consumes the owner on refusal.
pub fn verify_owned_child(
    child: &SuspendedChild,
    initial: &ProcessInfo,
    expected: &ExpectedCdHash,
) -> Result<(), ExecError> {
    if child.owner.reaped
        || initial.pid != child.pid()
        || !initial.live()
        || initial.unique_id == 0
        || initial.pid_version == 0
    {
        return Err(ExecError::Identity);
    }
    #[cfg(target_os = "macos")]
    {
        signature::verify(initial, expected)
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = expected.0;
        Err(ExecError::Unsupported)
    }
}
fn validate(spec: &SpawnSpec<'_>) -> Result<(), ExecError> {
    if spec.cwd.is_some_and(|cwd| !cwd.to_bytes().starts_with(b"/")) {
        return Err(ExecError::InvalidSpec);
    }
    if !spec.executable.to_bytes().starts_with(b"/") || spec.argv.is_empty() || spec.argv[0].to_bytes().is_empty() {
        return Err(ExecError::InvalidSpec);
    }
    let mut keys = std::collections::HashSet::new();
    for entry in spec.environment {
        let bytes = entry.to_bytes();
        let eq = bytes.iter().position(|b| *b == b'=').ok_or(ExecError::InvalidSpec)?;
        let key = &bytes[..eq];
        if key.starts_with(b"DYLD_") {
            return Err(ExecError::DyldEnvironment);
        }
        if key.is_empty() || !keys.insert(key) {
            return Err(ExecError::InvalidSpec);
        }
    }
    Ok(())
}
// Token synthesis is deliberately NOT an AuditToken constructor: owned-child tokens never
// become socket-origin capabilities. All eight words are copied from verified observations.
#[cfg(any(test, target_os = "macos"))]
fn child_token(own: &[u32; 8], initial: &ProcessInfo) -> Result<[u32; 8], ExecError> {
    if !initial.live()
        || initial.pid == 0
        || initial.pid > i32::MAX as u32
        || initial.pid_version == 0
        || initial.unique_id == 0
    {
        return Err(ExecError::Identity);
    }
    if own[1..5] != [initial.uid, initial.gid, initial.ruid, initial.rgid] {
        return Err(ExecError::Credentials);
    }
    Ok([
        own[0],
        initial.uid,
        initial.gid,
        initial.ruid,
        initial.rgid,
        initial.pid,
        own[6],
        initial.pid_version,
    ])
}
#[cfg(not(target_os = "macos"))]
impl Owner {
    fn wait(&mut self, _: bool) -> Result<WaitState, ExecError> {
        Err(ExecError::Unsupported)
    }
    fn signal(&self, _: bool, _: Signal) -> Result<(), ExecError> {
        Err(ExecError::Unsupported)
    }
    fn cleanup(&mut self) -> Result<ChildExit, ExecError> {
        Err(ExecError::Unsupported)
    }
}
#[cfg(not(target_os = "macos"))]
const _: Option<Signal> = Some(Signal::Kill);
#[cfg(test)]
mod tests;
