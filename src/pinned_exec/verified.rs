//! Strong spawn contract. Expected pins and environment policy come from the caller's
//! signed origin; construction does not turn observed candidate bytes into authority.
use super::PinnedExec;
use std::{ffi::CStr, os::fd::BorrowedFd, path::Path};

#[derive(Clone, Copy)]
pub struct ExpectedImage {
    /// sha256 (pre-spawn candidate), never a measurement of the running image.
    pub sha256: [u8; 32],
    /// cdhash (loaded image), checked using the owned-child token guest before resume.
    pub cdhash: [u8; 20],
}

pub struct SpawnInputs<'a> {
    pub argv: &'a [&'a CStr],
    pub environment: &'a [&'a CStr],
    /// Fixed caller policy or signed manifest keys, NEVER derived from config keys.
    pub allowed_environment: &'a [&'a [u8]],
    pub cwd: Option<&'a Path>,
    pub stdio: [BorrowedFd<'a>; 3],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stage {
    Preparation,
    Spawn,
    InitialIdentity,
    Signature,
    FinalIdentity,
    ChangedIdentity,
    Resume,
    Lifecycle,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reason {
    Unavailable,
    InvalidInput,
    Environment,
    Candidate,
    ShaMismatch,
    Changed,
    Io(std::io::ErrorKind),
    Identity,
    Credentials,
    Allocation,
    Os(i32),
    Security(i32),
    Cleanup(i32),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Refusal {
    pub stage: Stage,
    pub reason: Reason,
    /// Cleanup failure never masks the primary refusal and is never labelled success.
    pub cleanup: Option<Reason>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChildExit {
    Code(i32),
    Signal(i32),
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChildState {
    Running,
    Stopped(i32),
    Exited(ChildExit),
}

/// Sole owned child, no Clone or from-pid constructor. Drop is final kill/reap safety.
/// Serialize calls. Cleanup is blocking and must run off the async reactor.
pub struct VerifiedChild {
    #[cfg(target_os = "macos")]
    pid: u32,
    #[cfg(target_os = "macos")]
    lifecycle: super::lifecycle::Lifecycle<crate::darwin_sys::owned_exec::RunningChild>,
    #[cfg(not(target_os = "macos"))]
    never: std::convert::Infallible,
}

impl PinnedExec {
    pub fn prepare_verified(path: &Path, expected: ExpectedImage) -> Result<Self, Refusal> {
        #[cfg(target_os = "macos")]
        {
            if expected.cdhash == [0; 20] {
                return Err(refusal(Stage::Preparation, Reason::InvalidInput));
            }
            let candidate = super::prepare::Candidate::open(path, expected.sha256).map_err(preparation)?;
            let (file, identity) = candidate.retained_image();
            Ok(Self {
                file,
                identity,
                verified: Some(std::sync::Arc::new(Prepared { candidate, expected })),
            })
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (path, expected);
            Err(refusal(Stage::Preparation, Reason::Unavailable))
        }
    }

    pub fn spawn_verified(&self, inputs: SpawnInputs<'_>) -> Result<VerifiedChild, Refusal> {
        #[cfg(target_os = "macos")]
        {
            let prepared = self
                .verified
                .as_ref()
                .ok_or_else(|| refusal(Stage::Preparation, Reason::Unavailable))?;
            let running = super::darwin::launch_prepared(super::darwin::Request {
                candidate: &prepared.candidate,
                argv: inputs.argv,
                environment: inputs.environment,
                allowed_environment: inputs.allowed_environment,
                cwd: inputs.cwd,
                stdio: inputs.stdio,
                expected_cdhash: prepared.expected.cdhash,
            })
            .map_err(launch_error)?;
            Ok(VerifiedChild {
                pid: running.pid(),
                lifecycle: super::lifecycle::Lifecycle::new(running),
            })
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = inputs;
            Err(refusal(Stage::Spawn, Reason::Unavailable))
        }
    }
}

impl VerifiedChild {
    /// Observation only; never use this PID with an independent waiter or signal API.
    pub fn pid(&self) -> u32 {
        #[cfg(target_os = "macos")]
        {
            self.pid
        }
        #[cfg(not(target_os = "macos"))]
        {
            match self.never {}
        }
    }
    pub fn try_wait(&mut self) -> Result<ChildState, Refusal> {
        #[cfg(target_os = "macos")]
        {
            use super::lifecycle::Poll;
            self.lifecycle
                .poll()
                .map(|p| match p {
                    Poll::Running => ChildState::Running,
                    Poll::Stopped(s) => ChildState::Stopped(s),
                    Poll::Exited(e) => ChildState::Exited(exit(e)),
                })
                .map_err(lifecycle_error)
        }
        #[cfg(not(target_os = "macos"))]
        {
            match self.never {}
        }
    }
    pub fn terminate_group(&mut self) -> Result<(), Refusal> {
        #[cfg(target_os = "macos")]
        {
            self.lifecycle.terminate().map_err(lifecycle_error)
        }
        #[cfg(not(target_os = "macos"))]
        {
            match self.never {}
        }
    }
    /// Cached after success OR failure; never a second kill/reap on the numeric PID.
    pub fn kill_and_reap(&mut self) -> Result<ChildExit, Refusal> {
        #[cfg(target_os = "macos")]
        {
            self.lifecycle.cleanup().map(exit).map_err(lifecycle_error)
        }
        #[cfg(not(target_os = "macos"))]
        {
            match self.never {}
        }
    }
}

fn refusal(stage: Stage, reason: Reason) -> Refusal {
    Refusal {
        stage,
        reason,
        cleanup: None,
    }
}

#[cfg(target_os = "macos")]
pub(super) struct Prepared {
    candidate: super::prepare::Candidate,
    expected: ExpectedImage,
}
#[cfg(target_os = "macos")]
impl std::fmt::Debug for Prepared {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Prepared(..)")
    }
}
#[cfg(target_os = "macos")]
fn preparation(e: super::prepare::Refusal) -> Refusal {
    use super::prepare::Refusal as P;
    refusal(
        Stage::Preparation,
        match e {
            P::InvalidInput => Reason::InvalidInput,
            P::Environment => Reason::Environment,
            P::Candidate => Reason::Candidate,
            P::ShaMismatch => Reason::ShaMismatch,
            P::Changed => Reason::Changed,
            P::Io(e) => Reason::Io(e),
        },
    )
}
#[cfg(target_os = "macos")]
fn native(e: crate::darwin_sys::owned_exec::ExecError) -> Reason {
    use crate::darwin_sys::owned_exec::ExecError as E;
    match e {
        E::Unsupported => Reason::Unavailable,
        E::InvalidSpec => Reason::InvalidInput,
        E::DyldEnvironment => Reason::Environment,
        E::Identity => Reason::Identity,
        E::Credentials => Reason::Credentials,
        E::Allocation => Reason::Allocation,
        E::Os(n) => Reason::Os(n),
        E::Security(n) => Reason::Security(n),
        E::Cleanup(n) => Reason::Cleanup(n),
    }
}
#[cfg(target_os = "macos")]
fn observation(e: super::darwin::NativeError) -> Reason {
    match e {
        super::darwin::NativeError::Child(e) => native(e),
        super::darwin::NativeError::Changed => Reason::Changed,
        super::darwin::NativeError::Observation(e) => match e {
            crate::darwin_sys::Error::Unavailable => Reason::Unavailable,
            _ => Reason::Identity,
        },
    }
}
#[cfg(target_os = "macos")]
fn launch_error(e: super::darwin::LaunchError) -> Refusal {
    match e {
        super::darwin::LaunchError::Preparation(e) => preparation(e),
        super::darwin::LaunchError::Spawn(e) => refusal(Stage::Spawn, native(e)),
        super::darwin::LaunchError::Refused(e) => {
            use super::sequence::Stage as S;
            Refusal {
                stage: match e.stage {
                    S::InitialIdentity => Stage::InitialIdentity,
                    S::Signature => Stage::Signature,
                    S::FinalIdentity => Stage::FinalIdentity,
                    S::ChangedIdentity => Stage::ChangedIdentity,
                    S::Resume => Stage::Resume,
                },
                reason: e.cause.map(observation).unwrap_or(Reason::Changed),
                cleanup: e.cleanup.map(observation),
            }
        }
    }
}
#[cfg(target_os = "macos")]
fn lifecycle_error(e: super::lifecycle::Error<crate::darwin_sys::owned_exec::ExecError>) -> Refusal {
    refusal(
        Stage::Lifecycle,
        match e {
            super::lifecycle::Error::Native(e) => native(e),
            super::lifecycle::Error::Consumed => Reason::Identity,
        },
    )
}
#[cfg(target_os = "macos")]
fn exit(e: crate::darwin_sys::owned_exec::ChildExit) -> ChildExit {
    match e {
        crate::darwin_sys::owned_exec::ChildExit::Code(n) => ChildExit::Code(n),
        crate::darwin_sys::owned_exec::ChildExit::Signal(n) => ChildExit::Signal(n),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn verified_child_is_send_without_raw_owner_constructor() {
        fn assert_send<T: Send>() {}
        assert_send::<VerifiedChild>();
    }

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn strong_spawn_is_unavailable_without_changing_legacy_linux_exec() -> std::io::Result<()> {
        use std::{os::fd::AsFd, sync::Arc};
        assert!(matches!(
            PinnedExec::prepare_verified(
                Path::new("/not-opened"),
                ExpectedImage {
                    sha256: [1; 32],
                    cdhash: [1; 20]
                }
            ),
            Err(Refusal {
                reason: Reason::Unavailable,
                ..
            })
        ));
        let file = Arc::new(tempfile::tempfile()?);
        let exec = PinnedExec::from_open_image(Arc::clone(&file), (1, 2));
        let result = exec.spawn_verified(SpawnInputs {
            argv: &[c"helper"],
            environment: &[],
            allowed_environment: &[],
            cwd: None,
            stdio: [file.as_fd(), file.as_fd(), file.as_fd()],
        });
        assert!(matches!(
            result,
            Err(Refusal {
                stage: Stage::Spawn,
                reason: Reason::Unavailable,
                ..
            })
        ));
        assert_eq!(exec.identity(), (1, 2));
        #[cfg(target_os = "linux")]
        assert!(exec.exec_path().is_some());
        Ok(())
    }
}
