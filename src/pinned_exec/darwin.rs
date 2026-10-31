//! Native owned-child adapter; no socket capability, PID constructor or second reaper.
//! The caller must finish trusted-pin, file/SHA, argv and environment policy before launch.
use super::sequence::{Attempt, Refused, Snapshot, Stage, verify_then_resume};
use crate::darwin_sys::{ProcessInfo, boot_session, owned_exec as sys, process_info};
use std::cell::Cell;

use super::prepare;
use std::{ffi::CStr, os::fd::BorrowedFd, path::Path};

pub(super) enum LaunchError {
    Preparation(prepare::Refusal),
    Spawn(sys::ExecError),
    Refused(Refused<NativeError>),
}

#[derive(Debug)]
pub(super) enum NativeError {
    Observation(crate::darwin_sys::Error),
    Child(sys::ExecError),
    Changed,
}

struct OwnedAttempt {
    child: sys::SuspendedChild,
    expected: sys::ExpectedCdHash,
    initial: Cell<Option<ProcessInfo>>,
}

impl Attempt for OwnedAttempt {
    type Running = sys::RunningChild;
    type Error = NativeError;

    fn owned_pid(&self) -> u32 {
        self.child.pid()
    }

    fn snapshot(&self) -> Result<Snapshot, NativeError> {
        let boot = boot_session().map_err(NativeError::Observation)?;
        let info = process_info(self.child.pid()).map_err(NativeError::Observation)?;
        // Save the exact S0 credentials for token verification, not a reconstructed DTO.
        // The second read never replaces this initial observation.
        if self.initial.get().is_none() {
            self.initial.set(Some(info));
        }
        Ok(snapshot(boot, &info))
    }

    fn verify(&self, initial: &Snapshot) -> Result<(), NativeError> {
        let info = self.initial.get().ok_or(NativeError::Changed)?;
        if snapshot(initial.boot_session.clone(), &info) != *initial {
            return Err(NativeError::Changed);
        }
        sys::verify_owned_child(&self.child, &info, &self.expected).map_err(NativeError::Child)
    }

    fn kill_and_reap(self) -> Result<(), NativeError> {
        self.child.kill_and_reap().map(|_| ()).map_err(NativeError::Child)
    }

    fn resume(self) -> Result<sys::RunningChild, Refused<NativeError>> {
        // Consuming resume owns failure cleanup too. Never issue a second kill/wait here.
        self.child.resume().map_err(|error| Refused {
            stage: Stage::Resume,
            cause: Some(NativeError::Child(error.primary)),
            cleanup: error.cleanup.map(NativeError::Child),
        })
    }
}

fn snapshot(boot_session: String, info: &ProcessInfo) -> Snapshot {
    Snapshot {
        boot_session,
        pid: info.pid,
        unique_id: info.unique_id,
        pid_version: info.pid_version,
        live: info.live(),
    }
}

/// Internal only: cannot bypass the eventual facade's caller-policy preparation.
/// No public sys spec, child owner or signature expectation is exported by this adapter.
fn launch(spec: &sys::SpawnSpec<'_>, expected: sys::ExpectedCdHash) -> Result<sys::RunningChild, LaunchError> {
    let child = sys::spawn_suspended(spec).map_err(LaunchError::Spawn)?;
    verify_then_resume(OwnedAttempt {
        child,
        expected,
        initial: Cell::new(None),
    })
    .map_err(LaunchError::Refused)
}

/// Caller policy supplies fixed argv, explicit allowlisted environment and baked pins.
/// Candidate SHA is checked immediately before spawn; loaded cdhash is checked while suspended.
pub(super) struct Request<'a> {
    pub candidate: &'a prepare::Candidate,
    pub argv: &'a [&'a CStr],
    pub environment: &'a [&'a CStr],
    pub allowed_environment: &'a [&'a [u8]],
    pub cwd: Option<&'a Path>,
    pub stdio: [BorrowedFd<'a>; 3],
    pub expected_cdhash: [u8; 20],
}

pub(super) fn launch_prepared(request: Request<'_>) -> Result<sys::RunningChild, LaunchError> {
    let preparation = LaunchError::Preparation;
    prepare::environment(request.environment, request.allowed_environment).map_err(preparation)?;
    let cwd = prepare::cwd(request.cwd).map_err(preparation)?;
    let executable = request.candidate.executable().map_err(preparation)?;
    let expected = sys::ExpectedCdHash::new(request.expected_cdhash).map_err(LaunchError::Spawn)?;
    if request.argv.is_empty() || request.argv[0].to_bytes().is_empty() {
        return Err(preparation(prepare::Refusal::InvalidInput));
    }
    let spec = sys::SpawnSpec {
        executable: &executable,
        argv: request.argv,
        environment: request.environment,
        stdio: request.stdio,
        cwd: cwd.as_deref(),
    };
    request.candidate.recheck().map_err(preparation)?;
    launch(&spec, expected)
}

impl super::lifecycle::Owner for sys::RunningChild {
    type Exit = sys::ChildExit;
    type Error = sys::ExecError;

    fn poll(&mut self) -> Result<super::lifecycle::Poll<Self::Exit>, Self::Error> {
        use super::lifecycle::Poll;
        self.try_wait().map(|state| match state {
            sys::WaitState::Running => Poll::Running,
            sys::WaitState::Stopped(signal) => Poll::Stopped(signal),
            sys::WaitState::Exited(exit) => Poll::Exited(exit),
        })
    }

    fn terminate(&mut self) -> Result<(), Self::Error> {
        self.terminate_group()
    }

    fn cleanup(self) -> Result<Self::Exit, Self::Error> {
        self.kill_and_reap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn running_owner_is_send_and_snapshot_preserves_native_identity() {
        fn assert_send<T: Send>() {}
        assert_send::<sys::RunningChild>();
        assert_send::<sys::SuspendedChild>();
        let info = ProcessInfo {
            pid: 42,
            ppid: 2,
            pgid: 42,
            status: 4,
            uid: 501,
            gid: 20,
            ruid: 501,
            rgid: 20,
            unique_id: u64::MAX - 1,
            parent_unique_id: 4,
            pid_version: 19,
        };
        let observed = snapshot("boot".into(), &info);
        assert_eq!(observed.pid, 42);
        assert_eq!(observed.unique_id, u64::MAX - 1);
        assert_eq!(observed.pid_version, 19);
        assert!(observed.live);
        let zombie = ProcessInfo { status: 5, ..info };
        assert!(!snapshot("boot".into(), &zombie).live);
    }
}

#[cfg(test)]
mod native_outcomes;
