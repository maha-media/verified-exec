//! Fixed owned-exec spawn actions and single-owner reaping; no arbitrary action or flag surface.
use super::*;
use std::{
    mem::MaybeUninit,
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
};

struct Attributes(libc::posix_spawnattr_t);
impl Drop for Attributes {
    fn drop(&mut self) {
        // SAFETY: initialized by posix_spawnattr_init, owned here, destroyed once.
        unsafe {
            libc::posix_spawnattr_destroy(&mut self.0);
        }
    }
}
struct Actions(libc::posix_spawn_file_actions_t);
impl Drop for Actions {
    fn drop(&mut self) {
        // SAFETY: initialized actions, never shared, destroyed once after spawn returns.
        unsafe {
            libc::posix_spawn_file_actions_destroy(&mut self.0);
        }
    }
}
fn rc(code: i32) -> Result<(), ExecError> {
    if code == 0 { Ok(()) } else { Err(ExecError::Os(code)) }
}
pub(super) fn spawn(spec: &SpawnSpec<'_>) -> Result<Owner, ExecError> {
    // Duplicate every source ABOVE stdio before creating actions. This handles aliases and
    // cycles (e.g. input=1/output=0) without one dup2 clobbering a later source. CLOEXEC keeps
    // these scratch copies out of the child; only their 0/1/2 destinations are inherited.
    let mut copies: Vec<OwnedFd> = Vec::with_capacity(3);
    for fd in &spec.stdio {
        // SAFETY: borrowed live fd; fixed duplication command, minimum descriptor 3.
        let duplicate = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 3) };
        if duplicate < 0 {
            return Err(ExecError::Os(errno()));
        }
        // SAFETY: fcntl returned a new descriptor owned solely by this function.
        copies.push(unsafe { OwnedFd::from_raw_fd(duplicate) });
    }
    let mut attr = MaybeUninit::uninit();
    // SAFETY: writable storage for the opaque attribute; assumed initialized only on rc0.
    rc(unsafe { libc::posix_spawnattr_init(attr.as_mut_ptr()) })?;
    let mut attr = Attributes(unsafe { attr.assume_init() });
    let mut actions = MaybeUninit::uninit();
    // SAFETY: same initialize-on-success contract for actions.
    rc(unsafe { libc::posix_spawn_file_actions_init(actions.as_mut_ptr()) })?;
    let mut actions = Actions(unsafe { actions.assume_init() });
    if let Some(cwd) = spec.cwd {
        unsafe extern "C" {
            fn posix_spawn_file_actions_addchdir_np(
                actions: *mut libc::posix_spawn_file_actions_t,
                path: *const libc::c_char,
            ) -> i32;
        }
        // SAFETY: child-only cwd: initialized actions, validated absolute NUL-terminated cwd,
        // copied by the action. Changes child cwd only; no parent chdir/addopen/ctty.
        rc(unsafe { posix_spawn_file_actions_addchdir_np(&mut actions.0, cwd.as_ptr()) })?;
    }
    // Darwin spawn.h POSIX_SPAWN_SETSID (not exposed by locked libc). SDK assertion is a
    // required Mac row; no fallback flags if unsupported.
    const SETSID: i32 = 0x0400;
    let flags = (libc::POSIX_SPAWN_START_SUSPENDED | SETSID | libc::POSIX_SPAWN_CLOEXEC_DEFAULT) as i16;
    // SAFETY: initialized private attr; fixed reviewed flags only.
    rc(unsafe { libc::posix_spawnattr_setflags(&mut attr.0, flags) })?;
    for (target, source) in copies.iter().enumerate() {
        // SAFETY: initialized actions; live private source copy, destination only 0/1/2.
        rc(unsafe { libc::posix_spawn_file_actions_adddup2(&mut actions.0, source.as_raw_fd(), target as i32) })?;
    }
    let argv: Vec<_> = spec
        .argv
        .iter()
        .map(|s| s.as_ptr().cast_mut())
        .chain(std::iter::once(std::ptr::null_mut()))
        .collect();
    let env: Vec<_> = spec
        .environment
        .iter()
        .map(|s| s.as_ptr().cast_mut())
        .chain(std::iter::once(std::ptr::null_mut()))
        .collect();
    let mut pid = 0;
    // SAFETY: all C strings are borrowed and remain live throughout this synchronous call;
    // pointer lists are NUL-terminated, explicit env (never environ), initialized actions
    // and attributes, writable pid. posix_spawn copies inputs and retains no Rust pointer.
    rc(unsafe {
        libc::posix_spawn(
            &mut pid,
            spec.executable.as_ptr(),
            &actions.0,
            &attr.0,
            argv.as_ptr(),
            env.as_ptr(),
        )
    })?;
    // Successful posix_spawn returns our own unreaped child, never an observed arbitrary pid.
    Ok(Owner {
        pid: pid as u32,
        exit: None,
        reaped: false,
        resumed: false,
        kill_attempted: false,
        cleanup_error: None,
    })
}
fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(libc::EIO)
}
impl Owner {
    pub(super) fn signal(&self, group: bool, signal: Signal) -> Result<(), ExecError> {
        if self.reaped {
            return Err(ExecError::Identity);
        }
        let pid = i32::try_from(self.pid)
            .ok()
            .filter(|p| *p > 0)
            .ok_or(ExecError::Identity)?;
        let target = if group { -pid } else { pid };
        let signal = match signal {
            Signal::Continue => libc::SIGCONT,
            Signal::Terminate => libc::SIGTERM,
            Signal::Kill => libc::SIGKILL,
        };
        // SAFETY: only our unreaped child (or its SETSID group), fixed closed signal set.
        if unsafe { libc::kill(target, signal) } == 0 {
            Ok(())
        } else {
            Err(ExecError::Os(errno()))
        }
    }
    pub(super) fn wait(&mut self, blocking: bool) -> Result<WaitState, ExecError> {
        if let Some(exit) = self.exit {
            return Ok(WaitState::Exited(exit));
        }
        if self.reaped {
            return Err(ExecError::Identity);
        }
        let flags = libc::WUNTRACED | if blocking { 0 } else { libc::WNOHANG };
        loop {
            let mut status = 0;
            // SAFETY: the sole owner waits for its own positive pid; writable status. No
            // wait-any call, and a stopped report never consumes ownership.
            let got = unsafe { libc::waitpid(self.pid as i32, &mut status, flags) };
            if got < 0 {
                let e = errno();
                if e == libc::EINTR {
                    continue;
                }
                // A third-party reaper violates ownership. Do NOT signal a possibly reused
                // pid on Drop; record loss, but never manufacture an exit/success.
                if e == libc::ECHILD {
                    self.reaped = true;
                }
                return Err(ExecError::Os(e));
            }
            if got == 0 {
                return Ok(WaitState::Running);
            }
            if libc::WIFSTOPPED(status) {
                return Ok(WaitState::Stopped(libc::WSTOPSIG(status)));
            }
            let exit = if libc::WIFEXITED(status) {
                ChildExit::Code(libc::WEXITSTATUS(status))
            } else if libc::WIFSIGNALED(status) {
                ChildExit::Signal(libc::WTERMSIG(status))
            } else {
                return Err(ExecError::Identity);
            };
            self.exit = Some(exit);
            self.reaped = true;
            return Ok(WaitState::Exited(exit));
        }
    }
    pub(super) fn cleanup(&mut self) -> Result<ChildExit, ExecError> {
        if let Some(exit) = self.exit {
            return Ok(exit);
        }
        if self.reaped {
            return Err(ExecError::Identity);
        }
        if let Some(error) = self.cleanup_error {
            return Err(ExecError::Cleanup(error));
        }
        if !self.kill_attempted {
            self.kill_attempted = true;
            match self.signal(self.resumed, Signal::Kill) {
                Ok(()) | Err(ExecError::Os(libc::ESRCH)) => {}
                Err(ExecError::Os(e)) => {
                    self.cleanup_error = Some(e);
                    return Err(ExecError::Cleanup(e));
                }
                Err(e) => return Err(e),
            }
        }
        loop {
            match self.wait(true)? {
                WaitState::Exited(exit) => return Ok(exit),
                WaitState::Stopped(_) | WaitState::Running => {}
            }
        }
    }
}
