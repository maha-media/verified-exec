//! Opt-in owned fixtures only. release tester runs these on Darwin, never a live daemon/helper.
#![allow(clippy::unwrap_used, clippy::expect_used)]
use super::*;
use sha2::{Digest, Sha256};
use std::{
    ffi::CString,
    fs::File,
    os::{fd::AsFd, unix::ffi::OsStrExt},
    path::PathBuf,
    process::Command,
    time::{Duration, Instant},
};

fn executable() -> PathBuf {
    std::env::current_exe().unwrap().canonicalize().unwrap()
}
fn pin() -> [u8; 20] {
    // Fixture expectation comes from the test artifact BEFORE starting the owned child.
    // This is NOT a production pin selection mechanism.
    let output = Command::new("/usr/bin/codesign")
        .args(["-d", "--verbose=4"])
        .arg(executable())
        .output()
        .unwrap();
    assert!(output.status.success());
    let text = String::from_utf8(output.stderr).unwrap();
    let hex = text.lines().find_map(|l| l.strip_prefix("CDHash=")).unwrap();
    assert_eq!(hex.len(), 40);
    let mut result = [0; 20];
    for (i, b) in result.iter_mut().enumerate() {
        *b = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap();
    }
    result
}
fn args() -> Vec<CString> {
    [
        executable().as_os_str().as_bytes(),
        b"--ignored",
        b"--exact",
        b"pinned_exec::darwin::native_outcomes::marker_child",
        b"--nocapture",
    ]
    .into_iter()
    .map(|s| CString::new(s).unwrap())
    .collect()
}
fn bounded_exit(child: &mut crate::pinned_exec::VerifiedChild) -> crate::pinned_exec::ChildExit {
    let until = Instant::now() + Duration::from_secs(10);
    loop {
        if let crate::pinned_exec::ChildState::Exited(exit) = child.try_wait().unwrap() {
            return exit;
        }
        assert!(Instant::now() < until, "owned child exit deadline");
        std::thread::sleep(Duration::from_millis(5));
    }
}

#[test]
#[ignore = "internal owned child selected only by release tester fixture parent"]
fn marker_child() {
    let dir = PathBuf::from(std::env::var_os("VERIFIED_EXEC_FACADE_FIXTURE").unwrap());
    assert_eq!(std::env::current_dir().unwrap(), dir);
    std::fs::write(dir.join("marker"), b"ran").unwrap();
    if std::env::var_os("VERIFIED_EXEC_FACADE_TRANSITION").is_some() {
        use std::os::unix::process::CommandExt;
        let error = Command::new("/bin/sh")
            .args(["-c", "while :; do :; done"])
            .env_clear()
            .exec();
        panic!("owned fixture exec failed: {error}");
    }
}

#[test]
#[ignore = "release tester owned full-sequence right/wrong loaded cdhash; no daemon"]
fn full_sequence_right_pin_runs_wrong_pin_never_runs() {
    let own = executable();
    let sha: [u8; 32] = Sha256::digest(std::fs::read(&own).unwrap()).into();
    let good = pin();
    for wrong in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let cwd = dir.path().canonicalize().unwrap();
        let env = CString::new(format!("VERIFIED_EXEC_FACADE_FIXTURE={}", cwd.display())).unwrap();
        let args = args();
        let args: Vec<_> = args.iter().map(|a| a.as_c_str()).collect();
        let file = File::options().read(true).write(true).open("/dev/null").unwrap();
        let mut expected = good;
        if wrong {
            expected[0] ^= 1;
        }
        use crate::pinned_exec::{ExpectedImage, PinnedExec, SpawnInputs};
        let candidate = PinnedExec::prepare_verified(
            &own,
            ExpectedImage {
                sha256: sha,
                cdhash: expected,
            },
        )
        .unwrap();
        let result = candidate.spawn_verified(SpawnInputs {
            argv: &args,
            environment: &[&env],
            allowed_environment: &[b"VERIFIED_EXEC_FACADE_FIXTURE"],
            cwd: Some(&cwd),
            stdio: [file.as_fd(); 3],
        });
        if wrong {
            assert!(matches!(
                result,
                Err(crate::pinned_exec::Refusal {
                    stage: crate::pinned_exec::Stage::Signature,
                    cleanup: None,
                    ..
                })
            ));
            assert!(!cwd.join("marker").exists(), "wrong loaded cdhash ran marker");
        } else {
            let mut child = match result {
                Ok(c) => c,
                Err(_) => panic!("right pin refused"),
            };
            assert_eq!(bounded_exit(&mut child), crate::pinned_exec::ChildExit::Code(0));
            assert!(cwd.join("marker").exists());
            assert_eq!(
                child.try_wait().unwrap(),
                crate::pinned_exec::ChildState::Exited(crate::pinned_exec::ChildExit::Code(0))
            );
        }
    }
}

struct Interposed {
    inner: OwnedAttempt,
    stale: bool,
}
impl Attempt for Interposed {
    type Running = sys::RunningChild;
    type Error = NativeError;
    fn owned_pid(&self) -> u32 {
        self.inner.owned_pid()
    }
    fn snapshot(&self) -> Result<Snapshot, NativeError> {
        self.inner.snapshot()
    }
    fn verify(&self, snapshot: &Snapshot) -> Result<(), NativeError> {
        if self.stale {
            let mut info = self.inner.initial.get().unwrap();
            info.pid_version = info.pid_version.checked_add(1).unwrap();
            return sys::verify_owned_child(&self.inner.child, &info, &self.inner.expected).map_err(NativeError::Child);
        }
        // Deliberately exercise the accepted same-user early-SIGCONT residual using ONLY
        // the unreaped child this fixture owns. No raw-PID ownership is constructed.
        assert!(
            Command::new("/bin/kill")
                .args(["-CONT", &self.owned_pid().to_string()])
                .status()
                .unwrap()
                .success()
        );
        let until = Instant::now() + Duration::from_secs(10);
        loop {
            let now = process_info(self.owned_pid()).unwrap();
            if now.pid_version != snapshot.pid_version {
                break;
            }
            assert!(Instant::now() < until, "owned fixture failed to exec");
            std::thread::sleep(Duration::from_millis(5));
        }
        self.inner.verify(snapshot)
    }
    fn kill_and_reap(self) -> Result<(), NativeError> {
        self.inner.kill_and_reap()
    }
    fn resume(self) -> Result<Self::Running, Refused<NativeError>> {
        self.inner.resume()
    }
}

#[test]
#[ignore = "release tester owned stale-token/exec-after-S0 sequence; no daemon"]
fn full_sequence_stale_token_and_exec_after_s0_refuse() {
    for stale in [true, false] {
        let dir = tempfile::tempdir().unwrap();
        let cwd = dir.path().canonicalize().unwrap();
        let env = CString::new(format!("VERIFIED_EXEC_FACADE_FIXTURE={}", cwd.display())).unwrap();
        let cwd_c = CString::new(cwd.as_os_str().as_bytes()).unwrap();
        let exe = CString::new(executable().as_os_str().as_bytes()).unwrap();
        let args = args();
        let args: Vec<_> = args.iter().map(|a| a.as_c_str()).collect();
        let file = File::options().read(true).write(true).open("/dev/null").unwrap();
        let child = sys::spawn_suspended(&sys::SpawnSpec {
            executable: &exe,
            argv: &args,
            environment: &[&env, c"VERIFIED_EXEC_FACADE_TRANSITION=1"],
            stdio: [file.as_fd(); 3],
            cwd: Some(&cwd_c),
        })
        .unwrap();
        let pid = child.pid();
        let result = verify_then_resume(Interposed {
            inner: OwnedAttempt {
                child,
                expected: sys::ExpectedCdHash::new(pin()).unwrap(),
                initial: Cell::new(None),
            },
            stale,
        });
        assert!(
            matches!(
                result,
                Err(Refused {
                    stage: Stage::Signature,
                    cleanup: None,
                    ..
                })
            ),
            "stale/exec token did not refuse at signature"
        );
        assert!(process_info(pid).is_err(), "owned rejected child not reaped");
        if stale {
            assert!(!cwd.join("marker").exists());
        } else {
            assert!(cwd.join("marker").exists(), "early-resume exec fixture never ran");
        }
    }
}

// This entire module is private #[cfg(test)] under a Darwin-only parent. Interpose
// AFTER real signature success, without any hook in a production implementation.
struct AfterSignature(OwnedAttempt);
impl Attempt for AfterSignature {
    type Running = sys::RunningChild;
    type Error = NativeError;
    fn owned_pid(&self) -> u32 {
        self.0.owned_pid()
    }
    fn snapshot(&self) -> Result<Snapshot, NativeError> {
        self.0.snapshot()
    }
    fn verify(&self, initial: &Snapshot) -> Result<(), NativeError> {
        self.0.verify(initial)?;
        assert!(
            Command::new("/bin/kill")
                .args(["-CONT", &self.owned_pid().to_string()])
                .status()
                .unwrap()
                .success()
        );
        let until = Instant::now() + Duration::from_secs(10);
        loop {
            let now = process_info(self.owned_pid()).unwrap();
            if now.pid_version != initial.pid_version {
                break;
            }
            assert!(Instant::now() < until, "owned post-signature child failed to exec");
            std::thread::sleep(Duration::from_millis(5));
        }
        // The real sequence's NEXT operation is S1. It must reject this changed image.
        Ok(())
    }
    fn kill_and_reap(self) -> Result<(), NativeError> {
        self.0.kill_and_reap()
    }
    fn resume(self) -> Result<Self::Running, Refused<NativeError>> {
        self.0.resume()
    }
}

#[test]
#[ignore = "release tester owned post-signature image change must fail S1; no daemon"]
fn s1_refuses_image_change_after_signature_before_resume() {
    let dir = tempfile::tempdir().unwrap();
    let cwd = dir.path().canonicalize().unwrap();
    let env = CString::new(format!("VERIFIED_EXEC_FACADE_FIXTURE={}", cwd.display())).unwrap();
    let cwd_c = CString::new(cwd.as_os_str().as_bytes()).unwrap();
    let exe = CString::new(executable().as_os_str().as_bytes()).unwrap();
    let args = args();
    let args: Vec<_> = args.iter().map(|a| a.as_c_str()).collect();
    let file = File::options().read(true).write(true).open("/dev/null").unwrap();
    let child = sys::spawn_suspended(&sys::SpawnSpec {
        executable: &exe,
        argv: &args,
        environment: &[&env, c"VERIFIED_EXEC_FACADE_TRANSITION=1"],
        stdio: [file.as_fd(); 3],
        cwd: Some(&cwd_c),
    })
    .unwrap();
    let pid = child.pid();
    let result = verify_then_resume(AfterSignature(OwnedAttempt {
        child,
        expected: sys::ExpectedCdHash::new(pin()).unwrap(),
        initial: Cell::new(None),
    }));
    assert!(
        matches!(
            result,
            Err(Refused {
                stage: Stage::ChangedIdentity,
                cleanup: None,
                ..
            })
        ),
        "S1 failed to refuse the image change after successful signature validation"
    );
    assert!(process_info(pid).is_err(), "owned post-signature child not reaped");
    assert!(
        cwd.join("marker").exists(),
        "owned early-resume fixture did not execute"
    );
}
