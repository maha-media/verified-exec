//! release tester-only owned fixture rows. No live helpers, daemon, token, or production pins.
#![cfg(target_os = "macos")]
#![allow(clippy::unwrap_used, clippy::expect_used)]
use super::{boot_session, owned_exec::*, process_info};
use std::{
    ffi::CString,
    fs::{self, File},
    os::{fd::AsFd, unix::fs::PermissionsExt},
    path::PathBuf,
    process::Command,
    time::{Duration, Instant},
};
struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "verified-exec-fixture-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        Self(path.canonicalize().unwrap())
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn expected() -> ExpectedCdHash {
    expected_for(&std::env::current_exe().unwrap())
}
fn expected_for(path: &std::path::Path) -> ExpectedCdHash {
    let output = Command::new("/usr/bin/codesign")
        .args(["-d", "--verbose=4"])
        .arg(path)
        .output()
        .unwrap();
    assert!(output.status.success());
    let text = String::from_utf8(output.stderr).unwrap();
    let hex = text.lines().find_map(|l| l.strip_prefix("CDHash=")).unwrap();
    assert_eq!(hex.len(), 40);
    let mut hash = [0; 20];
    for (i, b) in hash.iter_mut().enumerate() {
        *b = u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).unwrap();
    }
    ExpectedCdHash::new(hash).unwrap()
}
fn child(fixture: &Fixture, entry: &str) -> SuspendedChild {
    child_with_mode(fixture, entry, "marker")
}
fn child_with_mode(fixture: &Fixture, entry: &str, mode: &str) -> SuspendedChild {
    use std::os::unix::ffi::OsStrExt;
    let exe = CString::new(std::env::current_exe().unwrap().as_os_str().as_bytes()).unwrap();
    let entry = CString::new(entry).unwrap();
    let root = CString::new(format!("VERIFIED_EXEC_FIXTURE={}", fixture.0.display())).unwrap();
    let mode = CString::new(format!("VERIFIED_EXEC_MODE={mode}")).unwrap();
    let cwd = CString::new(fixture.0.as_os_str().as_bytes()).unwrap();
    let file = File::options().read(true).write(true).open("/dev/null").unwrap();
    spawn_suspended(&SpawnSpec {
        executable: &exe,
        cwd: Some(&cwd),
        argv: &[&exe, c"--ignored", c"--exact", &entry, c"--nocapture"],
        environment: &[&root, &mode],
        stdio: [file.as_fd(); 3],
    })
    .unwrap()
}
fn marker(f: &Fixture) -> bool {
    f.0.join("marker").exists()
}
fn bounded_exit(child: &mut RunningChild) -> ChildExit {
    let until = Instant::now() + Duration::from_secs(10);
    loop {
        if let WaitState::Exited(exit) = child.try_wait().unwrap() {
            return exit;
        }
        assert!(Instant::now() < until, "child exit deadline");
        std::thread::sleep(Duration::from_millis(5));
    }
}
#[test]
#[ignore = "internal child, selected only by owned fixture parent"]
fn owned_exec_marker_child() {
    let path = PathBuf::from(std::env::var_os("VERIFIED_EXEC_FIXTURE").unwrap());
    assert_eq!(std::env::current_dir().unwrap(), path);
    fs::write(path.join("marker"), b"ran").unwrap();
    if std::env::var("VERIFIED_EXEC_MODE").unwrap() == "exec" {
        use std::os::unix::process::CommandExt;
        let error = Command::new("/bin/sh")
            .args(["-c", "printf exec > transitioned; while :; do :; done"])
            .env_clear()
            .exec();
        panic!("fixture exec failed: {error}");
    }
}
#[test]
#[ignore = "release tester Darwin owned exec right pin, stopped semantics, one reaper"]
fn right_pin_resumes_and_stopped_is_not_exit() {
    let fixture = Fixture::new();
    let mut suspended = child(&fixture, "darwin_sys::native_outcomes::owned_exec_marker_child");
    let pid = suspended.pid();
    let before = process_info(pid).unwrap();
    let boot = boot_session().unwrap();
    assert_eq!(before.status, 4, "START_SUSPENDED");
    assert_eq!(before.pgid, pid, "SETSID");
    assert!(!marker(&fixture));
    assert!(matches!(
        suspended.try_wait().unwrap(),
        WaitState::Stopped(_) | WaitState::Running
    ));
    verify_owned_child(&suspended, &before, &expected()).unwrap();
    let after = process_info(pid).unwrap();
    assert_eq!(
        (before.unique_id, before.pid_version),
        (after.unique_id, after.pid_version)
    );
    assert_eq!(boot, boot_session().unwrap());
    assert!(!marker(&fixture));
    let mut running = suspended.resume().unwrap_or_else(|e| panic!("resume {e:?}"));
    assert_eq!(bounded_exit(&mut running), ChildExit::Code(0));
    assert!(marker(&fixture));
    assert_eq!(
        running.try_wait().unwrap(),
        WaitState::Exited(ChildExit::Code(0)),
        "cached exit, never second waitpid"
    );
    drop(running);
    assert!(process_info(pid).is_err(), "already reaped");
}
#[test]
#[ignore = "release tester Darwin owned exec wrong pin never executes user marker"]
fn wrong_pin_never_runs_marker_and_refusal_reaps_once() {
    let fixture = Fixture::new();
    let suspended = child(&fixture, "darwin_sys::native_outcomes::owned_exec_marker_child");
    let pid = suspended.pid();
    let before = process_info(pid).unwrap();
    assert!(verify_owned_child(&suspended, &before, &ExpectedCdHash::new([0xa5; 20]).unwrap()).is_err());
    // Borrowed verifier did not reap or resume: still stopped and no user marker.
    assert_eq!(process_info(pid).unwrap().status, 4);
    assert!(!marker(&fixture));
    assert_eq!(suspended.kill_and_reap().unwrap(), ChildExit::Signal(9));
    assert!(!marker(&fixture));
    assert!(process_info(pid).is_err());
}
#[test]
#[ignore = "release tester Darwin unresumed Drop kills/reaps and cannot run a marker"]
fn dropped_suspended_child_never_runs_and_is_reaped() {
    let fixture = Fixture::new();
    let suspended = child(&fixture, "darwin_sys::native_outcomes::owned_exec_marker_child");
    let pid = suspended.pid();
    drop(suspended);
    assert!(!marker(&fixture));
    assert!(process_info(pid).is_err());
}
#[test]
#[ignore = "release tester Darwin stale token and wrong owner refuse without reaping"]
fn stale_image_generation_and_wrong_owned_pid_refuse() {
    let fixture = Fixture::new();
    let suspended = child(&fixture, "darwin_sys::native_outcomes::owned_exec_marker_child");
    let initial = process_info(suspended.pid()).unwrap();
    let mut stale = initial;
    stale.pid_version = stale.pid_version.checked_add(1).unwrap();
    assert!(verify_owned_child(&suspended, &stale, &expected()).is_err());
    let mut foreign = initial;
    foreign.pid = std::process::id();
    assert_eq!(
        verify_owned_child(&suspended, &foreign, &expected()),
        Err(ExecError::Identity)
    );
    assert_eq!(process_info(suspended.pid()).unwrap().status, 4);
    suspended.kill_and_reap().unwrap();
    assert!(!marker(&fixture));
}

// Deliberately adversarial same-user early SIGCONT is a named owned-exec residual. This fixture
// signals ONLY its own suspended child to force an exec between S0 and verification;
// no production wrapper exposes an unchecked-resume action.
fn early_continue(child: &SuspendedChild) {
    assert!(
        Command::new("/bin/kill")
            .args(["-CONT", &child.pid().to_string()])
            .status()
            .unwrap()
            .success()
    );
}
#[test]
#[ignore = "release tester Darwin deterministic exec after S0, no live process"]
fn exec_after_s0_refuses_old_token_and_bracket() {
    let fixture = Fixture::new();
    let suspended = child_with_mode(&fixture, "darwin_sys::native_outcomes::owned_exec_marker_child", "exec");
    let initial = process_info(suspended.pid()).unwrap();
    let pin = expected();
    verify_owned_child(&suspended, &initial, &pin).unwrap();
    early_continue(&suspended);
    let until = Instant::now() + Duration::from_secs(10);
    while !fixture.0.join("transitioned").exists() {
        assert!(Instant::now() < until, "exec marker deadline");
        std::thread::sleep(Duration::from_millis(5));
    }
    let after = process_info(suspended.pid()).unwrap();
    assert_eq!(initial.unique_id, after.unique_id);
    assert_ne!(initial.pid_version, after.pid_version, "final bracket must refuse");
    assert!(
        verify_owned_child(&suspended, &initial, &pin).is_err(),
        "stale token guest refuses"
    );
    assert!(
        verify_owned_child(&suspended, &after, &pin).is_err(),
        "new image wrong cdhash"
    );
    suspended.kill_and_reap().unwrap();
}
#[test]
#[ignore = "release tester Darwin zombie/reaped owner refusal"]
fn exited_child_never_verifies_and_cached_reap_is_idempotent() {
    let fixture = Fixture::new();
    let mut suspended = child(&fixture, "darwin_sys::native_outcomes::owned_exec_marker_child");
    let initial = process_info(suspended.pid()).unwrap();
    early_continue(&suspended);
    let until = Instant::now() + Duration::from_secs(10);
    loop {
        match process_info(suspended.pid()) {
            Ok(info) if info.live() => {}
            _ => break,
        }
        assert!(Instant::now() < until, "exit deadline");
        std::thread::sleep(Duration::from_millis(5));
    }
    assert!(
        verify_owned_child(&suspended, &initial, &expected()).is_err(),
        "zombie cannot verify"
    );
    loop {
        std::thread::sleep(Duration::from_millis(5));
        if let WaitState::Exited(exit) = suspended.try_wait().unwrap() {
            assert_eq!(exit, ChildExit::Code(0));
            break;
        }
        assert!(Instant::now() < until, "reap deadline");
    }
    assert_eq!(
        verify_owned_child(&suspended, &initial, &expected()),
        Err(ExecError::Identity)
    );
    assert_eq!(suspended.try_wait().unwrap(), WaitState::Exited(ChildExit::Code(0)));
    assert_eq!(suspended.kill_and_reap().unwrap(), ChildExit::Code(0));
}

#[test]
#[ignore = "release tester Darwin caller streams and aliased output survive CLOEXEC_DEFAULT"]
fn stdio_aliases_and_absolute_child_cwd_are_preserved() {
    use std::os::unix::ffi::OsStrExt;
    let fixture = Fixture::new();
    let parent_cwd = std::env::current_dir().unwrap();
    fs::write(fixture.0.join("in"), b"input-marker\n").unwrap();
    let input = File::open(fixture.0.join("in")).unwrap();
    let output = File::create(fixture.0.join("out")).unwrap();
    let cwd = CString::new(fixture.0.as_os_str().as_bytes()).unwrap();
    let script = cr#"IFS= read -r line; printf '%s\n' "$line"; printf 'stderr-marker\n' >&2; printf cwd > cwd-marker"#;
    let suspended = spawn_suspended(&SpawnSpec {
        executable: c"/bin/sh",
        cwd: Some(&cwd),
        argv: &[c"sh", c"-c", script],
        environment: &[],
        stdio: [input.as_fd(), output.as_fd(), output.as_fd()],
    })
    .unwrap();
    let initial = process_info(suspended.pid()).unwrap();
    verify_owned_child(&suspended, &initial, &expected_for(std::path::Path::new("/bin/sh"))).unwrap();
    let after = process_info(suspended.pid()).unwrap();
    assert_eq!(
        (initial.unique_id, initial.pid_version),
        (after.unique_id, after.pid_version)
    );
    let mut running = suspended.resume().unwrap_or_else(|e| panic!("resume {e:?}"));
    assert_eq!(bounded_exit(&mut running), ChildExit::Code(0));
    assert_eq!(
        fs::read(fixture.0.join("out")).unwrap(),
        b"input-marker\nstderr-marker\n"
    );
    assert_eq!(fs::read(fixture.0.join("cwd-marker")).unwrap(), b"cwd");
    assert_eq!(std::env::current_dir().unwrap(), parent_cwd, "parent cwd unchanged");
}

#[test]
#[ignore = "internal stdio-cycle child, no mutations of the parent test runner's descriptors"]
fn owned_exec_stdio_cycle_child() {
    let root = PathBuf::from(std::env::var_os("VERIFIED_EXEC_FIXTURE").unwrap());
    let input = std::io::stdin();
    let output = std::io::stdout();
    let error = std::io::stderr();
    {
        use std::io::{Seek, Write};
        let mut file = File::from(output.as_fd().try_clone_to_owned().unwrap());
        file.rewind().unwrap();
        file.write_all(b"cycle-input\n").unwrap();
        file.rewind().unwrap();
    }
    let suspended = spawn_suspended(&SpawnSpec {
        executable: c"/bin/sh",
        cwd: None,
        argv: &[
            c"sh",
            c"-c",
            cr#"IFS= read -r line; printf '%s\n' "$line"; printf cycle-error >&2"#,
        ],
        environment: &[],
        stdio: [output.as_fd(), input.as_fd(), error.as_fd()],
    })
    .unwrap();
    let initial = process_info(suspended.pid()).unwrap();
    verify_owned_child(&suspended, &initial, &expected_for(std::path::Path::new("/bin/sh"))).unwrap();
    let after = process_info(suspended.pid()).unwrap();
    assert_eq!(
        (initial.unique_id, initial.pid_version),
        (after.unique_id, after.pid_version)
    );
    let mut running = suspended.resume().unwrap_or_else(|e| panic!("resume {e:?}"));
    assert_eq!(bounded_exit(&mut running), ChildExit::Code(0));
    fs::write(root.join("cycle-done"), b"done").unwrap();
}
#[test]
#[ignore = "release tester Darwin stdio source0/1 cycle in isolated subprocess"]
fn source_stdio_zero_one_cycle_and_two_identity_are_safe() {
    use std::process::{Child, Stdio};
    struct Reap(Child);
    impl Drop for Reap {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    let fixture = Fixture::new();
    // Both are readable+writable: child fd1 is the input source, fd0 the output source.
    // The isolated child replaces the libtest banner and rewinds fd1 before spawning.
    let a = File::options()
        .create_new(true)
        .read(true)
        .write(true)
        .open(fixture.0.join("a"))
        .unwrap();
    let b = File::options()
        .create_new(true)
        .read(true)
        .write(true)
        .open(fixture.0.join("b"))
        .unwrap();
    let e = File::create(fixture.0.join("e")).unwrap();
    let mut child = Reap(
        Command::new(std::env::current_exe().unwrap())
            .args([
                "--ignored",
                "--exact",
                "darwin_sys::native_outcomes::owned_exec_stdio_cycle_child",
                "--nocapture",
            ])
            .env("VERIFIED_EXEC_FIXTURE", &fixture.0)
            .stdin(Stdio::from(a))
            .stdout(Stdio::from(b))
            .stderr(Stdio::from(e))
            .spawn()
            .unwrap(),
    );
    let until = Instant::now() + Duration::from_secs(15);
    loop {
        if let Some(status) = child.0.try_wait().unwrap() {
            assert!(status.success());
            break;
        }
        assert!(Instant::now() < until, "stdio child deadline");
        std::thread::sleep(Duration::from_millis(5));
    }
    assert!(fixture.0.join("cycle-done").exists());
    assert_eq!(fs::read(fixture.0.join("a")).unwrap(), b"cycle-input\n");
    assert_eq!(fs::read(fixture.0.join("e")).unwrap(), b"cycle-error");
}
