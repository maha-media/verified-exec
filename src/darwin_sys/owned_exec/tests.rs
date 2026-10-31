//! Portable input/token guards; Darwin runtime rows live alongside the backend.
#![allow(clippy::unwrap_used)]
use super::*;
use std::{fs::File, os::fd::AsFd};
#[test]
fn explicit_environment_rejects_every_dyld_key_before_any_spawn() {
    let file = File::open("/dev/null").unwrap();
    for key in [c"DYLD_INSERT_LIBRARIES=/tmp/x", c"DYLD_=", c"DYLD_LIBRARY_PATH="] {
        let env = [key];
        let spec = SpawnSpec {
            executable: c"/bin/true",
            cwd: None,
            argv: &[c"true"],
            environment: &env,
            stdio: [file.as_fd(); 3],
        };
        assert!(matches!(spawn_suspended(&spec), Err(ExecError::DyldEnvironment)));
    }
    let spec = SpawnSpec {
        executable: c"/bin/true",
        cwd: None,
        argv: &[c"true"],
        environment: &[c"HOME=/", c"PATH=/bin"],
        stdio: [file.as_fd(); 3],
    };
    assert_eq!(validate(&spec), Ok(()));
}
#[test]
fn absolute_image_argv_and_unambiguous_environment_are_required() {
    let file = File::open("/dev/null").unwrap();
    for env in [&[c"HOME=/", c"HOME=/x"][..], &[c"=bad"][..], &[c"NO_EQUALS"][..]] {
        let spec = SpawnSpec {
            executable: c"/bin/true",
            cwd: None,
            argv: &[c"true"],
            environment: env,
            stdio: [file.as_fd(); 3],
        };
        assert_eq!(validate(&spec), Err(ExecError::InvalidSpec));
    }
    let mut spec = SpawnSpec {
        executable: c"relative",
        cwd: None,
        argv: &[c"true"],
        environment: &[],
        stdio: [file.as_fd(); 3],
    };
    assert_eq!(validate(&spec), Err(ExecError::InvalidSpec));
    spec.executable = c"/bin/true";
    spec.argv = &[];
    assert_eq!(validate(&spec), Err(ExecError::InvalidSpec));
    assert!(matches!(ExpectedCdHash::new([0; 20]), Err(ExecError::InvalidSpec)));
}
fn initial() -> ProcessInfo {
    ProcessInfo {
        pid: 42,
        ppid: 20,
        pgid: 42,
        status: 4,
        uid: 501,
        gid: 20,
        ruid: 501,
        rgid: 20,
        unique_id: 99,
        parent_unique_id: 90,
        pid_version: 8,
    }
}
#[test]
fn each_child_credential_must_equal_own_and_all_token_words_are_observed() {
    let own = [111, 501, 20, 501, 20, 20, 222, 7];
    assert_eq!(child_token(&own, &initial()), Ok([111, 501, 20, 501, 20, 42, 222, 8]));
    for field in 0..4 {
        let mut info = initial();
        match field {
            0 => info.uid += 1,
            1 => info.gid += 1,
            2 => info.ruid += 1,
            _ => info.rgid += 1,
        }
        assert_eq!(child_token(&own, &info), Err(ExecError::Credentials));
    }
}
#[test]
fn zombie_zero_identity_and_invalid_pid_never_make_a_child_token() {
    let own = [111, 501, 20, 501, 20, 20, 222, 7];
    for field in 0..5 {
        let mut info = initial();
        match field {
            0 => info.status = 5,
            1 => info.pid = 0,
            2 => info.pid = u32::MAX,
            3 => info.unique_id = 0,
            _ => info.pid_version = 0,
        }
        assert_eq!(child_token(&own, &info), Err(ExecError::Identity));
    }
}

#[test]
fn owned_children_are_send_without_any_raw_owner_constructor() {
    fn assert_send<T: Send>() {}
    assert_send::<SuspendedChild>();
    assert_send::<RunningChild>();
}
#[test]
fn cwd_is_absolute_or_explicitly_inherited_never_silently_dropped() {
    let file = File::open("/dev/null").unwrap();
    let mut spec = SpawnSpec {
        executable: c"/bin/true",
        cwd: None,
        argv: &[c"true"],
        environment: &[],
        stdio: [file.as_fd(); 3],
    };
    assert_eq!(validate(&spec), Ok(()));
    for cwd in [c"", c"relative", c"./child"] {
        spec.cwd = Some(cwd);
        assert_eq!(validate(&spec), Err(ExecError::InvalidSpec));
    }
    spec.cwd = Some(c"/absolute");
    assert_eq!(validate(&spec), Ok(()));
}
