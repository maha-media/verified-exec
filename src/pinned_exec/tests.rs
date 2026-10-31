use super::*;

#[cfg(target_os = "linux")]
#[test]
fn target_names_the_parent_fd_and_retains_the_open_inode_after_rename() -> std::io::Result<()> {
    use std::{
        io::Read,
        os::{fd::AsRawFd, unix::fs::MetadataExt},
    };
    let root = tempfile::tempdir()?;
    let path = root.path().join("synaps");
    std::fs::write(&path, b"original")?;
    let file = Arc::new(File::open(&path)?);
    let meta = file.metadata()?;
    let identity = (meta.dev(), meta.ino());
    let fd = file.as_raw_fd();
    let exec = PinnedExec::from_open_image(Arc::clone(&file), identity);
    drop(file);
    std::fs::rename(&path, root.path().join("old"))?;
    std::fs::write(&path, b"replacement")?;
    let target = exec.exec_path().ok_or(std::io::ErrorKind::Unsupported)?;
    assert_eq!(target, PathBuf::from(format!("/proc/{}/fd/{fd}", std::process::id())));
    let mut text = String::new();
    File::open(target)?.read_to_string(&mut text)?;
    assert_eq!(text, "original");
    assert_eq!(exec.identity(), identity);
    assert_eq!(exec.file().metadata()?.ino(), meta.ino());
    assert_eq!(exec.exec_identity(u32::MAX), None);
    Ok(())
}

#[test]
fn linux_wait_and_read_bodies_stay_exact() {
    let source = include_str!("linux.rs");
    assert!(source.contains("const EXEC_WAIT: Duration = Duration::from_secs(2);"));
    let body = source
        .split("pub(super) fn exec_identity(pid: u32) -> Option<(u64, u64)> {")
        .nth(1)
        .unwrap_or_default();
    assert_eq!(
        body.trim(),
        r#"let own = image_identity(std::process::id());
    let end = Instant::now() + EXEC_WAIT;
    loop {
        let now = image_identity(pid)?;
        if Some(now) != own {
            return Some(now);
        }
        if Instant::now() >= end {
            return None;
        }
        std::thread::sleep(Duration::from_millis(1));
    }
}"#
    );
    assert!(source.contains(
        "let meta = std::fs::metadata(format!(\"/proc/{pid}/exe\")).ok()?;\n    Some((meta.dev(), meta.ino()))"
    ));
}

#[cfg(not(target_os = "linux"))]
#[test]
fn unsupported_never_substitutes_a_path_or_image_observation() -> std::io::Result<()> {
    let file = Arc::new(tempfile::tempfile()?);
    let exec = PinnedExec::from_open_image(file, (1, 2));
    assert_eq!(exec.exec_path(), None);
    assert_eq!(exec.exec_identity(std::process::id()), None);
    Ok(())
}
