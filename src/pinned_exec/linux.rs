use std::{
    fs::File,
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant},
};

const EXEC_WAIT: Duration = Duration::from_secs(2);

pub(super) fn exec_path(file: &Arc<File>) -> Option<PathBuf> {
    use std::os::fd::AsRawFd;
    Some(PathBuf::from(format!(
        "/proc/{}/fd/{}",
        std::process::id(),
        file.as_raw_fd()
    )))
}

/// The device and inode of the image process `pid` runs (`/proc/<pid>/exe`).
fn image_identity(pid: u32) -> Option<(u64, u64)> {
    use std::os::unix::fs::MetadataExt;
    let meta = std::fs::metadata(format!("/proc/{pid}/exe")).ok()?;
    Some((meta.dev(), meta.ino()))
}

/// Preserve the old PTY host's exact wait/read order, 2 s bound and 1 ms sleep.
pub(super) fn exec_identity(pid: u32) -> Option<(u64, u64)> {
    let own = image_identity(std::process::id());
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
}
