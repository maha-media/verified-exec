//! Private owned-exec kernel boundary; no socket or runtime-directory operations.
mod layout;
pub use layout::{ProcessInfo, decode_boot_session};
pub mod owned_exec;

/// Closed errors: never include kernel buffers, tokens or caller-controlled strings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Unavailable,
    InvalidPid,
    ShortRead,
    InvalidIdentity,
    InvalidBootSession,
}

#[cfg(target_os = "macos")]
mod darwin;
#[cfg(target_os = "macos")]
pub use darwin::{boot_session, process_info};

#[cfg(not(target_os = "macos"))]
pub fn boot_session() -> Result<String, Error> {
    Err(Error::Unavailable)
}
#[cfg(not(target_os = "macos"))]
pub fn process_info(_: u32) -> Result<ProcessInfo, Error> {
    Err(Error::Unavailable)
}

#[cfg(all(test, target_os = "macos"))]
mod native_outcomes;
