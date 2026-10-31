//! Verified-before-resume execution with a single owned child and explicit caller policy.
//! Expected pins must come from a trusted signed origin, never the candidate or environment.
#![deny(unsafe_code)]
#![deny(unsafe_op_in_unsafe_fn)]

// Fixed native operations only. No public socket/PID-to-owner capability constructors.
#[cfg(any(test, target_os = "macos"))]
#[cfg_attr(all(test, not(target_os = "macos")), allow(dead_code, unused_imports))]
#[allow(unsafe_code)]
mod darwin_sys;

#[forbid(unsafe_code)]
pub mod pinned_exec;
pub use pinned_exec::PinnedExec;
#[cfg(unix)]
pub use pinned_exec::{ChildExit, ChildState, ExpectedImage, Reason, Refusal, SpawnInputs, Stage, VerifiedChild};
