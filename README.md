# verified-exec

Owned, verified-before-resume execution on Darwin, with explicit caller policy and one child reaper. This crate is a library, not a launcher service or policy authority.

## Contract

`PinnedExec::prepare_verified(path, ExpectedImage { sha256, cdhash })` retains a nofollow-opened regular executable. `spawn_verified(SpawnInputs { argv, environment, allowed_environment, cwd, stdio })` checks inputs, rechecks the retained file, starts the child suspended, validates its loaded code, and resumes only after the final identity comparison succeeds.

- **sha256 (pre-spawn candidate)** checks retained file bytes against the caller's expected artifact hash. It does not measure a running image.
- **cdhash (loaded image)** is validated with the owned-child audit-token guest and an exact code-directory-hash requirement. Any nonzero validation status refuses. Fresh identity observations bracket validation before resume.
- Expected pins and allowed environment keys must come from a trusted origin controlled by the caller, never the candidate file, environment, request payload or mutable configuration keys.
- Environment entries are explicit; there is no implicit inheritance or expansion. Every `DYLD_*` key is refused even if allowlisted. The caller decides other allowed keys and their trusted/untrusted value sources.
- Optional cwd must be absolute and affects only the child. There is no parent-directory change, controlling-terminal setup or arbitrary file-action interface.
- Stdio consists of three borrowed descriptors, copied to child descriptors 0/1/2. The caller retains parent pipe ends.

`VerifiedChild` is the sole lifecycle owner. `pid()` is observation only. Never independently signal, reap, or construct another child owner from it. Serialize `try_wait`, `terminate_group` and `kill_and_reap`; terminal outcomes are cached. A stopped report is not an exit. Cleanup errors remain errors rather than fabricated successful exits.

Cleanup and dropping an unreaped owner can block while killing and reaping. Async callers must arrange off-reactor ownership/drop, including cancellation and eventual blocking-task results. During runtime shutdown, callers must explicitly account for blocking cleanup. Do not discard ownership to avoid a wait.

A resumed child has its own session/process group. Cleanup targets that group while the leader is still owned and unreaped. Once a terminal leader exit is cached, no further group signal is sent. Descendants that create a new session can escape the original group.

## Platforms and limits

Strong verified spawn is currently available only on Darwin. Other targets return a typed `Unavailable`; callers must not silently retry an unverified spawn. Existing Linux retained-file execution-path helpers are also exposed, but are not a Darwin-style pre-resume verification guarantee.

This is not protection against another same-user process sending an early continue signal. Tests demonstrate that such a child can run before an identity change is detected and reaped. The final identity comparison mitigates the race; it does not prevent early execution. Validation covers the main image, not arbitrary injected libraries. A candidate replacement can cause a safe refusal. Darwin private identity-layout assumptions are checked and fail closed on unexpected sizes.

The crate does not enforce private installation directory ancestry, manifest placement completeness, release packaging, network authorization or daemon-specific privileges. Those remain caller responsibilities. It does not expose socket peer-identity or arbitrary process-control constructors.

## Verification

Portable unit tests exercise candidate checks, environment/cwd rejection, sequence ordering, lifecycle caching, and unchanged Linux behavior. Darwin owned-child outcomes are ignored by default and must be selected by exact parent test name in an isolated test environment. Never run every ignored test indiscriminately: some are internal children used only by a parent fixture. The SDK ABI fixture is `tests/exec_abi.c`.

License: Apache-2.0. This repository is intended for a pinned git dependency; Cargo registry publication is disabled.
