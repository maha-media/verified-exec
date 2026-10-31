//! Private verification sequence. An implementation owns exactly one suspended child.
//! Observations and expected pins cannot construct an owned child or authorize a resume.

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Snapshot {
    pub boot_session: String,
    pub pid: u32,
    pub unique_id: u64,
    pub pid_version: u32,
    pub live: bool,
}

impl Snapshot {
    fn valid(&self) -> bool {
        !self.boot_session.is_empty() && self.pid != 0 && self.unique_id != 0 && self.pid_version != 0 && self.live
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Stage {
    InitialIdentity,
    Signature,
    FinalIdentity,
    ChangedIdentity,
    Resume,
}

/// Cleanup failure is retained alongside the original refusal. Never reported as a clean exit.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct Refused<E> {
    pub stage: Stage,
    pub cause: Option<E>,
    pub cleanup: Option<E>,
}

pub(super) trait Attempt: Sized {
    type Running;
    type Error;
    fn owned_pid(&self) -> u32;
    fn snapshot(&self) -> Result<Snapshot, Self::Error>;
    /// Must be token-bound and must check all four child credentials against our self token.
    /// Borrowed verification never reaps or resumes. It accepts only exact signature success.
    fn verify(&self, initial: &Snapshot) -> Result<(), Self::Error>;
    fn kill_and_reap(self) -> Result<(), Self::Error>;
    /// Consumes ownership. On failure this method must already have killed/reaped, or carry
    /// its cleanup failure explicitly. No caller-side second wait or raw-pid handoff.
    fn resume(self) -> Result<Self::Running, Refused<Self::Error>>;
}

fn refuse<A: Attempt>(attempt: A, stage: Stage, cause: Option<A::Error>) -> Refused<A::Error> {
    Refused {
        stage,
        cause,
        cleanup: attempt.kill_and_reap().err(),
    }
}

pub(super) fn verify_then_resume<A: Attempt>(attempt: A) -> Result<A::Running, Refused<A::Error>> {
    let first = match attempt.snapshot() {
        Ok(s) if s.valid() && s.pid == attempt.owned_pid() => s,
        Ok(_) => return Err(refuse(attempt, Stage::InitialIdentity, None)),
        Err(e) => return Err(refuse(attempt, Stage::InitialIdentity, Some(e))),
    };
    if let Err(e) = attempt.verify(&first) {
        return Err(refuse(attempt, Stage::Signature, Some(e)));
    }
    let last = match attempt.snapshot() {
        Ok(s) => s,
        Err(e) => return Err(refuse(attempt, Stage::FinalIdentity, Some(e))),
    };
    if !last.valid() || last != first {
        return Err(refuse(attempt, Stage::ChangedIdentity, None));
    }
    attempt.resume()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use std::{cell::RefCell, rc::Rc};

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Fault {
        Read,
        Signature,
        Cleanup,
        Resume,
    }
    struct Fake {
        calls: Rc<RefCell<Vec<&'static str>>>,
        reads: RefCell<Vec<Result<Snapshot, Fault>>>,
        signature: bool,
        cleanup: bool,
        resume: bool,
    }
    impl Attempt for Fake {
        type Running = ();
        type Error = Fault;
        fn owned_pid(&self) -> u32 {
            42
        }
        fn snapshot(&self) -> Result<Snapshot, Fault> {
            self.calls.borrow_mut().push("snapshot");
            self.reads.borrow_mut().remove(0)
        }
        fn verify(&self, _: &Snapshot) -> Result<(), Fault> {
            self.calls.borrow_mut().push("verify");
            if self.signature { Ok(()) } else { Err(Fault::Signature) }
        }
        fn kill_and_reap(self) -> Result<(), Fault> {
            self.calls.borrow_mut().push("kill+reap");
            if self.cleanup { Ok(()) } else { Err(Fault::Cleanup) }
        }
        fn resume(self) -> Result<(), Refused<Fault>> {
            self.calls.borrow_mut().push("resume");
            if self.resume {
                Ok(())
            } else {
                Err(refuse(self, Stage::Resume, Some(Fault::Resume)))
            }
        }
    }
    fn snapshot() -> Snapshot {
        Snapshot {
            boot_session: "boot".into(),
            pid: 42,
            unique_id: 91,
            pid_version: 7,
            live: true,
        }
    }
    fn fake() -> Fake {
        Fake {
            calls: Default::default(),
            reads: RefCell::new(vec![Ok(snapshot()), Ok(snapshot())]),
            signature: true,
            cleanup: true,
            resume: true,
        }
    }
    #[test]
    fn only_verified_unchanged_owned_child_reaches_resume() {
        let attempt = fake();
        let calls = Rc::clone(&attempt.calls);
        assert_eq!(verify_then_resume(attempt), Ok(()));
        assert_eq!(*calls.borrow(), ["snapshot", "verify", "snapshot", "resume"]);
        for field in 0..5 {
            let attempt = fake();
            let mut changed = snapshot();
            match field {
                0 => changed.boot_session = "other".into(),
                1 => changed.pid += 1,
                2 => changed.unique_id += 1,
                3 => changed.pid_version += 1,
                _ => changed.live = false,
            }
            attempt.reads.borrow_mut()[1] = Ok(changed);
            let calls = Rc::clone(&attempt.calls);
            assert_eq!(verify_then_resume(attempt).unwrap_err().stage, Stage::ChangedIdentity);
            assert_eq!(*calls.borrow(), ["snapshot", "verify", "snapshot", "kill+reap"]);
        }
    }
    #[test]
    fn every_failure_has_one_cleanup_and_never_resumes_unverified() {
        for stage in [
            Stage::InitialIdentity,
            Stage::Signature,
            Stage::FinalIdentity,
            Stage::Resume,
        ] {
            let mut attempt = fake();
            match stage {
                Stage::InitialIdentity => attempt.reads.borrow_mut()[0] = Err(Fault::Read),
                Stage::Signature => attempt.signature = false,
                Stage::FinalIdentity => attempt.reads.borrow_mut()[1] = Err(Fault::Read),
                Stage::Resume => attempt.resume = false,
                _ => unreachable!(),
            }
            attempt.cleanup = false;
            let calls = Rc::clone(&attempt.calls);
            let refused = verify_then_resume(attempt).unwrap_err();
            assert_eq!(refused.stage, stage);
            assert_eq!(refused.cleanup, Some(Fault::Cleanup));
            assert_eq!(calls.borrow().iter().filter(|c| **c == "kill+reap").count(), 1);
            if stage != Stage::Resume {
                assert!(!calls.borrow().contains(&"resume"));
            }
        }
        let attempt = fake();
        attempt.reads.borrow_mut()[0].as_mut().unwrap().pid = 99;
        assert_eq!(verify_then_resume(attempt).unwrap_err().stage, Stage::InitialIdentity);
    }
}
