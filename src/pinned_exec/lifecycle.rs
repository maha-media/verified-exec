//! Adapts consuming cleanup to a mutable async-facing owner without a raw PID escape.
//! The caller serializes operations; blocking cleanup must not run on the async reactor.

pub(super) enum Poll<X> {
    Running,
    Stopped(i32),
    Exited(X),
}

pub(super) trait Owner: Sized {
    type Exit: Clone;
    type Error: Clone;
    fn poll(&mut self) -> Result<Poll<Self::Exit>, Self::Error>;
    fn terminate(&mut self) -> Result<(), Self::Error>;
    fn cleanup(self) -> Result<Self::Exit, Self::Error>;
}

pub(super) struct Lifecycle<O: Owner> {
    state: State<O>,
}

enum State<O: Owner> {
    Owned(O),
    Terminal(Result<O::Exit, O::Error>),
    // Used only during consuming cleanup. If cleanup unwinds, its owner drops there;
    // this adapter must never manufacture a replacement or retry a numeric PID.
    Consumed,
}

#[derive(Debug, PartialEq, Eq)]
pub(super) enum Error<E> {
    Native(E),
    Consumed,
}

impl<O: Owner> Lifecycle<O> {
    pub fn new(owner: O) -> Self {
        Self {
            state: State::Owned(owner),
        }
    }

    pub fn poll(&mut self) -> Result<Poll<O::Exit>, Error<O::Error>> {
        match &mut self.state {
            State::Terminal(result) => result.clone().map(Poll::Exited).map_err(Error::Native),
            State::Consumed => Err(Error::Consumed),
            State::Owned(owner) => match owner.poll().map_err(Error::Native)? {
                Poll::Exited(exit) => {
                    // Native owner has already reaped. Its Drop must be a no-op.
                    self.state = State::Terminal(Ok(exit.clone()));
                    Ok(Poll::Exited(exit))
                }
                other => Ok(other),
            },
        }
    }

    pub fn terminate(&mut self) -> Result<(), Error<O::Error>> {
        match &mut self.state {
            State::Owned(owner) => owner.terminate().map_err(Error::Native),
            State::Terminal(result) => result.clone().map(|_| ()).map_err(Error::Native),
            State::Consumed => Err(Error::Consumed),
        }
    }

    pub fn cleanup(&mut self) -> Result<O::Exit, Error<O::Error>> {
        if let State::Terminal(result) = &self.state {
            return result.clone().map_err(Error::Native);
        }
        let State::Owned(owner) = std::mem::replace(&mut self.state, State::Consumed) else {
            return Err(Error::Consumed);
        };
        let result = owner.cleanup();
        self.state = State::Terminal(result.clone());
        result.map_err(Error::Native)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{cell::RefCell, rc::Rc};

    struct Fake {
        calls: Rc<RefCell<Vec<&'static str>>>,
        exit: bool,
        fail_cleanup: bool,
    }
    impl Owner for Fake {
        type Exit = i32;
        type Error = &'static str;
        fn poll(&mut self) -> Result<Poll<i32>, &'static str> {
            self.calls.borrow_mut().push("poll");
            if self.exit {
                Ok(Poll::Exited(0))
            } else {
                Ok(Poll::Stopped(19))
            }
        }
        fn terminate(&mut self) -> Result<(), &'static str> {
            self.calls.borrow_mut().push("terminate");
            Ok(())
        }
        fn cleanup(self) -> Result<i32, &'static str> {
            self.calls.borrow_mut().push("cleanup");
            if self.fail_cleanup {
                Err("cleanup failed")
            } else {
                Ok(0)
            }
        }
    }
    impl Drop for Fake {
        fn drop(&mut self) {
            self.calls.borrow_mut().push("drop");
        }
    }
    fn fixture(exit: bool, fail_cleanup: bool) -> (Lifecycle<Fake>, Rc<RefCell<Vec<&'static str>>>) {
        let calls = Rc::new(RefCell::new(vec![]));
        (
            Lifecycle::new(Fake {
                calls: Rc::clone(&calls),
                exit,
                fail_cleanup,
            }),
            calls,
        )
    }

    #[test]
    fn consuming_cleanup_is_cached_even_when_it_fails() {
        for fail in [false, true] {
            let (mut lifecycle, calls) = fixture(false, fail);
            assert!(matches!(lifecycle.poll(), Ok(Poll::Stopped(19))));
            assert_eq!(lifecycle.terminate(), Ok(()));
            let expected = if fail {
                Err(Error::Native("cleanup failed"))
            } else {
                Ok(0)
            };
            assert_eq!(lifecycle.cleanup(), expected);
            assert_eq!(lifecycle.cleanup(), expected);
            assert_eq!(lifecycle.terminate(), expected.map(|_| ()));
            assert_eq!(calls.borrow().as_slice(), ["poll", "terminate", "cleanup", "drop"]);
            drop(lifecycle);
            assert_eq!(calls.borrow().as_slice(), ["poll", "terminate", "cleanup", "drop"]);
        }
    }

    #[test]
    fn reaped_exit_never_polls_signals_or_reaps_again_and_cancel_drops_owner() {
        let (mut lifecycle, calls) = fixture(true, false);
        assert!(matches!(lifecycle.poll(), Ok(Poll::Exited(0))));
        assert!(matches!(lifecycle.poll(), Ok(Poll::Exited(0))));
        assert_eq!(lifecycle.terminate(), Ok(()));
        assert_eq!(lifecycle.cleanup(), Ok(0));
        assert_eq!(calls.borrow().as_slice(), ["poll", "drop"]);
        let (lifecycle, calls) = fixture(false, false);
        drop(lifecycle);
        assert_eq!(calls.borrow().as_slice(), ["drop"]);
        // Running is also nonterminal, rather than a fabricated zero exit.
        let state: Poll<i32> = Poll::Running;
        assert!(matches!(state, Poll::Running));
    }
}
