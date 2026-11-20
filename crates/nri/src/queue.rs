//! A connection's bounded queue of payloads: the trunk's reader pushes without waiting, the connection pops (D163).

use std::collections::VecDeque;
use std::sync::PoisonError;
use std::task::{Context, Poll, Waker};

use crate::sync::Mutex;

/// How a queue ended, once its frames are popped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum End {
    /// The trunk ended between two frames.
    Clean,
    /// The trunk failed, broke the protocol, or its multiplexer was dropped.
    Aborted,
}

/// The queue holds as many payloads as it may.
#[derive(Debug)]
pub(crate) struct Full;

#[derive(Debug)]
pub(crate) struct Queue {
    capacity: usize,
    inner: Mutex<Inner>,
}

#[derive(Debug, Default)]
struct Inner {
    payloads: VecDeque<Vec<u8>>,
    end: Option<End>,
    /// The connection is dropped: payloads for it are dropped too, as for an unknown ConnID.
    detached: bool,
    /// The connection's task, waiting for a payload or the end.
    waker: Option<Waker>,
}

impl Queue {
    pub(crate) fn new(capacity: usize) -> Self {
        Self {
            capacity,
            inner: Mutex::new(Inner::default()),
        }
    }

    pub(crate) const fn capacity(&self) -> usize {
        self.capacity
    }

    /// Queues `payload`, unless the queue is full; the reader never waits for one connection, which would stall the
    /// other.
    pub(crate) fn push(&self, payload: Vec<u8>) -> Result<(), Full> {
        let mut inner = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        if inner.detached {
            return Ok(());
        }
        if inner.payloads.len() == self.capacity {
            return Err(Full);
        }
        inner.payloads.push_back(payload);
        inner.wake();
        Ok(())
    }

    /// Ends the queue, unless it has already ended: the payloads queued are still popped first.
    pub(crate) fn end(&self, end: End) {
        let mut inner = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        inner.end.get_or_insert(end);
        inner.wake();
    }

    /// Drops the payloads queued and those to come.
    pub(crate) fn detach(&self) {
        let mut inner = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        inner.detached = true;
        inner.payloads = VecDeque::new();
    }

    /// The next payload, or how the queue ended once none is left.
    pub(crate) fn poll_pop(&self, cx: &Context<'_>) -> Poll<Result<Vec<u8>, End>> {
        let mut inner = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(payload) = inner.payloads.pop_front() {
            return Poll::Ready(Ok(payload));
        }
        if let Some(end) = inner.end {
            return Poll::Ready(Err(end));
        }
        inner.waker = Some(cx.waker().clone());
        Poll::Pending
    }
}

impl Inner {
    fn wake(&mut self) {
        if let Some(waker) = self.waker.take() {
            waker.wake();
        }
    }
}
