//! A connection's bounded queue of payloads: the trunk's reader pushes without waiting, the connection pops (D163).
//! Payloads read are handed back, and the reader fills them again (D107).

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

/// The most payloads read a queue keeps for the reader to fill again: one being read, one being filled.
const SPARES: usize = 2;
/// The largest payload a queue keeps: a few frames of requests, not a whole list of containers (D163).
const SPARE_MAX: usize = 64 << 10;

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
    /// Payloads read, emptied, for [`Queue::spare`].
    spares: Vec<Vec<u8>>,
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

    /// An empty buffer for the next payload: one read and handed back when there is one.
    pub(crate) fn spare(&self) -> Vec<u8> {
        let mut inner = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        inner.spares.pop().unwrap_or_default()
    }

    /// Keeps `payload`, read, for [`Self::spare`], unless the queue keeps enough, or it holds no buffer or one too large
    /// to keep.
    pub(crate) fn recycle(&self, mut payload: Vec<u8>) {
        if !(1..=SPARE_MAX).contains(&payload.capacity()) {
            return;
        }
        payload.clear();
        let mut inner = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        if inner.spares.len() < SPARES {
            inner.spares.reserve_exact(SPARES);
            inner.spares.push(payload);
        }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_payload_read_is_filled_again_unless_it_holds_nothing_or_too_much_or_is_one_too_many() {
        let queue = Queue::new(4);
        assert_eq!(queue.spare().capacity(), 0, "no payload read yet");
        let payload = vec![1; 10];
        let buffer = payload.as_ptr();
        queue.recycle(payload);
        let spare = queue.spare();
        assert_eq!(spare, []);
        assert_eq!(spare.as_ptr(), buffer, "the buffer read is filled again");
        queue.recycle(Vec::new());
        queue.recycle(vec![0; SPARE_MAX + 1]);
        assert_eq!(queue.spare().capacity(), 0);
        for _ in 0..=SPARES {
            queue.recycle(vec![0; SPARE_MAX]);
        }
        let kept = std::iter::from_fn(|| Some(queue.spare()))
            .take_while(|spare| spare.capacity() > 0)
            .count();
        assert_eq!(kept, SPARES);
    }
}
