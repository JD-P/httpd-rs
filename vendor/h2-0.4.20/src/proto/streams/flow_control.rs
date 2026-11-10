use crate::frame::Reason;
use crate::proto::WindowSize;

use std::fmt;

// We don't want to send WINDOW_UPDATE frames for tiny changes, but instead
// aggregate them when the changes are significant. Many implementations do
// this by keeping a "ratio" of the update version the allowed window size.
//
// While some may wish to represent this ratio as percentage, using a f32,
// we skip having to deal with float math and stick to integers. To do so,
// the "ratio" is represented by 2 i32s, split into the numerator and
// denominator. For example, a 50% ratio is simply represented as 1/2.
//
// An example applying this ratio: If a stream has an allowed window size of
// 100 bytes, WINDOW_UPDATE frames are scheduled when the unclaimed change
// becomes greater than 1/2, or 50 bytes.
const UNCLAIMED_NUMERATOR: i32 = 1;
const UNCLAIMED_DENOMINATOR: i32 = 2;

#[test]
#[allow(clippy::assertions_on_constants)]
fn sanity_unclaimed_ratio() {
    assert!(UNCLAIMED_NUMERATOR < UNCLAIMED_DENOMINATOR);
    assert!(UNCLAIMED_NUMERATOR >= 0);
    assert!(UNCLAIMED_DENOMINATOR > 0);
}

#[derive(Copy, Clone, Debug)]
pub struct FlowControl {
    /// Window the peer knows about.
    ///
    /// This can go negative if a SETTINGS_INITIAL_WINDOW_SIZE is received.
    ///
    /// For example, say the peer sends a request and uses 32kb of the window.
    /// We send a SETTINGS_INITIAL_WINDOW_SIZE of 16kb. The peer has to adjust
    /// its understanding of the capacity of the window, and that would be:
    ///
    /// ```notrust
    /// default (64kb) - used (32kb) - settings_diff (64kb - 16kb): -16kb
    /// ```
    window_size: Window,

    /// Window that we know about.
    ///
    /// This can go negative if a user declares a smaller target window than
    /// the peer knows about.
    available: Window,
}

impl FlowControl {
    pub fn new() -> FlowControl {
        FlowControl {
            window_size: Window(0),
            available: Window(0),
        }
    }

    /// Returns the window size as known by the peer
    pub fn window_size(&self) -> WindowSize {
        self.window_size.as_size()
    }

    /// Returns the window size available to the consumer
    pub fn available(&self) -> Window {
        self.available
    }

    /// Returns true if there is unavailable window capacity
    pub fn has_unavailable(&self) -> bool {
        if self.window_size < 0 {
            return false;
        }

        self.window_size > self.available
    }

    pub fn claim_capacity(&mut self, capacity: WindowSize) -> Result<(), Reason> {
        self.available.decrease_by(capacity)
    }

    pub fn assign_capacity(&mut self, capacity: WindowSize) -> Result<(), Reason> {
        self.available.increase_by(capacity)
    }

    /// If a WINDOW_UPDATE frame should be sent, returns a positive number
    /// representing the increment to be used.
    ///
    /// If there is no available bytes to be reclaimed, or the number of
    /// available bytes does not reach the threshold, this returns `None`.
    ///
    /// This represents pending outbound WINDOW_UPDATE frames.
    pub fn unclaimed_capacity(&self) -> Option<WindowSize> {
        let available = self.available;

        if self.window_size >= available {
            return None;
        }

        let unclaimed = available.0 - self.window_size.0;
        let threshold = self.window_size.0 / UNCLAIMED_DENOMINATOR * UNCLAIMED_NUMERATOR;

        if unclaimed < threshold {
            None
        } else {
            Some(unclaimed as WindowSize)
        }
    }

    /// Increase the window size.
    ///
    /// This is called after receiving a WINDOW_UPDATE frame
    pub fn inc_window(&mut self, sz: WindowSize) -> Result<(), Reason> {
        let next = self.window_size.add(sz)?;

        tracing::trace!(
            "inc_window; sz={}; old={}; new={}",
            sz,
            self.window_size,
            next
        );

        self.window_size = next;
        Ok(())
    }

    /// Decrement the send-side window size.
    ///
    /// This is called after receiving a SETTINGS frame with a lower
    /// INITIAL_WINDOW_SIZE value.
    pub fn dec_send_window(&mut self, sz: WindowSize) -> Result<(), Reason> {
        tracing::trace!(
            "dec_window; sz={}; window={}, available={}",
            sz,
            self.window_size,
            self.available
        );
        // ~~This should not be able to overflow `window_size` from the bottom.~~ wrong. it can.
        self.window_size.decrease_by(sz)?;
        Ok(())
    }

    /// Decrement the recv-side window size.
    ///
    /// This is called after receiving a SETTINGS ACK frame with a lower
    /// INITIAL_WINDOW_SIZE value.
    pub fn dec_recv_window(&mut self, sz: WindowSize) -> Result<(), Reason> {
        tracing::trace!(
            "dec_recv_window; sz={}; window={}, available={}",
            sz,
            self.window_size,
            self.available
        );
        // This should not be able to overflow `window_size` from the bottom.
        self.window_size.decrease_by(sz)?;
        self.available.decrease_by(sz)?;
        Ok(())
    }

    /// Decrements the window reflecting data has actually been sent. The caller
    /// must ensure that the window has capacity.
    pub fn send_data(&mut self, sz: WindowSize) -> Result<(), Reason> {
        tracing::trace!(
            "send_data; sz={}; window={}; available={}",
            sz,
            self.window_size,
            self.available
        );

        // If send size is zero it's meaningless to update flow control window
        if sz > 0 {
            // Ensure that the argument is correct
            assert!(self.window_size.0 >= sz as i32);

            // Update values
            self.window_size.decrease_by(sz)?;
            self.available.decrease_by(sz)?;
        }
        Ok(())
    }
}

/// The current capacity of a flow-controlled Window.
///
/// This number can go negative when either side has used a certain amount
/// of capacity when the other side advertises a reduction in size.
///
/// This type tries to centralize the knowledge of addition and subtraction
/// to this capacity, instead of having integer casts throughout the source.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd)]
pub struct Window(i32);

impl Window {
    fn verified_encoding(&self) -> u64 {
        (i64::from(self.0) - i64::from(i32::MIN)) as u64
    }

    fn from_verified_encoding(encoded: u64) -> Self {
        assert!(encoded <= u64::from(u32::MAX));
        let value = encoded as i64 + i64::from(i32::MIN);
        assert!(value >= i64::from(i32::MIN) && value <= i64::from(i32::MAX));
        Self(value as i32)
    }

    pub fn as_size(&self) -> WindowSize {
        if self.0 < 0 {
            0
        } else {
            self.0 as WindowSize
        }
    }

    pub fn checked_size(&self) -> WindowSize {
        assert!(self.0 >= 0, "negative Window");
        self.0 as WindowSize
    }

    pub fn decrease_by(&mut self, other: WindowSize) -> Result<(), Reason> {
        let encoded = vapache_verified::h2_signed_window_decrease(self.verified_encoding(), other)
            .ok_or(Reason::FLOW_CONTROL_ERROR)?;
        *self = Self::from_verified_encoding(encoded);
        Ok(())
    }

    pub fn increase_by(&mut self, other: WindowSize) -> Result<(), Reason> {
        let other = self.add(other)?;
        self.0 = other.0;
        Ok(())
    }

    pub fn add(&self, other: WindowSize) -> Result<Self, Reason> {
        let encoded = vapache_verified::h2_signed_window_increase(self.verified_encoding(), other)
            .ok_or(Reason::FLOW_CONTROL_ERROR)?;
        Ok(Self::from_verified_encoding(encoded))
    }
}

#[cfg(test)]
mod verified_window_tests {
    use super::*;

    #[test]
    fn signed_window_bounds_fail_closed_without_mutation() {
        let mut minimum = Window(i32::MIN);
        assert_eq!(minimum.decrease_by(1), Err(Reason::FLOW_CONTROL_ERROR));
        assert_eq!(minimum, Window(i32::MIN));

        let maximum = Window(i32::MAX);
        assert_eq!(maximum.add(1), Err(Reason::FLOW_CONTROL_ERROR));
        assert_eq!(maximum, Window(i32::MAX));

        let mut crossed = Window(0);
        crossed.decrease_by(i32::MAX as u32).unwrap();
        assert_eq!(crossed, Window(-i32::MAX));
        crossed.increase_by(i32::MAX as u32).unwrap();
        assert_eq!(crossed, Window(0));
    }
}

impl PartialEq<usize> for Window {
    fn eq(&self, other: &usize) -> bool {
        if self.0 < 0 {
            false
        } else {
            (self.0 as usize).eq(other)
        }
    }
}

impl PartialOrd<usize> for Window {
    fn partial_cmp(&self, other: &usize) -> Option<::std::cmp::Ordering> {
        if self.0 < 0 {
            Some(::std::cmp::Ordering::Less)
        } else {
            (self.0 as usize).partial_cmp(other)
        }
    }
}

impl fmt::Display for Window {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

impl From<Window> for isize {
    fn from(w: Window) -> isize {
        w.0 as isize
    }
}
