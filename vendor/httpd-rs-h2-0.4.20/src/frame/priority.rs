use crate::frame::*;

#[derive(Debug, Eq, PartialEq)]
pub struct Priority {
    stream_id: StreamId,
    dependency: StreamDependency,
}

#[derive(Debug, Eq, PartialEq)]
pub struct StreamDependency {
    /// The ID of the stream dependency target
    dependency_id: StreamId,

    /// The weight for the stream. The value exposed (and set) here is always in
    /// the range [0, 255], instead of [1, 256] (as defined in section 5.3.2.)
    /// so that the value fits into a `u8`.
    weight: u8,

    /// True if the stream dependency is exclusive.
    is_exclusive: bool,
}

impl Priority {
    pub fn load(head: Head, payload: &[u8]) -> Result<Self, Error> {
        let dependency = StreamDependency::load(payload)?;

        if dependency.dependency_id() == head.stream_id() {
            return Err(Error::InvalidDependencyId);
        }

        Ok(Priority {
            stream_id: head.stream_id(),
            dependency,
        })
    }

    pub fn encode<B: bytes::BufMut>(&self, dst: &mut B) {
        Head::new(Kind::Priority, 0, self.stream_id).encode(5, dst);
        self.dependency.encode(dst);
    }
}

impl<B> From<Priority> for Frame<B> {
    fn from(src: Priority) -> Self {
        Frame::Priority(src)
    }
}

// ===== impl StreamDependency =====

impl StreamDependency {
    pub fn new(dependency_id: StreamId, weight: u8, is_exclusive: bool) -> Self {
        StreamDependency {
            dependency_id,
            weight,
            is_exclusive,
        }
    }

    pub fn load(src: &[u8]) -> Result<Self, Error> {
        if src.len() != 5 {
            return Err(Error::InvalidPayloadLength);
        }

        // Parse the stream ID and exclusive flag
        let (dependency_id, is_exclusive) = StreamId::parse(&src[..4]);

        // Read the weight
        let weight = src[4];

        Ok(StreamDependency::new(dependency_id, weight, is_exclusive))
    }

    pub fn dependency_id(&self) -> StreamId {
        self.dependency_id
    }

    fn encode<B: bytes::BufMut>(&self, dst: &mut B) {
        let mut dependency: u32 = self.dependency_id.into();
        if self.is_exclusive {
            dependency |= 0x8000_0000;
        }
        dst.put_u32(dependency);
        dst.put_u8(self.weight);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::BytesMut;

    #[test]
    fn priority_encode_round_trips_exclusive_dependency_and_weight() {
        let priority = Priority {
            stream_id: StreamId::from(3),
            dependency: StreamDependency::new(StreamId::from(1), 255, true),
        };
        let mut wire = BytesMut::new();
        priority.encode(&mut wire);

        assert_eq!(wire.len(), HEADER_LEN + 5);
        let head = Head::parse(&wire[..HEADER_LEN]);
        assert_eq!(head.kind(), Kind::Priority);
        assert_eq!(head.stream_id(), StreamId::from(3));
        assert_eq!(Priority::load(head, &wire[HEADER_LEN..]).unwrap(), priority);
    }
}
