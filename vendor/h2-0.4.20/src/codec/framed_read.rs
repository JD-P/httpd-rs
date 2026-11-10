use crate::frame::{self, Frame, Kind, Reason};
use crate::frame::{
    DEFAULT_MAX_FRAME_SIZE, DEFAULT_SETTINGS_HEADER_TABLE_SIZE, MAX_MAX_FRAME_SIZE,
};
use crate::proto::Error;

use crate::hpack;

use futures_core::Stream;

use bytes::{Buf, BytesMut};

use std::fmt;
use std::io;

use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};
use tokio::io::AsyncRead;
use tokio_util::codec::FramedRead as InnerFramedRead;
use tokio_util::codec::{Decoder, LengthDelimitedCodec, LengthDelimitedCodecError};

// 16 MB "sane default" taken from golang http2
const DEFAULT_SETTINGS_MAX_HEADER_LIST_SIZE: usize = 16 << 20;
const FRAME_WORK_BURST: u64 = 131_072;
const FRAME_WORK_REFILL_PER_SECOND: u64 = 65_536;

#[derive(Debug)]
struct WireFrameCodec {
    inner: LengthDelimitedCodec,
}

#[derive(Debug)]
struct WireHeaderError(Reason);

impl fmt::Display for WireHeaderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "HTTP/2 wire header rejected: {:?}", self.0)
    }
}

impl std::error::Error for WireHeaderError {}

impl WireFrameCodec {
    fn new() -> Self {
        let inner = LengthDelimitedCodec::builder()
            .big_endian()
            .length_field_length(3)
            .length_adjustment(9)
            .num_skip(0)
            .new_codec();
        Self { inner }
    }

    fn max_frame_length(&self) -> usize {
        self.inner.max_frame_length()
    }

    fn set_max_frame_length(&mut self, value: usize) {
        self.inner.set_max_frame_length(value);
    }
}

impl Decoder for WireFrameCodec {
    type Item = BytesMut;
    type Error = io::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        // Do not invoke LengthDelimitedCodec until the complete nine-byte head
        // has been admitted: it reserves the declared frame payload as soon as
        // it sees the three-byte length field.
        if src.len() < frame::HEADER_LEN {
            return Ok(None);
        }
        let payload_len = ((src[0] as u32) << 16) | ((src[1] as u32) << 8) | src[2] as u32;
        let stream_id = u32::from_be_bytes([src[5], src[6], src[7], src[8]]) & 0x7fff_ffff;
        let decision = vapache_verified::h2_frame_header_admit(
            src[3],
            src[4],
            stream_id,
            payload_len,
            self.max_frame_length() as u32,
        );
        let reason = match decision {
            vapache_verified::H2FrameHeaderDecision::Accept => None,
            vapache_verified::H2FrameHeaderDecision::FrameSizeError => {
                Some(Reason::FRAME_SIZE_ERROR)
            }
            vapache_verified::H2FrameHeaderDecision::ProtocolError => Some(Reason::PROTOCOL_ERROR),
        };
        if let Some(reason) = reason {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                WireHeaderError(reason),
            ));
        }
        self.inner.decode(src)
    }
}

#[derive(Debug)]
struct FrameWorkBudget {
    available: u64,
    last_refill: Instant,
}

impl FrameWorkBudget {
    fn new() -> Self {
        Self {
            available: FRAME_WORK_BURST,
            last_refill: Instant::now(),
        }
    }

    fn consume(&mut self, kind: vapache_verified::H2WireFrameKind, payload_len: u32) -> bool {
        let now = Instant::now();
        let seconds = now.saturating_duration_since(self.last_refill).as_secs();
        let transition = vapache_verified::h2_frame_work_step(
            self.available,
            seconds,
            kind,
            payload_len,
            FRAME_WORK_BURST,
            FRAME_WORK_REFILL_PER_SECOND,
        );
        self.available = transition.available;
        if transition.refill_seconds != 0 {
            self.last_refill = self
                .last_refill
                .checked_add(Duration::from_secs(transition.refill_seconds))
                .unwrap_or(now);
        }
        transition.admitted
    }
}

#[derive(Debug)]
pub struct FramedRead<T> {
    inner: InnerFramedRead<T, WireFrameCodec>,

    decoder: FrameDecoder,
}

#[derive(Debug)]
struct FrameDecoder {
    // hpack decoder state
    hpack: hpack::Decoder,

    max_header_list_size: usize,

    max_continuation_frames: usize,

    partial: Option<Partial>,

    frame_work_budget: FrameWorkBudget,
}

/// Partially loaded headers frame
#[derive(Debug)]
struct Partial {
    /// Empty frame
    frame: Continuable,

    /// Partial header payload
    buf: BytesMut,

    /// Verified cumulative sequencing/size state for this partial block.
    header_block_state: vapache_verified::H2HeaderBlockState,
}

#[derive(Debug)]
enum Continuable {
    Headers(frame::Headers),
    PushPromise(frame::PushPromise),
}

impl<T> FramedRead<T> {
    pub fn new(io: T) -> FramedRead<T> {
        let inner = InnerFramedRead::new(io, WireFrameCodec::new());
        let decoder = FrameDecoder::new(inner.decoder().max_frame_length());
        FramedRead { inner, decoder }
    }

    pub fn get_ref(&self) -> &T {
        self.inner.get_ref()
    }

    pub fn get_mut(&mut self) -> &mut T {
        self.inner.get_mut()
    }

    /// Returns the current max frame size setting
    #[inline]
    pub fn max_frame_size(&self) -> usize {
        self.inner.decoder().max_frame_length()
    }

    /// Updates the max frame size setting.
    ///
    /// Must be within 16,384 and 16,777,215.
    #[inline]
    pub fn set_max_frame_size(&mut self, val: usize) {
        assert!(DEFAULT_MAX_FRAME_SIZE as usize <= val && val <= MAX_MAX_FRAME_SIZE as usize);
        self.inner.decoder_mut().set_max_frame_length(val);
        // Update max CONTINUATION frames too, since its based on this
        self.decoder.set_max_frame_size(val);
    }

    /// Update the max header list size setting.
    #[inline]
    pub fn set_max_header_list_size(&mut self, val: usize) {
        self.decoder
            .set_max_header_list_size(val, self.max_frame_size());
    }

    /// Update the header table size setting.
    #[inline]
    pub fn set_header_table_size(&mut self, val: usize) {
        self.decoder.set_header_table_size(val);
    }
}

fn calc_max_continuation_frames(header_max: usize, frame_max: usize) -> usize {
    // At least this many frames needed to use max header list size
    let min_frames_for_list = (header_max / frame_max).max(1);
    // Some padding for imperfectly packed frames
    // 25% without floats
    let padding = min_frames_for_list >> 2;
    min_frames_for_list.saturating_add(padding).max(5)
}

impl FrameDecoder {
    fn new(max_frame_size: usize) -> Self {
        let max_header_list_size = DEFAULT_SETTINGS_MAX_HEADER_LIST_SIZE;
        FrameDecoder {
            hpack: hpack::Decoder::new(DEFAULT_SETTINGS_HEADER_TABLE_SIZE),
            max_header_list_size,
            max_continuation_frames: calc_max_continuation_frames(
                max_header_list_size,
                max_frame_size,
            ),
            partial: None,
            frame_work_budget: FrameWorkBudget::new(),
        }
    }

    fn set_max_frame_size(&mut self, val: usize) {
        self.max_continuation_frames = calc_max_continuation_frames(self.max_header_list_size, val);
    }

    fn set_max_header_list_size(&mut self, val: usize, max_frame_size: usize) {
        self.max_header_list_size = val;
        // Update max CONTINUATION frames too, since its based on this
        self.max_continuation_frames = calc_max_continuation_frames(val, max_frame_size);
    }

    fn set_header_table_size(&mut self, val: usize) {
        self.hpack.queue_size_update(val);
    }

    fn decode(&mut self, bytes: BytesMut) -> Result<Option<Frame>, Error> {
        decode_frame(self, bytes)
    }
}

/// Decodes a frame.
///
/// This function is intentionally de-generified and outlined because it is very large.
fn decode_frame(decoder: &mut FrameDecoder, mut bytes: BytesMut) -> Result<Option<Frame>, Error> {
    let span = tracing::trace_span!("FramedRead::decode_frame", offset = bytes.len());
    let _e = span.enter();

    tracing::trace!("decoding frame from {}B", bytes.len());

    // Parse the head
    let head = frame::Head::parse(&bytes);
    let kind = head.kind();
    let payload_len = (bytes.len() - frame::HEADER_LEN) as u32;
    let wire_kind = vapache_verified::h2_wire_frame_kind(bytes[3]);
    if !decoder.frame_work_budget.consume(wire_kind, payload_len) {
        proto_err!(conn: "HTTP/2 frame work budget exhausted");
        return Err(Error::library_go_away(Reason::ENHANCE_YOUR_CALM));
    }

    let idle_header_block = vapache_verified::H2HeaderBlockState {
        stream_id: 0,
        encoded_bytes: 0,
        continuation_frames: 0,
    };
    let current_header_block = decoder
        .partial
        .as_ref()
        .map(|partial| partial.header_block_state)
        .unwrap_or(idle_header_block);
    let max_continuations = u32::try_from(decoder.max_continuation_frames)
        .unwrap_or(u32::MAX)
        .saturating_add(1);
    let next_header_block = match vapache_verified::h2_header_block_step(
        current_header_block,
        bytes[3],
        bytes[4],
        u32::from(head.stream_id()),
        payload_len,
        decoder.max_header_list_size as u64,
        max_continuations,
    ) {
        vapache_verified::H2HeaderBlockDecision::Accept(next) => next,
        vapache_verified::H2HeaderBlockDecision::SequenceError => {
            proto_err!(conn: "invalid HEADERS/CONTINUATION sequence");
            return Err(Error::library_go_away(Reason::PROTOCOL_ERROR));
        }
        vapache_verified::H2HeaderBlockDecision::SizeError => {
            proto_err!(conn: "encoded header block exceeded its frame/byte budget");
            return Err(Error::library_go_away_data(
                Reason::ENHANCE_YOUR_CALM,
                "header_block_budget_exhausted",
            ));
        }
    };

    tracing::trace!(frame.kind = ?kind);

    macro_rules! header_block {
        ($frame:ident, $head:ident, $bytes:ident) => ({
            // Drop the frame header
            $bytes.advance(frame::HEADER_LEN);

            // Parse the header frame w/o parsing the payload
            let (mut frame, mut payload) = match frame::$frame::load($head, $bytes) {
                Ok(res) => res,
                Err(frame::Error::InvalidDependencyId) => {
                    proto_err!(stream: "invalid HEADERS dependency ID");
                    // A stream cannot depend on itself. An endpoint MUST
                    // treat this as a stream error (Section 5.4.2) of type
                    // `PROTOCOL_ERROR`.
                    return Err(Error::library_reset($head.stream_id(), Reason::PROTOCOL_ERROR));
                },
                Err(e) => {
                    proto_err!(conn: "failed to load frame; err={:?}", e);
                    return Err(Error::library_go_away(Reason::PROTOCOL_ERROR));
                }
            };

            let is_end_headers = frame.is_end_headers();

            // Load the HPACK encoded headers
            match frame.load_hpack(&mut payload, decoder.max_header_list_size, &mut decoder.hpack) {
                Ok(_) => {},
                Err(frame::Error::Hpack(hpack::DecoderError::NeedMore(_))) if !is_end_headers => {},
                Err(frame::Error::MalformedMessage) => {
                    let id = $head.stream_id();
                    proto_err!(stream: "malformed header block; stream={:?}", id);
                    return Err(Error::library_reset(id, Reason::PROTOCOL_ERROR));
                },
                Err(frame::Error::HeaderListWayTooLarge) => {
                    proto_err!(conn: "decoded header list size over abuse limit");
                    return Err(Error::library_go_away_data(
                        Reason::ENHANCE_YOUR_CALM,
                        "header_list_way_too_large",
                    ));
                },
                Err(e) => {
                    proto_err!(conn: "failed HPACK decoding; err={:?}", e);
                    return Err(Error::library_go_away(Reason::PROTOCOL_ERROR));
                }
            }

            if is_end_headers {
                frame.into()
            } else {
                tracing::trace!("loaded partial header block");
                // Defer returning the frame
                decoder.partial = Some(Partial {
                    frame: Continuable::$frame(frame),
                    buf: payload,
                    header_block_state: next_header_block,
                });

                return Ok(None);
            }
        });
    }

    let frame = match kind {
        Kind::Settings => {
            let res = frame::Settings::load(head, &bytes[frame::HEADER_LEN..]);

            res.map_err(|e| {
                proto_err!(conn: "failed to load SETTINGS frame; err={:?}", e);
                Error::library_go_away(Reason::PROTOCOL_ERROR)
            })?
            .into()
        }
        Kind::Ping => {
            let res = frame::Ping::load(head, &bytes[frame::HEADER_LEN..]);

            res.map_err(|e| {
                proto_err!(conn: "failed to load PING frame; err={:?}", e);
                Error::library_go_away(Reason::PROTOCOL_ERROR)
            })?
            .into()
        }
        Kind::WindowUpdate => {
            let res = frame::WindowUpdate::load(head, &bytes[frame::HEADER_LEN..]);

            res.map_err(|e| {
                proto_err!(conn: "failed to load WINDOW_UPDATE frame; err={:?}", e);
                Error::library_go_away(Reason::PROTOCOL_ERROR)
            })?
            .into()
        }
        Kind::Data => {
            bytes.advance(frame::HEADER_LEN);
            let res = frame::Data::load(head, bytes.freeze());

            // TODO: Should this always be connection level? Probably not...
            res.map_err(|e| {
                proto_err!(conn: "failed to load DATA frame; err={:?}", e);
                Error::library_go_away(Reason::PROTOCOL_ERROR)
            })?
            .into()
        }
        Kind::Headers => header_block!(Headers, head, bytes),
        Kind::Reset => {
            let res = frame::Reset::load(head, &bytes[frame::HEADER_LEN..]);
            res.map_err(|e| {
                proto_err!(conn: "failed to load RESET frame; err={:?}", e);
                Error::library_go_away(Reason::PROTOCOL_ERROR)
            })?
            .into()
        }
        Kind::GoAway => {
            let res = frame::GoAway::load(head, &bytes[frame::HEADER_LEN..]);
            res.map_err(|e| {
                proto_err!(conn: "failed to load GO_AWAY frame; err={:?}", e);
                Error::library_go_away(Reason::PROTOCOL_ERROR)
            })?
            .into()
        }
        Kind::PushPromise => header_block!(PushPromise, head, bytes),
        Kind::Priority => {
            if head.stream_id() == 0 {
                // Invalid stream identifier
                proto_err!(conn: "invalid stream ID 0");
                return Err(Error::library_go_away(Reason::PROTOCOL_ERROR));
            }

            match frame::Priority::load(head, &bytes[frame::HEADER_LEN..]) {
                Ok(frame) => frame.into(),
                Err(frame::Error::InvalidDependencyId) => {
                    // A stream cannot depend on itself. An endpoint MUST
                    // treat this as a stream error (Section 5.4.2) of type
                    // `PROTOCOL_ERROR`.
                    let id = head.stream_id();
                    proto_err!(stream: "PRIORITY invalid dependency ID; stream={:?}", id);
                    return Err(Error::library_reset(id, Reason::PROTOCOL_ERROR));
                }
                Err(e) => {
                    proto_err!(conn: "failed to load PRIORITY frame; err={:?};", e);
                    return Err(Error::library_go_away(Reason::PROTOCOL_ERROR));
                }
            }
        }
        Kind::Continuation => {
            let is_end_headers = (head.flag() & 0x4) == 0x4;

            let mut partial = match decoder.partial.take() {
                Some(partial) => partial,
                None => {
                    proto_err!(conn: "received unexpected CONTINUATION frame");
                    return Err(Error::library_go_away(Reason::PROTOCOL_ERROR));
                }
            };

            // The stream identifiers must match
            if partial.frame.stream_id() != head.stream_id() {
                proto_err!(conn: "CONTINUATION frame stream ID does not match previous frame stream ID");
                return Err(Error::library_go_away(Reason::PROTOCOL_ERROR));
            }

            // Extend the buf
            if partial.buf.is_empty() {
                partial.buf = bytes.split_off(frame::HEADER_LEN);
            } else {
                if partial.frame.is_over_size() {
                    // If there was left over bytes previously, they may be
                    // needed to continue decoding, even though we will
                    // be ignoring this frame. This is done to keep the HPACK
                    // decoder state up-to-date.
                    //
                    // Still, we need to be careful, because if a malicious
                    // attacker were to try to send a gigantic string, such
                    // that it fits over multiple header blocks, we could
                    // grow memory uncontrollably again, and that'd be a shame.
                    //
                    // Instead, we use a simple heuristic to determine if
                    // we should continue to ignore decoding, or to tell
                    // the attacker to go away.
                    if partial.buf.len() + bytes.len() > decoder.max_header_list_size {
                        proto_err!(conn: "CONTINUATION frame header block size over ignorable limit");
                        return Err(Error::library_go_away(Reason::COMPRESSION_ERROR));
                    }
                }
                partial.buf.extend_from_slice(&bytes[frame::HEADER_LEN..]);
            }

            match partial.frame.load_hpack(
                &mut partial.buf,
                decoder.max_header_list_size,
                &mut decoder.hpack,
            ) {
                Ok(_) => {}
                Err(frame::Error::Hpack(hpack::DecoderError::NeedMore(_))) if !is_end_headers => {}
                Err(frame::Error::MalformedMessage) => {
                    let id = head.stream_id();
                    proto_err!(stream: "malformed CONTINUATION frame; stream={:?}", id);
                    return Err(Error::library_reset(id, Reason::PROTOCOL_ERROR));
                }
                Err(frame::Error::HeaderListWayTooLarge) => {
                    proto_err!(conn: "decoded CONTINUATION header list size over abuse limit");
                    return Err(Error::library_go_away_data(
                        Reason::ENHANCE_YOUR_CALM,
                        "header_list_way_too_large",
                    ));
                }
                Err(e) => {
                    proto_err!(conn: "failed HPACK decoding; err={:?}", e);
                    return Err(Error::library_go_away(Reason::PROTOCOL_ERROR));
                }
            }

            if is_end_headers {
                partial.frame.into()
            } else {
                partial.header_block_state = next_header_block;
                decoder.partial = Some(partial);
                return Ok(None);
            }
        }
        Kind::Unknown => {
            // Unknown frames are ignored
            return Ok(None);
        }
    };

    Ok(Some(frame))
}

impl<T> Stream for FramedRead<T>
where
    T: AsyncRead + Unpin,
{
    type Item = Result<Frame, Error>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let span = tracing::trace_span!("FramedRead::poll_next");
        let _e = span.enter();
        loop {
            tracing::trace!("poll");
            let bytes = match ready!(Pin::new(&mut self.inner).poll_next(cx)) {
                Some(Ok(bytes)) => bytes,
                Some(Err(e)) => return Poll::Ready(Some(Err(map_err(e)))),
                None => return Poll::Ready(None),
            };

            tracing::trace!(read.bytes = bytes.len());
            if let Some(frame) = self.decoder.decode(bytes)? {
                tracing::debug!(?frame, "received");
                return Poll::Ready(Some(Ok(frame)));
            }
        }
    }
}

fn map_err(err: io::Error) -> Error {
    if let io::ErrorKind::InvalidData = err.kind() {
        if let Some(custom) = err.get_ref() {
            if let Some(header) = custom.downcast_ref::<WireHeaderError>() {
                return Error::library_go_away(header.0);
            }
            if custom.is::<LengthDelimitedCodecError>() {
                return Error::library_go_away(Reason::FRAME_SIZE_ERROR);
            }
        }
    }
    err.into()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wire_head(payload_len: u32, kind: u8, flags: u8, stream_id: u32) -> BytesMut {
        let mut bytes = BytesMut::with_capacity(frame::HEADER_LEN + payload_len as usize);
        bytes.extend_from_slice(&[
            (payload_len >> 16) as u8,
            (payload_len >> 8) as u8,
            payload_len as u8,
            kind,
            flags,
        ]);
        bytes.extend_from_slice(&(stream_id & 0x7fff_ffff).to_be_bytes());
        bytes
    }

    #[test]
    fn fixed_frame_shape_is_rejected_before_payload_reservation() {
        let mut codec = WireFrameCodec::new();
        codec.set_max_frame_length(frame::DEFAULT_MAX_FRAME_SIZE as usize);
        let mut oversized_ping = wire_head(frame::DEFAULT_MAX_FRAME_SIZE, 6, 0, 0);
        let capacity = oversized_ping.capacity();

        let error = codec.decode(&mut oversized_ping).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(oversized_ping.capacity(), capacity);
        assert_eq!(oversized_ping.len(), frame::HEADER_LEN);
    }

    #[test]
    fn admitted_fixed_frame_is_delimited_normally() {
        let mut codec = WireFrameCodec::new();
        codec.set_max_frame_length(frame::DEFAULT_MAX_FRAME_SIZE as usize);
        let mut ping = wire_head(8, 6, 0, 0);
        ping.extend_from_slice(&[0; 8]);

        let decoded = codec.decode(&mut ping).unwrap().unwrap();
        assert_eq!(decoded.len(), frame::HEADER_LEN + 8);
        assert!(ping.is_empty());
    }

    #[test]
    fn unified_work_budget_charges_unknown_frames() {
        let mut budget = FrameWorkBudget {
            available: 1,
            last_refill: Instant::now(),
        };
        assert!(!budget.consume(vapache_verified::H2WireFrameKind::Unknown, 0));
        assert_eq!(budget.available, 1);
    }

    #[test]
    fn malformed_partial_header_does_not_orphan_sequence_state() {
        let mut decoder = FrameDecoder::new(frame::DEFAULT_MAX_FRAME_SIZE as usize);
        let mut invalid = wire_head(5, 1, 0x20, 1);
        invalid.extend_from_slice(&1u32.to_be_bytes());
        invalid.extend_from_slice(&[0]);

        assert!(decoder.decode(invalid).is_err());
        assert!(decoder.partial.is_none());

        let mut ping = wire_head(8, 6, 0, 0);
        ping.extend_from_slice(&[0; 8]);
        assert!(decoder.decode(ping).unwrap().is_some());
    }

    #[test]
    fn verified_continuation_state_bounds_sequence_and_bytes() {
        let idle = vapache_verified::H2HeaderBlockState {
            stream_id: 0,
            encoded_bytes: 0,
            continuation_frames: 0,
        };
        let started = match vapache_verified::h2_header_block_step(idle, 1, 0, 1, 8, 16, 2) {
            vapache_verified::H2HeaderBlockDecision::Accept(next) => next,
            other => panic!("unexpected transition: {other:?}"),
        };
        assert_eq!(started.stream_id, 1);
        assert!(matches!(
            vapache_verified::h2_header_block_step(started, 9, 4, 3, 1, 16, 2),
            vapache_verified::H2HeaderBlockDecision::SequenceError
        ));
        assert!(matches!(
            vapache_verified::h2_header_block_step(started, 9, 4, 1, 9, 16, 2),
            vapache_verified::H2HeaderBlockDecision::SizeError
        ));
        assert!(matches!(
            vapache_verified::h2_header_block_step(started, 9, 4, 1, 8, 16, 2),
            vapache_verified::H2HeaderBlockDecision::Accept(vapache_verified::H2HeaderBlockState {
                stream_id: 0,
                ..
            })
        ));
    }
}

// ===== impl Continuable =====

impl Continuable {
    fn stream_id(&self) -> frame::StreamId {
        match *self {
            Continuable::Headers(ref h) => h.stream_id(),
            Continuable::PushPromise(ref p) => p.stream_id(),
        }
    }

    fn is_over_size(&self) -> bool {
        match *self {
            Continuable::Headers(ref h) => h.is_over_size(),
            Continuable::PushPromise(ref p) => p.is_over_size(),
        }
    }

    fn load_hpack(
        &mut self,
        src: &mut BytesMut,
        max_header_list_size: usize,
        decoder: &mut hpack::Decoder,
    ) -> Result<(), frame::Error> {
        match *self {
            Continuable::Headers(ref mut h) => h.load_hpack(src, max_header_list_size, decoder),
            Continuable::PushPromise(ref mut p) => p.load_hpack(src, max_header_list_size, decoder),
        }
    }
}

impl<T> From<Continuable> for Frame<T> {
    fn from(cont: Continuable) -> Self {
        match cont {
            Continuable::Headers(mut headers) => {
                headers.set_end_headers();
                headers.into()
            }
            Continuable::PushPromise(mut push) => {
                push.set_end_headers();
                push.into()
            }
        }
    }
}
