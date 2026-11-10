#[cfg(any(fuzzing, feature = "fuzzing"))]
/// Fuzzing adapters for internal HPACK parsing and encoding.
pub mod fuzz_logic {
    use crate::hpack;
    use bytes::BytesMut;
    use http::header::HeaderName;
    use std::io::Cursor;
    use std::ops::ControlFlow;

    /// Exercise the HPACK decoder and, for valid textual methods, the encoder.
    pub fn fuzz_hpack(data_: &[u8]) {
        // Cover both Vapache's stateless policy and the fork's largest
        // explicitly supported dynamic table. This keeps the opt-in table
        // implementation under adversarial coverage even though production
        // defaults to zero.
        for table_size in [0, hpack::MAX_DYNAMIC_TABLE_SIZE] {
            let mut decoder_ = hpack::Decoder::new(table_size);
            let mut buf = BytesMut::new();
            buf.extend(data_);
            let _dec_res =
                decoder_.decode(&mut Cursor::new(&mut buf), |_h| ControlFlow::Continue(()));
        }

        // Exercise every integer prefix directly so malformed continuation
        // families cannot hide behind representation dispatch.
        for prefix in 1..=8 {
            let _ = vapache_verified::hpack_decode_integer(data_, prefix);
        }

        if let Ok(s) = std::str::from_utf8(data_) {
            if let Ok(h) = http::Method::from_bytes(s.as_bytes()) {
                let m_ = hpack::Header::Method(h);
                let mut stateless = hpack::Encoder::new(0, 0);
                let _res = encode(&mut stateless, vec![m_.clone()]);

                // Repetition drives insert then exact dynamic lookup.
                let mut dynamic = hpack::Encoder::new(4096, 0);
                let _res = encode(&mut dynamic, vec![m_.clone(), m_]);
            }
        }
    }

    fn encode(e: &mut hpack::Encoder, hdrs: Vec<hpack::Header<Option<HeaderName>>>) -> BytesMut {
        let mut dst = BytesMut::with_capacity(1024);
        e.encode(&mut hdrs.into_iter(), &mut dst);
        dst
    }
}
