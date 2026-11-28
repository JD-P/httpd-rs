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
        // Exercise the total verified preflight kernels independently of the
        // concrete parser.  This keeps short/truncated inputs and every first
        // octet family visible even when the higher-level decoder rejects an
        // earlier field.
        let _ = httpd_rs_verified::h2_parse_wire_header(data_);
        let _ = httpd_rs_verified::hpack_string_preflight(data_);
        if let Some(&first) = data_.first() {
            let representation = httpd_rs_verified::hpack_representation(first);
            let _ = httpd_rs_verified::hpack_block_step(
                httpd_rs_verified::HpackBlockPhase::Start,
                representation,
            );
            let _ = httpd_rs_verified::hpack_block_step(
                httpd_rs_verified::HpackBlockPhase::Fields,
                representation,
            );
        }
        let _ = httpd_rs_verified::hpack_huffman_decode_bounds(0, data_.len());

        // Cover both httpd-rs's stateless policy and the fork's largest
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
            let _ = httpd_rs_verified::hpack_decode_integer(data_, prefix);
        }

        // A CONTINUATION frame may split an HPACK representation at any byte.
        // Whenever the complete block is valid, decoding it across a
        // deterministic adversarial split must produce the same fields.  In
        // particular this covers the persistent size-update phase that is
        // easy to accidentally reset at a physical frame boundary.
        if !data_.is_empty() {
            let split = usize::from(data_[0]) % (data_.len() + 1);
            assert_split_equivalent(data_, split);
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

    fn assert_split_equivalent(data: &[u8], split: usize) {
        let mut whole_decoder = hpack::Decoder::new(hpack::MAX_DYNAMIC_TABLE_SIZE);
        let mut whole_buf = BytesMut::from(data);
        let mut whole_headers = Vec::new();
        let whole = whole_decoder.decode(&mut Cursor::new(&mut whole_buf), |header| {
            whole_headers.push(header);
            ControlFlow::Continue(())
        });
        if whole.is_err() {
            return;
        }

        let mut split_decoder = hpack::Decoder::new(hpack::MAX_DYNAMIC_TABLE_SIZE);
        let mut split_buf = BytesMut::from(&data[..split]);
        let mut split_headers = Vec::new();
        let first =
            split_decoder.decode_fragment(&mut Cursor::new(&mut split_buf), false, |header| {
                split_headers.push(header);
                ControlFlow::Continue(())
            });
        assert!(matches!(
            first,
            Ok(()) | Err(hpack::DecoderError::NeedMore(_))
        ));

        split_buf.extend_from_slice(&data[split..]);
        let second =
            split_decoder.decode_fragment(&mut Cursor::new(&mut split_buf), true, |header| {
                split_headers.push(header);
                ControlFlow::Continue(())
            });
        assert!(second.is_ok());
        assert_eq!(split_headers, whole_headers);
    }

    fn encode(e: &mut hpack::Encoder, hdrs: Vec<hpack::Header<Option<HeaderName>>>) -> BytesMut {
        let mut dst = BytesMut::with_capacity(1024);
        e.encode(hdrs, &mut dst);
        dst
    }
}
