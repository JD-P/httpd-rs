//! SHA-1 compatibility operations consolidated on the already-required Ring
//! provider. SHA-1 remains available only for legacy protocol formats such as
//! OCSP CertID, WebSocket acceptance, and Apache password records.

const OUTPUT_LEN: usize = 20;

pub(crate) struct Context(ring::digest::Context);

impl Context {
    pub(crate) fn new() -> Self {
        Self(ring::digest::Context::new(
            &ring::digest::SHA1_FOR_LEGACY_USE_ONLY,
        ))
    }

    pub(crate) fn update(&mut self, input: &[u8]) {
        self.0.update(input);
    }

    pub(crate) fn finish(self) -> [u8; OUTPUT_LEN] {
        copy_digest(self.0.finish())
    }
}

pub(crate) fn digest(input: impl AsRef<[u8]>) -> [u8; OUTPUT_LEN] {
    copy_digest(ring::digest::digest(
        &ring::digest::SHA1_FOR_LEGACY_USE_ONLY,
        input.as_ref(),
    ))
}

fn copy_digest(digest: ring::digest::Digest) -> [u8; OUTPUT_LEN] {
    let mut output = [0; OUTPUT_LEN];
    output.copy_from_slice(digest.as_ref());
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_shot_and_incremental_match_the_sha1_vector() {
        let expected = [
            0xa9, 0x99, 0x3e, 0x36, 0x47, 0x06, 0x81, 0x6a, 0xba, 0x3e, 0x25, 0x71, 0x78, 0x50,
            0xc2, 0x6c, 0x9c, 0xd0, 0xd8, 0x9d,
        ];
        assert_eq!(digest(b"abc"), expected);

        let mut context = Context::new();
        context.update(b"a");
        context.update(b"bc");
        assert_eq!(context.finish(), expected);
    }
}
