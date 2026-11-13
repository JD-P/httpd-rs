mod decoder;
mod encoder;
pub(crate) mod header;
pub(crate) mod huffman;
mod table;

#[cfg(test)]
mod test;

pub use self::decoder::{Decoder, DecoderError, NeedMore};
pub use self::encoder::Encoder;
pub use self::header::{BytesStr, Header};

/// Fork-wide resource ceiling for explicitly enabled HPACK dynamic tables.
/// httpd-rs uses zero; this bound protects other/future callers of the fork.
pub(crate) const MAX_DYNAMIC_TABLE_SIZE: usize = 64 * 1024;
