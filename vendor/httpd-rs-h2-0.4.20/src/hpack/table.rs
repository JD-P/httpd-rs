use super::Header;

use http::header;
use http::method::Method;

use std::collections::VecDeque;

/// HPACK encoder table
///
/// Entries are kept newest-first, exactly like the RFC address space. The
/// previous implementation layered truncated FNV hashing, wrapping relative
/// indices, Robin Hood probing, and linked same-name chains over this small
/// bounded table. A linear walk is deterministic, collision-free, and makes
/// the storage order identical to the wire-index order.
#[derive(Debug)]
pub struct Table {
    slots: VecDeque<Header>,
    // Size is in bytes
    size: usize,
    max_size: usize,
}

#[derive(Debug)]
pub enum Index {
    // The header is already fully indexed
    Indexed(usize, Header),

    // The name is indexed, but not the value
    Name(usize, Header),

    // The full header has been inserted into the table.
    Inserted(usize),

    // Only the value has been inserted (hpack table idx, slots idx)
    InsertedValue(usize, usize),

    // The header is not indexed by this table
    NotIndexed(Header),
}

impl Table {
    pub fn new(max_size: usize, capacity: usize) -> Table {
        Table {
            slots: VecDeque::with_capacity(capacity),
            size: 0,
            max_size,
        }
    }

    pub fn max_size(&self) -> usize {
        self.max_size
    }

    /// Gets the header stored in the table
    pub fn resolve<'a>(&'a self, index: &'a Index) -> &'a Header {
        use self::Index::*;

        match *index {
            Indexed(_, ref h) => h,
            Name(_, ref h) => h,
            Inserted(idx) => &self.slots[idx],
            InsertedValue(_, idx) => &self.slots[idx],
            NotIndexed(ref h) => h,
        }
    }

    pub fn resolve_idx(&self, index: &Index) -> usize {
        use self::Index::*;

        match *index {
            Indexed(idx, ..) => idx,
            Name(idx, ..) => idx,
            Inserted(idx) => dynamic_index(idx, self.slots.len()),
            InsertedValue(_name_idx, slot_idx) => dynamic_index(slot_idx, self.slots.len()),
            NotIndexed(_) => panic!("cannot resolve index"),
        }
    }

    /// Index the header in the HPACK table.
    pub fn index(&mut self, header: Header) -> Index {
        // Check the static table
        let statik = index_static(&header);

        // Don't index certain headers. This logic is borrowed from nghttp2.
        if header.skip_value_index() {
            // Right now, if this is true, the header name is always in the
            // static table. At some point in the future, this might not be true
            // and this logic will need to be updated.
            debug_assert!(statik.is_some(), "skip_value_index requires a static name",);
            return Index::new(statik, header);
        }

        // If the header is already indexed by the static table, return that
        if let Some((n, true)) = statik {
            return Index::Indexed(n, header);
        }

        self.index_dynamic(header, statik)
    }

    fn index_dynamic(&mut self, header: Header, statik: Option<(usize, bool)>) -> Index {
        debug_assert!(self.valid());

        let mut dynamic_name = None;
        for (position, entry) in self.slots.iter().enumerate() {
            if entry.name() == header.name() {
                let wire_index = dynamic_index(position, self.slots.len());
                if entry.value_eq(&header) {
                    return Index::Indexed(wire_index, header);
                }
                if dynamic_name.is_none() {
                    dynamic_name = Some(wire_index);
                }
            }
        }

        let name_index = statik.map(|(index, _)| index).or(dynamic_name);
        if header.is_sensitive() {
            return match name_index {
                Some(index) => Index::Name(index, header),
                None => Index::NotIndexed(header),
            };
        }

        let entry_size = header.len();
        // nghttp2's 3/4-table heuristic avoids churning the entire table for
        // one large field. Express it without multiplication overflow.
        let index_limit = self.max_size - self.max_size / 4;
        if entry_size > index_limit {
            return match name_index {
                Some(index) => Index::Name(index, header),
                None => Index::NotIndexed(header),
            };
        }

        self.insert(header);
        debug_assert!(self.valid());
        match name_index {
            Some(index) => Index::InsertedValue(index, 0),
            None => Index::Inserted(0),
        }
    }

    fn insert(&mut self, header: Header) {
        let incoming = header.len();
        loop {
            match httpd_rs_verified::hpack_table_insert_action(
                self.size,
                self.max_size,
                incoming,
                !self.slots.is_empty(),
            ) {
                httpd_rs_verified::HpackTableInsertAction::Insert { new_size } => {
                    self.size = new_size;
                    self.slots.push_front(header);
                    return;
                }
                httpd_rs_verified::HpackTableInsertAction::Evict => self.evict_oldest(),
                httpd_rs_verified::HpackTableInsertAction::Clear => {
                    self.slots.clear();
                    self.size = 0;
                    return;
                }
            }
        }
    }

    pub fn resize(&mut self, size: usize) {
        self.max_size = size;
        loop {
            match httpd_rs_verified::hpack_table_resize_action(
                self.size,
                self.max_size,
                !self.slots.is_empty(),
            ) {
                httpd_rs_verified::HpackTableResizeAction::Done => break,
                httpd_rs_verified::HpackTableResizeAction::Evict => self.evict_oldest(),
            }
        }
        debug_assert!(self.valid());
    }

    fn evict_oldest(&mut self) {
        let entry = self
            .slots
            .pop_back()
            .expect("verified HPACK transition requested eviction from a non-empty table");
        self.size = httpd_rs_verified::hpack_table_after_evict(self.size, entry.len())
            .expect("HPACK table accounting diverged from its entries");
    }

    fn valid(&self) -> bool {
        self.size <= self.max_size
            && self
                .slots
                .iter()
                .try_fold(0usize, |size, entry| size.checked_add(entry.len()))
                == Some(self.size)
    }
}

#[cfg(test)]
impl Table {
    /// Returns the number of headers in the table
    pub fn len(&self) -> usize {
        self.slots.len()
    }

    /// Returns the table size
    pub fn size(&self) -> usize {
        self.size
    }
}

impl Index {
    fn new(v: Option<(usize, bool)>, e: Header) -> Index {
        match v {
            None => Index::NotIndexed(e),
            Some((n, true)) => Index::Indexed(n, e),
            Some((n, false)) => Index::Name(n, e),
        }
    }
}

fn dynamic_index(position: usize, table_len: usize) -> usize {
    httpd_rs_verified::hpack_dynamic_index(position, table_len)
        .expect("bounded HPACK table position must have a wire index")
}

/// Checks the static table for the header. If found, returns the index and a
/// boolean representing if the value matched as well.
fn index_static(header: &Header) -> Option<(usize, bool)> {
    match *header {
        Header::Field {
            ref name,
            ref value,
        } => match *name {
            header::ACCEPT_CHARSET => Some((15, false)),
            header::ACCEPT_ENCODING => {
                if value == "gzip, deflate" {
                    Some((16, true))
                } else {
                    Some((16, false))
                }
            }
            header::ACCEPT_LANGUAGE => Some((17, false)),
            header::ACCEPT_RANGES => Some((18, false)),
            header::ACCEPT => Some((19, false)),
            header::ACCESS_CONTROL_ALLOW_ORIGIN => Some((20, false)),
            header::AGE => Some((21, false)),
            header::ALLOW => Some((22, false)),
            header::AUTHORIZATION => Some((23, false)),
            header::CACHE_CONTROL => Some((24, false)),
            header::CONTENT_DISPOSITION => Some((25, false)),
            header::CONTENT_ENCODING => Some((26, false)),
            header::CONTENT_LANGUAGE => Some((27, false)),
            header::CONTENT_LENGTH => Some((28, false)),
            header::CONTENT_LOCATION => Some((29, false)),
            header::CONTENT_RANGE => Some((30, false)),
            header::CONTENT_TYPE => Some((31, false)),
            header::COOKIE => Some((32, false)),
            header::DATE => Some((33, false)),
            header::ETAG => Some((34, false)),
            header::EXPECT => Some((35, false)),
            header::EXPIRES => Some((36, false)),
            header::FROM => Some((37, false)),
            header::HOST => Some((38, false)),
            header::IF_MATCH => Some((39, false)),
            header::IF_MODIFIED_SINCE => Some((40, false)),
            header::IF_NONE_MATCH => Some((41, false)),
            header::IF_RANGE => Some((42, false)),
            header::IF_UNMODIFIED_SINCE => Some((43, false)),
            header::LAST_MODIFIED => Some((44, false)),
            header::LINK => Some((45, false)),
            header::LOCATION => Some((46, false)),
            header::MAX_FORWARDS => Some((47, false)),
            header::PROXY_AUTHENTICATE => Some((48, false)),
            header::PROXY_AUTHORIZATION => Some((49, false)),
            header::RANGE => Some((50, false)),
            header::REFERER => Some((51, false)),
            header::REFRESH => Some((52, false)),
            header::RETRY_AFTER => Some((53, false)),
            header::SERVER => Some((54, false)),
            header::SET_COOKIE => Some((55, false)),
            header::STRICT_TRANSPORT_SECURITY => Some((56, false)),
            header::TRANSFER_ENCODING => Some((57, false)),
            header::USER_AGENT => Some((58, false)),
            header::VARY => Some((59, false)),
            header::VIA => Some((60, false)),
            header::WWW_AUTHENTICATE => Some((61, false)),
            _ => None,
        },
        Header::Authority(_) => Some((1, false)),
        Header::Method(ref v) => match *v {
            Method::GET => Some((2, true)),
            Method::POST => Some((3, true)),
            _ => Some((2, false)),
        },
        Header::Scheme(ref v) => match &**v {
            "http" => Some((6, true)),
            "https" => Some((7, true)),
            _ => Some((6, false)),
        },
        Header::Path(ref v) => match &**v {
            "/" => Some((4, true)),
            "/index.html" => Some((5, true)),
            _ => Some((4, false)),
        },
        Header::Protocol(..) => None,
        Header::Status(ref v) => match u16::from(*v) {
            200 => Some((8, true)),
            204 => Some((9, true)),
            206 => Some((10, true)),
            304 => Some((11, true)),
            400 => Some((12, true)),
            404 => Some((13, true)),
            500 => Some((14, true)),
            _ => Some((8, false)),
        },
    }
}
