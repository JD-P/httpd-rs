//! Small `mod_status` endpoint for the configured `server-status` handler.

use crate::http::Response;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::OnceLock;
use std::time::Instant;

static START: OnceLock<Instant> = OnceLock::new();
static REQUESTS: AtomicU64 = AtomicU64::new(0);
static BYTES: AtomicU64 = AtomicU64::new(0);

pub fn hit(bytes: u64) {
    START.get_or_init(Instant::now);
    REQUESTS.fetch_add(1, Ordering::Relaxed);
    BYTES.fetch_add(bytes, Ordering::Relaxed);
}

pub fn response(
    auto: bool,
    extended: bool,
    resources: &crate::resource::ResourceBudget,
) -> Response {
    let uptime = START.get().map(|s| s.elapsed().as_secs()).unwrap_or(0);
    let requests = REQUESTS.load(Ordering::Relaxed);
    let bytes = BYTES.load(Ordering::Relaxed);
    let resource = resources.telemetry();
    if auto {
        let mut body = format!(
            "Total Accesses: {requests}\nTotal kBytes: {}\nUptime: {uptime}\n",
            bytes / 1024
        );
        if extended {
            body.push_str(&format!(
                "HttpdRsDiskBytes: {}\nHttpdRsDiskByteLimit: {}\n\
                 HttpdRsDiskFiles: {}\nHttpdRsDiskFileLimit: {}\n\
                 HttpdRsDiskFilesystems: {}\nHttpdRsDiskMinByteHeadroom: {}\n\
                 HttpdRsDiskMinFileHeadroom: {}\n\
                 HttpdRsTransportBytes: {}\nHttpdRsTransportByteLimit: {}\n\
                 HttpdRsQueuedH2Outputs: {}\nHttpdRsH2HpackScratchHighWater: {}\n",
                resource.disk_bytes,
                resource.disk_byte_limit,
                resource.disk_files,
                resource.disk_file_limit,
                resource.disk_filesystems,
                resource.disk_min_byte_headroom,
                resource.disk_min_file_headroom,
                resource.transport_bytes,
                resource.transport_byte_limit,
                resource.queued_h2_outputs,
                resource.h2_hpack_scratch_high_water,
            ));
        }
        return Response::bytes(200, "text/plain", body.into_bytes());
    }
    let mut body = format!(
        "<!DOCTYPE html><html><head><title>Server Status</title></head><body>\
         <h1>Server Status</h1><p>Server uptime: {uptime} seconds</p>\
         <p>Total accesses: {requests}</p><p>Total kBytes: {}</p>",
        bytes / 1024,
    );
    if extended {
        body.push_str(&format!(
            "<p>Writable disk: {} / {} bytes, {} / {} files across {} filesystems; \
             most constrained filesystem has {} bytes and {} files available</p>\
             <p>Transport buffers: {} / {} bytes</p>\
             <p>Queued H2 outputs: {}; HPACK scratch high-water: {} bytes</p>",
            resource.disk_bytes,
            resource.disk_byte_limit,
            resource.disk_files,
            resource.disk_file_limit,
            resource.disk_filesystems,
            resource.disk_min_byte_headroom,
            resource.disk_min_file_headroom,
            resource.transport_bytes,
            resource.transport_byte_limit,
            resource.queued_h2_outputs,
            resource.h2_hpack_scratch_high_water,
        ));
    }
    body.push_str("</body></html>\n");
    Response::bytes(200, "text/html; charset=iso-8859-1", body.into_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_exports_resource_parent_telemetry_in_both_formats() {
        let budget = crate::resource::ResourceBudget::default();
        for auto in [true, false] {
            let response = response(auto, true, &budget);
            let crate::http::Body::Bytes(body) = response.body else {
                panic!("status response was not inline")
            };
            let body = String::from_utf8(body).unwrap();
            assert!(body.contains("Transport"));
            assert!(body.contains("QueuedH2") || body.contains("Queued H2"));
            assert!(body.contains("Hpack") || body.contains("HPACK"));
            assert!(body.contains("Disk") || body.contains("disk"));
        }
        let crate::http::Body::Bytes(body) = response(true, false, &budget).body else {
            panic!("status response was not inline")
        };
        assert!(!String::from_utf8(body).unwrap().contains("HttpdRsDisk"));
    }
}
