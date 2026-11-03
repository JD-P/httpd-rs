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

pub fn response(auto: bool, resources: &crate::resource::ResourceBudget) -> Response {
    let uptime = START.get().map(|s| s.elapsed().as_secs()).unwrap_or(0);
    let requests = REQUESTS.load(Ordering::Relaxed);
    let bytes = BYTES.load(Ordering::Relaxed);
    let resource = resources.telemetry();
    if auto {
        let body = format!(
            "Total Accesses: {requests}\nTotal kBytes: {}\nUptime: {uptime}\n\
             VapacheDiskBytes: {}\nVapacheDiskByteLimit: {}\n\
             VapacheDiskFiles: {}\nVapacheDiskFileLimit: {}\n\
             VapacheTransportBytes: {}\nVapacheTransportByteLimit: {}\n",
            bytes / 1024,
            resource.disk_bytes,
            resource.disk_byte_limit,
            resource.disk_files,
            resource.disk_file_limit,
            resource.transport_bytes,
            resource.transport_byte_limit,
        );
        return Response::bytes(200, "text/plain", body.into_bytes());
    }
    let body = format!(
        "<!DOCTYPE html><html><head><title>Server Status</title></head><body>\
         <h1>Server Status</h1><p>Server uptime: {uptime} seconds</p>\
         <p>Total accesses: {requests}</p><p>Total kBytes: {}</p>\
         <p>Writable disk: {} / {} bytes, {} / {} files</p>\
         <p>Transport buffers: {} / {} bytes</p></body></html>\n",
        bytes / 1024,
        resource.disk_bytes,
        resource.disk_byte_limit,
        resource.disk_files,
        resource.disk_file_limit,
        resource.transport_bytes,
        resource.transport_byte_limit,
    );
    Response::bytes(200, "text/html; charset=iso-8859-1", body.into_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_exports_resource_parent_telemetry_in_both_formats() {
        let budget = crate::resource::ResourceBudget::default();
        for auto in [true, false] {
            let response = response(auto, &budget);
            let crate::http::Body::Bytes(body) = response.body else {
                panic!("status response was not inline")
            };
            let body = String::from_utf8(body).unwrap();
            assert!(body.contains("Transport"));
            assert!(body.contains("Disk") || body.contains("disk"));
        }
    }
}
