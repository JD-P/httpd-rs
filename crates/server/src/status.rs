//! Small `mod_status` endpoint for the configured `server-status` handler.

use crate::http::Response;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::OnceLock;
use std::time::Instant;

static START: OnceLock<Instant> = OnceLock::new();
static REQUESTS: AtomicU64 = AtomicU64::new(0);
static BYTES: AtomicU64 = AtomicU64::new(0);

fn metric_suffix(name: &str) -> String {
    name.split('-')
        .map(|part| {
            let mut chars = part.chars();
            match chars.next() {
                Some(first) => first.to_ascii_uppercase().to_string() + chars.as_str(),
                None => String::new(),
            }
        })
        .collect()
}

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
                 HttpdRsDiskByteHighWater: {}\nHttpdRsDiskByteShadowCandidate: {}\n\
                 HttpdRsDiskByteRejections: {}\n\
                 HttpdRsDiskFiles: {}\nHttpdRsDiskFileLimit: {}\n\
                 HttpdRsDiskFileHighWater: {}\nHttpdRsDiskFileShadowCandidate: {}\n\
                 HttpdRsDiskFileRejections: {}\n\
                 HttpdRsDiskFilesystems: {}\nHttpdRsDiskMinByteHeadroom: {}\n\
                 HttpdRsDiskMinFileHeadroom: {}\n\
                 HttpdRsTransportBytes: {}\nHttpdRsTransportByteLimit: {}\n\
                 HttpdRsTransportHighWater: {}\nHttpdRsTransportShadowCandidate: {}\n\
                 HttpdRsTransportRejections: {}\n\
                 HttpdRsQueuedH2Outputs: {}\nHttpdRsQueuedH2OutputsHighWater: {}\n\
                 HttpdRsH2HpackScratchHighWater: {}\n",
                resource.disk_bytes,
                resource.disk_byte_limit,
                resource.disk_byte_high_water,
                resource.disk_byte_shadow_candidate,
                resource.disk_byte_rejections,
                resource.disk_files,
                resource.disk_file_limit,
                resource.disk_file_high_water,
                resource.disk_file_shadow_candidate,
                resource.disk_file_rejections,
                resource.disk_filesystems,
                resource.disk_min_byte_headroom,
                resource.disk_min_file_headroom,
                resource.transport_bytes,
                resource.transport_byte_limit,
                resource.transport_high_water,
                resource.transport_shadow_candidate,
                resource.transport_rejections,
                resource.queued_h2_outputs,
                resource.queued_h2_outputs_high_water,
                resource.h2_hpack_scratch_high_water,
            ));
            for gauge in &resource.gauges {
                let suffix = metric_suffix(gauge.name);
                body.push_str(&format!(
                    "HttpdRsBudget{suffix}Observed: {}\n\
                     HttpdRsBudget{suffix}Current: {}\n\
                     HttpdRsBudget{suffix}HighWater: {}\n\
                     HttpdRsBudget{suffix}Limit: {}\n\
                     HttpdRsBudget{suffix}ShadowCandidate: {}\n\
                     HttpdRsBudget{suffix}Rejections: {}\n",
                    u8::from(gauge.observed),
                    gauge.current,
                    gauge.high_water,
                    gauge.limit,
                    gauge.shadow_candidate,
                    gauge.rejections,
                ));
            }
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
            "<p>Writable disk: {} / {} bytes (high {}, shadow {}, rejected {}), \
             {} / {} files (high {}, shadow {}, rejected {}) across {} filesystems; \
             most constrained filesystem has {} bytes and {} files available</p>\
             <p>Transport buffers: {} / {} bytes (high {}, shadow {}, rejected {})</p>\
             <p>Queued H2 outputs: {} (high {}); HPACK scratch high-water: {} bytes</p>",
            resource.disk_bytes,
            resource.disk_byte_limit,
            resource.disk_byte_high_water,
            resource.disk_byte_shadow_candidate,
            resource.disk_byte_rejections,
            resource.disk_files,
            resource.disk_file_limit,
            resource.disk_file_high_water,
            resource.disk_file_shadow_candidate,
            resource.disk_file_rejections,
            resource.disk_filesystems,
            resource.disk_min_byte_headroom,
            resource.disk_min_file_headroom,
            resource.transport_bytes,
            resource.transport_byte_limit,
            resource.transport_high_water,
            resource.transport_shadow_candidate,
            resource.transport_rejections,
            resource.queued_h2_outputs,
            resource.queued_h2_outputs_high_water,
            resource.h2_hpack_scratch_high_water,
        ));
        body.push_str("<table><tr><th>Budget</th><th>Observed</th><th>Current</th><th>High-water</th><th>Limit</th><th>Shadow candidate</th><th>Rejections</th></tr>");
        for gauge in &resource.gauges {
            body.push_str(&format!(
                "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
                gauge.name,
                gauge.observed,
                gauge.current,
                gauge.high_water,
                gauge.limit,
                gauge.shadow_candidate,
                gauge.rejections,
            ));
        }
        body.push_str("</table>");
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
            assert!(body.contains("ShadowCandidate") || body.contains("Shadow candidate"));
        }
        let crate::http::Body::Bytes(body) = response(true, false, &budget).body else {
            panic!("status response was not inline")
        };
        assert!(!String::from_utf8(body).unwrap().contains("HttpdRsDisk"));
    }
}
