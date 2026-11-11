//! vapached: an Apache HTTPD-compatible web server with a Verus-verified
//! security core.
//!
//! Module layering:
//!
//! ```text
//!   main        CLI, daemon lifecycle, privilege drop
//!   server      accept loop, request dispatch, connection policy
//!   config      Apache 2.4 configuration parser/compiler
//!   files       static file semantics (ranges, conditionals, indexes)
//!   cgi         CGI/1.1 execution and header translation
//!   access      Require/Order access control, fail-closed
//!   http        strict HTTP/1.1 parser and response writer
//!   log         access/error logging
//!   verified    (Verus) pure security kernels: percent decoding, path
//!               canonicalization, request-head parsing/framing, header
//!               sanitization, token validation, byte-range arithmetic
//! ```
//!
//! I/O and policy are separated so that the pure kernels can be verified and
//! the syscall boundary can be audited independently.

// Library diagnostics can run on request and background workers. Keep every
// existing call site on the bounded, overload-safe stderr path; the CLI binary
// still reports startup failures synchronously before request processing.
macro_rules! eprintln {
    ($($arg:tt)*) => {{
        crate::log::bounded_stderr(format_args!($($arg)*));
    }};
}

pub mod access;
pub mod apache_regex;
pub mod auth;
pub mod cache;
pub mod cgi;
pub mod compression;
pub mod config;
pub mod config_frontend;
mod config_payload;
pub mod expires;
pub mod expr;
pub mod fastcgi;
pub mod fault;
pub mod files;
pub mod glob;
pub mod h2;
pub mod htaccess;
pub mod http;
pub mod http_fields;
pub mod log;
pub mod ocsp;
pub mod policy_ref;
pub mod process;
pub mod proxy;
pub mod request_plan;
pub mod resource;
pub mod rewrite;
pub mod scope_policy;
pub mod server;
pub mod status;
pub mod tls;
pub mod util;

pub use vapache_verified as verified;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
pub const SERVER_SOFTWARE: &str = concat!("vapache/", env!("CARGO_PKG_VERSION"));
