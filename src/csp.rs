//! CSPv4 ("AB Ethernet") legacy transport over TCP 2222 — fallback for pre-EtherNet/IP
//! PLC-5E / SLC-5/05.
//!
//! Clean-room SCAFFOLD. CSPv4 carries the same PCCC command blocks (see pccc.rs) inside a fixed
//! CSP header after a session open. The exact CSP header field offsets are legacy and best
//! confirmed against the AB reference or a packet capture before enabling in production; this
//! module intentionally exposes the shape without asserting unverified byte offsets.
//!
//! See ARCHITECTURE.md §5.

use crate::error::{Error, Result};
use crate::pccc::{PcccReply, PcccRequest};
use std::time::Duration;
use tokio::net::TcpStream;

pub struct CspSession {
    _stream: TcpStream,
    _session: u32,
}

impl CspSession {
    pub async fn connect(host: &str, connect_timeout: Duration) -> Result<Self> {
        let addr = if host.contains(':') {
            host.to_string()
        } else {
            format!("{host}:{}", crate::cip::CSP_PORT)
        };
        let stream = tokio::time::timeout(connect_timeout, TcpStream::connect(&addr))
            .await
            .map_err(|_| Error::Timeout)??;
        // TODO(csp): send the CSP "register" / open-session command and capture the
        // returned session id. Deferred until validated against a capture.
        Ok(CspSession { _stream: stream, _session: 0 })
    }

    pub async fn transact(&mut self, _req: &PcccRequest) -> Result<PcccReply> {
        Err(Error::Other(
            "CSPv4 transport not yet implemented; enable EtherNet/IP or DF1".into(),
        ))
    }
}
