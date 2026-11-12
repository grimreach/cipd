//! EtherNet/IP session transport (TCP 44818): RegisterSession state machine + SendRRData.
//!
//! Clean-room from ODVA EtherNet/IP. See ARCHITECTURE.md §4.

use crate::cip::{self, cmd, EncapHeader, MrReply, MrRequest, ENCAP_HEADER_LEN};
use crate::error::{Error, Result};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

static CONTEXT: AtomicU64 = AtomicU64::new(1);

fn next_context() -> u64 {
    CONTEXT.fetch_add(1, Ordering::Relaxed)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    Disconnected,
    Active,
}

/// A registered EtherNet/IP session to one interface (PLC or bridge).
pub struct EnipSession {
    stream: TcpStream,
    session_handle: u32,
    state: State,
    rr_timeout: Duration,
}

impl EnipSession {
    /// Connect and RegisterSession. `host` may be `ip` or `ip:port`.
    pub async fn connect(host: &str, connect_timeout: Duration, rr_timeout: Duration) -> Result<Self> {
        let addr = if host.contains(':') {
            host.to_string()
        } else {
            format!("{host}:{}", cip::ENIP_PORT)
        };
        let stream = timeout(connect_timeout, TcpStream::connect(&addr))
            .await
            .map_err(|_| Error::Timeout)??;
        stream.set_nodelay(true).ok();
        let mut s = EnipSession {
            stream,
            session_handle: 0,
            state: State::Disconnected,
            rr_timeout,
        };
        s.register().await?;
        Ok(s)
    }

    pub fn state(&self) -> State {
        self.state
    }

    async fn register(&mut self) -> Result<()> {
        // RegisterSession data: protocol version = 1, options = 0.
        let data = [1u8, 0, 0, 0];
        let (hdr, _body) = self.transact(cmd::REGISTER_SESSION, 0, &data).await?;
        if hdr.status != 0 {
            return Err(Error::Protocol(format!(
                "RegisterSession refused (status 0x{:08x})",
                hdr.status
            )));
        }
        self.session_handle = hdr.session_handle;
        self.state = State::Active;
        Ok(())
    }

    pub async fn unregister(&mut self) -> Result<()> {
        if self.state == State::Active {
            // Best-effort; no reply expected.
            let h = EncapHeader::new(cmd::UNREGISTER_SESSION, self.session_handle, next_context());
            let _ = self.stream.write_all(&h.encode(&[])).await;
            self.state = State::Disconnected;
        }
        Ok(())
    }

    /// One encapsulation request/reply exchange.
    async fn transact(
        &mut self,
        command: u16,
        session: u32,
        data: &[u8],
    ) -> Result<(EncapHeader, Vec<u8>)> {
        let ctx = next_context();
        let h = EncapHeader::new(command, session, ctx);
        self.stream.write_all(&h.encode(data)).await?;

        // Read the 24-byte reply header, then its body.
        let mut hbuf = [0u8; ENCAP_HEADER_LEN];
        timeout(self.rr_timeout, self.stream.read_exact(&mut hbuf))
            .await
            .map_err(|_| Error::Timeout)??;
        let rh = EncapHeader::decode(&hbuf)?;
        let mut body = vec![0u8; rh.length as usize];
        if !body.is_empty() {
            timeout(self.rr_timeout, self.stream.read_exact(&mut body))
                .await
                .map_err(|_| Error::Timeout)??;
        }
        Ok((rh, body))
    }

    /// Send an unconnected (UCMM) CIP Message Router request and return the reply.
    pub async fn send_cip_unconnected(&mut self, req: &MrRequest) -> Result<MrReply> {
        if self.state != State::Active {
            return Err(Error::NotConnected);
        }
        let body = cip::build_send_rr_data(10 /*enc timeout, seconds*/, &req.encode());
        let (hdr, resp) = self
            .transact(cmd::SEND_RR_DATA, self.session_handle, &body)
            .await?;
        if hdr.status != 0 {
            return Err(Error::Protocol(format!(
                "SendRRData encapsulation status 0x{:08x}",
                hdr.status
            )));
        }
        let mr = cip::parse_send_rr_data(&resp)?;
        MrReply::decode(&mr)
    }
}
