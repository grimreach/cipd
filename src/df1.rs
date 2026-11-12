//! DF1 serial/USB transport: framing, BCC/CRC-16, ACK/NAK/ENQ link state machine.
//!
//! Clean-room from the public Allen-Bradley DF1 Protocol and Command Set
//! (pub. 1770-6.5.16). See ARCHITECTURE.md §7.

use crate::error::{Error, Result};
use crate::pccc::{PcccReply, PcccRequest};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;
use tokio_serial::{SerialPortBuilderExt, SerialStream};

// DF1 control characters.
pub const DLE: u8 = 0x10;
pub const STX: u8 = 0x02;
pub const ETX: u8 = 0x03;
pub const ENQ: u8 = 0x05;
pub const ACK: u8 = 0x06;
pub const NAK: u8 = 0x15;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorCheck {
    Bcc,
    Crc,
}

/// DF1 BCC: two's complement of the 8-bit sum of the payload bytes.
pub fn bcc(data: &[u8]) -> u8 {
    let sum = data.iter().fold(0u8, |a, &b| a.wrapping_add(b));
    (!sum).wrapping_add(1)
}

/// DF1 CRC-16 (reflected poly 0xA001, init 0), computed over payload followed by ETX.
pub fn crc16(data: &[u8]) -> u16 {
    let mut crc: u16 = 0;
    let feed = |crc: &mut u16, byte: u8| {
        *crc ^= byte as u16;
        for _ in 0..8 {
            if *crc & 1 != 0 {
                *crc = (*crc >> 1) ^ 0xA001;
            } else {
                *crc >>= 1;
            }
        }
    };
    for &b in data {
        feed(&mut crc, b);
    }
    feed(&mut crc, ETX);
    crc
}

/// Encode a full-duplex DF1 frame: `DLE STX <stuffed payload> DLE ETX <check>`.
pub fn encode_full_duplex(payload: &[u8], ec: ErrorCheck) -> Vec<u8> {
    let mut f = Vec::with_capacity(payload.len() + 6);
    f.push(DLE);
    f.push(STX);
    for &b in payload {
        if b == DLE {
            f.push(DLE); // byte-stuff
        }
        f.push(b);
    }
    f.push(DLE);
    f.push(ETX);
    match ec {
        ErrorCheck::Bcc => f.push(bcc(payload)),
        ErrorCheck::Crc => {
            let c = crc16(payload);
            f.push((c & 0xFF) as u8);
            f.push((c >> 8) as u8);
        }
    }
    f
}

/// Result of scanning a received byte stream for one DF1 message frame.
enum FrameScan {
    /// A complete, check-verified payload.
    Payload(Vec<u8>),
    /// A control char (ACK/NAK/ENQ) consumed.
    Control(u8),
    /// Need more bytes.
    Incomplete,
    /// Framing/check error — caller should NAK.
    Bad,
}

/// Incremental DF1 full-duplex receiver.
struct Receiver {
    ec: ErrorCheck,
    buf: Vec<u8>,
}

impl Receiver {
    fn new(ec: ErrorCheck) -> Self {
        Receiver { ec, buf: Vec::with_capacity(256) }
    }

    fn push(&mut self, bytes: &[u8]) {
        self.buf.extend_from_slice(bytes);
    }

    /// Try to extract one frame or control token from the head of the buffer.
    fn scan(&mut self) -> FrameScan {
        // Parse against an owned snapshot so we can mutate self.buf freely below.
        let b = self.buf.clone();
        if b.is_empty() {
            return FrameScan::Incomplete;
        }
        if b[0] != DLE {
            // resync: drop one byte
            self.buf.remove(0);
            return FrameScan::Bad;
        }
        if b.len() < 2 {
            return FrameScan::Incomplete;
        }
        match b[1] {
            ACK | NAK | ENQ => {
                let c = b[1];
                self.buf.drain(0..2);
                return FrameScan::Control(c);
            }
            STX => {}
            _ => {
                // DLE followed by unexpected byte — drop both
                self.buf.drain(0..2);
                return FrameScan::Bad;
            }
        }

        // Parse DLE STX <stuffed> DLE ETX <check>, un-stuffing DLE DLE.
        let mut payload = Vec::new();
        let mut i = 2;
        while i < b.len() {
            if b[i] == DLE {
                if i + 1 >= b.len() {
                    return FrameScan::Incomplete;
                }
                match b[i + 1] {
                    DLE => {
                        payload.push(DLE);
                        i += 2;
                    }
                    ETX => {
                        // check bytes follow
                        let check_len = match self.ec {
                            ErrorCheck::Bcc => 1,
                            ErrorCheck::Crc => 2,
                        };
                        if i + 2 + check_len > b.len() {
                            return FrameScan::Incomplete;
                        }
                        let ok = match self.ec {
                            ErrorCheck::Bcc => b[i + 2] == bcc(&payload),
                            ErrorCheck::Crc => {
                                let c = crc16(&payload);
                                b[i + 2] == (c & 0xFF) as u8 && b[i + 3] == (c >> 8) as u8
                            }
                        };
                        let consumed = i + 2 + check_len;
                        self.buf.drain(0..consumed);
                        return if ok {
                            FrameScan::Payload(payload)
                        } else {
                            FrameScan::Bad
                        };
                    }
                    other => {
                        // DLE <other> inside data is a framing error
                        let _ = other;
                        self.buf.drain(0..=i + 1);
                        return FrameScan::Bad;
                    }
                }
            } else {
                payload.push(b[i]);
                i += 1;
            }
        }
        FrameScan::Incomplete
    }
}

/// A DF1 full-duplex point-to-point link over a serial/USB (CDC-ACM) port.
pub struct Df1Link {
    port: SerialStream,
    ec: ErrorCheck,
    dst: u8,
    src: u8,
    ack_timeout: Duration,
    max_retries: u32,
}

impl Df1Link {
    /// Open `path` (e.g. `/dev/ttyS0` or `/dev/ttyACM0`) at `baud`.
    pub fn open(
        path: &str,
        baud: u32,
        ec: ErrorCheck,
        dst: u8,
        src: u8,
        ack_timeout_ms: u64,
        max_retries: u32,
    ) -> Result<Self> {
        let port = tokio_serial::new(path, baud)
            .data_bits(tokio_serial::DataBits::Eight)
            .parity(tokio_serial::Parity::None)
            .stop_bits(tokio_serial::StopBits::One)
            .flow_control(tokio_serial::FlowControl::None)
            .open_native_async()?;
        Ok(Df1Link {
            port,
            ec,
            dst,
            src,
            ack_timeout: Duration::from_millis(ack_timeout_ms),
            max_retries,
        })
    }

    async fn write_all(&mut self, bytes: &[u8]) -> Result<()> {
        self.port.write_all(bytes).await?;
        self.port.flush().await?;
        Ok(())
    }

    /// Send one PCCC request and wait for the matching reply (by TNS).
    pub async fn transact(&mut self, req: &PcccRequest) -> Result<PcccReply> {
        // DF1 application payload = DST, SRC, then the PCCC block.
        let mut payload = Vec::with_capacity(2 + 8);
        payload.push(self.dst);
        payload.push(self.src);
        payload.extend_from_slice(&req.encode());
        let frame = encode_full_duplex(&payload, self.ec);

        let mut attempts = 0;
        loop {
            attempts += 1;
            self.write_all(&frame).await?;

            // Await link-level ACK/NAK for our frame.
            match self.await_control().await {
                Ok(ACK) => {}
                Ok(NAK) | Err(Error::Timeout) => {
                    if attempts > self.max_retries {
                        return Err(Error::Timeout);
                    }
                    // DF1 recovery: poll with ENQ, then retransmit on next loop.
                    let _ = self.write_all(&[DLE, ENQ]).await;
                    continue;
                }
                Ok(_) => continue,
                Err(e) => return Err(e),
            }

            // Await the reply message frame and ACK it.
            let reply_payload = self.await_message().await?;
            // reply payload = DST, SRC, then PCCC reply block.
            if reply_payload.len() < 2 {
                return Err(Error::Protocol("short DF1 reply payload".into()));
            }
            let reply = PcccReply::decode(&reply_payload[2..])?;
            if reply.tns == req.tns {
                return Ok(reply);
            }
            // TNS mismatch: not ours; keep waiting within the same attempt.
        }
    }

    /// Read until a single control token (ACK/NAK/ENQ) arrives, or timeout.
    async fn await_control(&mut self) -> Result<u8> {
        let mut rx = Receiver::new(self.ec);
        let mut tmp = [0u8; 256];
        loop {
            let n = timeout(self.ack_timeout, self.port.read(&mut tmp))
                .await
                .map_err(|_| Error::Timeout)??;
            if n == 0 {
                return Err(Error::NotConnected);
            }
            rx.push(&tmp[..n]);
            loop {
                match rx.scan() {
                    FrameScan::Control(c) => return Ok(c),
                    FrameScan::Payload(_) => { /* unexpected here; ignore */ }
                    FrameScan::Bad => { /* resync */ }
                    FrameScan::Incomplete => break,
                }
            }
        }
    }

    /// Read until a complete, verified message frame arrives; ACK or NAK it.
    async fn await_message(&mut self) -> Result<Vec<u8>> {
        let mut rx = Receiver::new(self.ec);
        let mut tmp = [0u8; 512];
        loop {
            let n = timeout(self.ack_timeout, self.port.read(&mut tmp))
                .await
                .map_err(|_| Error::Timeout)??;
            if n == 0 {
                return Err(Error::NotConnected);
            }
            rx.push(&tmp[..n]);
            loop {
                match rx.scan() {
                    FrameScan::Payload(p) => {
                        self.write_all(&[DLE, ACK]).await?;
                        return Ok(p);
                    }
                    FrameScan::Bad => {
                        let _ = self.write_all(&[DLE, NAK]).await;
                    }
                    FrameScan::Control(_) => { /* stray control; ignore */ }
                    FrameScan::Incomplete => break,
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bcc_is_twos_complement() {
        // sum of {0x01,0x02,0x03} = 6; BCC = 0xFA
        assert_eq!(bcc(&[0x01, 0x02, 0x03]), 0xFA);
    }

    #[test]
    fn frame_has_envelope() {
        let f = encode_full_duplex(&[0x41], ErrorCheck::Bcc);
        assert_eq!(f[0], DLE);
        assert_eq!(f[1], STX);
        assert_eq!(f[f.len() - 3], DLE);
        assert_eq!(f[f.len() - 2], ETX);
    }

    #[test]
    fn dle_is_stuffed() {
        let f = encode_full_duplex(&[DLE], ErrorCheck::Bcc);
        // DLE STX DLE DLE DLE ETX BCC
        assert_eq!(&f[0..6], &[DLE, STX, DLE, DLE, DLE, ETX]);
    }

    #[test]
    fn receiver_unstuffs_and_verifies() {
        let payload = vec![0x10, 0x42, 0x10];
        let f = encode_full_duplex(&payload, ErrorCheck::Crc);
        let mut rx = Receiver::new(ErrorCheck::Crc);
        rx.push(&f);
        match rx.scan() {
            FrameScan::Payload(p) => assert_eq!(p, payload),
            _ => panic!("expected payload"),
        }
    }
}
