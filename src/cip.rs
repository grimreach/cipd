//! EtherNet/IP encapsulation + CIP Message Router + EPATH.
//!
//! Clean-room implementation from the public ODVA EtherNet/IP and CIP specifications
//! (see ARCHITECTURE.md §4). No code is derived from any vendor binary.

use crate::error::{Error, Result};

/// EtherNet/IP registered TCP/UDP port (44818).
pub const ENIP_PORT: u16 = 0xAF12;
/// Legacy CSPv4 ("AB Ethernet") TCP port.
pub const CSP_PORT: u16 = 2222;

pub const ENCAP_HEADER_LEN: usize = 24;

pub mod cmd {
    pub const NOP: u16 = 0x0000;
    pub const LIST_SERVICES: u16 = 0x0004;
    pub const LIST_IDENTITY: u16 = 0x0063;
    pub const LIST_INTERFACES: u16 = 0x0064;
    pub const REGISTER_SESSION: u16 = 0x0065;
    pub const UNREGISTER_SESSION: u16 = 0x0066;
    pub const SEND_RR_DATA: u16 = 0x006F;
    pub const SEND_UNIT_DATA: u16 = 0x0070;
}

pub mod cpf {
    pub const ADDR_NULL: u16 = 0x0000;
    pub const ADDR_CONNECTED: u16 = 0x00A1;
    pub const DATA_CONNECTED: u16 = 0x00B1;
    pub const DATA_UNCONNECTED: u16 = 0x00B2;
}

// ---------------------------------------------------------------------------
// Encapsulation header
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default)]
pub struct EncapHeader {
    pub command: u16,
    pub length: u16,
    pub session_handle: u32,
    pub status: u32,
    pub sender_context: [u8; 8],
    pub options: u32,
}

impl EncapHeader {
    pub fn new(command: u16, session_handle: u32, context: u64) -> Self {
        EncapHeader {
            command,
            session_handle,
            sender_context: context.to_le_bytes(),
            ..Default::default()
        }
    }

    /// Serialize header + trailing `data` (sets `length` from `data`).
    pub fn encode(&self, data: &[u8]) -> Vec<u8> {
        let mut b = Vec::with_capacity(ENCAP_HEADER_LEN + data.len());
        b.extend_from_slice(&self.command.to_le_bytes());
        b.extend_from_slice(&(data.len() as u16).to_le_bytes());
        b.extend_from_slice(&self.session_handle.to_le_bytes());
        b.extend_from_slice(&self.status.to_le_bytes());
        b.extend_from_slice(&self.sender_context);
        b.extend_from_slice(&self.options.to_le_bytes());
        b.extend_from_slice(data);
        b
    }

    pub fn decode(buf: &[u8]) -> Result<EncapHeader> {
        if buf.len() < ENCAP_HEADER_LEN {
            return Err(Error::Protocol("short encapsulation header".into()));
        }
        let mut sc = [0u8; 8];
        sc.copy_from_slice(&buf[12..20]);
        Ok(EncapHeader {
            command: le16(buf, 0),
            length: le16(buf, 2),
            session_handle: le32(buf, 4),
            status: le32(buf, 8),
            sender_context: sc,
            options: le32(buf, 20),
        })
    }
}

// ---------------------------------------------------------------------------
// SendRRData (UCMM / unconnected) body <-> CIP MR payload
// ---------------------------------------------------------------------------

/// Wrap a CIP Message Router request as a SendRRData body (Null addr + 0x00B2 data item).
pub fn build_send_rr_data(timeout: u16, cip: &[u8]) -> Vec<u8> {
    let mut b = Vec::with_capacity(16 + cip.len());
    b.extend_from_slice(&0u32.to_le_bytes()); // interface handle = CIP
    b.extend_from_slice(&timeout.to_le_bytes());
    b.extend_from_slice(&2u16.to_le_bytes()); // item count
    b.extend_from_slice(&cpf::ADDR_NULL.to_le_bytes());
    b.extend_from_slice(&0u16.to_le_bytes()); // null addr length
    b.extend_from_slice(&cpf::DATA_UNCONNECTED.to_le_bytes());
    b.extend_from_slice(&(cip.len() as u16).to_le_bytes());
    b.extend_from_slice(cip);
    b
}

/// Extract the CIP MR reply bytes (0x00B2 data item) from a SendRRData reply body.
pub fn parse_send_rr_data(data: &[u8]) -> Result<Vec<u8>> {
    if data.len() < 8 {
        return Err(Error::Protocol("short SendRRData body".into()));
    }
    let mut off = 6; // skip interface handle (4) + timeout (2)
    let item_count = le16(data, off);
    off += 2;
    for _ in 0..item_count {
        if off + 4 > data.len() {
            break;
        }
        let type_id = le16(data, off);
        let len = le16(data, off + 2) as usize;
        off += 4;
        if off + len > data.len() {
            return Err(Error::Protocol("CPF item overruns buffer".into()));
        }
        let item = &data[off..off + len];
        off += len;
        if type_id == cpf::DATA_UNCONNECTED {
            return Ok(item.to_vec());
        }
    }
    Err(Error::Protocol("no unconnected-data item in reply".into()))
}

// ---------------------------------------------------------------------------
// CIP Message Router request / reply
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct MrRequest {
    pub service: u8,
    /// EPATH bytes (request path); length is emitted as word count.
    pub path: Vec<u8>,
    pub data: Vec<u8>,
}

impl MrRequest {
    pub fn new(service: u8, path: Vec<u8>, data: Vec<u8>) -> Self {
        MrRequest { service, path, data }
    }

    pub fn encode(&self) -> Vec<u8> {
        debug_assert!(self.path.len() % 2 == 0, "EPATH must be word-aligned");
        let mut b = Vec::with_capacity(2 + self.path.len() + self.data.len());
        b.push(self.service);
        b.push((self.path.len() / 2) as u8);
        b.extend_from_slice(&self.path);
        b.extend_from_slice(&self.data);
        b
    }
}

#[derive(Debug, Clone)]
pub struct MrReply {
    pub service: u8,
    pub general_status: u8,
    pub additional_status: Vec<u16>,
    pub data: Vec<u8>,
}

impl MrReply {
    pub fn decode(buf: &[u8]) -> Result<MrReply> {
        if buf.len() < 4 {
            return Err(Error::Protocol("short MR reply".into()));
        }
        let service = buf[0]; // reply service = request service | 0x80
        // buf[1] reserved (0)
        let general_status = buf[2];
        let addl_words = buf[3] as usize;
        let mut off = 4;
        let mut addl = Vec::with_capacity(addl_words);
        for _ in 0..addl_words {
            if off + 2 > buf.len() {
                break;
            }
            addl.push(le16(buf, off));
            off += 2;
        }
        Ok(MrReply {
            service,
            general_status,
            additional_status: addl,
            data: buf[off..].to_vec(),
        })
    }

    pub fn ok(&self) -> Result<&[u8]> {
        if self.general_status == 0 {
            Ok(&self.data)
        } else {
            Err(Error::CipStatus(self.general_status, cip_status_name(self.general_status)))
        }
    }
}

// ---------------------------------------------------------------------------
// EPATH segments
// ---------------------------------------------------------------------------

pub fn seg_class(class: u16) -> Vec<u8> {
    if class <= 0xFF {
        vec![0x20, class as u8]
    } else {
        let mut v = vec![0x21, 0x00];
        v.extend_from_slice(&class.to_le_bytes());
        v
    }
}

pub fn seg_instance(inst: u16) -> Vec<u8> {
    if inst <= 0xFF {
        vec![0x24, inst as u8]
    } else {
        let mut v = vec![0x25, 0x00];
        v.extend_from_slice(&inst.to_le_bytes());
        v
    }
}

pub fn seg_attribute(attr: u16) -> Vec<u8> {
    if attr <= 0xFF {
        vec![0x30, attr as u8]
    } else {
        let mut v = vec![0x31, 0x00];
        v.extend_from_slice(&attr.to_le_bytes());
        v
    }
}

/// Convenience: class + instance EPATH.
pub fn path_class_instance(class: u16, inst: u16) -> Vec<u8> {
    let mut p = seg_class(class);
    p.extend(seg_instance(inst));
    p
}

/// Port segment for a route hop (port 1..14, single-byte numeric link / slot).
pub fn seg_port(port: u8, link: u8) -> Vec<u8> {
    assert!((1..=14).contains(&port), "use extended port segment for port > 14");
    vec![port & 0x0F, link]
}

// ---------------------------------------------------------------------------
// Unconnected_Send (CIP Connection Manager, service 0x52) for multi-hop routing
// ---------------------------------------------------------------------------

pub const CLASS_CONNECTION_MANAGER: u16 = 0x06;

/// Wrap `embedded` (a CIP MR request) in an Unconnected_Send routed along `route_path`.
pub fn unconnected_send(
    priority_ticks: u8,
    timeout_ticks: u8,
    embedded: &[u8],
    route_path: &[u8],
) -> MrRequest {
    debug_assert!(route_path.len() % 2 == 0);
    let mut data = Vec::with_capacity(6 + embedded.len() + route_path.len());
    data.push(priority_ticks);
    data.push(timeout_ticks);
    data.extend_from_slice(&(embedded.len() as u16).to_le_bytes());
    data.extend_from_slice(embedded);
    if embedded.len() % 2 == 1 {
        data.push(0x00); // pad to even
    }
    data.push((route_path.len() / 2) as u8);
    data.push(0x00); // reserved
    data.extend_from_slice(route_path);
    MrRequest::new(0x52, path_class_instance(CLASS_CONNECTION_MANAGER, 1), data)
}

/// Encode a priority/tick timeout pair for a whole-seconds timeout.
/// (time = tick_time_ms * ticks; tick base 2^priority ms.) Clean-room per CIP Vol.1.
pub fn tick_timeout(seconds: u32) -> (u8, u8) {
    // priority 0x0A => 1024 ms tick; ticks = ceil(seconds*1000/1024), clamped to u8.
    let ms = seconds.saturating_mul(1000);
    let ticks = ((ms + 1023) / 1024).clamp(1, 255) as u8;
    (0x0A, ticks)
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

#[inline]
fn le16(b: &[u8], o: usize) -> u16 {
    u16::from_le_bytes([b[o], b[o + 1]])
}
#[inline]
fn le32(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}

/// Subset of CIP general status names (CIP Vol.1 Appendix B).
pub fn cip_status_name(s: u8) -> &'static str {
    match s {
        0x00 => "Success",
        0x01 => "Connection failure",
        0x02 => "Resource unavailable",
        0x03 => "Invalid parameter value",
        0x04 => "Path segment error",
        0x05 => "Path destination unknown",
        0x08 => "Service not supported",
        0x09 => "Invalid attribute value",
        0x0C => "Object state conflict",
        0x0E => "Attribute not settable",
        0x11 => "Reply data too large",
        0x13 => "Not enough data",
        0x14 => "Attribute not supported",
        0x15 => "Too much data",
        0x16 => "Object does not exist",
        0x1E => "Embedded service error",
        0x1F => "Vendor specific error",
        0x20 => "Invalid parameter",
        0x26 => "Invalid path size",
        _ => "Unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encap_roundtrip() {
        let h = EncapHeader::new(cmd::REGISTER_SESSION, 0, 0x1122334455667788);
        let bytes = h.encode(&[1, 0, 0, 0]);
        assert_eq!(bytes.len(), ENCAP_HEADER_LEN + 4);
        let d = EncapHeader::decode(&bytes).unwrap();
        assert_eq!(d.command, cmd::REGISTER_SESSION);
        assert_eq!(d.length, 4);
        assert_eq!(d.sender_context, 0x1122334455667788u64.to_le_bytes());
    }

    #[test]
    fn rr_data_roundtrip() {
        let cip = [0x52u8, 0x02, 0x20, 0x06, 0x24, 0x01];
        let body = build_send_rr_data(10, &cip);
        // simulate a reply body with the same single data item
        let got = parse_send_rr_data(&body).unwrap();
        assert_eq!(got, cip);
    }

    #[test]
    fn epath_forms() {
        assert_eq!(seg_class(0x06), vec![0x20, 0x06]);
        assert_eq!(seg_class(0x1234), vec![0x21, 0x00, 0x34, 0x12]);
        assert_eq!(seg_instance(1), vec![0x24, 0x01]);
    }
}
