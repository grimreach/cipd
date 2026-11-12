//! PCCC command blocks + PCCC-in-CIP wrapping.
//!
//! Clean-room from the public Allen-Bradley DF1 Protocol and Command Set
//! (pub. 1770-6.5.16) and the CIP PCCC object. See ARCHITECTURE.md §6.

use crate::cip::{self, MrRequest};
use crate::error::{Error, Result};

/// PCCC object class for PCCC-in-CIP (service 0x4B).
pub const CLASS_PCCC: u16 = 0x67;

/// Common command/function codes (subset).
pub mod fnc {
    /// CMD 0x0F, FNC 0xA2 — SLC protected typed logical read (3 address fields).
    pub const SLC_TYPED_READ: (u8, u8) = (0x0F, 0xA2);
    /// CMD 0x0F, FNC 0xAA — SLC protected typed logical write.
    pub const SLC_TYPED_WRITE: (u8, u8) = (0x0F, 0xAA);
    /// CMD 0x0F, FNC 0x68 — PLC-5 typed read.
    pub const PLC5_TYPED_READ: (u8, u8) = (0x0F, 0x68);
    /// CMD 0x0F, FNC 0x67 — PLC-5 typed write.
    pub const PLC5_TYPED_WRITE: (u8, u8) = (0x0F, 0x67);
    /// CMD 0x06, FNC 0x03 — diagnostic status.
    pub const DIAG_STATUS: (u8, u8) = (0x06, 0x03);
}

/// A PCCC command message (without the DST/SRC link bytes — those belong to the transport).
#[derive(Debug, Clone)]
pub struct PcccRequest {
    pub cmd: u8,
    pub fnc: u8,
    pub tns: u16,
    pub data: Vec<u8>,
}

impl PcccRequest {
    pub fn new(cmd_fnc: (u8, u8), tns: u16, data: Vec<u8>) -> Self {
        PcccRequest { cmd: cmd_fnc.0, fnc: cmd_fnc.1, tns, data }
    }

    /// Encode `CMD STS(=0) TNS FNC <data>`.
    pub fn encode(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(5 + self.data.len());
        b.push(self.cmd);
        b.push(0x00); // STS = 0 in a command
        b.extend_from_slice(&self.tns.to_le_bytes());
        b.push(self.fnc);
        b.extend_from_slice(&self.data);
        b
    }
}

#[derive(Debug, Clone)]
pub struct PcccReply {
    pub sts: u8,
    pub ext_sts: u8,
    pub tns: u16,
    pub data: Vec<u8>,
}

impl PcccReply {
    /// Parse `CMD STS TNS [EXT_STS] <data>`.
    pub fn decode(buf: &[u8]) -> Result<PcccReply> {
        if buf.len() < 4 {
            return Err(Error::Protocol("short PCCC reply".into()));
        }
        let sts = buf[1];
        let tns = u16::from_le_bytes([buf[2], buf[3]]);
        let mut off = 4;
        let mut ext_sts = 0u8;
        if sts == 0xF0 {
            if buf.len() < 5 {
                return Err(Error::Protocol("PCCC EXT_STS missing".into()));
            }
            ext_sts = buf[4];
            off = 5;
        }
        Ok(PcccReply { sts, ext_sts, tns, data: buf[off..].to_vec() })
    }

    pub fn ok(&self) -> Result<&[u8]> {
        if self.sts == 0 {
            Ok(&self.data)
        } else {
            Err(Error::PcccStatus(self.sts, self.ext_sts))
        }
    }
}

/// Build an SLC protected typed read for `size` bytes starting at
/// file `file_number` (type `file_type`), element/sub-element.
pub fn slc_typed_read(
    tns: u16,
    size: u8,
    file_number: u8,
    file_type: u8,
    element: u8,
    sub_element: u8,
) -> PcccRequest {
    PcccRequest::new(
        fnc::SLC_TYPED_READ,
        tns,
        vec![size, file_number, file_type, element, sub_element],
    )
}

/// Build an SLC protected typed write of `values` to the given address.
pub fn slc_typed_write(
    tns: u16,
    file_number: u8,
    file_type: u8,
    element: u8,
    sub_element: u8,
    values: &[u8],
) -> PcccRequest {
    let mut data = Vec::with_capacity(5 + values.len());
    data.push(values.len() as u8);
    data.push(file_number);
    data.push(file_type);
    data.push(element);
    data.push(sub_element);
    data.extend_from_slice(values);
    PcccRequest::new(fnc::SLC_TYPED_WRITE, tns, data)
}

/// Wrap a PCCC block as a CIP PCCC-object Execute request (service 0x4B, class 0x67, inst 1).
/// `vendor`/`serial` identify this client (requestor id).
pub fn pccc_in_cip(vendor: u16, serial: u32, pccc: &PcccRequest) -> MrRequest {
    let block = pccc.encode();
    let mut data = Vec::with_capacity(7 + block.len());
    data.push(7); // requestor id length (this byte + vendor(2) + serial(4))
    data.extend_from_slice(&vendor.to_le_bytes());
    data.extend_from_slice(&serial.to_le_bytes());
    data.extend_from_slice(&block);
    MrRequest::new(0x4B, cip::path_class_instance(CLASS_PCCC, 1), data)
}

/// Strip the requestor-id echo from a PCCC-in-CIP reply, returning the PCCC reply block.
pub fn pccc_from_cip_reply(cip_reply_data: &[u8]) -> Result<PcccReply> {
    // Reply data = requestor_id (echoed, length-prefixed) + PCCC reply block.
    if cip_reply_data.is_empty() {
        return Err(Error::Protocol("empty PCCC-in-CIP reply".into()));
    }
    let id_len = cip_reply_data[0] as usize;
    let off = 1 + id_len.saturating_sub(1); // length byte counts itself
    let off = off.min(cip_reply_data.len());
    PcccReply::decode(&cip_reply_data[off..])
}

// ---------------------------------------------------------------------------
// MicroLogix / SLC logical address parsing
// (N7:0, B3:0, F8:2, T4:0.ACC, I:0, O:0, N7:0/4, N7:300 ...)
// ---------------------------------------------------------------------------

/// How the elements of a data file decode on the wire (little-endian).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WordType {
    I16,
    U16,
    F32,
    I32,
    /// Structured/opaque (ST, MG, PD) — no scalar decode.
    Raw,
}

/// A parsed SLC/MicroLogix logical address.
#[derive(Debug, Clone)]
pub struct SlcAddress {
    pub letter: String,
    pub file_number: u16,
    pub file_type: u8,
    pub element: u16,
    pub sub_element: u16,
    pub has_sub: bool,
    pub bit: Option<u8>,
    /// Bytes per whole element for this file type.
    pub element_size: u8,
    pub word_type: WordType,
}

/// `(file_type code, element size bytes, decode type, default file number)` for a type letter.
/// File-type codes are the public SLC/MicroLogix data-file-type values (DF1 command set).
fn file_type_info(letter: &str) -> Option<(u8, u8, WordType, Option<u16>)> {
    Some(match letter {
        "O" => (0x8B, 2, WordType::U16, Some(0)),  // Output
        "I" => (0x8C, 2, WordType::U16, Some(1)),  // Input
        "S" => (0x84, 2, WordType::I16, Some(2)),  // Status
        "B" => (0x85, 2, WordType::U16, Some(3)),  // Bit
        "T" => (0x86, 6, WordType::I16, Some(4)),  // Timer (3 words)
        "C" => (0x87, 6, WordType::I16, Some(5)),  // Counter (3 words)
        "R" => (0x88, 6, WordType::I16, Some(6)),  // Control (3 words)
        "N" => (0x89, 2, WordType::I16, Some(7)),  // Integer
        "F" => (0x8A, 4, WordType::F32, Some(8)),  // Float
        "ST" => (0x8D, 84, WordType::Raw, None),   // String
        "A" => (0x8E, 2, WordType::U16, None),     // ASCII
        "L" => (0x91, 4, WordType::I32, None),     // Long (MicroLogix)
        "MG" => (0x92, 50, WordType::Raw, None),   // Message
        "PD" => (0x93, 46, WordType::Raw, None),   // PID
        _ => return None,
    })
}

/// Map a sub-element token to `(word offset, is-word-sub, optional control bit)`.
fn parse_sub(letter: &str, tok: &str) -> Option<(u16, bool, Option<u8>)> {
    if let Ok(n) = tok.parse::<u16>() {
        return Some((n, true, None));
    }
    match tok.to_ascii_uppercase().as_str() {
        "PRE" => Some((1, true, None)),
        "ACC" => Some((2, true, None)),
        "LEN" => Some((1, true, None)),
        "POS" => Some((2, true, None)),
        "CON" | "CTL" | "WORD" => Some((0, true, None)),
        // control-word status bits (word 0) — read returns word 0, bit noted.
        up => {
            let bit = match (letter, up) {
                ("T", "EN") => 15, ("T", "TT") => 14, ("T", "DN") => 13,
                ("C", "CU") => 15, ("C", "CD") => 14, ("C", "DN") => 13,
                ("C", "OV") => 12, ("C", "UN") => 11, ("C", "UA") => 10,
                ("R", "EN") => 15, ("R", "EU") => 14, ("R", "DN") => 13,
                ("R", "EM") => 12, ("R", "ER") => 11, ("R", "UL") => 10,
                ("R", "IN") => 9, ("R", "FD") => 8,
                _ => return None,
            };
            Some((0, true, Some(bit)))
        }
    }
}

/// Parse a logical address such as `N7:0`, `B3:0/4`, `F8:2`, `T4:0.ACC`, `I:0`, `O:0`.
pub fn parse_slc_address(addr: &str) -> Result<SlcAddress> {
    let bad = || Error::Protocol(format!("invalid SLC address '{addr}'"));
    let s = addr.trim();

    // optional explicit bit:  .../4
    let (s, bit) = match s.split_once('/') {
        Some((a, b)) => (a, Some(b.parse::<u8>().map_err(|_| bad())?)),
        None => (s, None),
    };
    // optional sub-element:  ....ACC  |  ....1
    let (head, sub_tok) = match s.split_once('.') {
        Some((a, b)) => (a, Some(b)),
        None => (s, None),
    };
    // file spec and element separated by ':'
    let (filespec, elem_str) = head.split_once(':').ok_or_else(bad)?;

    let letter: String = filespec
        .chars()
        .take_while(|c| c.is_ascii_alphabetic())
        .collect::<String>()
        .to_ascii_uppercase();
    let num_str: String = filespec
        .chars()
        .skip_while(|c| c.is_ascii_alphabetic())
        .collect();
    if letter.is_empty() {
        return Err(bad());
    }

    let (file_type, element_size, word_type, default_file) = file_type_info(&letter)
        .ok_or_else(|| Error::Protocol(format!("unknown file type '{letter}'")))?;

    let file_number = if num_str.is_empty() {
        default_file.ok_or_else(|| Error::Protocol(format!("file number required for '{letter}'")))?
    } else {
        num_str.parse::<u16>().map_err(|_| bad())?
    };
    let element = elem_str.parse::<u16>().map_err(|_| bad())?;

    let (sub_element, has_sub, bit_from_sub) = match sub_tok {
        None => (0, false, None),
        Some(t) => parse_sub(&letter, t)
            .ok_or_else(|| Error::Protocol(format!("invalid sub-element '.{t}' for '{letter}'")))?,
    };

    Ok(SlcAddress {
        letter,
        file_number,
        file_type,
        element,
        sub_element,
        has_sub,
        bit: bit.or(bit_from_sub),
        element_size,
        word_type,
    })
}

/// Read size in bytes for `count` elements/sub-elements at this address.
pub fn read_size(a: &SlcAddress, count: u16) -> u16 {
    let per = if a.has_sub { 2 } else { a.element_size as u16 };
    per.saturating_mul(count.max(1))
}

/// Push an address field, using the 0xFF extended form for values ≥ 255.
fn push_addr_field(buf: &mut Vec<u8>, v: u16) {
    if v < 0xFF {
        buf.push(v as u8);
    } else {
        buf.push(0xFF);
        buf.extend_from_slice(&v.to_le_bytes());
    }
}

/// SLC protected typed logical read of `size` bytes at a parsed address.
pub fn slc_typed_read_addr(tns: u16, size: u8, a: &SlcAddress) -> PcccRequest {
    let mut data = Vec::with_capacity(8);
    data.push(size);
    push_addr_field(&mut data, a.file_number);
    data.push(a.file_type);
    push_addr_field(&mut data, a.element);
    push_addr_field(&mut data, a.sub_element);
    PcccRequest::new(fnc::SLC_TYPED_READ, tns, data)
}

/// SLC protected typed logical write of `values` at a parsed address.
pub fn slc_typed_write_addr(tns: u16, a: &SlcAddress, values: &[u8]) -> PcccRequest {
    let mut data = Vec::with_capacity(8 + values.len());
    data.push(values.len() as u8);
    push_addr_field(&mut data, a.file_number);
    data.push(a.file_type);
    push_addr_field(&mut data, a.element);
    push_addr_field(&mut data, a.sub_element);
    data.extend_from_slice(values);
    PcccRequest::new(fnc::SLC_TYPED_WRITE, tns, data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn typed_read_encode() {
        let r = slc_typed_read(0x0001, 2, 7, 0x89, 0, 0);
        let b = r.encode();
        // CMD=0F STS=00 TNS(lo,hi)=01,00 FNC=A2 size=2 file=7 type=89 elem=0 sub=0
        assert_eq!(b, vec![0x0F, 0x00, 0x01, 0x00, 0xA2, 0x02, 0x07, 0x89, 0x00, 0x00]);
    }

    #[test]
    fn reply_ext_status() {
        // CMD STS=0xF0 TNS=0x0001 EXT=0x07 data=..
        let r = PcccReply::decode(&[0x4F, 0xF0, 0x01, 0x00, 0x07]).unwrap();
        assert_eq!(r.sts, 0xF0);
        assert_eq!(r.ext_sts, 0x07);
        assert!(r.ok().is_err());
    }

    #[test]
    fn parse_basic() {
        let a = parse_slc_address("N7:0").unwrap();
        assert_eq!((a.file_number, a.file_type, a.element), (7, 0x89, 0));
        assert!(!a.has_sub);
        assert_eq!(a.word_type, WordType::I16);
    }

    #[test]
    fn parse_default_io_files() {
        assert_eq!(parse_slc_address("I:0").unwrap().file_number, 1);
        assert_eq!(parse_slc_address("O:0").unwrap().file_number, 0);
        assert_eq!(parse_slc_address("B3:0").unwrap().file_type, 0x85);
        assert_eq!(parse_slc_address("F8:2").unwrap().element, 2);
    }

    #[test]
    fn parse_sub_acc() {
        let a = parse_slc_address("T4:0.ACC").unwrap();
        assert_eq!((a.file_type, a.sub_element, a.has_sub), (0x86, 2, true));
        assert_eq!(read_size(&a, 1), 2); // one sub-element word
    }

    #[test]
    fn parse_bit() {
        let a = parse_slc_address("B3:0/4").unwrap();
        assert_eq!(a.bit, Some(4));
    }

    #[test]
    fn extended_address_field() {
        let a = parse_slc_address("N7:300").unwrap();
        let enc = slc_typed_read_addr(1, 2, &a).encode();
        // element 300 => 0xFF, 0x2C, 0x01
        assert!(enc.windows(3).any(|w| w == [0xFF, 0x2C, 0x01]));
    }
}
