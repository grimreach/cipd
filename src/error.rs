//! Error type for the daemon.

use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    #[error("serial: {0}")]
    Serial(#[from] tokio_serial::Error),

    #[error("protocol: {0}")]
    Protocol(String),

    /// CIP general status (CIP Vol.1 Appendix B); `.1` is a human-readable name.
    #[error("cip status 0x{0:02x} ({1})")]
    CipStatus(u8, &'static str),

    /// PCCC STS / EXT STS (AB 1770-6.5.16).
    #[error("pccc sts 0x{0:02x} ext 0x{1:02x}")]
    PcccStatus(u8, u8),

    #[error("timeout")]
    Timeout,

    #[error("device not connected")]
    NotConnected,

    #[error("unknown device: {0}")]
    UnknownDevice(String),

    #[error("{0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, Error>;

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Error::Protocol(format!("json: {e}"))
    }
}
