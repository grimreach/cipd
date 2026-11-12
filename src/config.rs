//! Daemon configuration (JSON). See `cipd.example.json`.

use crate::error::Result;
use serde::Deserialize;
use std::path::Path;

fn default_api_socket() -> String {
    "/run/cipd/cipd.sock".to_string()
}
fn default_connect_timeout() -> u64 {
    5_000
}
fn default_request_timeout() -> u64 {
    3_000
}
fn default_vendor() -> u16 {
    0x1234
}
fn default_serial() -> u32 {
    0x0000_0001
}

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    #[serde(default = "default_api_socket")]
    pub api_socket: String,
    #[serde(default)]
    pub devices: Vec<DeviceConfig>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DeviceConfig {
    pub name: String,
    pub transport: TransportConfig,
    /// Multi-hop CIP route (empty = direct).
    #[serde(default)]
    pub route: Vec<RouteHop>,
    #[serde(default = "default_vendor")]
    pub vendor_id: u16,
    #[serde(default = "default_serial")]
    pub serial_number: u32,
    #[serde(default = "default_connect_timeout")]
    pub connect_timeout_ms: u64,
    #[serde(default = "default_request_timeout")]
    pub request_timeout_ms: u64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RouteHop {
    pub port: u8,
    pub link: u8,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum TransportConfig {
    /// EtherNet/IP over TCP 44818.
    Enip { host: String },
    /// Legacy CSPv4 over TCP 2222.
    Csp { host: String },
    /// DF1 serial / USB (CDC-ACM).
    Df1 {
        port: String,
        baud: u32,
        #[serde(default)]
        crc: bool, // false => BCC
        #[serde(default)]
        dst: u8,
        #[serde(default)]
        src: u8,
        #[serde(default = "default_ack_timeout")]
        ack_timeout_ms: u64,
        #[serde(default = "default_retries")]
        max_retries: u32,
    },
}

fn default_ack_timeout() -> u64 {
    1_000
}
fn default_retries() -> u32 {
    3
}

impl Config {
    pub fn load(path: &Path) -> Result<Config> {
        let text = std::fs::read_to_string(path)?;
        Ok(serde_json::from_str(&text)?)
    }
}
