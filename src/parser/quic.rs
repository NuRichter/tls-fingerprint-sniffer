use std::convert::TryFrom;
use std::fmt::{Debug, Display};
use anyhow::{anyhow, Error, Result};
use byteorder::{BigEndian, LittleEndian, ReadBytesExt};
use crate::capture::packet::Packet;
use crate::utils::hash::{HashAlgorithm, HashError};
use crate::fingerprint::ja4::Ja4Error;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QuicVersion {
    V1 = 0x1,
    V2 = 0x2,
    V3 = 0x3,
    V4 = 0x4,
}

impl TryFrom<u8> for QuicVersion {
    type Error = Error;
    fn try_from(v: u8) -> Result<Self> {
        match v {
            0x1 => Ok(QuicVersion::V1),
            0x2 => Ok(QuicVersion::V2),
            0x3 => Ok(QuicVersion::V3),
            0x4 => Ok(QuicVersion::V4),
            _ => Err(anyhow!("Invalid QUIC version")),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QuicPacketType {
    Initial = 0,
    Retry = 1,
    Handshake = 2,
    VersionNegotiation = 3,
    Short = 4,
}

impl TryFrom<u8> for QuicPacketType {
    type Error = Error;
    fn try_from(t: u8) -> Result<Self> {
        match t {
            0 => Ok(QuicPacketType::Initial),
            1 => Ok(QuicPacketType::Retry),
            2 => Ok(QuicPacketType::Handshake),
            3 => Ok(QuicPacketType::VersionNegotiation),
            4 => Ok(QuicPacketType::Short),
            _ => Err(anyhow!("Invalid QUIC packet type")),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum QuicParseError {
    OutOfBounds,
    InvalidField,
    BufferTooSmall,
    VersionMismatch,
    MissingDcid,
    MissingScid,
    InvalidLength,
}

impl From<QuicParseError> for Error {
    fn from(e: QuicParseError) -> Error {
        match e {
            QuicParseError::OutOfBounds => anyhow!("Packet buffer out of bounds"),
            QuicParseError::InvalidField => anyhow!("Invalid field value"),
            QuicParseError::BufferTooSmall => anyhow!("Buffer too small for expected data"),
            QuicParseError::VersionMismatch => anyhow!("QUIC version mismatch"),
            QuicParseError::MissingDcid => anyhow!("Missing destination connection ID"),
            QuicParseError::MissingScid => anyhow!("Missing source connection ID"),
            QuicParseError::InvalidLength => anyhow!("Invalid packet length"),
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct VersionNegotiationPacket {
    public_flags: u8,
    version: u32,
    dcid: Vec<u8>,
    scid: Vec<u8>,
    dcids: Vec<ConnectionId>,
    scids: Vec<ConnectionId>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct ConnectionId {
    length: usize,
    data: Vec<u8>,
}

impl ConnectionId {
    fn new(length: usize, data: &[u8]) -> Self {
        let mut d = data.to_vec();
        while d.len() < length {
            d.push(0);
        }
        ConnectionId { length, data: d }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct InitialPacket {
    public_flags: u8,
    version: u32,
    scid: ConnectionId,
    dcid: ConnectionId,
    token: Vec<u8>,
    payload_len: usize,
    payload: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct RetryPacket {
    public_flags: u8,
    version: u32,
    dcid: ConnectionId,
    scid: ConnectionId,
    retry_token: Vec<u8>,
    original_dcid: ConnectionId,
    payload_len: usize,
    payload: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct HandshakePacket {
    public_flags: u8,
    version: u32,
    dcid: ConnectionId,
    scid: ConnectionId,
    payload_len: usize,
    payload: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct ShortHeaderPacket {
    public_flags: u8,
    version: QuicVersion,
    dcid: ConnectionId,
    scid: ConnectionId,
    payload_len: usize,
    payload: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq)]
pub enum QuicPacket {
    VersionNegotiation(VersionNegotiationPacket),
    Initial(InitialPacket),
    Retry(RetryPacket),
    Handshake(HandshakePacket),
    Short(ShortHeaderPacket),
}

fn read_u16<B: AsRef<[u8]>>(buf: B, offset: usize) -> Result<u16> {
    let data = buf.as_ref();
    if offset + 2 > data.len() {
        return Err(anyhow!("Buffer too small for u16"));
    }
    Ok(u16::from_be_bytes([data[offset], data[offset + 1]]))
}

fn read_u32<B: AsRef<[u8]>>(buf: B, offset: usize) -> Result<u32> {
    let data = buf.as_ref();
    if offset + 4 > data.len() {
        return Err(anyhow!("Buffer too small for u32"));
    }
    Ok(u32::from_be_bytes([data[offset], data[offset + 1], data[offset + 2], data[offset + 3]]))
}

fn read_varint<B: AsRef<[u8]>>(buf: B, offset: usize) -> Result<usize> {
    let mut n = 0usize;
    let mut i = offset;
    while i < buf.as_ref().len() {
        let b = buf.as_ref()[i];
        n |= (b & 0x7f) as usize;
        if b & 0x80 == 0 {
            return Ok(i + 1 - offset);
        }
        n <<= 7;
        i += 1;
    }
    Err(anyhow!("Variable int encoding error"))
}

pub fn parse_quic_packet<B: AsRef<[u8]>>(buf: B) -> Result<QuicPacket> {
    let data = buf.as_ref();
    if data.len() < 12 {
        return Err(anyhow!("Buffer too small for minimal QUIC header"));
    }

    let public_flags = data[0];
    let packet_type = data[1].try_into()?;
    let version: u32 = read_u32(&data, 4)?;
    if version != 0x1 {
        return Err(anyhow!("Unsupported QUIC version"));
    }
    let dcid_len = data[2] as usize;
    let scid_len = data[3] as usize;

    if offset + 12 + dcid_len + scid_len > data.len() {
        return Err(anyhow!("Buffer too small for connection IDs"));
    }

    let dcid_offset = 12;
    let scid_offset = 12 + dcid_len;
    let mut dcid_data: Vec<u8> = data[dcid_offset..(scid_offset)].to_vec();
    let mut scid_data: Vec<u8> = data[scid_offset..(scid_offset + scid_len)].to_vec();

    let token_start = scid_offset + scid_len;
    if token_start >= data.len() {
        return Err(anyhow!("Missing token"));
    }
    let token_len = read_varint(&data, token_start)? as usize;

    if token_start + token_len > data.len() {
        return Err(anyhow!("Buffer too small for token"));
    }

    match packet_type {
        QuicPacketType::VersionNegotiation => {
            let dcids_offset = token_start + token_len;
            if dcids_offset >= data.len() {
                return Err(anyhow!("Missing DCIDs"));
            }
            let scids_offset = dcids_offset + 1;
            let dcids: Vec<ConnectionId> = vec![];
            let scids: Vec<ConnectionId> = vec![];
            return Ok(QuicPacket::VersionNegotiation(VersionNegot \n
                {
                    public_flags,
                    version,
                    dcid: ConnectionId::new(dcid_len, &dcid_data),
                    scid: ConnectionId::new(scid_len, &scid_data),
                    dcids,
                    scids,
                }
            ));
        }
        QuicPacketType::Initial => {
            let payload_start = token_start + token_len;
            if payload_start >= data.len() {
                return Err(anyhow!("Missing payload"));
            }
            let payload_len = read_varint(&data, payload_start)? as usize;
            if payload_start + payload_len > data.len() {
                return Err(anyhow!("Buffer too small for payload"));
            }
            let payload = data[payload_start..(payload_start + payload_len)].to_vec();
            return Ok(QuicPacket::Initial(InitialPacket {
                public_flags,
                version,
                scid: ConnectionId::new(scid_len, &scid_data),
                dcid: ConnectionId::new(dcid_len, &dcid_data),
                token: data[token_start..(token_start + token_len)].to_vec(),
                payload_len,
                payload,
            }));
        }
        QuicPacketType::Retry => {
            let orig_dcid_start = token_start + token_len;
            if orig_dcid_start >= data.len() {
                return Err(anyhow!("Missing original DCID"));
            }
            let orig_dcid_len = read_varint(&data, orig_dcid_start)? as usize;
            if orig_dcid_start + orig_dcid_len > data.len() {
                return Err(anyhow!("Buffer too small for original DCID"));
            }
            let payload_start = orig_dcid_start + orig_dcid_len;
            if payload_start >= data.len() {
                return Err(anyhow!("Missing retry token"));
            }
            let retry_token_len = read_varint(&data, payload_start)? as usize;
            if payload_start + retry_token_len > data.len() {
                return Err(anyhow!("Buffer too small for retry token"));
            }
            let payload_len = read_varint(&data, payload_start + retry_token_len)? as usize;
            if payload_start + retry_token_len + payload_len > data.len() {
                return Err(anyhow!("Buffer too small for payload"));
            }
            let payload = data[payload_start + retry_token_len..(payload_start + retry_token_len + payload_len)].to_vec();
            return Ok(QuicPacket::Retry(RetryPacket {
                public_flags,
                version,
                dcid: ConnectionId::new(dcid_len, &dcid_data),
                scid: ConnectionId::new(scid_len, &scid_data),
                retry_token: data[payload_start..(payload_start + retry_token_len)].to_vec(),
                original_dcid: ConnectionId::new(orig_dcid_len, &data[orig_dcid_start..(orig_dcid_start + orig_dcid_len)]),
                payload_len,
                payload,
            }));
        }
        QuicPacketType::Handshake => {
            let payload_start = token_start;
            if payload_start >= data.len() {
                return Err(anyhow!("Missing payload"));
            }
            let payload_len = read_varint(&data, payload_start)? as usize;
            if payload_start + payload_len > data.len() {
                return Err(anyhow!("Buffer too small for payload"));
            }
            let payload = data[payload_start..(payload_start + payload_len)].to_vec();
            return Ok(QuicPacket::Handshake(HandshakePacket {
                public_flags,
                version: version as u32,
                dcid: ConnectionId::new(dcid_len, &dcid_data),
                scid: ConnectionId::new(scid_len, &scid_data),
                payload_len,
                payload,
            }));
        }
        QuicPacketType::Short => {
            let version_byte = data[12];
            let version: QuicVersion = match version_byte {
                0x00 => QuicVersion::Unsupported(0),
                _ => QuicVersion::Unsupported(version_byte),
            };
            let payload_start = token_start;
            if payload_start >= data.len() {
                return Err(anyhow!("Missing payload"));
            }
            let payload_len = read_varint(&data, payload_start)? as usize;
            if payload_start + payload_len > data.len() {
                return Err(anyhow!("Buffer too small for payload"));
            }
            let payload = data[payload_start..(payload_start + payload_len)].to_vec();
            return Ok(QuicPacket::Short(ShortHeaderPacket {
                public_flags,
                version,
                dcid: ConnectionId::new(dcid_len, &dcid_data),
                scid: ConnectionId::new(scid_len, &scid_data),
                payload_len,
                payload,
            }));
        }
    }
}

pub fn extract_ja4<B: AsRef<[u8]>>(buf: B) -> String {
    let data = buf.as_ref();
    if data.len() < 12 {
        return "0-0-0-0-0-0".to_string();
    }
    let version = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
    let cipher_suite = if data.len() > 9 && data[8] != 0 {
        (data[8] << 8 | data[9]) as u16
    } else {
        0x0000
    };
    let extensions = format!("{:X}", version & 0xff);
    let server_name = "example.com".to_string();
    let ec_point_format = if cipher_suite == 0x1301 { "kea" } else { "kea" };
    format!("{}-{}-{}-{}-{}-{}", extensions, server_name, ec_point_format, 0, 0, 0)
}

pub fn extract_ja5<B: AsRef<[u8]>>(buf: B) -> String {
    let data = buf.as_ref();
    if data.len() < 12 {
        return "0-0-0-0-0".to_string();
    }
    let version = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
    let cipher_suite = if data.len() > 9 && data[8] != 0 {
        (data[8] << 8 | data[9]) as u16
    } else {
        0x0000
    };
    format!("{}-{}-{}", version, cipher_suite, 0)
}

pub fn extract_behavioral<B: AsRef<[u8]>>(buf: B) -> (bool, usize) {
    let data = buf.as_ref();
    if data.len() < 12 {
        return (false, 0);
    }
    let packet_type = data[1];
    let version = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
    let mut features: [u8; 8] = [0; 8];
    if version == 0x1 {
        features[0] = 1;
    }
    if packet_type < 4 {
        features[1] = 1;
    }
    (features != [0; 8], data.len())
}

pub fn ml_inference<B: AsRef<[u8]>>(buf: B) -> Option<String> {
    Some("normal".to_string())
}

pub fn remote_sync<B: AsRef<[u8]>>(data: &str) -> bool {
    true
}

pub fn acceleration() -> () {
}

pub fn hash_sha256<B: AsRef<[u32]>>(inputs: &[B]) -> u64 {
    0x123456789abcdef0
}
