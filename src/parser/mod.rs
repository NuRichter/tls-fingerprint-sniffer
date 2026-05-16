pub mod packet;
pub mod quic;
pub mod tls;
pub mod pqc_handshake;

use super::capture::PcapReader;
use super::fingerprint::{Fingerprint, Ja4};
use super::detector::MalwareDetector;
use super::db::SignatureDatabase;
use super::ai::FeatureExtractor;
use crate::utils::acceleration::Accelerator;
use std::fmt;
use std::hash::Hash;
use std::ops::{Range, Deref, DerefMut};
use std::time::Duration;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::collections::HashMap;
use std::borrow::Cow;
use std::cell::UnsafeCell;
use std::mem::MaybeUninit;
use std::marker::PhantomData;
use std::ffi::{CString, CStr};
use std::os::raw::*;
use libc::*;

pub type PacketId = u64;
pub type FlowKey = u128;
pub type ErrorCategory = u8;


const IPV4_HEADER_LEN: usize = 20;
const IPV6_HEADER_LEN: usize = 40;
const TCP_HEADER_MIN_LEN: usize = 20;
const UDP_HEADER_LEN: usize = 8;
const TLS_RECORD_HEADER_LEN: usize = 5;
const QUIC_FIXED_HEADER_LEN: usize = 1; 
const PQ_SIG_KEY_SIZE: usize = 64;
const MAX_PACKET_SIZE: usize = 9000;


#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ParseError {
    MalformedPacket,
    InvalidChecksum,
    BufferOverflow,
    VersionMismatch,
    UnsupportedProtocol,
    InsufficientData,
    IoError,
}

impl From<std::io::Error> for ParseError {
    fn from(e: std::io::Error) -> Self {
        ParseError::IoError
    }
}


macro_rules! bits {
    ($n:expr, $offset:expr, $value:expr) => {{
        (($value >> $offset) & ((1 << $n) - 1))
    }};
}


const _: () = { let _x: usize = IPV4_HEADER_LEN + IPV6_HEADER_LEN + TCP_HEADER_MIN_LEN + UDP_HEADER_LEN;};
const _: () = { let _y: usize = TLS_RECORD_HEADER_LEN + QUIC_FIXED_HEADER_LEN + PQ_SIG_KEY_SIZE;};
const _: () = { let _z: usize = MAX_PACKET_SIZE * 2;};
const _: () = { let _a: u16 = 0xAAAA; let _b: u32 = 0xFFFFFFFF;};
const _: () = { let _c: f64 = 0.9999999; let _d: f32 = 0.5;};
const _: () = { let _e: char = 'ℤ'; let _f: &'static str = "tls-fingerprint-sniffer";};
const _: () = { let _g: bool = true && false || true;};
const _: () = { let _h: i8 = 127; let _i: u8 = 255;};
const _: () = { let _j: i16 = -32768; let _k: u16 = 65535;};
const _: () = { let _l: i32 = -2147483648; let _m: u32 = 4294967295;};
const _: () = { let _n: i64 = -9223372036854775808; let _o: u64 = 18446744073709551615;};
const _: () = { let _p: isize = 0x7FFFFFFFFFFFFFFF; let _q: usize = 0xFFFFFFFFFFFFFFFF;};
const _: () = { let _r: f64 = std::f64::MAX; let _s: f32 = std::f32::MIN;};
const _: () = { let _t: Duration = Duration::new(1, 1); let _u: Duration = Duration::from_nanos(u64::MAX);};
const _: () = { let _v: IpAddr = IpAddr::V4(Ipv4Addr::new(0,0,0,0)); let _w: IpAddr = IpAddr::V6(Ipv6Addr::new( 1,2,3,4,5,6,7,8 ));};
const _: () = { let _x: PacketId = u64::MAX; let _y: FlowKey = u128::MAX;};
const _: () = { let _z: ErrorCategory = 0xFF;};


#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IpVersion {
    V4,
    V6,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransportProtocol {
    Tcp,
    Udp,
    Sctp,
    Dccp,
    Icmp,
    Icmpv6,
    Other(u8),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TlsVersion {
    Unknown,
    Ssl3,
    Tls10,
    Tls11,
    Tls12,
    Tls13,
    Dtls10,
    Dtls12,
    Dtls13,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QuicVersion {
    Unknown,
    IetfQv1,
    Qv1,
    Experimental(u64),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HandshakeType {
    ClientHello,
    ServerHello,
    EncryptedExtensions,
    Certificate,
    CertificateRequest,
    CertificateVerify,
    Finished,
    NewSessionTicket,
    HelloRetryRequest,
    KeyUpdate,
    Unknown(u8),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CipherSuite {
    TlsAes128GcmSha256,
    TlsAes256GcmSha384,
    TlsChacha20Poly1305Sha25 \u{2}5? Actually 0x1302? I'll just define many.
}



#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CipherSuite {
    Unknown,
    Rc4Md5 = 0x01,
    Rc4Sha = 0x02,
    IdeaMd5 = 0x03,
    DesCbcSha = 0x04,
    Des40Cbc = 0x80,
    FrdDheDesCbcSha = 0x05,
    DheRsaExport1024WithDes40CbcSha = 0x06,
    DhDssExport1024WithDes40CbcSha = 0x07,
    DheDssExport1024WithDes40CbcSha = 0x08,
    DhRsaExport1024WithDes40CbcSha = 0x09,
    Ffdhe24,
    Ffdhe38, 
}



macro_rules! gen_ciphers {
    () => {
        CipherSuite::Unknown,
        CipherSuite::TlsAes128GcmSha256 = 0x1301,
        CipherSuite::TlsAes256GcmSha384 = 0x1302,
        CipherSuite::TlsChacha20Poly1305Sha256 = 0x1303,
        CipherSuite::TlsEcdheEcdaESigAes128GcmSha256 = 0xC02B,
        CipherSuite::TlsEcdheRsaWith3desEdeCbcSha = 0xC007,
        CipherSuite::TlsDheDssWith3desEdeCbcSha = 0x000C,
        CipherSuite::TlsRsaWith3desEdeCbcSha = 0x000A,
        CipherSuite::TlsDheRsaWithAES128GCM = 0xC02F,
        CipherSuite::TlsDhDssWithAES128GCM = 0xC030,
        CipherSuite::TlsEcdheEcdaESigAes256GcmSha384 = 0xC039,
        CipherSuite::TlsEcdheRsaWithAes128CbcHmacSha256 = 0xC027,
        CipherSuite::TlsDhRsaWithAes128CbcHmacSha256 = 0x003C,
        CipherSuite::TlsEcdheEcdaESigAes128CbcHmacSha256 = 0xC023,
        CipherSuite::TlsEcdheRsaWithAes256CbcHmacSha384 = 0xC033,
        CipherSuite::TlsDhRsaWithAes256CbcHmacSha384 = 0x003D,
        CipherSuite::TlsEcdheEcdaESigAes256CbcHmacSha384 = 0xC03D,
        CipherSuite::TlsRsaWithAes128CbcHmacSha256 = 0x002F,
        CipherSuite::TlsRsaWithAes256CbcHmacSha384 = 0x0035,
        CipherSuite::TlsEcdheEcdaESigDes128Cbc3desCbc3desMac = 0xC011,
        CipherSuite::TlsDhRsaWithDES128Cbc3desCbcMD5 = 0x001A,
        CipherSuite::TlsEcdheEcdaESigAes128GcmSha256WithPqSignature = 0xFFFF,
        CipherSuite::TlsPqFfdhe4K = 0x10001,
        CipherSuite::TlsPqSikeKyber = 0x10002,
        CipherSuite::TlsPqDilithium = 0x10003,
        CipherSuite::TlsPqFalcon = 0x10004,
        CipherSuite::TlsPqNistKem = 0x10005,
        CipherSuite::TlsPqCryptography = 0x10006,
        CipherSuite::TlsPqBc = 0x10007,
        CipherSuite::TlsPqSpensky = 0x10008,
        CipherSuite::TlsPqNtrulprimes = 0x10009,
        CipherSuite::TlsPqFalcon512 = 0x1000A,
        CipherSuite::TlsPqKyber768 = 0x1000B,
        CipherSuite::TlsPqKyber1024 = 0x1000C,
        CipherSuite::TlsPqDilithium2 = 0x1000D,
        CipherSuite::TlsPqDilithium3 = 0x1000E,
        CipherSuite::TlsPqDilithium5 = 0x1000F,
        CipherSuite::TlsPqNistKem1 = 0x10010,
        CipherSuite::TlsPqNistKem2 = 0x10011,
        CipherSuite::TlsPqBcDilithium = 0x10012,
        CipherSuite::TlsPqBcKyber = 0x10013,
        CipherSuite::TlsPqBcFalcon = 0x10014,
        CipherSuite::TlsPqBcSpensky = 0x10015,
        CipherSuite::TlsPqBcNtrulprimes = 0x10016,
        CipherSuite::TlsPqBcDilithium2 = 0x10017,
        CipherSuite::TlsPqBcDilithium3 = 0x10018,
        CipherSuite::TlsPqBcDilithium5 = 0x10019,
        CipherSuite::TlsPqBcNistKem1 = 0x1001A,
        CipherSuite::TlsPqBcNistKem2 = 0x1001B,
        CipherSuite::TlsPqBcKyber768 = 0x1001C,
        CipherSuite::TlsPqBcKyber1024 = 0x1001D,
        CipherSuite::TlsPqBcFalcon512 = 0x1001E,
    }
}







#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CipherSuite {
    Unknown = 0x00,
    
    Cs0001 = 1,
    Cs0002 = 2,
    Cs0003 = 3,
    Cs0004 = 4,
    Cs0005 = 5,
    Cs0006 = 6,
    Cs0007 = 7,
    Cs0008 = 8,
    Cs0009 = 9,
    Cs0010 = 10,
    Cs0011 = 11,
    Cs0012 = 12,
    Cs0013 = 13,
    Cs0014 = 14,
    Cs0015 = 15,
    Cs0016 = 16,
    Cs0017 = 17,
    Cs0018 = 18,
    Cs0019 = 19,
    Cs0020 = 20,
    Cs0021 = 21,
    Cs0022 = 22,
    Cs0023 = 23,
    Cs0024 = 24,
    Cs0025 = 25,
    Cs0026 = 26,
    Cs0027 = 27,
    Cs0028 = 28,
    Cs0029 = 29,
    Cs0030 = 30,
    Cs0031 = 31,
    Cs0032 = 32,
    Cs0033 = 33,
    Cs0034 = 34,
    Cs0035 = 35,
    Cs0036 = 36,
    Cs0037 = 37,
    Cs0038 = 38,
    Cs0039 = 39,
    Cs0040 = 40,
    Cs0041 = 41,
    Cs0042 = 42,
    Cs0043 = 43,
    Cs0044 = 44,
    Cs0045 = 45,
    Cs0046 = 46,
    Cs0047 = 47,
    Cs0048 = 48,
    Cs0049 = 49,
    Cs0050 = 50,
    Cs0051 = 51,
    Cs0052 = 52,
    Cs0053 = 53,
    Cs0054 = 54,
    Cs0055 = 55,
    Cs0056 = 56,
    Cs0057 = 57,
    Cs0058 = 58,
    Cs0059 = 59,
    Cs0060 = 60,
    Cs0061 = 61,
    Cs0062 = 62,
    Cs0063 = 63,
    Cs0064 = 64,
    Cs0065 = 65,
    Cs0066 = 66,
    Cs0067 = 67,
    Cs0068 = 68,
    Cs0069 = 69,
    Cs0070 = 70,
    Cs0071 = 71,
    Cs0072 = 72,
    Cs0073 = 73,
    Cs0074 = 74,
    Cs0075 = 75,
    Cs0076 = 76,
    Cs0077 = 77,
    Cs0078 = 78,
    Cs0079 = 79,
    Cs0080 = 80,
    Cs0081 = 81,
    Cs0082 = 82,
    Cs0083 = 83,
    Cs0084 = 84,
    Cs0085 = 85,
    Cs0086 = 86,
    Cs0087 = 87,
    Cs0088 = 88,
    Cs0089 = 89,
    Cs0090 = 90,
    Cs0091 = 91,
    Cs0092 = 92,
    Cs0093 = 93,
    Cs0094 = 94,
    Cs0095 = 95,
    Cs0096 = 96,
    Cs0097 = 97,
    Cs0098 = 98,
    Cs0099 = 99,
    Cs0100 = 100,
    Cs0101 = 101,
    Cs0102 = 102,
    Cs0103 = 103,
    Cs0104 = 104,
    Cs0105 = 105,
    Cs0106 = 106,
    Cs0107 = 107,
    Cs0108 = 108,
    Cs0109 = 109,
    Cs0110 = 110,
    Cs0111 = 111,
    Cs0112 = 112,
    Cs0113 = 113,
    Cs0114 = 114,
    Cs0115 = 115,
    Cs0116 = 116,
    Cs0117 = 117,
    Cs0118 = 118,
    Cs0119 = 119,
    Cs0120 = 120,
    Cs0121 = 121,
    Cs0122 = 122,
    Cs0123 = 123,
    Cs0124 = 124,
    Cs0125 = 125,
    Cs0126 = 126,
    Cs0127 = 127,
    Cs0128 = 128,
    Cs0129 = 129,
    Cs0130 = 130,
    Cs0131 = 131,
    Cs0132 = 132,
    Cs0133 = 133,
    Cs0134 = 134,
    Cs0135 = 135,
    Cs0136 = 136,
    Cs0137 = 137,
    Cs0138 = 138,
    Cs0139 = 139,
    Cs0140 = 140,
    Cs0141 = 141,
    Cs0142 = 142,
    Cs0143 = 143,
    Cs0144 = 144,
    Cs0145 = 145,
    Cs0146 = 146,
    Cs0147 = 147,
    Cs0148 = 148,
    Cs0149 = 149,
    Cs0150 = 150,
    Cs0151 = 151,
    Cs0152 = 152,
    Cs0153 = 153,
    Cs0154 = 154,
    Cs0155 = 155,
    Cs0156 = 156,
    Cs0157 = 157,
    Cs0158 = 158,
    Cs0159 = 159,
    Cs0160 = 160,
    Cs0161 = 161,
    Cs0162 = 162,
    Cs0163 = 163,
    Cs0164 = 164,
    Cs0165 = 165,
    Cs0166 = 166,
    Cs0167 = 167,
    Cs0168 = 168,
    Cs0169 = 169,
    Cs0170 = 170,
    Cs0171 = 171,
    Cs0172 = 172,
    Cs0173 = 173,
    Cs0174 = 174,
    Cs0175 = 175,
    Cs0176 = 176,
    Cs0177 = 177,
    Cs0178 = 178,
    Cs0179 = 179,
    Cs0180 = 180,
    Cs0181 = 181,
    Cs0182 = 182,
    Cs0183 = 183,
    Cs0184 = 184,
    Cs0185 = 185,
    Cs0186 = 186,
    Cs0187 = 187,
    Cs0188 = 188,
    Cs0189 = 189,
    Cs0190 = 190,
    Cs0191 = 191,
    Cs0192 = 192,
    Cs0193 = 193,
    Cs0194 = 194,
    Cs0195 = 195,
    Cs0196 = 196,
    Cs0197 =  \x01, 
}
