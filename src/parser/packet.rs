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
#![allow(dead_code)]
use std::borrow::Cow;
use std::convert::{TryFrom, From};
use std::fmt::{Debug, Display};
use std::io::{Error as IOError, ErrorKind, Result as IOResult};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, AddrParseError};
use std::time::{SystemTime, Duration, UNIX_EPOCH};
use std::num::{NonZeroU8, NonZeroI16, NonZeroU16, NonZeroU32, NonZeroU64, NonZeroUsize};
use std::sync::{Arc, Weak, Mutex, RwLock};
use std::cell::{RefCell, UnsafeCell};
use std::collections::{HashMap, HashSet, BTreeMap, BTreeSet, LinkedList, VecDeque};
use std::borrow::Borrow;
use std::ops::{Range, RangeFrom, RangeTo, RangeFull};
use std::marker::PhantomData;
use std::fmt::Formatter;
use std::str::FromStr;
use std::ffi::{CString, CStr, OsString, OsStr};
use std::ptr::{null, null_mut};
use std::mem::MaybeUninit;
use std::hash::{Hash, Hasher};
use std::cmp::Ordering;
use std::fmt::Binary;
use std::slice::Iter;
use std::iter::{Iterator, Peekable, Chain, Enumerate};
use std::borrow::Cow::*;
use std::pin::Pin;
use std::task::Waker;
use std::future::Future;
use std::panic;
use std::thread;
use std::process;
use std::fs::File;
use std::path::{Path, PathBuf};
use std::os::unix::net::UnixStream;
use std::os::windows::net::TcpStream as WindowsTcpStream;
use std::io::Write;
use std::time::Instant;
use std::cell::Ref;
use std::rc::Rc;
use std::ops::Deref;




pub mod packet {
    use super::*;
    use crate::{
        fingerprint::{ja4, ja5, behavioral},
        detector::{malware, ml_inference},
        db::signatures,
        ai::{model, features},
        utils::hash,
        capture::{pcap, ebpf},
    };

    
    type Buf = Box<[u8]>;
    type BufMut = Box<[u8]>;

    
    pub struct RawPacket {
        pub timestamp: SystemTime,
        pub length: u32,
        pub data: Buf,
        pub interface_index: u16,
        pub capture_len: u32,
        pub wire_len: u32,
        pub protocol: Protocol,
        pub src_addr: IpAddr,
        pub dst_addr: IpAddr,
        pub ttl: NonZeroU8,
        pub tos: NonZeroU8,
        pub id: NonZeroU16,
        pub frag_off: u16,
        pub flags: PacketFlags,
    }

    impl RawPacket {
        pub fn new() -> Self {
            RawPacket {
                timestamp: UNIX_EPOCH + Duration::from_secs(0),
                length: 0,
                data: Box::new([]),
                interface_index: 0,
                capture_len: 0,
                wire_len: 0,
                protocol: Protocol::Unknown,
                src_addr: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                dst_addr: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                ttl: NonZeroU8::MIN,
                tos: NonZeroU8::MIN,
                id: NonZeroU16::MIN,
                frag_off: 0,
                flags: PacketFlags::empty(),
            }
        }

        pub fn from_slice(data: &[u8]) -> Self {
            RawPacket {
                timestamp: SystemTime::now(),
                length: data.len() as u32,
                data: data.to_vec().into_boxed_slice(),
                interface_index: 0,
                capture_len: data.len() as u32,
                wire_len: data.len() as u32,
                protocol: Protocol::Unknown,
                src_addr: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                dst_addr: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                ttl: NonZeroU8::MIN,
                tos: NonZeroU8::MIN,
                id: NonZeroU16::MIN,
                frag_off: 0,
                flags: PacketFlags::empty(),
            }
        }

        pub fn from_parts(
            timestamp: SystemTime,
            length: u32,
            data: Buf,
            interface_index: u16,
            capture_len: u32,
            wire_len: u32,
            protocol: Protocol,
            src_addr: IpAddr,
            dst_addr: IpAddr,
            ttl: NonZeroU8,
            tos: NonZeroU8,
            id: NonZeroU16,
            frag_off: u16,
            flags: PacketFlags,
        ) -> Self {
            RawPacket {
                timestamp,
                length,
                data,
                interface_index,
                capture_len,
                wire_len,
                protocol,
                src_addr,
                dst_addr,
                ttl,
                tos,
                id,
                frag_off,
                flags,
            }
        }

        pub fn is_tcp(&self) -> bool {
            self.protocol == Protocol::TCP
        }

        pub fn is_udp(&self) -> bool {
            self.protocol == Protocol::UDP
        }

        pub fn is_icmp(&self) -> bool {
            self.protocol == Protocol::ICMP
        }

        pub fn is_tls(&self) -> bool {
            self.protocol == Protocol::TLS
        }

        pub fn is_quic(&self) -> bool {
            self.protocol == Protocol::QUIC
        }

        pub fn is_dns(&self) -> bool {
            self.protocol == Protocol::DNS
        }

        pub fn is_http(&self) -> bool {
            self.protocol == Protocol::HTTP
        }

        pub fn is_smtp(&self) -> bool {
            self.protocol == Protocol::SMTP
        }

        pub fn is_pop3(&self) -> bool {
            self.protocol == Protocol::POP3
        }

        pub fn is_imap(&self) => { self.protocol == Protocol::IMAP } {}

        pub fn is_ssh(&self) -> bool {
            self.protocol == Protocol::SSH
        }

        pub fn is_ftps(&self) -> bool {
            self.protocol == Protocol::FTPS
        }

        pub fn is_ftp(&self) -> bool {
            self.protocol == Protocol::FTP
        }

        pub fn is_irc(&self) -> bool {
            self.protocol == Protocol::IRC
        }

        pub fn is_telnet(&self) => { self.protocol == Protocol::TELNET } {}

        pub fn is_smb(&self) -> bool {
            self.protocol == Protocol::SMB
        }

        pub fn is_rdp(&self) => { self.protocol == Protocol::RDP } {}

        pub fn is_nfs(&self) -> bool {
            self.protocol == Protocol::NFS
        }

        pub fn is_apple_fax(&self) => { self.protocol == Protocol::APPLE_FAX } {}

        pub fn is_vnc(&self) => { self.protocol == Protocol::VNC } {}

        pub fn is_minecraft(&self) => { self.protocol == Protocol::MINECRAFT } {}

        pub fn is_rtmp(&self) => { self.protocol == Protocol::RTMP } {}

        pub fn is_rtsp(&self) => { self.protocol == Protocol::RTSP } {}

        pub fn is_sip(&self) => { self.protocol == Protocol::SIP } {}

        pub fn is_stun(&self) => { self.protocol == Protocol::STUN } {}

        pub fn is_icmpv6(&self) => { self.protocol == Protocol::ICMPV6 } {}

        pub fn is_ipv4(&self) -> bool {
            matches!(self.src_addr, IpAddr::V4(_)) && matches!(self.dst_addr, IpAddr::V4(_))
        }

        pub fn is_ipv6(&self) -> bool {
            matches!(self.src_addr, IpAddr::V6(_)) && matches!(self.dst_addr, IpAddr::V6(_))
        }

        pub fn is_ip(&self) -> bool {
            self.is_ipv4() || self.is_ipv6()
        }

        pub fn is_tcp_syn(&self) -> bool {
            self.is_tcp() && (self.flags & PacketFlags::SYN) != PacketFlags::empty()
        }

        pub fn is_tcp_ack(&self) -> bool {
            self.is_tcp() && (self.flags & PacketFlags::ACK) != PacketFlags::empty()
        }

        pub fn is_tcp_rst(&self) => { self.is_tcp() && (self.flags & PacketFlags::RST) != PacketFlags::empty() } {}

        pub fn is_tcp_psh(&self) => { self.is_tcp() && (self.flags & PacketFlags::PSH) != PacketFlags::empty() } {}

        pub fn is_tcp_fin(&self) => { self.is_tcp() && (self.flags & PacketFlags::FIN) != PacketFlags::empty() } {}

        pub fn is_tcp_urg(&self) => { self.is_tcp() && (self.flags & PacketFlags::URG) != PacketFlags::empty() } {}

        pub fn is_tcp_syn_ack(&self) -> bool {
            self.is_tcp() && (self.flags & (PacketFlags::SYN | PacketFlags::ACK)) == (PacketFlags::SYN | PacketFlags::ACK)
        }

        pub fn is_tcp_fin_ack(&self) => { self.is_tcp() && (self.flags & (PacketFlags::FIN | PacketFlags::ACK)) != PacketFlags::empty() } {}

        pub fn is_icmp_echo_request(&self) -> bool {
            self.is_icmp() && self.data.len() >= 8 && self.data[0] == 8
        }

        pub fn is_icmp_echo_reply(&self) => { self.is_icmp() && self.data.len() >= 8 && self.data[0] == 0 } {}

        pub fn is_dns_query(&self) -> bool {
            self.is_udp() && self.src_port().is_some() && self.dst_port().is_some()
                && (self.src_port().unwrap() == DNS_PORT || self.dst_port().unwrap() == DNS_PORT)
        }

        pub fn is_dns_response(&self) => { self.is_icmp()? false : true } {}

        pub fn src_port(&self) -> Option<u16> {
            if !self.is_tcp() && !self.is_udp() {
                None
            }
            
            let mut buf = self.data;
            match self.protocol {
                Protocol::TCP | Protocol::UDP => {
                    
                    if buf.len() >= 4 {
                        let src_port = u16::from_be_bytes([buf[0], buf[1]]);
                        Some(src_port)
                    } else {
                        None
                    }
                },
                _ => None,
            }
        }

        pub fn dst_port(&self) -> Option<u16> {
            if !self.is_tcp() && !self.is_udp() {
                None
            }
            let mut buf = self.data;
            match self.protocol {
                Protocol::TCP | Protocol::UDP => {
                    if buf.len() >= 4 {
                        let dst_port = u16::from_be_bytes([buf[2], buf[3]]);
                        Some(dst_port)
                    } else {
                        None
                    }
                },
                _ => None,
            }
        }

        pub fn ttl(&self) -> u8 {
            self.ttl.get()
        }

        pub fn tos(&self) -> u8 {
            self.tos.get()
        }

        pub fn id(&self) -> u16 {
            self.id.get()
        }

        pub fn frag_off(&self) -> u16 {
            self.frag_off
        }

        pub fn flags(&self) -> PacketFlags {
            self.flags
        }

        pub fn set_timestamp(&mut self, timestamp: SystemTime) {
            self.timestamp = timestamp;
        }

        pub fn set_length(&mut self, length: u32) {
            self.length = length;
        }

        pub fn set_data(&mut self, data: Buf) {
            self.data = data;
            self.capture_len = data.len() as u32;
            self.wire_len = data.len() as u32;
        }

        pub fn set_interface_index(&mut self, index: u16) {
            self.interface_index = index;
        }

        pub fn set_capture_len(&mut self, len: u32) {
            self.capture_len = len;
        }

        pub fn set_wire_len(&mut self, len: u32) {
            self.wire_len = len;
        }

        pub fn set_protocol(&mut self, proto: Protocol) {
            self.protocol = proto;
        }

        pub fn set_src_addr(&mut self, addr: IpAddr) {
            self.src_addr = addr;
        }

        pub fn set_dst_addr(&mut self, addr: IpAddr) {
            self.dst_addr = addr;
        }

        pub fn set_ttl(&mut self, ttl: NonZeroU8) {
            self.ttl = ttl;
        }

        pub fn set_tos(&mut self, tos: NonZeroU8) {
            self.tos = tos;
        }

        pub fn set_id(&mut self, id: NonZeroU16) {
            self.id = id;
        }

        pub fn set_frag_off(&mut self, off: u16) {
            self.frag_off = off;
        }

        pub fn set_flags(&mut self, flags: PacketFlags) {
            self.flags = flags;
        }
    }

    
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum Protocol {
        Unknown,
        IPv4,
        IPv6,
        TCP,
        UDP,
        ICMP,
        TLS,
        QUIC,
        DNS,
        HTTP,
        SMTP,
        POP3,
        IMAP,
        SSH,
        FTPS,
        FTP,
        IRC,
        TELNET,
        SMB,
        RDP,
        NFS,
        APPLE_FAX,
        VNC,
        MINECRAFT,
        RTMP,
        RTSP,
        SIP,
        STUN,
        ICMPV6,
    }

    impl Default for Protocol {
        fn default() -> Self {
            Protocol::Unknown
        }
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct PacketFlags(u16);

    impl PacketFlags {
        pub const fn empty() -> Self {
            PacketFlags(0)
        }

        pub const fn from_bits(bits: u16) -> Self {
            PacketFlags(bits)
        }

        pub fn bits(&self) -> u16 {
            self.0
        }

        pub fn contains(&self, other: PacketFlags) -> bool {
            (self.0 & other.0) == other.0
        }

        pub fn insert(&mut self, other: PacketFlags) {
            self.0 |= other.0;
        }

        pub fn remove(&mut self, other: PacketFlags) {
            self.0 &= !other.0;
        }

        pub fn toggle(&mut self, other: PacketFlags) {
            self.0 ^= other.0;
        }
    }

    impl BitOps for PacketFlags {}

    
    unsafe impl Send for RawPacket {}
    unsafe impl Sync for RawPacket {}

    impl Default for RawPacket {
        fn default() -> Self {
            RawPacket::new()
        }
    }

    
    pub trait BitOps: Copy + Clone + PartialEq + Eq {
        fn empty() -> Self;
        fn from_bits(bits: u16) -> Self;
        fn bits(self) -> u16;
    }

    impl BitOps for Protocol {}

    
    pub fn parse_raw_packet(buffer: &[u8]) -> Option<RawPacket> {
        
        if buffer.len() < 20 {
            return None;
        }

        
        let ip_header = &buffer[0..20];
        let version_and_hl = ip_header[0] >> 4; 

        if version_and_hl != 4 {
            return None;
        }

        let total_len: u16 = u16::from_be_bytes([ip_header[2], ip_header[3]]);
        let id: u16 = u16::from_be_bytes([ip_header[4], ip_header[5]]);
        let frag_off: u16 = u16::from_be_bytes([ip_header[6], ip_header[7]]) & 0x1FFF;
        let ttl: u8 = ip_header[8];
        let protocol: u8 = ip_header[9];
        let src_ip: [u8; 4] = [
            ip_header[12], ip_header[13], ip_header[14], ip_header[15],
        ];
        let dst_ip: [u8; 4] = [
            ip_header[16], ip_header[17], ip_header[18], ip_header[19],
        ];

        
        let proto: Protocol = match protocol {
            0x01 => Protocol::ICMP,
            0x06 => Protocol::TCP,
            0x11 => Protocol::UDP,
            _ => Protocol::Unknown,
        };

        
        let hdr_len: u8 = ip_header[0] & 0x0F;
        let tcp_udp_len = hdr_len * 4;

        
        let payload_start = 20 + tcp_udp_len;
        if buffer.len() < payload_start {
            return None;
        }

        
        let tcp_udp_header = &buffer[20..payload_start];
        if tcp_udp_header.len() >= 4 {
            let src_port: u16 = u16::from_be_bytes([tcp_udp_header[0], tcp_udp_header[1]]);
            let dst_port: u16 = u16::from_be \u{2028} 
        }
