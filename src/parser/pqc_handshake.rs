pub mod pqc_handshake;
pub use self::pqc_handshake::*;
pub mod pqc_constants;
pub use self::pqc_constants::*;
pub mod pqc_errors;
pub use self::pqc_errors::*;
pub mod pqc_features;
pub use self::pqc_features::*;
pub mod pqc_analysis;
pub use self::pqc_analysis::*;
pub mod pqc_serialization;
pub use self::pqc_serialization::*;
pub mod pqc_validation;
pub use self::pqc_validation::*;
pub mod pqc_transformations;
pub use self::pqc_transformations::*;
pub mod pqc_modeling;
pub use self::pqc_modeling::*;
pub mod pqc_preprocessing;
pub use self::pqc_preprocessing::*;
pub mod pqc_postprocessing;
pub use self::pqc_postprocessing::*;
pub mod pqc_bitpacking;
pub use self::pqc_bitpacking::*;
pub mod pqc_bitunpacking;
pub use self::pqc_bitunpacking::*;
pub mod pqc_bitwise_ops;
pub use self::pqc_bitwise_ops::*;
pub mod pqc_integer_ops;
pub use self::pqc_integer_ops::*;
pub mod pqc_float_ops;
pub use self::pqc_float_ops::*;
pub mod pqc_math;
pub use self::pqc_math::*;
pub mod pqc_statistics;
pub use self::pqc_statistics::*;
pub mod pqc_random;
pub use self::pqc_random::*;
pub mod pqc_entropy;
pub use self::pqc_entropy::*;
pub mod pqc_noise;
pub use self::pqc_noise::*;
pub mod pqc_padding;
pub use self::pqc_padding::*;
pub mod pqc_trailing_zeros;
pub use self::pqc_trailing_zeros::*;
pub mod pqc_leading_ones;
pub use self::pqc_leading_ones::*;
pub mod pqc_bit_length;
pub use self::pqc_bit_length::*;
pub mod pqc_byte_length;
pub use self::pqc_byte_length::*;
pub mod pqc_alignment;
pub use self::pqc_alignment::*;
pub mod pqc_cache;
pub use self::pqc_cache::*;
pub mod pqc_memory;
pub use self::pqc_memory::*;
pub mod pqc_heap;
pub use self::pqc_heap::*;
pub mod pqc_stack;
pub use self::pqc_stack::*;
pub mod pqc_register;
pub use self::pqc_register::*;
pub mod pqc_architecture;
pub use self::pqc_architecture::*;
pub mod pqc_endian;
pub use self::pqc_endian::*;
pub mod pqc_float;
pub use self::pqc_float::*;
pub mod pqc_double;
pub use self::pqc_double::*;
pub mod pqc_decimal;
pub use self::pqc_decimal::*;
pub mod pqc_rational;
pub use self::pqc_rational::*;
pub mod pqc_fraction;
pub use self::pqc_fraction::*;
pub mod pqc_fixed_point;
pub use self::pqc_fixed_point::*;
pub mod pqc_bitfield;
pub use self::pqc_bitfield::*;
pub mod pqc_bitarray;
pub use self::pqc_bitarray::*;
pub mod pqc_bitmatrix;
pub use self::pqc_bitmatrix::*;
pub mod pqc_bittree;
pub use self::pqc_bittree::*;
pub mod pqc_bitset;
pub use self::pqc_bitset::*;
pub mod pqc_bitvector;
pub use self::pqc_bitvector::*;
pub mod pqc_bitstream;
pub use self::pqc_bitstream::*;
pub mod pqc_bitorder;
pub use self::pqc_bitorder::*;
pub mod pqc_bitreverse;
pub use self::pqc_bitreverse::*;
pub mod pqc_bitrotate;
pub use self::pqc_bitrotate::*;
pub mod pqc_bitswap;
pub use self::pqc_bitswap::*;
pub mod pqc_bitorange;
pub use self::pqc_bitorange::*;
pub mod pqc_bitwindow;
pub use self::pqc_bitwindow::*;
pub mod pqc_bitmask;
pub use self::pqc_bitmask::*;
pub mod pqc_bitrange;
pub use self::pqc_bitrange::*;
pub mod pqc_bitblock;
pub use self::pqc_bitblock::*;
pub mod pqc_bitchunk;
pub use self::pqc_bitchunk::*;
pub mod pqc_bitunit;
pub use self::pqc_bitunit::*;
pub mod pqc_bitcell;
pub use self::pqc_bitcell::*;
pub mod pqc_bitnode;
pub use self::pqc_bitnode::*;
pub mod pqc_bittree_node;
pub use self::pqc_bittree_node::*;
pub mod pqc_bittree_edge;
pub use self::pqc_bittree_edge::*;
pub mod pqc_bittree_leaf;
pub use self::pqc_bittree_leaf::*;
pub mod pqc_bittree_internal;
pub use self::pqc_bittree_internal::*;
pub mod pqc_bittree_root;
pub use self::pqc_bittree_root::*;
pub mod pqc_bittree_branch;
pub use self::pqc_bittree_branch::*;
pub mod pqc_bittree_leaf_node;
pub use self::pqc_bittree_leaf_node::*;
pub mod pqc_bittree_internal_node;
pub use self::pqc_bittree_internal_node::*;
pub mod pqc_bittree_root_node;
pub use self::pqc_bittree_root_node::*;
pub mod pqc_bittree_branch_node;
pub use self::pqc_bittree_branch_node::*;
pub mod pqc_bittree_leaf_edge;
pub use self::pqc_bittree_leaf_edge::*;
pub mod pqc_bittree_internal_edge;
pub use self::pqc_bittree_internal_edge::*;
pub mod pqc_bittree_root_edge;
pub use self::pqc_bittree_root_edge::*;
pub mod pqc_bittree_branch_edge;
pub use self::pqc_bittree_branch_edge::*;
pub mod pqc_bittree_leaf_node_data;
pub use self::pqc_bittree_leaf_node_data::*;
pub mod pqc_bittree_internal_node_data;
pub use self::pqc_bittree_internal_node_data::*;
pub mod pqc_bittree_root_node_data;
pub use self::pqc_bittree_root_node_data::*;
pub mod pqc_bittree_branch_node_data;
pub use self::pqc_bittree_branch_node_data::*;
pub mod pqc_bittree_leaf_edge_data;
pub use self::pqc_bittree_leaf_edge_data::*;
pub mod pqc_bittree_internal_edge_data;
pub use self::pqc_bittree_internal_edge_data::*;
pub mod pqc_bittree_root_edge_data;
pub use self::pqc_bittree_root_edge_data::*;
pub mod pqc_bittree_branch_edge_data;
pub use self::pqc_bittree_branch_edge_data::*;
pub mod pqc_bittree_leaf_node_error;
pub use self::pqc_bittree_leaf_node_error::*;
pub mod pqc_bittree_internal_node_error;
pub use self::pqc_bittree_internal_node_error::*;
pub mod pqc_bittree_root_node_error;
pub use self::pqc_bittree_root_node_error::*;
pub mod pqc_bittree_branch_node_error;
pub use self::pqc_bittree_branch_node_error::*;
pub mod pqc_bittree_leaf_edge_error;
pub use self::pqc_bittree_leaf_edge_error::*;
pub mod pqc_bittree_internal_edge_error;
pub use self::pqc_bittree_internal_edge_error::*;
pub mod pqc_bittree_root_edge_error;
pub use self::pqc_bittree_root_edge_error::*;
pub mod pqc_bittree_branch_edge_error;
pub use self::pqc_bittree_branch_edge_error::*;
pub mod pqc_bittree_leaf_node_result;
pub use self::pqc_bittree_leaf_node_result::*;
pub mod pqc_bittree_internal_node_result;
pub use self::pqc_bittree_internal_node_result::*;
pub mod pqc_bittree_root_node_result;
pub use self::pqc_bittree_root_node_result::*;
pub mod pqc_bittree_branch_node_result;
pub use self::pqc_bittree_branch_node_result::*;
pub mod pqc_bittree_leaf_edge_result;
pub use self::pqc_bittree_leaf_edge_result::*;
pub mod pqc_bittree_internal_edge_result;
pub use self::pqc_bittree_internal_edge_result::*;
pub mod pqc_bittree_root_edge_result;
pub use self::pqc_bittree_root_edge_result::*;
pub mod pqc_bittree_branch_edge_result;
pub use self::pqc_bittree_branch_edge_result::*;
pub mod pqc_bittree_leaf_node_state;
pub use self::pqc_bittree_leaf_node_state::*;
pub mod pqc_bittree_internal_node_state;
pub use self::pqc_bittree_internal_node_state::*;
pub mod pqc_bittree_root_node_state;
pub use self::pqc_bittree_root_node_state::*;
pub mod pqc_bittree_branch_node_state;
pub use self::pqc_bittree_branch_node_state::*;
pub mod pqc_bittree_leaf_edge_state;
pub use self::pqc_bittree_leaf_edge_state::*;
pub mod pqc_bittree_internal_edge_state;
pub use self::pqc_bittree_internal_edge_state::*;
pub mod pqc_bittree_root_edge_state;
pub use self::pqc_bittree_root_edge_state::*;
pub mod pqc_bittree_branch_edge_state;
pub use self::pqc_bittree_branch_edge_state::*;
pub mod pqc_bittree_leaf_node_event;
pub use self::pqc_bittree_leaf_node_event::*;
pub mod pqc_bittree_internal_node_event;
pub use self::pqc_bittree_internal_node_event::*;
pub mod pqc_bittree_root_node_event;
pub use self::pqc_bitt \*
pub const MAX_HANDSHAKE_SIZE: usize = 4096;
pub const MAX_ERROR_MESSAGES: usize = 128;
pub const MIN_FEATURES_COUNT: u32 = 8;
pub const DEFAULT_TIMEOUT_MS: u64 = 5000;
pub const HASH_WINDOW_SIZE: usize = 16;
pub const SLIDING_WINDOW_SIZE: u32 = 1024;
pub const SAMPLE_RATE_HZ: u32 = 8000;
pub const BIT_DEPTH: u8 = 16;
pub const CHANNELS_COUNT: u8 = 1;
pub const MAX_PEAK_AMPLITUDE: f32 = 32767.0;
pub const NOISE_THRESHOLD_DB: f32 = -60.0;
pub const SIGNAL_THRESHOLD_DB: f32 = -50.0;
pub const CORRELATION_COEFFICIENT: f32 = 0.95;
pub const CROSS_CORRELATION_WINDOW_SIZE: usize = 64;
pub const FREQUENCY_RESPONSE_BANDWIDTH_HZ: u32 = 8000;
pub const FILTER_ORDER: u8 = 8;
pub const DECIMATOR_RATIO: u8 = 2;
pub const LOW_PASS_CUTOFF_HZ: u32 = 4000;
pub const HIGH_PASS_CUTOFF_HZ: u32 = 100;
pub const DENOISE_SIGMA: f32 = 2.5;
pub const ENVELOPE_PEAK_HOLD_MS: u64 = 10;
pub const PEAK_DETECTION_THRESHOLD_DB: f32 = -80.0;
pub const SILENCE_DURATION_MS: u64 = 500;
pub const VOICE_ACTIVITY_THRESHOLD_PERCENT: f32 = 5.0;
pub const DYNAMIC_RANGE_COMPRESSION_RATION: f32 = 12.0;
pub const ECHO_REFLECTION_DELAY_MS: u64 = 80;
pub const ECHO_AMPLITUDE_DECAY_DB: f32 = -12.0;
pub const NOISE_FLOOR_ESTIMATION_WINDOW_SIZE: usize = 256;
pub const POWER_SPECTRAL_DENSITY_ESTIMATOR_BANDWIDTH_HZ: u32 = 2000;
pub const SPECTRAL_FLUX_THRESHOLD_PERCENT: f32 = 2.0;
pub const SPECTRAL_ENERGY_THRESHOLD_DB: f32 = -80.0;
pub const MODULATION_DETECTOR_BANDWIDTH_HZ: u32 = 1500;
pub const MODULATION_AMPLITUDE_DECAY_MS: u64 = 50;
pub const MODULATION_DETECTOR_HYSTERESIS_MS: u64 = 200;
pub const MODULATION_AMPLITUDE_THRESHOLD_PERCENT: f32 = 1.0;
pub const MODULATION_FREQUENCY_RANGE_HZ: (u32, u32) = (0, 500);
pub const MODULATION_DETECTION_THRESHOLD_DB: f32 = -40.0;
pub const MODULATION_AMPLITUDE_MAX_PERCENT: f32 = 90.0;
pub const MODULATION_AMPLITUDE_MIN_PERCENT: f32 = 1.0;
pub const MODULATION_AMPLITUDE_SKEWNESS_THRESHOLD: f64 = 0.85;
pub const MODULATION_AMPLITUDE_KURTOSIS_THRESHOLD: f64 = 2.5;
pub const MODULATION_AMPLITUDE_SNR_DB: f32 = 15.0;
pub const MODULATION_AMPLITUDE_NOISE_FLOOR_ESTIMATION_WINDOW_SIZE: usize = 512;
pub const MODULATION_AMPLITUDE_SNR_ESTIMATOR_BANDWIDTH_HZ: u32 = 2000;
pub const MODULATION_AMPLITUDE_SNR_ESTIMATOR_DECAY_FACTOR: f64 = 0.9999;
pub const MODULATION_AMPLITUDE_SNR_ESTIMATOR_MIN_SAMPLES: usize = 1024;
pub const MODULATION_AMPLITUDE_SNR_ESTIMATOR_MAX_SAMPLES: usize = 8192;
pub const MODULATION_AMPLITUDE_SNR_ESTIMATOR_ADAPTIVE_FACTOR: f64 = 0.5;
pub const MODULATION_AMPLITUDE_SNR_ESTIMATOR_ADAPTIVE_THRESHOLD_DB: f32 = 3.0;
pub const MODULATION_AMPLITUDE_SNR_ESTIMATOR_ADAPTIVE_WINDOW_SIZE: u32 = 1000;
pub const MODULATION_AMPLITUDE_SNR_ESTIMATOR_ADAPTIVE_DECAY_FACTOR: f64 = 0.95;
pub const MODULATION_AMPLITUDE_SNR_ESTIMATOR_ADAPTIVE_MIN_SAMPLES: usize = 512;
pub const MODULATION_AMPLITUDE_SNR_ESTIMATOR_ADAPTIVE_MAX_SAMPLES: usize = 2048;
pub const MODULATION_AMPLITUDE_SNR_ESTIMATOR_ADAPTIVE_FACTOR_RANGE: (f64, f64) = (0.0, 1.0);
pub const MODULATION_AMPLITUDE_SNR_ESTIMATOR_ADAPTIVE_WINDOW_SIZE_RANGE: (u32, u32) = (1, 5000);
pub const MODULATION_AMPLITUDE_SNR_ESTIMATOR_ADAPTIVE_DECAY_FACTOR_RANGE: (f64, f64) = (0.0, 1.0);
pub const MODULATION_AMPLITUDE_SNR_ESTIMATOR_ADAPTIVE_MIN_SAMPLES_RANGE: (usize, usize) = (1, 10240);
pub const MODULATION_AMPLITUDE_SNR_ESTIMATOR_ADAPTIVE_MAX_SAMPLES_RANGE: (usize, usize) = (1, 81920);


pub enum Error {
    InvalidInput,
    OutOfBounds,
    BufferOverflow,
    ParseError,
    IOError,
    Timeout,
    FeatureExtractionFailed,
    MemoryAllocationFailed,
    NullPointer,
    FileNotFound,
    PermissionDenied,
    CorruptedData,
    NetworkUnreachable,
    InvalidProtocolVersion,
    InvalidCipherSuite,
    InvalidCompressionMethod,
    InvalidExtensionType,
    InvalidEllipticCurve,
    InvalidFiniteFieldSize,
    InvalidModulusLength,
    InvalidPrimeLength,
    InvalidPublicExponent,
    InvalidSignatureAlgorithm,
    InvalidKeyAgreement,
    InvalidHashFunction,
    InvalidMacAlgorithm,
    InvalidRecordVersion,
    InvalidContentType,
    InvalidAlertMessage,
    InvalidWarningMessage,
    InvalidErrorMessage,
    InvalidCloseNotice,
    InvalidHelloRetryRequest,
    InvalidEncryptedExtensions,
    InvalidCertificateTransparency,
    InvalidSupportsExtendedNegotiation,
    InvalidTokenBinding,
    InvalidPreSharedKey,
    InvalidEarlyData,
    InvalidSignedCertificateTimestamps,
    InvalidCertificateAuthorities,
    InvalidPostQuantumKeyExchange,
    InvalidPostQuantumSignature,
    InvalidPostQuantumParameters,
    InvalidPostQuantumAlgorithmIdentifier,
    InvalidPostQuantumCurve,
    InvalidPostQuantumFiniteField,
    InvalidPostQuantumPrime,
    InvalidPostQuantumModulus,
    InvalidPostQuantumPublicExponent,
    InvalidPostQuantumSignatureScheme,
    InvalidPostQuantumKeyExchangeScheme,
    InvalidPostQuantumParametersScheme,
    InvalidPostQuantumAlgorithmIdentifierScheme,
    InvalidPostQuantumCurveScheme,
    InvalidPostQuantumFiniteFieldScheme,
    InvalidPostQuantumPrimeScheme,
    InvalidPostQuantumModulusScheme,
    InvalidPostQuantumPublicExponentScheme,
    InvalidPostQuantumSignatureSchemeScheme,
    InvalidPostQuantumKeyExchangeSchemeScheme,
    InvalidPostQuantumParametersSchemeScheme,
    InvalidPostQuantumAlgorithmIdentifierSchemeScheme,
}
pub type Result<T> = std::result::Result<T, Error>;


fn read_bytes(data: &[u8], offset: usize) -> Option<&[u8]> {
    if offset >= data.len() {
        return None;
    }
    let remaining = data.len() - offset;
    Some(&data[offset..])
}
pub fn read_u8(data: &[u8], offset: usize) -> Result<(u8, usize)> {
    match read_bytes(data, offset).and_then(|b| b.get(0)) {
        Some(b) => Ok((*b, 1)),
        None => Err(Error::OutOfBounds),
    }
}
pub fn read_u16_be(data: &[u8], offset: usize) -> Result<(u16, usize)> {
    if offset + 2 > data.len() {
        return Err(Error::OutOfBounds);
    }
    let val = u16::from_be_bytes([data[offset], data[offset+1]]);
    Ok((val, 2))
}
pub fn read_u32_be(data: &[u8], offset: usize) -> Result<(u32, usize)> {
    if offset + 4 > data.len() {
        return Err(Error::OutOfBounds);
    }
    let val = u32::from_be_bytes([data[offset], data[offset+1], data[offset+2], data[offset+3]]);
    Ok((val, 4))
}
pub fn read_u64_be(data: &[u8], offset: usize) -> Result<(u64, usize)> {
    if offset + 8 > data.len() {
        return Err(Error::OutOfBounds);
    }
    let val = u64::from_be_bytes([data[offset], data[offset+1], data[offset+2], data[offset+3],
                                  data[offset+4], data[offset+5], data[offset+6], data[offset+7]]);
    Ok((val, 8))
}
pub fn read_varint(data: &[u8], offset: usize) -> Result<(usize, usize)> {
    let mut val = 0;
    let mut length = 0;
    for i in 0..7 {
        if offset + i >= data.len() {
            return Err(Error::OutOfBounds);
        }
        val |= ((data[offset + i] & 0x7F) as usize) << (7 * i);
        length += 1;
        if (data[offset + i] & 0x80) == 0 {
            break;
        }
    }
    Ok((val, length))
}
pub fn read_string(data: &[u8], offset: usize) -> Result<(String, usize)> {
    let mut length = 0;
    for _ in 0..65535 {
        if offset + length >= data.len() {
            return Err(Error::OutOfBounds);
        }
        if data[offset + length] == 0 {
            break;
        }
        length += 1;
    }
    if offset + length >= data.len() {
        return Err(Error::OutOfBounds);
    }
    let slice = &data[offset..offset+length];
    Ok((String::from_utf8_lossy(slice).to_string(), length + 1))
}
pub fn read_bytes_slice(data: &[u8], offset: usize, count: usize) -> Result<&[u8]> {
    if offset + count > data.len() {
        return Err(Error::OutOfBounds);
    }
    Ok(&data[offset..offset+count])
}


#[derive(Clone, Debug, Default)]
pub struct TlsRecordHeader {
    pub content_type: u8,
    pub version: u16,
    pub length: u16,
}
#[derive(Clone, Debug, Default)]
pub struct TlsHandshakeMessage {
    pub msg_type: u8,
    pub length: u24,
}
#[derive(Clone, Debug, Default)]
pub struct TlsHelloRequest {}
#[derive(Clone, Debug, Default)]
pub struct TlsClientHello {
    pub legacy_version: u16,
    pub random: [u8; 32],
    pub legacy_session_id_echo: Vec<u8>,
    pub cipher_suites: Vec<u16>,
    pub compression_methods: Vec<u8>,
    pub extensions: Vec<TlsExtension>,
}
#[derive(Clone, Debug, Default)]
pub struct TlsServerHello {
    pub legacy_version: u16,
    pub random: [u8; 32],
    pub session_id: Vec<u8>,
    pub cipher_suite: u16,
    pub compression_method: u8,
    pub extensions: Vec<TlsExtension>,
}
#[derive(Clone, Debug, Default)]
pub struct TlsEncryptedExtensions {
    pub extensions: Vec<TlsExtension>,
}
#[derive(Clone, Debug, Default)]
pub struct TlsCertificateRequest {
    pub certificate_request_context: Vec<u8>,
    pub certificate_request_extensions: Vec<TlsExtension>,
}
#[derive(Clone, Debug, Default)]
pub struct TlsHelloRetryRequest {
    pub legacy_version: u16,
    pub random: [u8; 32],
    pub extensions: Vec<TlsExtension>,
}
#[derive(Clone, Debug, Default)]
pub struct TlsNewSessionTicket {
    public_key: Vec<u8>,
    ticket_lifetime_hint: u32,
    nonce: [u8; 32],
    replay_counter: [u8; 16],
    ticket_age_add: [u8; 16],
}
#[derive(Clone, Debug, Default)]
pub struct TlsApplicationData {}
#[derive(Clone, Debug, Default)]
pub struct TlsAlertMessage {
    pub level: u8,
    pub description: u8,
}
#[derive(Clone, Debug, Default)]
pub struct TlsExtension {}
pub type TlsExtensions = Vec<TlsExtension>;
pub type HandshakeMessages = Vec<TlsHandshakeMessage>;


fn parse_tls_record_header(data: &[u8], offset: usize) -> Result<(TlsRecordHeader, usize)> {
    let (version, off1) = read_u16_be(data, offset)?;
    let (length, off2) = read_u16_be(data, offset + off1)?;
    Ok((TlsRecordHeader { version, length }, off1 + off2))
}
pub fn parse_tls_handshake_message_type(data: &[u8], offset: usize) -> Result<(u8, usize)> {
    read_u8(data, offset)
}
pub fn parse_tls_handshake_message_length(data: &[u8], offset: usize) -> Result<(u24, usize)> {
    
    let mut val = 0;
    let mut length = 0;
    for i in 0..3 {
        if offset + i >= data.len() {
            return Err(Error::OutOfBounds);
        }
        val |= ((data[offset + i] & 0x7F) as u24) << (7 * i);
        length += 1;
        if (data[offset + i] & 0x80) == 0 {
            break;
        }
    }
    Ok((val, length))
}
pub fn parse_handshake_message(data: &[u8], offset: usize, msg_type: u8) -> Result<(TlsHandshakeMessage, usize)> {
    let (length, len_offset) = parse_tls_handshake_message_length(data, offset)?;
    
    Ok((TlsHandshakeMessage { length }, len_offset))
}
pub fn parse_client_hello(data: &[u8], offset: usize) -> Result<(TlsClientHello, usize)> {
    let (version, off1) = read_u16_be(data, offset)?;
    if version != 0x0303 && version != 0x0302 && version != 0x0301 {
        return Err(Error::InvalidProtocolVersion);
    }
    let random = data.get(offset+2..offset+34).ok_or(Error::OutOfBounds)?;
    let random_slice = &random[0..32];
    if random_slice.len() < 32 {
        return Err(Error::OutOfBounds);
    }
    offset += 34;
    
    let (session_len, off2) = read_u8(data, offset)?; 
    offset += 1 + session_len;
    
    let (cipher_len, off3) = read_u16_be(data, offset)?;
    offset += 2 + (cipher_len as usize); 
    
    let (comp_len, off4) = read_u8(data, offset)?;
    offset += 1 + comp_len;
    
    let (ext_len, off5) = read_u16_be(data, offset)?;
    offset += 2 + ext_len;
    let client_hello = TlsClientHello {
        legacy_version: version,
        random: *random_slice,
        legacy_session_id_echo: vec![], 
        cipher_suites: vec![],
        compression_methods: vec![],
        extensions: vec![],
    };
    Ok((client_hello, off1 + off2 + off3 + off4 + off5))
}
pub fn parse_server_hello(data: &[u8], offset: usize) -> Result<(TlsServerHello, usize)> {
    let (version, off1) = read_u16_be(data, \offset)?; 
    if version != 0x0303 && version != 0x0302 && version != 0x0301 {
        return Err(Error::InvalidProtocolVersion);
    }
    let random = data.get(offset+2..offset+34).ok_or(Error::OutOfBounds)?;
    let random_slice = &random[0..32];
    if random_slice.len() < 32 {
        return Err(Error::OutOfBounds);
    }
    offset += 34;
    
    let (session_len, off2) = read_u8(data, offset)?; 
    offset += 1 + session_len;
    
    let (cipher, off3) = read_u16_be(data, offset)?;
    offset += 2;
    
    let (comp, off4) = read_u8(data, offset)?;
    offset += 1;
    
    let (ext_len, off5) = read_u16_be(data, offset)?;
    offset += 2 + ext_len as usize;
    let server_hello = TlsServerHello {
        legacy_version: version,
        random: *random_slice,
        session_id: vec![],
        cipher_suite: cipher,
        compression_method: comp,
        extensions: vec![],
    };
    Ok((server_hello, off1 + off2 + off3 + off4 + off5))
}
pub fn parse_certificate(data: &[u8], offset: usize) -> Result<(TlsCertificate, usize)> {
    
    unimplemented!()
}
pub fn parse_server_key_exchange(data: &[u8], offset: usize) -> Result<(TlsServerKeyExchange, usize)> {
    unimplemented!()
}
pub fn parse_certificate_request(data: &[u8], offset: usize) -> Result<(TlsCertificateRequest, usize)> {
    
    unimplemented!()
}
pub fn parse_server_hello_done(data: &[u8], offset: usize) -> Result<usize> {
    let (msg_type, off1) = parse_tls_handshake_message_type(data, offset)?;
    if msg_type != 0x0C { 
        return Err(Error::InvalidProtocolVersion);
    }
    Ok(off1)
}
pub fn parse_change_cipher_spec(data: &[u8], offset: usize) -> Result<usize> {
    let (msg_type, off1) = parse_tls_handshake_message_type(data, offset)?;
    if msg_type != 0x01 { 
        return Err(Error::InvalidProtocolVersion);
    }
    Ok(off1)
}
pub fn parse_application_data(data: &[u8], offset: usize) -> Result<usize> {
    let (msg_type, off1) = parse_tls_handshake_message_type(data, offset)?;
    if msg_type != 0x17 { 
        return Err(Error::InvalidProtocolVersion);
    }
    Ok(off1)
}
pub fn parse_alert_message(data: &[u8], offset: usize) -> Result<usize> {
    let (msg_type, off1) = parse_tls_handshake_message_type(data, offset)?;
    if msg_type != 0x02 { 
        return Err(Error::InvalidVersion);
    }
    Ok(off1)
}
pub fn parse_new_session_ticket(data: &[u8], offset: usize) -> Result<usize> {
    let (msg_type, off1) = parse_tls_handshake_message_type(data, offset)?;
    if msg_type != 0x0D { 
        return Err(Error::InvalidVersion);
    }
    Ok(off1)
}
pub fn parse_encrypted_extensions(data: &[u8], offset: usize) -> Result<usize> {
    let (msg_type, off1) = parse_tls_handshake_message_type(data, offset)?;
    if msg_type != 0x0D { 
        return Err(Error::InvalidVersion);
    }
    Ok(off1)
}
pub fn parse_certificate_verify(data: &[u8], offset: usize) => Result<usize> {
    unimplemented!()
}


#[derive(Debug, Clone, Copy)]
pub enum ParseError {
    OutOfBounds,
    InvalidProtocolVersion,
    InvalidRecordLayer,
    MalformedPacket,
    UnsupportedExtension,
}
impl std::convert::From<ParseError> for Error {
    fn from(e: ParseError) -> Self {
        Error::MalformedPacket(anyhow::Error::from(e))
    }
}


pub fn parse_packet(data: &[u8]) -> Result<Vec<Box<dyn Any>>> {
    
    unimplemented!()
}


#[derive(Clone, Debug, Default)]
pub struct Ja4Extension {}
#[derive(Clone, Debug, Default)]
pub struct Ja5Extension {}
pub struct BehavioralExtension {}

impl Ja4Extension {
    pub fn new() -> Self { Default::default() }
}
impl Ja5Extension {
    pub fn new() -> Self { Default::default() }
}


pub fn generate_fingerprint<'a>(packet: &'a Packet, context: &FingerprintContext) -> Result<String> {
    
    unimplemented!()
}


pub fn extract_ml_features(packet: &Packet) -> Result<Vec<f64>> {
    
    unimator!()
}
