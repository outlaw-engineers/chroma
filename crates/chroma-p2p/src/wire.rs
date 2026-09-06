use chroma_core::error::{CoreError, Result};
use chroma_core::hash::Hash;

pub const MAGIC: [u8; 4] = [0xC4, 0x48, 0x52, 0x4F];
pub const MAX_MESSAGE_SIZE: usize = 4 * 1024 * 1024;
pub const HEADER_SIZE: usize = 13;

/// Largest address list we will send or act on in one message. Bounds both the
/// work a peer can ask of us and how fast a hostile peer can seed our table.
pub const MAX_ADDRS_PER_MESSAGE: usize = 1000;

#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
pub enum MessageType {
    Version = 0x01,
    VerAck = 0x02,
    Ping = 0x03,
    Pong = 0x04,
    GetAddr = 0x05,
    Addr = 0x06,
    GetHeaders = 0x07,
    Headers = 0x08,
    Inv = 0x09,
    GetData = 0x0A,
    Tx = 0x0B,
    Block = 0x0C,
    NotFound = 0x0D,
    Reject = 0x0E,
    /// Ask a node where its chain stands.
    GetChainInfo = 0x0F,
    ChainInfo = 0x10,
    /// Ask a node for one account's balance and nonce.
    GetAccount = 0x11,
    Account = 0x12,
    /// Ask a node where one transaction was mined. Answerable only by a node
    /// keeping the index.
    GetTransaction = 0x13,
    TransactionAt = 0x14,
    /// Ask a node for the transactions touching one address.
    GetHistory = 0x15,
    History = 0x16,
}

impl MessageType {
    pub fn from_u8(v: u8) -> Result<Self> {
        match v {
            0x01 => Ok(MessageType::Version),
            0x02 => Ok(MessageType::VerAck),
            0x03 => Ok(MessageType::Ping),
            0x04 => Ok(MessageType::Pong),
            0x05 => Ok(MessageType::GetAddr),
            0x06 => Ok(MessageType::Addr),
            0x07 => Ok(MessageType::GetHeaders),
            0x08 => Ok(MessageType::Headers),
            0x09 => Ok(MessageType::Inv),
            0x0A => Ok(MessageType::GetData),
            0x0B => Ok(MessageType::Tx),
            0x0C => Ok(MessageType::Block),
            0x0D => Ok(MessageType::NotFound),
            0x0E => Ok(MessageType::Reject),
            0x0F => Ok(MessageType::GetChainInfo),
            0x10 => Ok(MessageType::ChainInfo),
            0x11 => Ok(MessageType::GetAccount),
            0x12 => Ok(MessageType::Account),
            0x13 => Ok(MessageType::GetTransaction),
            0x14 => Ok(MessageType::TransactionAt),
            0x15 => Ok(MessageType::GetHistory),
            0x16 => Ok(MessageType::History),
            _ => Err(CoreError::Serialization(format!("unknown message type: 0x{:02X}", v))),
        }
    }
}

#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
pub enum InvType {
    Block = 0x01,
    Tx = 0x02,
}

impl InvType {
    pub fn from_u8(v: u8) -> Result<Self> {
        match v {
            0x01 => Ok(InvType::Block),
            0x02 => Ok(InvType::Tx),
            _ => Err(CoreError::Serialization(format!("unknown inv type: {}", v))),
        }
    }
}

/// Result of attempting to decode one frame from a stream buffer.
///
/// A stream reader must distinguish "the rest of this frame has not arrived
/// yet" from "this peer sent garbage". The former means read more; the latter
/// means drop (and score) the peer.
#[derive(Clone, Debug)]
pub enum FrameDecode {
    /// A complete frame was decoded, consuming `consumed` bytes.
    Complete { message: Message, consumed: usize },
    /// The buffer holds a valid prefix but not a whole frame yet.
    /// `needed` is the total frame length once known, else None.
    Incomplete { needed: Option<usize> },
}

/// Decode one frame from the front of a stream buffer.
///
/// Unlike [`Message::decode`], a short buffer is reported as
/// [`FrameDecode::Incomplete`] rather than an error, so the caller can wait for
/// more bytes instead of tearing the connection down.
pub fn decode_frame(data: &[u8]) -> Result<FrameDecode> {
    if data.len() < HEADER_SIZE {
        return Ok(FrameDecode::Incomplete { needed: None });
    }
    if data[0..4] != MAGIC {
        return Err(CoreError::Serialization("message: bad magic".to_string()));
    }
    let msg_type = MessageType::from_u8(data[4])?;
    let len = u32::from_le_bytes([data[5], data[6], data[7], data[8]]) as usize;
    if len > MAX_MESSAGE_SIZE {
        return Err(CoreError::Serialization(format!(
            "message: payload too large: {}",
            len
        )));
    }
    let total = HEADER_SIZE + len;
    if data.len() < total {
        return Ok(FrameDecode::Incomplete { needed: Some(total) });
    }
    let checksum = [data[9], data[10], data[11], data[12]];
    let payload = data[HEADER_SIZE..total].to_vec();
    let expected = blake3::hash(&payload);
    if checksum != expected.as_bytes()[..4] {
        return Err(CoreError::Serialization("message: checksum mismatch".to_string()));
    }
    Ok(FrameDecode::Complete {
        message: Message { msg_type, payload },
        consumed: total,
    })
}

#[derive(Clone, Debug)]
pub struct Message {
    pub msg_type: MessageType,
    pub payload: Vec<u8>,
}

impl Message {
    pub fn new(msg_type: MessageType, payload: Vec<u8>) -> Self {
        Message { msg_type, payload }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(HEADER_SIZE + self.payload.len());
        buf.extend_from_slice(&MAGIC);
        buf.push(self.msg_type as u8);
        let len = self.payload.len() as u32;
        buf.extend_from_slice(&len.to_le_bytes());
        let checksum = blake3::hash(&self.payload);
        buf.extend_from_slice(&checksum.as_bytes()[..4]);
        buf.extend_from_slice(&self.payload);
        buf
    }

    pub fn decode(data: &[u8]) -> Result<(Message, usize)> {
        if data.len() < HEADER_SIZE {
            return Err(CoreError::Serialization("message: header too short".to_string()));
        }
        if data[0..4] != MAGIC {
            return Err(CoreError::Serialization("message: bad magic".to_string()));
        }
        let msg_type = MessageType::from_u8(data[4])?;
        let len = u32::from_le_bytes([data[5], data[6], data[7], data[8]]) as usize;
        if len > MAX_MESSAGE_SIZE {
            return Err(CoreError::Serialization(format!(
                "message: payload too large: {}",
                len
            )));
        }
        let checksum = [data[9], data[10], data[11], data[12]];
        let total = HEADER_SIZE + len;
        if data.len() < total {
            return Err(CoreError::Serialization("message: payload truncated".to_string()));
        }
        let payload = data[HEADER_SIZE..total].to_vec();
        let expected = blake3::hash(&payload);
        if checksum != expected.as_bytes()[..4] {
            return Err(CoreError::Serialization("message: checksum mismatch".to_string()));
        }
        Ok((Message { msg_type, payload }, total))
    }
}

/// Version handshake payload (34 bytes).
///
/// `listen_port` is the port the sender accepts inbound connections on. An
/// inbound TCP connection arrives from an ephemeral source port, which is
/// useless as a peer identity, so peers are keyed by
/// `(remote_ip, listen_port)` once the version is known.
///
/// `nonce` is the sender's per-process identity nonce, used to detect and drop
/// self-connections.
#[derive(Clone, Debug)]
pub struct VersionMessage {
    pub version: u32,
    pub services: u64,
    pub timestamp: u64,
    pub height: u32,
    pub nonce: u64,
    pub listen_port: u16,
}

impl VersionMessage {
    /// Canonical encoded size.
    pub const SERIALIZED_SIZE: usize = 4 + 8 + 8 + 4 + 8 + 2;

    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(Self::SERIALIZED_SIZE);
        buf.extend_from_slice(&self.version.to_le_bytes());
        buf.extend_from_slice(&self.services.to_le_bytes());
        buf.extend_from_slice(&self.timestamp.to_le_bytes());
        buf.extend_from_slice(&self.height.to_le_bytes());
        buf.extend_from_slice(&self.nonce.to_le_bytes());
        buf.extend_from_slice(&self.listen_port.to_le_bytes());
        buf
    }

    /// Decode a version payload.
    ///
    /// Trailing bytes are ignored rather than rejected, which is deliberate
    /// and the one place in this module that is so. Version is the message
    /// that negotiates what two nodes speak: a future protocol version adding
    /// a field here has to remain readable by nodes that predate it, or the
    /// negotiation below — clamping to `min(theirs, ours)` and rejecting only
    /// what is older than `MIN_PROTOCOL_VERSION` — could never happen with a
    /// newer peer. Every other message is fixed by the version already agreed,
    /// so trailing bytes there mean a peer sending something we did not agree
    /// to, and those decoders refuse it.
    ///
    /// The payload is still bounded: a frame cannot exceed `MAX_MESSAGE_SIZE`.
    pub fn decode(data: &[u8]) -> Result<Self> {
        if data.len() < Self::SERIALIZED_SIZE {
            return Err(CoreError::Serialization("version: too short".to_string()));
        }
        Ok(VersionMessage {
            version: u32::from_le_bytes(data[0..4].try_into().unwrap()),
            services: u64::from_le_bytes(data[4..12].try_into().unwrap()),
            timestamp: u64::from_le_bytes(data[12..20].try_into().unwrap()),
            height: u32::from_le_bytes(data[20..24].try_into().unwrap()),
            nonce: u64::from_le_bytes(data[24..32].try_into().unwrap()),
            listen_port: u16::from_le_bytes(data[32..34].try_into().unwrap()),
        })
    }
}

/// A run of consecutive block headers, in ascending height order.
///
/// Encoded as a LEB128 count followed by that many canonical 124-byte headers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HeadersMessage {
    pub headers: Vec<chroma_block::BlockHeader>,
}

impl HeadersMessage {
    pub fn encode(&self) -> Vec<u8> {
        use chroma_core::serialize::CanonicalEncode;
        let mut buf = chroma_core::serialize::encode_leb128(self.headers.len() as u64);
        for header in &self.headers {
            buf.extend_from_slice(&header.encode());
        }
        buf
    }

    pub fn decode(data: &[u8]) -> Result<Self> {
        use chroma_core::serialize::CanonicalDecode;
        let (count, mut pos) = chroma_core::serialize::decode_leb128(data, 0)?;
        let count = count as usize;

        // Reject an inflated count before allocating for it.
        let available = data.len().saturating_sub(pos) / chroma_block::BlockHeader::SERIALIZED_SIZE;
        if count > available {
            return Err(CoreError::Serialization(format!(
                "headers: declared {} headers but only {} fit in the payload",
                count, available
            )));
        }

        let mut headers = Vec::with_capacity(count);
        for _ in 0..count {
            let (header, used) = chroma_block::BlockHeader::decode_partial(&data[pos..])?;
            headers.push(header);
            pos += used;
        }
        if pos != data.len() {
            return Err(CoreError::Serialization(format!(
                "headers: {} trailing bytes",
                data.len() - pos
            )));
        }
        Ok(HeadersMessage { headers })
    }
}

#[derive(Clone, Debug)]
pub struct PingMessage {
    pub nonce: u64,
}

impl PingMessage {
    pub fn encode(&self) -> Vec<u8> {
        self.nonce.to_le_bytes().to_vec()
    }

    pub fn decode(data: &[u8]) -> Result<Self> {
        if data.len() < 8 {
            return Err(CoreError::Serialization("ping: too short".to_string()));
        }
        Ok(PingMessage {
            nonce: u64::from_le_bytes(data[0..8].try_into().unwrap()),
        })
    }
}

#[derive(Clone, Debug)]
pub struct GetHeadersMessage {
    pub start_hash: Hash,
    pub stop_hash: Hash,
}

impl GetHeadersMessage {
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(64);
        buf.extend_from_slice(self.start_hash.as_bytes());
        buf.extend_from_slice(self.stop_hash.as_bytes());
        buf
    }

    pub fn decode(data: &[u8]) -> Result<Self> {
        if data.len() < 64 {
            return Err(CoreError::Serialization("getheaders: too short".to_string()));
        }
        let mut start = [0u8; 32];
        let mut stop = [0u8; 32];
        start.copy_from_slice(&data[0..32]);
        stop.copy_from_slice(&data[32..64]);
        Ok(GetHeadersMessage {
            start_hash: Hash::from_bytes(start),
            stop_hash: Hash::from_bytes(stop),
        })
    }
}

#[derive(Clone, Debug)]
pub struct InvEntry {
    pub inv_type: InvType,
    pub hash: Hash,
}

#[derive(Clone, Debug)]
pub struct InvMessage {
    pub inventory: Vec<InvEntry>,
}

impl InvMessage {
    pub fn encode(&self) -> Vec<u8> {
        let count = self.inventory.len() as u32;
        let mut buf = Vec::with_capacity(4 + self.inventory.len() * 33);
        buf.extend_from_slice(&count.to_le_bytes());
        for entry in &self.inventory {
            buf.push(entry.inv_type as u8);
            buf.extend_from_slice(entry.hash.as_bytes());
        }
        buf
    }

    pub fn decode(data: &[u8]) -> Result<Self> {
        if data.len() < 4 {
            return Err(CoreError::Serialization("inv: too short".to_string()));
        }
        let count = u32::from_le_bytes([data[0], data[1], data[2], data[3]]) as usize;
        let expected = 4_usize
            .checked_add(count.checked_mul(33).ok_or_else(|| {
                CoreError::Serialization("inv: count overflow".to_string())
            })?)
            .ok_or_else(|| CoreError::Serialization("inv: size overflow".to_string()))?;
        if data.len() < expected {
            return Err(CoreError::Serialization("inv: truncated".to_string()));
        }
        let mut inventory = Vec::with_capacity(count);
        let mut pos = 4;
        for _ in 0..count {
            let inv_type = InvType::from_u8(data[pos])?;
            let mut hash = [0u8; 32];
            hash.copy_from_slice(&data[pos + 1..pos + 33]);
            inventory.push(InvEntry {
                inv_type,
                hash: Hash::from_bytes(hash),
            });
            pos += 33;
        }
        Ok(InvMessage { inventory })
    }
}

#[derive(Clone, Debug)]
pub struct GetDataMessage {
    pub inventory: Vec<InvEntry>,
}

impl GetDataMessage {
    pub fn encode(&self) -> Vec<u8> {
        let count = self.inventory.len() as u32;
        let mut buf = Vec::with_capacity(4 + self.inventory.len() * 33);
        buf.extend_from_slice(&count.to_le_bytes());
        for entry in &self.inventory {
            buf.push(entry.inv_type as u8);
            buf.extend_from_slice(entry.hash.as_bytes());
        }
        buf
    }

    pub fn decode(data: &[u8]) -> Result<Self> {
        if data.len() < 4 {
            return Err(CoreError::Serialization("getdata: too short".to_string()));
        }
        let count = u32::from_le_bytes([data[0], data[1], data[2], data[3]]) as usize;
        let expected = 4_usize
            .checked_add(count.checked_mul(33).ok_or_else(|| {
                CoreError::Serialization("getdata: count overflow".to_string())
            })?)
            .ok_or_else(|| CoreError::Serialization("getdata: size overflow".to_string()))?;
        if data.len() < expected {
            return Err(CoreError::Serialization("getdata: truncated".to_string()));
        }
        let mut inventory = Vec::with_capacity(count);
        let mut pos = 4;
        for _ in 0..count {
            let inv_type = InvType::from_u8(data[pos])?;
            let mut hash = [0u8; 32];
            hash.copy_from_slice(&data[pos + 1..pos + 33]);
            inventory.push(InvEntry {
                inv_type,
                hash: Hash::from_bytes(hash),
            });
            pos += 33;
        }
        Ok(GetDataMessage { inventory })
    }
}

/// A list of peers, exchanged so nodes can find each other without every one
/// of them having to be configured by hand.
///
/// Each entry carries the peer's node identity as well as its address: Noise
/// XK authenticates the responder, so a dialer that only learned an address
/// would have nothing to check the far end against.
///
/// Encoded per entry as the 32-byte node id, a one-byte address family (4 or
/// 6), the address bytes, then a little-endian port.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AddrMessage {
    pub addrs: Vec<crate::peer::PeerAddress>,
}

impl AddrMessage {
    pub fn encode(&self) -> Vec<u8> {
        use std::net::IpAddr;
        let count = std::cmp::min(self.addrs.len(), MAX_ADDRS_PER_MESSAGE);
        let mut buf = chroma_core::serialize::encode_leb128(count as u64);
        for peer in self.addrs.iter().take(count) {
            buf.extend_from_slice(&peer.node_id.0);
            buf.extend_from_slice(&peer.noise_key.0);
            match peer.socket.ip() {
                IpAddr::V4(v4) => {
                    buf.push(4);
                    buf.extend_from_slice(&v4.octets());
                }
                IpAddr::V6(v6) => {
                    buf.push(6);
                    buf.extend_from_slice(&v6.octets());
                }
            }
            buf.extend_from_slice(&peer.socket.port().to_le_bytes());
        }
        buf
    }

    pub fn decode(data: &[u8]) -> Result<Self> {
        use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

        let (count, mut pos) = chroma_core::serialize::decode_leb128(data, 0)?;
        let count = count as usize;
        if count > MAX_ADDRS_PER_MESSAGE {
            return Err(CoreError::Serialization(format!(
                "addr: {} entries exceeds the {} limit",
                count, MAX_ADDRS_PER_MESSAGE
            )));
        }

        let mut addrs = Vec::with_capacity(count);
        for _ in 0..count {
            if pos + 32 > data.len() {
                return Err(CoreError::Serialization("addr: truncated node id".to_string()));
            }
            let mut key = [0u8; 32];
            key.copy_from_slice(&data[pos..pos + 32]);
            pos += 32;

            // The static key travels with the identity: without it the entry
            // cannot be dialed, and a receiver has no way to fill it in.
            if pos + 32 > data.len() {
                return Err(CoreError::Serialization(
                    "addr: truncated noise key".to_string(),
                ));
            }
            let mut noise_key = [0u8; 32];
            noise_key.copy_from_slice(&data[pos..pos + 32]);
            pos += 32;

            if pos >= data.len() {
                return Err(CoreError::Serialization("addr: truncated".to_string()));
            }
            let family = data[pos];
            pos += 1;

            let ip = match family {
                4 => {
                    if pos + 4 > data.len() {
                        return Err(CoreError::Serialization("addr: truncated v4".to_string()));
                    }
                    let mut octets = [0u8; 4];
                    octets.copy_from_slice(&data[pos..pos + 4]);
                    pos += 4;
                    IpAddr::V4(Ipv4Addr::from(octets))
                }
                6 => {
                    if pos + 16 > data.len() {
                        return Err(CoreError::Serialization("addr: truncated v6".to_string()));
                    }
                    let mut octets = [0u8; 16];
                    octets.copy_from_slice(&data[pos..pos + 16]);
                    pos += 16;
                    IpAddr::V6(Ipv6Addr::from(octets))
                }
                other => {
                    return Err(CoreError::Serialization(format!(
                        "addr: unknown address family {}",
                        other
                    )))
                }
            };

            if pos + 2 > data.len() {
                return Err(CoreError::Serialization("addr: truncated port".to_string()));
            }
            let port = u16::from_le_bytes([data[pos], data[pos + 1]]);
            pos += 2;

            addrs.push(crate::peer::PeerAddress::new(
                chroma_crypto::noise::NodeId(key),
                chroma_crypto::noise::NoiseKey(noise_key),
                SocketAddr::new(ip, port),
            ));
        }

        if pos != data.len() {
            return Err(CoreError::Serialization(format!(
                "addr: {} trailing bytes",
                data.len() - pos
            )));
        }
        Ok(AddrMessage { addrs })
    }
}

/// Where a node's chain stands: what a client needs to show chain status
/// without opening the database, which it cannot do while the node holds it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChainInfoMessage {
    pub height: u32,
    pub tip: Hash,
    pub bits: u32,
    pub supply: u64,
}

impl ChainInfoMessage {
    pub const SERIALIZED_SIZE: usize = 4 + 32 + 4 + 8;

    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(Self::SERIALIZED_SIZE);
        buf.extend_from_slice(&self.height.to_le_bytes());
        buf.extend_from_slice(self.tip.as_bytes());
        buf.extend_from_slice(&self.bits.to_le_bytes());
        buf.extend_from_slice(&self.supply.to_le_bytes());
        buf
    }

    pub fn decode(data: &[u8]) -> Result<Self> {
        if data.len() != Self::SERIALIZED_SIZE {
            return Err(CoreError::Serialization(format!(
                "chaininfo: expected {} bytes, got {}",
                Self::SERIALIZED_SIZE,
                data.len()
            )));
        }
        let mut tip = [0u8; 32];
        tip.copy_from_slice(&data[4..36]);
        Ok(ChainInfoMessage {
            height: u32::from_le_bytes(data[0..4].try_into().unwrap()),
            tip: Hash::from_bytes(tip),
            bits: u32::from_le_bytes(data[36..40].try_into().unwrap()),
            supply: u64::from_le_bytes(data[40..48].try_into().unwrap()),
        })
    }
}

/// Which account a client is asking about.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GetAccountMessage {
    pub address: chroma_core::types::Address,
}

impl GetAccountMessage {
    pub const SERIALIZED_SIZE: usize = 20;

    pub fn encode(&self) -> Vec<u8> {
        self.address.as_hash160().as_bytes().to_vec()
    }

    pub fn decode(data: &[u8]) -> Result<Self> {
        if data.len() != Self::SERIALIZED_SIZE {
            return Err(CoreError::Serialization(format!(
                "getaccount: expected {} bytes, got {}",
                Self::SERIALIZED_SIZE,
                data.len()
            )));
        }
        let mut raw = [0u8; 20];
        raw.copy_from_slice(data);
        Ok(GetAccountMessage {
            address: chroma_core::types::Address::from_hash160(chroma_core::hash::Hash160(raw)),
        })
    }
}

/// The answer. `exists` distinguishes an account holding nothing from one the
/// chain has never seen — the balance is zero either way, and which it is
/// tells a user whether they are looking in the right place.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccountMessage {
    pub address: chroma_core::types::Address,
    pub exists: bool,
    pub balance: u64,
    pub nonce: u64,
}

impl AccountMessage {
    pub const SERIALIZED_SIZE: usize = 20 + 1 + 8 + 8;

    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(Self::SERIALIZED_SIZE);
        buf.extend_from_slice(self.address.as_hash160().as_bytes());
        buf.push(u8::from(self.exists));
        buf.extend_from_slice(&self.balance.to_le_bytes());
        buf.extend_from_slice(&self.nonce.to_le_bytes());
        buf
    }

    pub fn decode(data: &[u8]) -> Result<Self> {
        if data.len() != Self::SERIALIZED_SIZE {
            return Err(CoreError::Serialization(format!(
                "account: expected {} bytes, got {}",
                Self::SERIALIZED_SIZE,
                data.len()
            )));
        }
        let mut raw = [0u8; 20];
        raw.copy_from_slice(&data[..20]);
        if data[20] > 1 {
            return Err(CoreError::Serialization(
                "account: exists flag is not a boolean".to_string(),
            ));
        }
        Ok(AccountMessage {
            address: chroma_core::types::Address::from_hash160(chroma_core::hash::Hash160(raw)),
            exists: data[20] == 1,
            balance: u64::from_le_bytes(data[21..29].try_into().unwrap()),
            nonce: u64::from_le_bytes(data[29..37].try_into().unwrap()),
        })
    }
}

#[derive(Clone, Debug)]
pub struct RejectMessage {
    pub message: String,
    pub code: u8,
    pub reason: String,
}

impl RejectMessage {
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        let msg_bytes = self.message.as_bytes();
        buf.push(msg_bytes.len() as u8);
        buf.extend_from_slice(msg_bytes);
        buf.push(self.code);
        let reason_bytes = self.reason.as_bytes();
        buf.push(reason_bytes.len() as u8);
        buf.extend_from_slice(reason_bytes);
        buf
    }

    pub fn decode(data: &[u8]) -> Result<Self> {
        if data.len() < 3 {
            return Err(CoreError::Serialization("reject: too short".to_string()));
        }
        let msg_len = data[0] as usize;
        if data.len() < 2 + msg_len {
            return Err(CoreError::Serialization("reject: message truncated".to_string()));
        }
        let message = String::from_utf8_lossy(&data[1..1 + msg_len]).to_string();
        let code = data[1 + msg_len];
        let reason_start = 2 + msg_len;
        if data.len() < reason_start + 1 {
            return Err(CoreError::Serialization("reject: reason length missing".to_string()));
        }
        let reason_len = data[reason_start] as usize;
        let reason_end = reason_start + 1 + reason_len;
        if data.len() < reason_end {
            return Err(CoreError::Serialization("reject: reason truncated".to_string()));
        }
        let reason = String::from_utf8_lossy(&data[reason_start + 1..reason_end]).to_string();
        Ok(RejectMessage {
            message,
            code,
            reason,
        })
    }
}

// ============================================================================
// Transaction lookup
// ============================================================================

/// How many history entries one answer may carry.
///
/// Bounded so the reply cannot approach `MAX_MESSAGE_SIZE`: an entry is 72
/// bytes, so a thousand of them is 72 KB. A miner's address gains an entry
/// every ten seconds, and answering with all of them is not a service anyone
/// wants on either end of the connection.
pub const MAX_HISTORY_ENTRIES: u32 = 1000;

/// Why a lookup came back without an answer.
///
/// "Not found" and "this node does not keep the index" are different facts,
/// and a client told only the first would conclude a transaction never
/// happened when the truth is that nobody looked.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LookupStatus {
    Found = 0,
    NotFound = 1,
    NotIndexed = 2,
}

impl LookupStatus {
    fn from_u8(v: u8) -> Result<Self> {
        match v {
            0 => Ok(LookupStatus::Found),
            1 => Ok(LookupStatus::NotFound),
            2 => Ok(LookupStatus::NotIndexed),
            _ => Err(CoreError::Serialization(format!(
                "lookup status: unknown value {}",
                v
            ))),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GetTransactionMessage {
    pub tx_hash: Hash,
}

impl GetTransactionMessage {
    pub const SERIALIZED_SIZE: usize = 32;

    pub fn encode(&self) -> Vec<u8> {
        self.tx_hash.as_bytes().to_vec()
    }

    pub fn decode(data: &[u8]) -> Result<Self> {
        if data.len() != Self::SERIALIZED_SIZE {
            return Err(CoreError::Serialization(format!(
                "gettransaction: expected {} bytes, got {}",
                Self::SERIALIZED_SIZE,
                data.len()
            )));
        }
        let mut raw = [0u8; 32];
        raw.copy_from_slice(data);
        Ok(GetTransactionMessage { tx_hash: Hash(raw) })
    }
}

/// Where a transaction was mined, and the transaction itself.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransactionAtMessage {
    pub status: LookupStatus,
    pub tx_hash: Hash,
    pub block_hash: Hash,
    pub height: u32,
    pub position: u32,
    /// False when the block that carries it lost a fork. The transaction is
    /// real and was mined, but not on the chain anyone is following.
    pub on_active_chain: bool,
    pub transaction: Option<chroma_tx::Transaction>,
}

impl TransactionAtMessage {
    /// The whole answer when a transaction was found.
    pub const FOUND_SIZE: usize = 1 + 32 + 32 + 4 + 4 + 1 + chroma_tx::Transaction::SERIALIZED_SIZE;

    pub fn missing(status: LookupStatus) -> Self {
        TransactionAtMessage {
            status,
            tx_hash: Hash::ZERO,
            block_hash: Hash::ZERO,
            height: 0,
            position: 0,
            on_active_chain: false,
            transaction: None,
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        use chroma_core::serialize::CanonicalEncode;

        if self.status != LookupStatus::Found {
            return vec![self.status as u8];
        }
        let mut buf = Vec::with_capacity(Self::FOUND_SIZE);
        buf.push(self.status as u8);
        buf.extend_from_slice(self.tx_hash.as_bytes());
        buf.extend_from_slice(self.block_hash.as_bytes());
        buf.extend_from_slice(&self.height.to_le_bytes());
        buf.extend_from_slice(&self.position.to_le_bytes());
        buf.push(self.on_active_chain as u8);
        match &self.transaction {
            Some(tx) => buf.extend_from_slice(&tx.encode()),
            None => buf.extend_from_slice(&[0u8; chroma_tx::Transaction::SERIALIZED_SIZE]),
        }
        buf
    }

    pub fn decode(data: &[u8]) -> Result<Self> {
        use chroma_core::serialize::CanonicalDecode;

        if data.is_empty() {
            return Err(CoreError::Serialization(
                "transactionat: empty payload".to_string(),
            ));
        }
        let status = LookupStatus::from_u8(data[0])?;
        if status != LookupStatus::Found {
            return Ok(Self::missing(status));
        }
        if data.len() != Self::FOUND_SIZE {
            return Err(CoreError::Serialization(format!(
                "transactionat: expected {} bytes, got {}",
                Self::FOUND_SIZE,
                data.len()
            )));
        }
        let mut tx_hash = [0u8; 32];
        tx_hash.copy_from_slice(&data[1..33]);
        let mut block_hash = [0u8; 32];
        block_hash.copy_from_slice(&data[33..65]);
        let mut height = [0u8; 4];
        height.copy_from_slice(&data[65..69]);
        let mut position = [0u8; 4];
        position.copy_from_slice(&data[69..73]);
        let on_active_chain = data[73] != 0;
        let transaction = chroma_tx::Transaction::decode(&data[74..])?;

        Ok(TransactionAtMessage {
            status,
            tx_hash: Hash(tx_hash),
            block_hash: Hash(block_hash),
            height: u32::from_le_bytes(height),
            position: u32::from_le_bytes(position),
            on_active_chain,
            transaction: Some(transaction),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GetHistoryMessage {
    pub address: chroma_core::types::Address,
    /// Entries wanted, from the newest end. Clamped to `MAX_HISTORY_ENTRIES`.
    pub limit: u32,
}

impl GetHistoryMessage {
    pub const SERIALIZED_SIZE: usize = 20 + 4;

    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(Self::SERIALIZED_SIZE);
        buf.extend_from_slice(self.address.as_hash160().as_bytes());
        buf.extend_from_slice(&self.limit.to_le_bytes());
        buf
    }

    pub fn decode(data: &[u8]) -> Result<Self> {
        if data.len() != Self::SERIALIZED_SIZE {
            return Err(CoreError::Serialization(format!(
                "gethistory: expected {} bytes, got {}",
                Self::SERIALIZED_SIZE,
                data.len()
            )));
        }
        let mut raw = [0u8; 20];
        raw.copy_from_slice(&data[..20]);
        let mut limit = [0u8; 4];
        limit.copy_from_slice(&data[20..24]);
        Ok(GetHistoryMessage {
            address: chroma_core::types::Address::from_hash160(chroma_core::hash::Hash160(raw)),
            limit: u32::from_le_bytes(limit),
        })
    }
}

/// One transaction in an address's history.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HistoryEntry {
    pub tx_hash: Hash,
    pub block_hash: Hash,
    pub height: u32,
    pub position: u32,
}

impl HistoryEntry {
    pub const SERIALIZED_SIZE: usize = 32 + 32 + 4 + 4;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HistoryMessage {
    pub status: LookupStatus,
    /// How many the node holds in total, which may exceed what it sent.
    pub total: u32,
    pub entries: Vec<HistoryEntry>,
}

impl HistoryMessage {
    pub fn not_indexed() -> Self {
        HistoryMessage {
            status: LookupStatus::NotIndexed,
            total: 0,
            entries: Vec::new(),
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        if self.status == LookupStatus::NotIndexed {
            return vec![self.status as u8];
        }
        let mut buf = Vec::with_capacity(9 + self.entries.len() * HistoryEntry::SERIALIZED_SIZE);
        buf.push(LookupStatus::Found as u8);
        buf.extend_from_slice(&self.total.to_le_bytes());
        buf.extend_from_slice(&(self.entries.len() as u32).to_le_bytes());
        for entry in &self.entries {
            buf.extend_from_slice(entry.tx_hash.as_bytes());
            buf.extend_from_slice(entry.block_hash.as_bytes());
            buf.extend_from_slice(&entry.height.to_le_bytes());
            buf.extend_from_slice(&entry.position.to_le_bytes());
        }
        buf
    }

    pub fn decode(data: &[u8]) -> Result<Self> {
        if data.is_empty() {
            return Err(CoreError::Serialization(
                "history: empty payload".to_string(),
            ));
        }
        let status = LookupStatus::from_u8(data[0])?;
        if status == LookupStatus::NotIndexed {
            return Ok(Self::not_indexed());
        }
        if data.len() < 9 {
            return Err(CoreError::Serialization(
                "history: truncated header".to_string(),
            ));
        }
        let mut total = [0u8; 4];
        total.copy_from_slice(&data[1..5]);
        let mut count = [0u8; 4];
        count.copy_from_slice(&data[5..9]);
        let count = u32::from_le_bytes(count) as usize;

        if count > MAX_HISTORY_ENTRIES as usize {
            return Err(CoreError::Serialization(format!(
                "history: {} entries, more than the {} allowed",
                count, MAX_HISTORY_ENTRIES
            )));
        }
        let expected = 9 + count * HistoryEntry::SERIALIZED_SIZE;
        if data.len() != expected {
            return Err(CoreError::Serialization(format!(
                "history: expected {} bytes for {} entries, got {}",
                expected,
                count,
                data.len()
            )));
        }

        let mut entries = Vec::with_capacity(count);
        for i in 0..count {
            let at = 9 + i * HistoryEntry::SERIALIZED_SIZE;
            let mut tx_hash = [0u8; 32];
            tx_hash.copy_from_slice(&data[at..at + 32]);
            let mut block_hash = [0u8; 32];
            block_hash.copy_from_slice(&data[at + 32..at + 64]);
            let mut height = [0u8; 4];
            height.copy_from_slice(&data[at + 64..at + 68]);
            let mut position = [0u8; 4];
            position.copy_from_slice(&data[at + 68..at + 72]);
            entries.push(HistoryEntry {
                tx_hash: Hash(tx_hash),
                block_hash: Hash(block_hash),
                height: u32::from_le_bytes(height),
                position: u32::from_le_bytes(position),
            });
        }

        Ok(HistoryMessage {
            status: LookupStatus::Found,
            total: u32::from_le_bytes(total),
            entries,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chroma_core::serialize::CanonicalEncode;

    #[test]
    fn test_message_roundtrip() {
        let msg = Message::new(MessageType::Ping, vec![1, 2, 3, 4]);
        let encoded = msg.encode();
        let (decoded, consumed) = Message::decode(&encoded).unwrap();
        assert_eq!(consumed, encoded.len());
        assert_eq!(decoded.msg_type, MessageType::Ping);
        assert_eq!(decoded.payload, vec![1, 2, 3, 4]);
    }

    #[test]
    fn test_message_rejects_bad_magic() {
        let mut data = Message::new(MessageType::Ping, vec![0]).encode();
        data[0] = 0xFF;
        assert!(Message::decode(&data).is_err());
    }

    #[test]
    fn test_message_rejects_bad_checksum() {
        let mut data = Message::new(MessageType::Ping, vec![0]).encode();
        data[9] ^= 0xFF;
        assert!(Message::decode(&data).is_err());
    }

    #[test]
    fn test_message_rejects_truncated() {
        let data = Message::new(MessageType::Ping, vec![0]).encode();
        assert!(Message::decode(&data[..5]).is_err());
    }

    #[test]
    fn test_message_rejects_oversized() {
        let msg = Message::new(MessageType::Block, vec![0u8; MAX_MESSAGE_SIZE + 1]);
        let encoded = msg.encode();
        assert!(Message::decode(&encoded).is_err());
    }

    #[test]
    fn test_version_roundtrip() {
        let v = VersionMessage {
            version: 1,
            services: 0,
            timestamp: 1700000000,
            height: 100,
            nonce: 42,
            listen_port: 8333,
        };
        let enc = v.encode();
        assert_eq!(enc.len(), VersionMessage::SERIALIZED_SIZE);
        let dec = VersionMessage::decode(&enc).unwrap();
        assert_eq!(dec.version, 1);
        assert_eq!(dec.height, 100);
        assert_eq!(dec.nonce, 42);
        assert_eq!(dec.listen_port, 8333);
    }

    /// A newer peer may append fields to its version message. Refusing those
    /// would mean an older node could never complete a handshake with a newer
    /// one, and the version negotiation right after this decode would never
    /// get to run.
    #[test]
    fn test_version_accepts_a_longer_payload_from_a_newer_peer() {
        let version = VersionMessage {
            version: crate::PROTOCOL_VERSION + 1,
            services: 1,
            timestamp: 1_700_000_000,
            height: 42,
            nonce: 7,
            listen_port: 8333,
        };
        let mut payload = version.encode();
        payload.extend_from_slice(b"a field from a later version");

        let decoded = VersionMessage::decode(&payload).expect("must stay readable");
        assert_eq!(
            decoded.encode(),
            version.encode(),
            "the fields we know must decode unchanged"
        );
    }

    #[test]
    fn test_version_rejects_short() {
        assert!(VersionMessage::decode(&[0u8; 31]).is_err());
        // One byte short of the listen_port field.
        assert!(VersionMessage::decode(&[0u8; 33]).is_err());
    }

    // ------------------------------------------------------------------
    // Stream framing
    // ------------------------------------------------------------------

    #[test]
    fn test_decode_frame_complete() {
        let msg = Message::new(MessageType::Ping, vec![1, 2, 3, 4]);
        let encoded = msg.encode();
        match decode_frame(&encoded).unwrap() {
            FrameDecode::Complete { message, consumed } => {
                assert_eq!(consumed, encoded.len());
                assert_eq!(message.msg_type, MessageType::Ping);
                assert_eq!(message.payload, vec![1, 2, 3, 4]);
            }
            other => panic!("expected Complete, got {:?}", other),
        }
    }

    #[test]
    fn test_decode_frame_incomplete_is_not_an_error() {
        let encoded = Message::new(MessageType::Block, vec![7u8; 4096]).encode();

        // Fewer bytes than the header: length not yet known.
        match decode_frame(&encoded[..HEADER_SIZE - 1]).unwrap() {
            FrameDecode::Incomplete { needed } => assert_eq!(needed, None),
            other => panic!("expected Incomplete, got {:?}", other),
        }

        // Header present, payload partial: total length is known.
        match decode_frame(&encoded[..encoded.len() - 1]).unwrap() {
            FrameDecode::Incomplete { needed } => assert_eq!(needed, Some(encoded.len())),
            other => panic!("expected Incomplete, got {:?}", other),
        }
    }

    #[test]
    fn test_decode_frame_rejects_garbage() {
        let mut data = Message::new(MessageType::Ping, vec![0]).encode();
        data[0] = 0xFF;
        assert!(decode_frame(&data).is_err(), "bad magic must be an error");

        let mut data = Message::new(MessageType::Ping, vec![0]).encode();
        data[9] ^= 0xFF;
        assert!(decode_frame(&data).is_err(), "bad checksum must be an error");

        // An oversized declared length is an error even before the payload
        // arrives — otherwise a peer could pin unbounded memory.
        let mut data = Message::new(MessageType::Block, vec![]).encode();
        data[5..9].copy_from_slice(&((MAX_MESSAGE_SIZE + 1) as u32).to_le_bytes());
        assert!(decode_frame(&data).is_err(), "oversized length must be an error");
    }

    #[test]
    fn test_decode_frame_stream_of_messages() {
        // Two frames back to back, delivered one byte at a time, must decode
        // in order with no loss — the property the old fixed-buffer reader
        // violated.
        let m1 = Message::new(MessageType::Ping, PingMessage { nonce: 1 }.encode());
        let m2 = Message::new(MessageType::Block, vec![9u8; 20_000]);
        let mut wire = m1.encode();
        wire.extend_from_slice(&m2.encode());

        let mut acc: Vec<u8> = Vec::new();
        let mut decoded: Vec<Message> = Vec::new();
        for byte in &wire {
            acc.push(*byte);
            loop {
                match decode_frame(&acc).unwrap() {
                    FrameDecode::Complete { message, consumed } => {
                        acc.drain(..consumed);
                        decoded.push(message);
                    }
                    FrameDecode::Incomplete { .. } => break,
                }
            }
        }

        assert!(acc.is_empty(), "no bytes should be left over");
        assert_eq!(decoded.len(), 2);
        assert_eq!(decoded[0].msg_type, MessageType::Ping);
        assert_eq!(decoded[1].msg_type, MessageType::Block);
        assert_eq!(decoded[1].payload.len(), 20_000);
    }

    #[test]
    fn test_decode_frame_max_size_payload() {
        // A 1 MiB block (the protocol maximum) must survive framing.
        let payload = vec![0xABu8; chroma_core::constants::MAX_BLOCK_SIZE];
        let encoded = Message::new(MessageType::Block, payload.clone()).encode();
        match decode_frame(&encoded).unwrap() {
            FrameDecode::Complete { message, consumed } => {
                assert_eq!(consumed, encoded.len());
                assert_eq!(message.payload.len(), payload.len());
            }
            other => panic!("expected Complete, got {:?}", other),
        }
    }

    fn sample_header(height: u32) -> chroma_block::BlockHeader {
        use chroma_core::types::{BlockHeight, CompactTarget};
        chroma_block::BlockHeader {
            version: 1,
            previous_hash: Hash::blake3(&height.to_le_bytes()),
            state_root: Hash::blake3(b"state"),
            tx_merkle_root: Hash::blake3(b"txs"),
            timestamp: 1_700_000_000 + height as u64 * 10,
            bits: CompactTarget::DIFFICULTY_1,
            height: BlockHeight(height),
            nonce: height as u64,
        }
    }

    #[test]
    fn test_headers_roundtrip() {
        let headers: Vec<_> = (0..5).map(sample_header).collect();
        let msg = HeadersMessage {
            headers: headers.clone(),
        };
        let dec = HeadersMessage::decode(&msg.encode()).unwrap();
        assert_eq!(dec.headers, headers);
    }

    #[test]
    fn test_headers_empty() {
        let dec = HeadersMessage::decode(&HeadersMessage { headers: vec![] }.encode()).unwrap();
        assert!(dec.headers.is_empty());
    }

    #[test]
    fn test_headers_rejects_inflated_count() {
        // A peer claiming more headers than the payload can hold must be
        // rejected before anything is allocated for the claim.
        let mut data = chroma_core::serialize::encode_leb128(100_000);
        data.extend_from_slice(&sample_header(1).encode());
        assert!(HeadersMessage::decode(&data).is_err());
    }

    #[test]
    fn test_headers_rejects_trailing_bytes() {
        let mut data = HeadersMessage {
            headers: vec![sample_header(1)],
        }
        .encode();
        data.push(0xFF);
        assert!(HeadersMessage::decode(&data).is_err());
    }

    #[test]
    fn test_headers_survives_full_frame() {
        // A maximum-size headers response must fit inside one message.
        let headers: Vec<_> = (0..crate::sync::MAX_HEADERS_PER_RESPONSE as u32)
            .map(sample_header)
            .collect();
        let payload = HeadersMessage {
            headers: headers.clone(),
        }
        .encode();
        assert!(payload.len() < MAX_MESSAGE_SIZE);

        let framed = Message::new(MessageType::Headers, payload).encode();
        match decode_frame(&framed).unwrap() {
            FrameDecode::Complete { message, .. } => {
                assert_eq!(HeadersMessage::decode(&message.payload).unwrap().headers, headers);
            }
            other => panic!("expected Complete, got {:?}", other),
        }
    }

    #[test]
    fn test_ping_roundtrip() {
        let p = PingMessage { nonce: 999 };
        let enc = p.encode();
        let dec = PingMessage::decode(&enc).unwrap();
        assert_eq!(dec.nonce, 999);
    }

    #[test]
    fn test_ping_rejects_short() {
        assert!(PingMessage::decode(&[0u8; 7]).is_err());
    }

    #[test]
    fn test_getheaders_roundtrip() {
        let gh = GetHeadersMessage {
            start_hash: Hash::blake3(b"start"),
            stop_hash: Hash::blake3(b"stop"),
        };
        let enc = gh.encode();
        let dec = GetHeadersMessage::decode(&enc).unwrap();
        assert_eq!(dec.start_hash, gh.start_hash);
        assert_eq!(dec.stop_hash, gh.stop_hash);
    }

    #[test]
    fn test_inv_roundtrip() {
        let inv = InvMessage {
            inventory: vec![
                InvEntry {
                    inv_type: InvType::Block,
                    hash: Hash::blake3(b"block1"),
                },
                InvEntry {
                    inv_type: InvType::Tx,
                    hash: Hash::blake3(b"tx1"),
                },
            ],
        };
        let enc = inv.encode();
        let dec = InvMessage::decode(&enc).unwrap();
        assert_eq!(dec.inventory.len(), 2);
        assert_eq!(dec.inventory[0].inv_type, InvType::Block);
        assert_eq!(dec.inventory[1].inv_type, InvType::Tx);
    }

    #[test]
    fn test_inv_empty() {
        let inv = InvMessage {
            inventory: vec![],
        };
        let enc = inv.encode();
        let dec = InvMessage::decode(&enc).unwrap();
        assert!(dec.inventory.is_empty());
    }

    #[test]
    fn test_getdata_roundtrip() {
        let gd = GetDataMessage {
            inventory: vec![InvEntry {
                inv_type: InvType::Block,
                hash: Hash::blake3(b"test"),
            }],
        };
        let enc = gd.encode();
        let dec = GetDataMessage::decode(&enc).unwrap();
        assert_eq!(dec.inventory.len(), 1);
    }

    /// A peer address with distinct, arbitrary keys.
    fn test_peer(socket: std::net::SocketAddr) -> crate::peer::PeerAddress {
        crate::peer::PeerAddress::new(
            chroma_crypto::noise::NodeId::generate(),
            chroma_crypto::noise::NoiseKey::from_bytes(chroma_crypto::noise::NodeId::generate().0),
            socket,
        )
    }

    #[test]
    fn test_addr_roundtrip() {
        use std::net::SocketAddr;
        let addrs: Vec<crate::peer::PeerAddress> = vec![
            "127.0.0.1:8333".parse::<SocketAddr>().unwrap(),
            "192.0.2.42:19000".parse::<SocketAddr>().unwrap(),
            "[2001:db8::1]:8333".parse::<SocketAddr>().unwrap(),
        ]
        .into_iter()
        .map(test_peer)
        .collect();
        let msg = AddrMessage {
            addrs: addrs.clone(),
        };
        let decoded = AddrMessage::decode(&msg.encode()).unwrap();
        assert_eq!(decoded.addrs, addrs, "v4 and v6 must both survive");
    }

    #[test]
    fn test_addr_empty() {
        let msg = AddrMessage { addrs: vec![] };
        assert_eq!(AddrMessage::decode(&msg.encode()).unwrap().addrs.len(), 0);
    }

    #[test]
    fn test_addr_rejects_oversized_count() {
        // A declared count beyond the cap must be refused before anything is
        // allocated for it.
        let mut payload = chroma_core::serialize::encode_leb128((MAX_ADDRS_PER_MESSAGE + 1) as u64);
        payload.extend_from_slice(&[0u8; 64]);
        payload.push(4);
        payload.extend_from_slice(&[127, 0, 0, 1]);
        payload.extend_from_slice(&8333u16.to_le_bytes());
        assert!(AddrMessage::decode(&payload).is_err());
    }

    #[test]
    fn test_addr_rejects_truncated_and_trailing() {
        let msg = AddrMessage {
            addrs: vec![test_peer("127.0.0.1:8333".parse().unwrap())],
        };
        let encoded = msg.encode();
        assert!(AddrMessage::decode(&encoded[..encoded.len() - 1]).is_err());

        let mut extra = encoded.clone();
        extra.push(0);
        assert!(AddrMessage::decode(&extra).is_err());
    }

    #[test]
    fn test_addr_rejects_unknown_family() {
        let mut payload = chroma_core::serialize::encode_leb128(1);
        payload.extend_from_slice(&[0u8; 64]);
        payload.push(9); // neither 4 nor 6
        payload.extend_from_slice(&[0; 4]);
        payload.extend_from_slice(&8333u16.to_le_bytes());
        assert!(AddrMessage::decode(&payload).is_err());
    }

    #[test]
    fn test_addr_encode_caps_the_list() {
        use std::net::{IpAddr, Ipv4Addr, SocketAddr};
        let addrs: Vec<crate::peer::PeerAddress> = (0..(MAX_ADDRS_PER_MESSAGE + 50))
            .map(|i| {
                test_peer(SocketAddr::new(
                    IpAddr::V4(Ipv4Addr::new(10, 0, (i / 256) as u8, (i % 256) as u8)),
                    8333,
                ))
            })
            .collect();
        let decoded = AddrMessage::decode(&AddrMessage { addrs }.encode()).unwrap();
        assert_eq!(decoded.addrs.len(), MAX_ADDRS_PER_MESSAGE);
    }

    #[test]
    fn test_reject_roundtrip() {
        let r = RejectMessage {
            message: "tx".to_string(),
            code: 0x01,
            reason: "bad sig".to_string(),
        };
        let enc = r.encode();
        let dec = RejectMessage::decode(&enc).unwrap();
        assert_eq!(dec.message, "tx");
        assert_eq!(dec.code, 0x01);
        assert_eq!(dec.reason, "bad sig");
    }

    #[test]
    fn test_reject_rejects_short() {
        assert!(RejectMessage::decode(&[0u8; 2]).is_err());
    }

    #[test]
    fn test_message_type_roundtrips() {
        for i in 0x01..=0x16 {
            let mt = MessageType::from_u8(i).unwrap();
            assert_eq!(MessageType::from_u8(mt as u8).unwrap(), mt);
        }
        assert!(MessageType::from_u8(0x00).is_err());
        // The first code past the ones defined. Kept as an explicit bound so
        // adding a type without extending the loop above fails here.
        assert!(MessageType::from_u8(0x17).is_err());
    }

    #[test]
    fn test_chain_info_roundtrip() {
        let info = ChainInfoMessage {
            height: 152,
            tip: Hash::blake3(b"tip"),
            bits: 0x1f100000,
            supply: 152_000_000,
        };
        assert_eq!(ChainInfoMessage::decode(&info.encode()).unwrap(), info);
        assert!(ChainInfoMessage::decode(&[0u8; 4]).is_err());
        let mut long = info.encode();
        long.push(0);
        assert!(ChainInfoMessage::decode(&long).is_err());
    }

    #[test]
    fn test_account_roundtrip() {
        use chroma_core::hash::Hash160;
        use chroma_core::types::Address;

        let account = AccountMessage {
            address: Address::from_hash160(Hash160([7u8; 20])),
            exists: true,
            balance: 21_000_000,
            nonce: 3,
        };
        assert_eq!(AccountMessage::decode(&account.encode()).unwrap(), account);

        let absent = AccountMessage {
            exists: false,
            balance: 0,
            nonce: 0,
            ..account
        };
        assert_eq!(AccountMessage::decode(&absent.encode()).unwrap(), absent);

        // The flag is a boolean on the wire, so anything else is a peer
        // sending something we did not agree to.
        let mut bad = account.encode();
        bad[20] = 2;
        assert!(AccountMessage::decode(&bad).is_err());

        assert!(AccountMessage::decode(&[0u8; 10]).is_err());
    }

    #[test]
    fn test_get_account_roundtrip() {
        use chroma_core::hash::Hash160;
        use chroma_core::types::Address;

        let request = GetAccountMessage {
            address: Address::from_hash160(Hash160([9u8; 20])),
        };
        assert_eq!(GetAccountMessage::decode(&request.encode()).unwrap(), request);
        assert!(GetAccountMessage::decode(&[0u8; 19]).is_err());
        assert!(GetAccountMessage::decode(&[0u8; 21]).is_err());
    }

    #[test]
    fn test_inv_type_roundtrips() {
        assert_eq!(InvType::from_u8(0x01).unwrap(), InvType::Block);
        assert_eq!(InvType::from_u8(0x02).unwrap(), InvType::Tx);
        assert!(InvType::from_u8(0x00).is_err());
        assert!(InvType::from_u8(0x03).is_err());
    }

    #[test]
    fn test_multiple_messages_concatenated() {
        let m1 = Message::new(MessageType::Ping, PingMessage { nonce: 1 }.encode());
        let m2 = Message::new(MessageType::Pong, PingMessage { nonce: 2 }.encode());
        let mut buf = m1.encode();
        buf.extend_from_slice(&m2.encode());

        let (msg1, pos1) = Message::decode(&buf).unwrap();
        assert_eq!(msg1.msg_type, MessageType::Ping);
        let (msg2, pos2) = Message::decode(&buf[pos1..]).unwrap();
        assert_eq!(msg2.msg_type, MessageType::Pong);
        assert_eq!(pos1 + pos2, buf.len());
    }

    #[test]
    fn test_get_transaction_roundtrip() {
        let msg = GetTransactionMessage {
            tx_hash: Hash::blake3(b"a transaction"),
        };
        assert_eq!(
            GetTransactionMessage::decode(&msg.encode()).unwrap(),
            msg
        );
        assert!(GetTransactionMessage::decode(&[0u8; 31]).is_err());
    }

    #[test]
    fn test_transaction_at_roundtrip() {
        // A real public key: decode validates it, and an arbitrary 32 bytes
        // is almost never a point on the curve.
        let secret = chroma_crypto::schnorr::SecretKey32::from_bytes([0x33; 32]).unwrap();
        let pubkey = chroma_crypto::schnorr::PublicKey32::from_secret(&secret).unwrap();
        let tx = chroma_tx::Transaction {
            sender_pubkey: pubkey,
            recipient: chroma_core::types::Address::from_hash160(chroma_core::hash::Hash160(
                [4u8; 20],
            )),
            amount: chroma_core::types::Amount(1234),
            nonce: chroma_core::types::Nonce(7),
            signature: chroma_crypto::schnorr::Signature64([5u8; 64]),
        };
        let msg = TransactionAtMessage {
            status: LookupStatus::Found,
            tx_hash: Hash::blake3(b"tx"),
            block_hash: Hash::blake3(b"block"),
            height: 918,
            position: 3,
            on_active_chain: true,
            transaction: Some(tx),
        };
        assert_eq!(TransactionAtMessage::decode(&msg.encode()).unwrap(), msg);
    }

    #[test]
    fn a_missing_transaction_says_which_kind_of_missing() {
        // "not found" and "this node keeps no index" have to stay apart on
        // the wire: told only the first, a client concludes a transaction
        // never happened when in fact nobody looked.
        for status in [LookupStatus::NotFound, LookupStatus::NotIndexed] {
            let msg = TransactionAtMessage::missing(status);
            let decoded = TransactionAtMessage::decode(&msg.encode()).unwrap();
            assert_eq!(decoded.status, status);
            assert!(decoded.transaction.is_none());
        }
    }

    #[test]
    fn test_get_history_roundtrip() {
        let msg = GetHistoryMessage {
            address: chroma_core::types::Address::from_hash160(chroma_core::hash::Hash160(
                [9u8; 20],
            )),
            limit: 50,
        };
        assert_eq!(GetHistoryMessage::decode(&msg.encode()).unwrap(), msg);
        assert!(GetHistoryMessage::decode(&[0u8; 23]).is_err());
    }

    #[test]
    fn test_history_roundtrip() {
        let entries: Vec<HistoryEntry> = (0..4u32)
            .map(|i| HistoryEntry {
                tx_hash: Hash::blake3(&i.to_le_bytes()),
                block_hash: Hash::blake3(b"block"),
                height: 100 + i,
                position: i,
            })
            .collect();
        let msg = HistoryMessage {
            status: LookupStatus::Found,
            total: 900,
            entries,
        };
        let decoded = HistoryMessage::decode(&msg.encode()).unwrap();
        assert_eq!(decoded, msg);
        assert_eq!(decoded.total, 900, "how many the node holds, not how many it sent");

        let none = HistoryMessage::not_indexed();
        assert_eq!(HistoryMessage::decode(&none.encode()).unwrap(), none);
    }

    #[test]
    fn history_refuses_a_count_it_would_never_send() {
        // A peer claiming more entries than the cap allows would have us
        // allocate for them before reading a single one.
        let mut payload = vec![LookupStatus::Found as u8];
        payload.extend_from_slice(&0u32.to_le_bytes());
        payload.extend_from_slice(&(MAX_HISTORY_ENTRIES + 1).to_le_bytes());
        assert!(HistoryMessage::decode(&payload).is_err());
    }
}
