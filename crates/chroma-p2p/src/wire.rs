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
        for i in 0x01..=0x0E {
            let mt = MessageType::from_u8(i).unwrap();
            assert_eq!(MessageType::from_u8(mt as u8).unwrap(), mt);
        }
        assert!(MessageType::from_u8(0x00).is_err());
        assert!(MessageType::from_u8(0x0F).is_err());
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
}
