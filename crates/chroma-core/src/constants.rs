//! Protocol Constants
//!
//! All values here are FINALIZED per Chroma Protocol Specification v0.1.
//! Changing any of these requires a hard fork.

/// Project identity
pub const PROJECT_NAME: &str = "Chroma";
pub const TICKER: &str = "CHR";
pub const SLOGAN: &str = "We are truly free.";

/// Monetary parameters
/// 1 CHR = 1,000,000 units (integer-only arithmetic)
pub const UNITS_PER_CHR: u64 = 1_000_000;
pub const MAX_SUPPLY_CHR: u64 = 100_000_000;
pub const MAX_SUPPLY_UNITS: u128 = (MAX_SUPPLY_CHR as u128) * (UNITS_PER_CHR as u128); // 100,000,000,000,000
pub const INITIAL_SUPPLY_UNITS: u128 = 0;

/// Block reward (fixed 1 CHR per block)
pub const BLOCK_REWARD_UNITS: u64 = UNITS_PER_CHR; // 1,000,000 units

/// Block timing
pub const TARGET_BLOCK_TIME_SECS: u64 = 10;
pub const DIFFICULTY_ADJUSTMENT_WINDOW: u32 = 10; // blocks
pub const TARGET_TIME_PER_WINDOW_SECS: u64 = TARGET_BLOCK_TIME_SECS * DIFFICULTY_ADJUSTMENT_WINDOW as u64; // 100 seconds

/// Difficulty bounds
pub const MAX_DIFFICULTY_INCREASE_FACTOR: u64 = 4; // 4x max increase per window
pub const MAX_DIFFICULTY_DECREASE_FACTOR: u64 = 4; // 4x max decrease per window (1/4)

/// Block size limits
pub const MAX_BLOCK_SIZE: usize = 1_048_576; // 1 MiB per spec
pub const MAX_TRANSACTION_SIZE: usize = 65536; // 64 KiB per spec

/// How many transactions one account may have in a single block.
///
/// A consensus rule, not a relay policy: a block carrying more than this from
/// one sender is invalid, so it holds even against a miner who would rather
/// ignore it. Every other lever against a flooded mempool is advisory, and a
/// chain with no fees has no price to raise instead.
///
/// It does not stop an attacker who splits a balance across many accounts —
/// nothing that counts per account can. What it does is put a floor under
/// everyone else: no single account takes more than this share of a block.
///
/// Two, because blocks are ten seconds apart. One account sending more often
/// than that is a service, and a service can hold more than one account.
/// Erring low costs a determined attacker only more accounts, while erring
/// high cannot be corrected without a hard fork.
///
/// The coinbase is exempt: it has no sender.
pub const MAX_TXS_PER_SENDER_PER_BLOCK: usize = 2;

/// Mempool limits
pub const MAX_MEMPOOL_SIZE: usize = 50_000_000; // 50 MB
pub const MAX_MEMPOOL_TXS: usize = 100_000;

/// Network
pub const DEFAULT_PORT: u16 = 8333;
pub const PROTOCOL_VERSION: u32 = 1;

/// Genesis
pub const GENESIS_TIMESTAMP: u64 = 1767225600; // 2026-01-01 00:00:00 UTC
/// Genesis target: about 2^12 hashes per block.
///
/// Not Bitcoin's difficulty 1 (2^32). That number worked for a chain hashing
/// SHA-256 on 2009 CPUs against a ten-minute target; RandomX is deliberately
/// slow and the target here is ten seconds, so difficulty 1 would put the
/// first block days to years away — and the retarget only moves 4x per ten
/// blocks, so a chain that cannot mine cannot get easier either.
///
/// Erring low is the safe direction: too easy costs a few fast blocks before
/// the retarget tightens, while too hard cannot be recovered from.
pub const GENESIS_TARGET_BITS: u32 = 0x1f100000;

/// Timestamp validation
pub const MTP_WINDOW: usize = 7; // Median Time Past window
pub const MAX_FUTURE_TIMESTAMP_OFFSET: i64 = 20; // seconds in future allowed

/// RandomX
pub const RANDOMX_EPOCH_LENGTH: u32 = 1000; // blocks
pub const RANDOMX_SEED_LAG: u32 = 100; // blocks
pub const GENESIS_RANDOMX_SEED: &[u8] = b"Chroma Genesis Seed";

/// Reorg journal
pub const REORG_JOURNAL_DEPTH: u32 = 2000; // blocks (~5.5 hours)

/// State
pub const ADDRESS_HASH_LEN: usize = 20; // RIPEMD160(SHA256(pubkey))
pub const ACCOUNT_VALUE_LEN: usize = 16; // balance: u64 (8) + nonce: u64 (8)

/// Network identifiers
pub const DEVNET_NETWORK_ID: &str = "chroma-devnet";
pub const TESTNET_NETWORK_ID: &str = "chroma-testnet";
pub const MAINNET_NETWORK_ID: &str = "chroma-mainnet";

/// Address HRP (Human Readable Part)
pub const ADDRESS_HRP: &str = "chr";

/// Peer scoring
pub const PEER_BAN_THRESHOLD: i32 = 100;
pub const PEER_SCORE_DECAY_FACTOR: f64 = 0.99; // per minute

/// Rate limits (per peer)
pub const PEER_MSG_RATE_LIMIT: usize = 100; // messages per second
pub const PEER_TX_RATE_LIMIT: usize = 10; // transactions per second

/// Connection limits
pub const DEFAULT_OUTBOUND_CONNECTIONS: usize = 8;
pub const DEFAULT_INBOUND_CONNECTIONS: usize = 128;