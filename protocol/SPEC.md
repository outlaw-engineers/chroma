# Chroma プロトコル仕様書 v0.1

> "We are truly free."

## 1. プロトコル識別情報

| パラメータ    | 値                                           |
| -------- | ------------------------------------------- |
| 名称       | Chroma                                      |
| ティッカー    | CHR                                         |
| 最小単位     | 1 unit = 10⁻⁶ CHR                           |
| 最大供給量    | 100,000,000 CHR = 100,000,000,000,000 units |
| 初期供給量    | 0 CHR（プレマインなし）                              |
| ブロック報酬   | 1 CHR/block                                 |
| 上限到達後の報酬 | 0                                           |
| 目標ブロック時間 | 10秒                                         |

## 2. コンセンサス

### 2.1 フォーク選択

* 累積PoW仕事量が最大のチェーンを正規チェーンとする
* ブロック数ではなく、チェーン全体の累積仕事量を比較する
* 累積仕事量は各ブロックについて `2²⁵⁶ / target_i` を合計して求める
* 累積仕事量が同一の場合、先端ブロックのハッシュが小さいチェーンを優先する

### 2.2 実用上のファイナリティ

* 1ブロック確認はUX上の目安であり、プロトコル上の確定性を意味しない
* プロトコルレベルのファイナリティ機構は設けない
* チェックポイントおよび投票による確定機構は使用しない

### 2.3 Reorg

* 直近2000ブロック分（約5.5時間）のState Journalを保持する
* Reorg発生時はJournalを巻き戻し、新しいチェーンを適用する
* Journalの範囲を超えるReorgではGenesisから状態を再計算する

## 3. RandomX Seed

| パラメータ    | 値                                 |
| -------- | --------------------------------- |
| Epoch長   | 1000ブロック                          |
| Seed Lag | 100ブロック                           |
| Seed導出   | `epoch_start - lag` のブロックハッシュから導出 |
| ハッシュ関数   | BLAKE3                            |
| Cacheコスト | 約2 GB RAM、初期化1〜2秒                 |

100ブロックのSeed Lagにより、Seedのgrindingを抑制する。

* Seedを意図的に操作するためのブロック隠蔽確率：1/1000 per block
* 100ブロック未満のReorgではSeedは変更されない

## 4. Canonical Serialization

### 4.1 ルール

* エンコーダーとデコーダーは明示的に定義する
* `repr(C)` およびSerdeのデフォルトシリアライズには依存しない
* 整数は固定幅のlittle-endianでエンコードする
* Hashはbig-endian（display order）で扱う
* 可変長データはLEB128 length prefixを使用する
* 配列はLEB128 length prefixに続けて各要素を連結する
* `Option` は1-byte tagを使用する（`0x00 = None`, `0x01 = Some`）
* Structのフィールドは宣言順にエンコードする
* Enumは1-byte discriminantに続けてvariant dataをエンコードする

### 4.2 Canonical Hash

```text
canonical_hash(S) = BLAKE3(encode(S))
```

### 4.3 Test Vectors

```text
u64(0)                          → 00 00 00 00 00 00 00 00
u64(1_000_000)                 → 40 42 0F 00 00 00 00 00
u64(18446744073709551615)      → FF FF FF FF FF FF FF FF
Vec<u8>([])                     → 00
Vec<u8>([1,2,3])                → 03 01 02 03
Option(u32, Some(42))           → 01 2A 00 00 00
```

## 5. ブロックおよびトランザクションの制限

| 制限                 | 値                     |
| ------------------ | --------------------- |
| 最大ブロックサイズ          | 1 MB（1,048,576 bytes） |
| 最大トランザクションサイズ      | 64 KB                 |
| Mempool最大サイズ       | 50 MB                 |
| Mempool最大トランザクション数 | 100,000               |
| Peerレート制限          | 100 msg/s / peer      |
| Txレート制限            | 10 tx/s / peer        |

## 6. 署名

**アルゴリズム:** secp256k1上のSchnorr署名（BIP-340 style）

**Batch Verification:** 有効

**Nonce:** 決定論的Nonce（RFC 6979 / BIP-340 synthetic nonce）

## 7. State Model

### 7.1 Account

```text
key: Hash160(pubkey) → 20 bytes
value: { balance: u64, nonce: u64 } → 16 bytes
```

### 7.2 State Commitment

Stateは、`(key, value)` ペアをkeyの辞書順でソートしたSorted Merkle Treeによってcommitする。

* Leaf: `H(encode(key) || encode(value))`
* Internal Node: `H(left || right)`
* Empty Root: 32 bytes of zero
* Proof: Merkle path（`log₂N` sibling hashes）

## 8. Difficulty Adjustment

**調整間隔:** 10ブロック

**計算式:**

```text
new_target = old_target × actual_time / target_time
```

**変化幅:** 0.25×〜4× / adjustment

**最初の調整:** height 10。GenesisからBlock 10までのtimestampを使用する。

**演算:** overflow防止のため、intermediate calculationにはu256を使用する。

**表現:** Compact `bits`（1-byte exponent + 3-byte mantissa）

## 9. Timestamp

| ルール        | 値                               |
| ---------- | ------------------------------- |
| 過去側の制限     | `T > median_time_past`（直近7ブロック） |
| 未来側の制限     | `T ≤ network_time + 20 seconds` |
| MTP Window | 7ブロック                           |
| 使用箇所       | Difficulty Adjustment           |

## 10. Networking

| プロパティ                | 値                                    |
| -------------------- | ------------------------------------ |
| Transport            | TCP                                  |
| Node Identity        | ed25519 keypair、Node ID = public key |
| Encryption           | Noise_XK_25519_ChaChaPoly_BLAKE2s    |
| Discovery（Devnet）    | Hard-coded Bootstrap Nodes           |
| Discovery（Testnet以降） | DNS Seeds + Gossip                   |
| Outbound Connections | 8（default）                           |
| Inbound Connections  | 128（default）                         |
| Peer Scoring         | Score > 100 → Ban                    |

## 11. 不変条件

以下の条件は、いかなる場合も破ってはならない。

1. Total Supply ≤ 100,000,000 CHR
2. Balanceが負にならないこと（checked arithmetic）
3. AccountごとのNonceが厳密に増加すること
4. Signatureが有効であること（Schnorr verification）
5. Block HashがPoW Targetを満たすこと
6. Merkle RootがTransactionと一致すること
7. State RootがBlock適用後のStateと一致すること
8. `Timestamp > MTP` かつ `Timestamp ≤ network_time + 20s`
9. Block Size ≤ 1 MB
10. Transaction Size ≤ 64 KB
11. Integer overflow / underflowが発生しないこと

## 12. 実装アーキテクチャ

```text
chroma/
├── Cargo.toml
├── crates/
│   ├── chroma-core/          # Constants, Types, Serialization
│   ├── chroma-crypto/        # Schnorr, Hashing, RandomX, Noise
│   ├── chroma-state/         # Merkle Tree, State Transition, Journal
│   ├── chroma-tx/            # Transaction, Validation, Mempool
│   ├── chroma-block/         # Header, Block, Validation
│   ├── chroma-consensus/     # Fork Choice, Difficulty, PoW Verify
│   ├── chroma-storage/       # RocksDB Backend
│   ├── chroma-p2p/            # Networking
│   ├── chroma-wallet/         # Key Management
│   └── chroma-cli/            # Main Binary
├── tests/
│   ├── unit/
│   ├── integration/
│   ├── consensus/
│   ├── fuzz/
│   └── devnet/
└── protocol/
    ├── SPEC.md               # 本仕様書
    └── test_vectors/
```

### Consensus-Critical Crates

1. `chroma-core`
2. `chroma-crypto`
3. `chroma-state`
4. `chroma-tx`
5. `chroma-block`
6. `chroma-consensus`
7. `chroma-storage`（State Root persistence）

## 13. 未解決事項

* Upgrade mechanism（v1では仕様をfreezeし、別途設計する）
* DNS Seed Operatorのgovernance
* Light Client Protocol
* RPC/API仕様
* Wallet Seed Phrase（Protocolでは規定しない。UX上の方式は別途検討する）
* Testnet parameters（Mainnetとは異なる可能性がある）
