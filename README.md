# Chroma

Chroma（CHR）は、Rustで開発されている独立型のProof-of-Work（PoW）ブロックチェーンです。

**ティッカー:** CHR
**開発状況:** 初期開発段階

## 概要

Chromaは、独立した分散型PoWネットワークの構築を目的としたブロックチェーンプロジェクトです。

プロトコルの仕様は [`protocol/SPEC.md`](protocol/SPEC.md) に定義されています。

## ワークスペース構成

```text
chroma/
 crates/
    chroma-block/       # ブロック構造ブロック関連処理
    chroma-cli/         # コマンドラインインターフェース
    chroma-consensus/   # コンセンサスマイニング
    chroma-core/        # コア型基本プリミティブ
    chroma-crypto/      # 暗号プリミティブ
    chroma-p2p/         # P2Pネットワーク
    chroma-state/       # ブロックチェーン状態
    chroma-storage/     # 永続ストレージ
    chroma-tx/          # トランザクション
    chroma-wallet/      # ウォレット
 protocol/
    SPEC.md             # プロトコル仕様
 tests/
    integration/        # 統合テスト
 Cargo.toml
 Cargo.lock
```

## ビルド

必要なもの：

* Rust toolchain
* Cargo

ワークスペース全体をビルド：

```bash
cargo build --workspace
```

## テスト

ワークスペース全体のテストを実行：

```bash
cargo test --workspace
```

## 開発状況

Chromaは現在、初期開発段階です。

プロトコルおよび実装は、今後の開発に伴って大きく変更される可能性があります。

コンセンサスやプロトコルレベルの仕様については、[`protocol/SPEC.md`](protocol/SPEC.md) を主要なリファレンスとします。

## ライセンス

ライセンスはプロジェクトのライセンス方針確定後に追加されます。
