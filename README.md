# Chroma

Chroma（CHR）は、Rustで開発されている独立型のProof-of-Work（PoW）ブロックチェーンです。

**ティッカー:** CHR
**開発状況:** 初期開発段階

## 概要

Chromaは、独立した分散型PoWネットワークの構築を目的としたブロックチェーンプロジェクトです。

プロトコルの仕様は [`protocol/SPEC.md`](protocol/SPEC.md) に定義されています。
DNSシードレコードの形式と内容は [`SEED_RECORD.md`](SEED_RECORD.md) にあります。

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

### cmakeが無い環境

デフォルトのビルドにはRandomX（C++実装、cmakeでビルドされる）が含まれる。
cmakeとC++ツールチェーンが無い環境では、この依存を外してビルドできる。

```bash
cargo build --workspace --no-default-features
```

このビルドはRandomXでハッシュを計算できないため、**regtest以外のネットワークでは
マイニングも検証もできない**。該当するネットワークを指定して起動した場合は、
起動時にその旨を表示して終了する。

Windowsでcmakeを入れる場合：

```powershell
winget install Kitware.CMake
```

インストール後、PATHを読み直すためにシェルを開き直すこと。

## テスト

ワークスペース全体のテストを実行：

```bash
cargo test --workspace
```

RandomXを外した構成でも通ることを確認する場合：

```bash
cargo test --workspace --no-default-features
```

## 開発状況

Chromaは現在、初期開発段階です。

プロトコルおよび実装は、今後の開発に伴って大きく変更される可能性があります。

コンセンサスやプロトコルレベルの仕様については、[`protocol/SPEC.md`](protocol/SPEC.md) を主要なリファレンスとします。

## ライセンス

ライセンスはプロジェクトのライセンス方針確定後に追加されます。
