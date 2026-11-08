# 概要書

[ドキュメント](../README.md) › 概要書

| 項目 | 内容 |
|---|---|
| 目的 | SDK の目的、適用範囲、設計方針とその理由を定める |
| 読む人 | SDK を変更・レビューするコントリビューター |
| 前提文書 | [README](../../README.md) |
| 関連文書 | [基本設計](../architecture/README.md)、[開発標準](../standards/README.md) |

## 1. 目的

wired は C で書いた QUIC・HTTP/3・WebTransport・MoQT のサーバー SDK である。TLS 1.3 と暗号から MoQT までを、外部依存なしでユーザー空間に実装する。対応範囲と成果物は [README の 1 章](../../README.md#1-概要) にある。

## 2. 適用範囲

| 項目 | 範囲 |
|---|---|
| 役割 | サーバーの SDK |
| プロトコル | TLS 1.3、QUIC、HTTP/3 と QPACK、WebTransport、MoQT(draft-18/19/22/23) |
| 動作環境 | x86_64 Linux |
| カーネルに任せること | UDP データグラムの送受信、ソケットの準備、`poll`、`getrandom`([システムコール](../syscalls.md)) |
| SDK が持つこと | パケット、暗号、TLS ハンドシェイク、損失回復、輻輳制御、ストリーム、HTTP/3、X.509 の検証、イベントループ |
| 利用者の操作と API の使い方 | 対象外。[wired ガイド](https://hakkadaikon.github.io/wired/guide/ja/) に置く |

## 3. 設計方針

| 方針 | 理由 | 確かめる仕組み | 詳細 |
|---|---|---|---|
| libc を使わない | SDK の振る舞い、メモリ使用量、攻撃面をホストの libc に左右させない | `-ffreestanding -nostdlib` のコンパイル、`-nostdlib -static` のリンク、grep | [コーディング規約](../standards/coding.md)、[README 2.1](../../README.md#21-依存関係) |
| ヒープを使わない | use-after-free と double free を構造から起こさない | 容量はすべてコンパイル時の定数 | [README 2.2](../../README.md#22-メモリ管理)、[メモリ配置とサイズ](../architecture/memory.md) |
| 関数の CCN を 3 以下にする | RFC の節と並べて 1 段ずつレビューできる | `just ccn` | [コーディング規約](../standards/coding.md) |
| 検証駆動 | 自分どうしの通信では両側の同じバグが打ち消し合う | 一次資料、テストベクター、TLA+ と Lean 4、相互運用性テスト | [テスト](../standards/testing.md) |

### 3.1 libc を使わない

SDK は自前のシステムコールラッパーでカーネルを直接呼び、バイト列も自前のヘルパーでコピーする。CRT(`main` の前に動くスタートアップコード)も使わない。システムコールの経路は [基本設計](../architecture/README.md#21-システムコールの経路) にある。

### 3.2 関数の CCN を 3 以下にする

CCN の上限は小さい関数、名前付きの判定ヘルパー、表による振り分けを強いる。長い `if`/`else` の連鎖は書けない。プロトコルのコーデックを RFC の節と並べて読める。

### 3.3 検証駆動

振る舞いは IETF の一次資料(RFC の本文)に沿って実装し、テストベクターは手で計算し直す。状態機械と重要な数学の性質は、コードを書く前に TLA+ か Lean 4 で検査する。準拠を確かめるのは、仕様のベクターか独立した実装との通信だけである。
