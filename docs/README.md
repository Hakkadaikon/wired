# ドキュメント

| 項目 | 内容 |
|---|---|
| 目的 | docs/ の文書体系と、各文書の置き場所を示す |
| 読む人 | コントリビューター |
| 前提文書 | [README](../README.md) |
| 関連文書 | [wired ガイド](https://hakkadaikon.github.io/wired/guide/ja/)(利用者向け)、[API リファレンス](https://hakkadaikon.github.io/wired/) |

<a id="wired-documentation"></a><a id="wired-のドキュメント"></a><a id="where-to-start"></a><a id="どこから読むか"></a>

## 1. 読む順

```mermaid
flowchart LR
    ov["overview<br/>purpose, policy"] --> arch["architecture<br/>basic design"]
    arch --> des["design<br/>per-domain design"]
    st["standards<br/>rules, build, gate"] --> des
    des --> ver["verification<br/>tests, interop, performance"]
    des --> sec["security<br/>threats, limits, ledger"]
```

| 順 | 文書 | 内容 |
|---|---|---|
| 1 | [概要書](overview/README.md) | 目的、適用範囲、設計方針と理由 |
| 2 | [開発標準](standards/README.md) | 準備、規約、ビルド、コミットゲート、ドメインの追加、テスト、文書の書き方 |
| 3 | [基本設計](architecture/README.md) | 全体構成、データの流れ、I/O ドライバー、鍵、メモリ |
| 4 | [詳細設計](design/README.md) | ドメインごとの設計、実装している仕様 |

アプリケーションの作り方(API の使い方、フラグ、証明書の設定)は [wired ガイド](https://hakkadaikon.github.io/wired/guide/ja/) にある。

<a id="learn-it"></a><a id="学ぶ"></a><a id="understand-it"></a><a id="理解する"></a><a id="use-it-as-a-dependency"></a><a id="依存先として使う"></a>
<a id="check-how-well-it-is-tested"></a><a id="テストの度合いを確かめる"></a><a id="measure-it"></a><a id="測る"></a><a id="change-it"></a><a id="変更する"></a>

## 2. 文書体系

| ディレクトリ | 文書の種類 | 主な文書 |
|---|---|---|
| [overview/](overview/README.md) | 概要書 | 目的、適用範囲、設計方針 |
| [architecture/](architecture/README.md) | 基本設計書 | [データの流れ](architecture/dataflow.md)、[I/O ドライバー](architecture/io-drivers.md)、[鍵](architecture/keys.md)、[メモリ](architecture/memory.md) |
| [design/](design/README.md) | 詳細設計書 | [common](design/common.md)、[crypto](design/crypto.md)、[transport](design/transport.md)、[tls](design/tls.md)、[app](design/app.md)、[実装している仕様](design/specs.md) |
| [standards/](standards/README.md) | 開発標準 | [準備](standards/setup.md)、[コーディング規約](standards/coding.md)、[ビルド](standards/build.md)、[コミットゲート](standards/commit-gate.md)、[ドメインの追加](standards/add-domain.md)、[テスト](standards/testing.md)、[ドキュメント規約](standards/documentation.md) |
| [reference/](reference/README.md) | 参照資料 | [Stable API](reference/api-stable.md)、[Low-level API](reference/api-lowlevel.md)、[MoQT API](reference/api-moqt.md)、[バージョニング](reference/api-versioning.md)、[システムコール](syscalls.md) |
| [verification/](verification/README.md) | 試験と品質 | [テストの範囲](verification/coverage.md)、[相互運用性テスト](verification/interop.md)、[その経緯](verification/interop-history.md)、[性能の比較](performance/comparison.md)、[計測の生データ](performance/comparison-runs.md)、[リソース監視](performance/monitoring.md) |
| [security/](security/README.md) | セキュリティ設計 | [脅威モデル](security/threat-model.md)、[暗号](security/crypto.md)、[PKI](security/pki.md)、[プロトコルの防御](security/protocols.md)、[既知の制限](security/limitations/README.md)、[脆弱性台帳](security/vuln-ledger.md) |
| [features/](features/README.md) | 要件台帳 | 仕様ごとの要件とテスト、[台帳の書式](features/FORMAT.md)、[MoQT の Track 切り替え](features/moqt-track-switching.md) |
| [ubiquitous/](ubiquitous/README.md) | 用語集 | 技術用語の表記 |
| superpowers/ | 過去の設計と計画の記録 | 機能ごとの設計書と実装計画 |

## 3. 生成物

`sdk/` は doxygen の出力で、git の管理外である([API リファレンス](https://hakkadaikon.github.io/wired/) として公開)。直すときは、生成された HTML ではなくヘッダーのドキュメントコメントを編集する。
