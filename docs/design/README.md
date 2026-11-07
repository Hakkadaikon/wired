# 詳細設計

[ドキュメント](../README.md) › 詳細設計

| 項目 | 内容 |
|---|---|
| 目的 | `src/` の 5 つの層の設計と、実装している仕様を示す |
| 読む人 | 層の中のコードを変更・レビューするコントリビューター、ある仕組みのコードの場所を探すコントリビューター |
| 前提文書 | [基本設計](../architecture/README.md)(全体構成と層の依存の図) |
| 関連文書 | [要件台帳](../features/README.md)、ガイド(<https://hakkadaikon.github.io/wired/guide/ja/>) |

## 1. 文書

| 文書 | 層 | 中身 |
|---|---|---|
| [common](common.md) | common | 可変長整数、バイトカーソル、カーネルとの境界 |
| [crypto](crypto.md) | crypto | 暗号プリミティブ、tls との接点 |
| [transport](transport.md) | transport | UDP の選択、フロー制御、損失検出、輻輳制御、パス MTU 探索 |
| [tls](tls.md) | tls | QUIC 上の TLS、トランスポートパラメーター、鍵更新 |
| [app](app.md) | app | HTTP/3、QPACK、DATAGRAM、WebTransport、MoQT、生の QUIC、MP4 |
| [実装している仕様](specs.md) | すべて | 仕様の一覧と、それぞれが必要な理由 |

## 2. 層の依存の例外

依存はおおむね下向き(common → crypto → transport と tls → app)である。例外は次の 3 つで、詳細は各層の文書にある。

| 例外 | 内容 | 文書 |
|---|---|---|
| transport と tls | 互いに include する。tls がハンドシェイクメッセージを CRYPTO ストリームとやり取りするため | [tls](tls.md) |
| crypto → tls | `crypto/kdf/keys/`、`cvecdsa`、`certreq` が tls の型と定数を使う。プリミティブは tls を include しない | [crypto](crypto.md) |
| transport、tls → app | `app/datagram/` の DATAGRAM の定義を使う。TLS クライアントが `app/http3/server/srvwire/` を使う | [app](app.md) |
