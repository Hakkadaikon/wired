# tls の詳細設計

[ドキュメント](../README.md) › [詳細設計](README.md) › tls

| 項目 | 内容 |
|---|---|
| 目的 | tls 層の設計(QUIC 上の TLS、トランスポートパラメーター、鍵更新)を示す |
| 読む人 | tls のコードを変更・レビューするコントリビューター |
| 前提文書 | [詳細設計](README.md) |
| 関連文書 | [暗号化レベルと鍵](../architecture/keys.md)、[crypto](crypto.md)、[transport](transport.md)、ガイドの [TLS ハンドシェイク](https://hakkadaikon.github.io/wired/guide/ja/tls/handshake/)、[X25519 鍵交換](https://hakkadaikon.github.io/wired/guide/ja/tls/x25519/) |

tls は暗号化の鍵を作り、ピアを認証する。ハンドシェイクは ECDHE 鍵交換(両者がそれぞれ新しい鍵ペアを出す)で共有シークレットを作り、そこから QUIC のパケット保護の鍵を導出する。同時にサーバーの証明書と署名を検査する。

| 項目 | 内容 |
|---|---|
| 依存先 | crypto(署名検証、鍵導出、ハッシュ)、common、transport のパケットとバージョンの型 |
| 提供するもの | 暗号化レベル(Initial、Handshake、1-RTT)ごとの保護鍵を transport に渡す |
| 層に含むもの | X25519 鍵交換 |

## 1. QUIC が TLS を運ぶ仕組み

TLS 1.3 は通常 TCP の上で、メッセージを独自のレコード層で包む。QUIC はレコード層を使わず、ハンドシェイクメッセージを CRYPTO フレームで運ぶ。

tls はハンドシェイクメッセージを組み立てて transport の CRYPTO ストリームに渡し、受け取った CRYPTO のバイトをメッセージに組み立て直す。この受け渡しが、transport と tls が互いに include し合う主な理由である。

## 2. トランスポートパラメーター

QUIC の接続の設定は TLS の拡張に入れてハンドシェイクで運ぶ。初期のフロー制御のクレジット、最大アイドル時間、接続 ID の上限などである。

## 3. 鍵更新

1 つの AEAD 鍵で保護できるパケットの数には上限がある(RFC 9001 §6.6)。長い接続は途中で新しい 1-RTT 鍵に切り替える。

| 項目 | 内容 |
|---|---|
| 次の鍵 | 現在のシークレットからラベル `"quic ku"` の `HKDF-Expand-Label` で作る(`kuswitch_next_keys`、暗号スイートを考慮する `kuswitch_next_keys_suite`)。ヘッダー保護の鍵は変えない |
| 切り替えの合図 | 送信側がショートヘッダーの Key Phase ビットを反転する |
| サーバーの受信 | 現在の鍵、古い鍵、次の世代の鍵の順に試し、次の世代の鍵で復号できたときだけ切り替える(`onertt_try_any`) |
| 汎用の接続ランナーの受信 | Key Phase ビットで鍵を選ぶ(`kuswitch_key_for_phase`) |
| 古い鍵の破棄 | PTO 3 回分保持してから破棄する(`srvrun_ku_discard_stale`)。その間は古い鍵で送られた途中のパケットも復号できる |
| サーバーからの開始 | 暗号化したパケット数が上限に達したとき(`wired_srvloop_send_onertt`)。前回の更新が確認されるまでは次を始めない |

## 4. ドメイン

ClientHello と ServerHello の組み立てと解析、鍵スケジュール、証明書と CertificateVerify の検証、鍵更新、トランスポートパラメーター拡張。
