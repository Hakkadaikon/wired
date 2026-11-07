# crypto の詳細設計

[ドキュメント](../README.md) › [詳細設計](README.md) › crypto

| 項目 | 内容 |
|---|---|
| 目的 | crypto 層の範囲、依存、tls との接点を示す |
| 読む人 | crypto のコードを変更・レビューするコントリビューター |
| 前提文書 | [詳細設計](README.md) |
| 関連文書 | [tls](tls.md)、[実装している仕様](specs.md)、ガイドの [SHA-256](https://hakkadaikon.github.io/wired/guide/ja/tls/sha256/) |

crypto は暗号だけを扱う。QUIC は Initial パケットも含めてすべてのパケットを暗号化するので、パケット保護は接続のどの段階でも要る。証明書の検査には署名検証、鍵スケジュールには鍵導出が要る。

## 1. 独立した層にする理由

AES-GCM、ChaCha20-Poly1305、SHA-256、Ed25519 などのプリミティブは、QUIC の状態も TLS のメッセージも読まない。入力バイトから出力バイトを決定的に計算する。そのため、それぞれを単独で公式のテストベクターと照合できる。

| 依存 | 内容 |
|---|---|
| プリミティブ → common | プリミティブが依存するのは common だけ。tls のヘッダーは include しない |
| `crypto/kdf/keys/` → tls | 鍵セットが tls の Initial 鍵の型を使う |
| `cvecdsa`、`certreq` → tls | 証明書署名のコードが TLS ハンドシェイクと署名アルゴリズムの定数を使う |

crypto は transport にパケット保護の AEAD(認証付き暗号)を、tls に鍵スケジュールの HKDF を提供する。

## 2. tls との接点

接点は `HKDF-Expand-Label`(`hkdf_expand_label`)である。TLS 1.3 の鍵スケジュールはすべてのシークレットをこの関数で導出し、QUIC もパケット保護の鍵を同じ関数で導出する。

そのため `crypto/kdf/keys/` の鍵セットは tls の Initial 鍵と同じ型を使う。Initial 鍵は公開値から導出する(RFC 9001 §5.2)。導出した鍵セットは変換なしで transport のパケット保護に渡る。

## 3. ドメイン

| 区分 | 中身 |
|---|---|
| AEAD | AES-GCM、ChaCha20-Poly1305 |
| ハッシュ | SHA-256、SHA-384、SHA-512、HMAC |
| 署名 | Ed25519、ECDSA P-256 / P-384 / P-521、RSA-PSS、RSA PKCS#1 v1.5 |
| 鍵導出 | HKDF |
| 証明書 | X.509 の解析と検証 |

X25519 鍵交換は crypto ではなく、それを使うハンドシェイクと同じ tls にある。
