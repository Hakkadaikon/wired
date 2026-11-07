# 既知の制限: TLS と暗号

[ドキュメント](../../README.md) › [セキュリティ設計](../README.md) › [既知の制限](README.md) › TLS と暗号

| 項目 | 内容 |
|---|---|
| 目的 | TLS 1.3、証明書、暗号プリミティブの制限を示す |
| 読む人 | `src/tls/` と `src/crypto/` を変更するコントリビューター、サーバーを本番に入れる人 |
| 前提文書 | [既知の制限](README.md) |
| 関連文書 | [BoringSSL のベクター](../boringssl-vectors.md)、[RFC 8446 の台帳](../../features/rfc8446.md) |

## 1. TLS 1.3

### 1.1 ALPN はサーバーの順で選ぶ(interop のイメージを除く)

影響: 複数のプロトコルを提示するクライアント。

サーバーは、提示されたもののうち自分が最も優先するプロトコルを選ぶ(RFC 7301 3.2)。順序は設定した raw の ID、h3、hq-interop である。interop のイメージは `--alpn-client-order`(`alpn_client_order`)を渡してクライアントの順に従う。msquic の相互運用性テストの実行がこれを期待しているためである。

参照: `sdrv_negotiate_alpn`

### 1.2 チケットと Retry トークンの鍵は、既定では 1 つのプロセスの間だけ有効

影響: 再起動をまたいだ再開とアドレス検証、および 1 つのアドレスの後ろで別々に起動したサーバーの間での再開とアドレス検証。

アプリケーションがシードを渡さない限り、どちらの鍵もサーバーの起動時に CSPRNG から取る(fork した `srvworkers` と `srvthreads` のワーカーは 1 回の取得を共有する)。そのため、再起動の前に発行したチケットや Retry トークン、独立して起動した別のサーバーが発行したものは開けない。

| 項目 | 内容 |
|---|---|
| 有効なままにする手段 | サーバーの起動前に `wired_srvboot_id.ticket_key` に同じ秘密値を設定し、`wired_srvkeys_set_token_key` に同じシードを渡す |
| シードの性質 | 長期のルートの秘密値。CSPRNG から生成した 32 バイトを秘密にしておく前提 |
| シードを変えたとき | 発行済みのチケットとトークンはすべて無効になる |
| `ticket_key` とトークンのシードに同じ値を使ったとき | 用途ラベルで導出する鍵が分かれるので、致命的ではない。別々の秘密値を使う前提 |
| シードを共有したとき | 0-RTT のリプレイの記録はプロセスごとなので、早期データはサーバーごとに 1 回リプレイできる([QUIC 5.1](quic.md#51-0-rtt-のリプレイ検出用リング)) |

参照: `srvkeys.h`

### 1.3 0-RTT のリプレイと NEW_TOKEN の追跡は、それぞれスピンロック 1 つを共有する

影響: `srvworkers` を使う運用。

どちらの追跡も `MAP_SHARED` のマッピングで fork したワーカー間で共有し、上限のある走査を 1 つのスピンロックで守る。スピンには上限がある(`ZERORTT_SEEN_SPIN` 回)。

走査の途中でワーカーが殺される(ちょうどその瞬間の SIGKILL)と、ロックは取られたまま残る。最初にタイムアウトした確認で追跡を固まった状態として印を付け、以降の確認はスピンせずにすぐ断る。そのため、再起動するまでどのワーカーでも 0-RTT(または NEW_TOKEN)を断り、クライアントは 1-RTT に戻る(または検証なしで進む)。

コストはタイムアウトする確認での `ZERORTT_SEEN_SPIN` 回分の停止 1 回である。単なる競合でタイムアウトした場合も、同じく再起動するまで追跡が無効になる(上限は走査 1 回よりずっと大きいので、起きない想定である)。

参照: `zerortt_seen.c`(ponytail、shortcut)、`sdrv_zerortt_share`、`srvkeys_newtoken_share`

### 1.4 起動後 21 秒は、起動前のチケットで 0-RTT を使えない

影響: サーバーの起動直後に、前のサーバーインスタンスが発行したチケット(再起動をまたいで `ticket_key` を固定している場合)で早期データ付きの再開をするクライアント。

0-RTT のリプレイの記録は最初の `sdrv_init` で記録の窓を開き、`ZERORTT_SEEN_LIVE_SECS`(21 秒)の間、それより前に発行されたチケットでの早期データを断る(RFC 8446 8.2: 再起動の前に受け付けた ClientHello はどの記録にも残っていない)。そうした接続は 1-RTT に戻る。このインスタンスが発行したチケットは 0-RTT を使える。

確認は 1 秒単位なので、窓を開いたのと同じ秒に前のインスタンスが発行したチケットは、起動前のものとして認識しない。同じ秒のうちに再起動したサーバーがこれに当たる。

参照: `zerortt_seen_pre_start`(shortcut)、[rfc8446.md](../../features/rfc8446.md) 8446-123

### 1.5 暗号スイートの優先順位は AES-128-GCM、ChaCha20-Poly1305、AES-256-GCM

影響: 自分のスイートの順序にこだわるクライアント。

TLS 1.3 の AEAD スイートは 3 つともネゴシエートし、クライアントではなくサーバーの順序に従う。

`TLS_AES_256_GCM_SHA384` は、独立した相手との相互運用性テストの実行をまだ記録していない。このスイートのもとでも `tls_exporter`(RFC 8446 7.5)はコンテキストを SHA-256 でハッシュする(本番の呼び出し元はない)。CCM のスイートは断る。

参照: `cipher.c`、[rfc8446.md](../../features/rfc8446.md) 8446-099

### 1.6 クライアント認証を使うと再開が無効になり、チェーンの扱いが厳格になる

影響: 相互 TLS を有効にするアプリケーション(`wired_srvboot_id.client_auth`)。

- すべての接続が証明書を使う完全なハンドシェイクになる。提示された PSK と 0-RTT は無視し、セッションチケットも発行しない(RFC 8446 4.4 は、PSK のハンドシェイクで証明書による認証を認めていない)。
- クライアントのチェーンは、リーフから順に信頼ストアまで 1 つずつつながる形で送る必要がある。余分な証明書や順序の入れ替わった証明書は bad_certificate で断る(RFC 8446 4.4.2 は受け入れるべき (SHOULD) としている)。
- チェーンの失敗はすべて bad_certificate で、unknown_ca や certificate_expired にはしない。
- 失効の確認も、ハンドシェイク後の認証(RFC 9001 4.4 が禁じている)もない。CertificateRequest に `certificate_authorities` も `oid_filters` も入れない。
- 証明書を見られるのは HTTP のハンドラーだけである(`wired_http_exchange.peer_cert`、最初の回)。クライアント役は証明書を送らない。

クライアントの Certificate、CertificateVerify、Finished は、次の 2 つに収まる必要がある。

| バッファー | 大きさ |
|---|---|
| Handshake の受信バッファー(`CRECV_BUF`) | 12,288 バイト(2 KB の RSA 証明書なら約 4 枚) |
| トランスクリプト(`WIRED_SERVER_TRANSCRIPT_MAX`) | 16,384 バイトから ClientHello とサーバーの送信分を除いた残り |

それより大きいクライアントのチェーンは、CRYPTO_BUFFER_EXCEEDED(RFC 9000 7.5)か bad_certificate で接続を閉じる。

参照: `server_cauth.c`、`server_feed.c`、[rfc8446.md](../../features/rfc8446.md) 8446-133..139

### 1.7 TLS の抜け

影響: これらを必要とする相手。

OCSP/SCT、サーバーのチェーンを選ぶための `certificate_authorities`、FFDHE はなく、外部 PSK(「ext binder」)にも対応していない。

参照: [rfc8446.md](../../features/rfc8446.md) の対象外

### 1.8 出荷していない TLS 拡張

影響: これらの拡張を必要とするクライアント。

max_fragment_length、client_certificate_url、trusted_ca_keys、truncated_hmac、status_request は実装していない。

参照: [rfc6066.md](../../features/rfc6066.md)

### 1.9 ClientHello と Retry の作業用バッファーは MTU に合わせた大きさ

影響: メモリの使用量と、Initial パケット 2 つより大きい ClientHello。

起動段階の蓄積用バッファーは接続のスロットごとに約 4 KB(`WIRED_CONNTABLE_CAP` 個のスロット、BSS)で、Initial 2 つ分を受けられる。耐量子暗号の大きさの ClientHello も収まる。`retry_tag` の擬似パケット用の作業領域は 1521 バイトである。

参照: `wired_srvboot_acc`(ponytail)、`retry_tag.c`(ponytail)

### 1.10 クライアント / サーバーのポンプの簡略化

影響: これらの古い入口の利用者だけ。`wired_server_run` のサーバーは使わない。

`wired_server_pump` は生のデータグラムを `wired_server_feed` へ渡し、`client_build_initial` は ClientHello を組み立てる。どちらも送信路上での Initial の AEAD による保護をしない。

参照: `wired_server_pump`、`client_build_initial`(ponytail)

## 2. 証明書

### 2.1 証明書パスの処理

影響: これらの機能を使って証明書チェーンを検証するアプリケーション。

iPAddress の名前制約のサブツリーは、IP アドレスをそのまま書いた CN には適用しない。CRL、OCSP などの失効の確認、ポリシーのマッピング、IDN の処理、SRV-ID や URI-ID の照合はない(DNS-ID の dNSName だけ)。

参照: `nameconstraints.c`(ponytail)、[rfc5280.md](../../features/rfc5280.md)、[rfc6125.md](../../features/rfc6125.md) の対象外

### 2.2 チェーンの署名アルゴリズム

影響: 古い方式の鍵や圧縮形式の鍵を含むチェーン。

古い RSA-SHA-1 で署名したチェーンは検証できない。P-521 の発行者は検証できる(ecdsa-with-SHA256/384/512)が、SPKI の点が非圧縮形式の場合だけである。圧縮形式の P-521 の鍵は拒否する。

参照: [BoringSSL のベクターの README](../../../tests/vectors/boringssl/README.md)、`ec_pubkey.c`

## 3. 暗号プリミティブ

### 3.1 ハッシュと MAC の種類

影響: SHA-1 で署名した証明書チェーンだけ。TLS 1.3 のハンドシェイクは影響を受けない。

| 種類 | 出荷している | 出荷していない |
|---|---|---|
| ハッシュ | SHA-256、SHA-384、SHA-512 | SHA-1、SHA-224、SHA-512/224、SHA-512/256、MD5 |
| HMAC | SHA-256、SHA-384、SHA-512 | HMAC-SHA1、HMAC-SHA224、HMAC-MD5 |
| HKDF | TLS/QUIC のプロファイルでは SHA-256 だけ | — |

参照: [BoringSSL のベクター](../boringssl-vectors.md)、[BoringSSL のベクターの README](../../../tests/vectors/boringssl/README.md)、[fips180-4.md](../../features/fips180-4.md)、[rfc5869.md](../../features/rfc5869.md)

### 3.2 曲線は P-256、P-384、P-521 だけ

影響: ほかの曲線の証明書。

P-224、secp224k1、P-192、二進体の曲線、Koblitz 曲線はない。

| 曲線 | 用途 |
|---|---|
| P-256 | 検証と署名(決定的な RFC 6979、`ecdsa_secp256r1_sha256` だけ) |
| P-384 | 検証だけ(証明書チェーン) |
| P-521 | 検証だけ(証明書チェーン。TLS の CertificateVerify の方式ではない) |

このため BoringSSL の ECDSA のベクターのうち 91 件をスキップしている。

参照:

- [BoringSSL のベクター](../boringssl-vectors.md)
- [BoringSSL のベクターの README](../../../tests/vectors/boringssl/README.md)
- [fips180-4.md](../../features/fips180-4.md)
- [rfc5869.md](../../features/rfc5869.md)
- [rfc6979.md](../../features/rfc6979.md)
- [rfc5480.md](../../features/rfc5480.md)

### 3.3 X448、Ed448、Ed25519ctx、Ed25519ph はない

影響: これらのアルゴリズムを必要とする相手。

あるのは X25519 と素の Ed25519 だけである。Ed25519 は PKCS#8/OneAsymmetricKey を解析せず(生の 32 バイトのシードを受け取る)、DER だけを受け付ける(BER は受け付けない)。

参照: [rfc7748.md](../../features/rfc7748.md)、[rfc8032.md](../../features/rfc8032.md)、[rfc8410.md](../../features/rfc8410.md)

### 3.4 AEAD は 96 ビットの nonce と 128 ビットのタグだけ

影響: QUIC と TLS 1.3 ではなし。

`GCM_NONCE` は 12 バイト、`GCM_TAG` は 16 バイトである。BoringSSL の AES-GCM のうち、nonce の長さが異なるケース(AES-128 で 5 件、AES-256 で 2 件)はスキップしている。GMAC はなく、短いタグにも対応しない。

参照: [BoringSSL のベクター](../boringssl-vectors.md)、[sp800-38d.md](../../features/sp800-38d.md)

### 3.5 AES-192 は実装していない

影響: QUIC と TLS 1.3 ではなし。

QUIC のパケット保護の鍵は AES-128-GCM と AES-256-GCM(`gcm256.h`。BoringSSL のベクターは通る)である。AES-192 も AES の復号のプリミティブもない(GCM もヘッダー保護も必要としない)。

参照: [fips197.md](../../features/fips197.md)、[BoringSSL のベクター](../boringssl-vectors.md)

### 3.6 RSA は公開指数 e = 65537 だけで、検証だけ

影響: ほかの指数の証明書と、RSA で署名するアプリケーション。

PKCS#1 v1.5 の検証は SHA-256/384/512 の DigestInfo を受け付ける。RSA-PSS は SHA-256、ソルト長 32、MGF1-SHA-256 の組み合わせだけである(TLS 1.3 の `rsa_pss_rsae_sha256`)。RSA の署名、暗号化、鍵生成、秘密鍵の型はなく、BoringSSL の RSA のベクターもない。

参照: `rsa_verify.h`、`pss.c`、[rfc8017.md](../../features/rfc8017.md)

### 3.7 ECDSA の nonce は FIPS 186-4 B.5 ではなく RFC 6979 の決定的な方式

影響: FIPS 186-4 の検証が必要な運用。

P-256 の署名は k を RFC 6979 で導出する(FIPS 186-4 ではなく FIPS 186-5 §6.3.2 が承認している方式)。そのため署名者は署名の時点で RBG に依存しない。SDK は FIPS 186-4 の検証に合格しているとは主張しない。

参照: `p256sign_sign`、[fips186-4.md](../../features/fips186-4.md) の対象外(F186-029)

### 3.8 ECDSA/ECC の鍵生成は出荷していない

影響: 実行時に鍵を作るアプリケーション。

鍵は証明書か PEM から読み込む。DSA はない。

参照: [fips186-4.md](../../features/fips186-4.md)

### 3.9 作業領域の大きさは固定

影響: 大きな入力で AEAD のプリミティブを呼ぶ側。

ChaCha20-Poly1305 の MAC の作業領域は 3032 バイトである(MTU に合わせた大きさで、それより大きい入力には対応しない)。GCM は設計として、呼び出しのたびに AES-NI の鍵スケジュールを展開し直す。

参照: `aead.c`、`gcm.c`(ponytail)

### 3.10 HKDF、素の SHA-2 のダイジェスト、RSA には BoringSSL のベクターがない

影響: なし。

上流がこれらのケースを FileTest のファイルから移したためである。代わりに RFC と FIPS のベクターで確かめている。

参照: [BoringSSL のベクター](../boringssl-vectors.md)
