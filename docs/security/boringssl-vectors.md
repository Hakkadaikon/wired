# BoringSSL のテストベクター

[ドキュメント](../README.md) › [セキュリティ設計](README.md) › BoringSSL のテストベクター

<a id="boringssl-test-vectors-as-a-third-party-oracle"></a><a id="第三者オラクルとしての-boringssl-テストベクター"></a>

| 項目 | 内容 |
|---|---|
| 目的 | wired の暗号が BoringSSL のテストベクターと同じ答えを出すかの結果を示す |
| 読む人 | 暗号のコードを読まずに wired の暗号化、署名、鍵交換を監査する人 |
| 前提文書 | [セキュリティ設計](README.md)(第三者のテストベクターを使う理由) |
| 関連文書 | [Wycheproof のテストベクター](wycheproof-vectors.md)、[暗号](crypto.md) |

## 1. 出どころ

<a id="what-a-test-vector-is"></a><a id="テストベクターとは"></a><a id="why-vectors-from-another-implementation"></a><a id="ほかの実装のベクターを使う理由"></a>

RFC や FIPS の例は数が少なく、通常の経路しか扱わない。まれな分岐のバグ(多倍長演算の繰り上がり、境界にある長さ、拒否すべき不正な形式の署名)は、RFC の例をすべて通ることがある。

BoringSSL は Google の TLS ライブラリで、Chrome と Android が使う。開発者がアルゴリズムごとにケースを集めており、ほかの独立した出どころのベクターも同梱している。

| 同梱のベクター | 件数 |
|---|---|
| Google の Wycheproof プロジェクトの X25519 ケース(既知の攻撃とエッジケース) | 518 |
| Ed25519 の作者による参照セットの Ed25519 ケース | 514 |

どの期待値も wired から来ていない。期待値を wired 自身の出力から導くことはしない。

## 2. FileTest 形式

<a id="boringssls-filetest-format"></a><a id="boringssl-の-filetest-形式"></a>

BoringSSL はベクターをプレーンテキストのファイルに保存し、FileTest というテストランナーがそれを読む。各ケースは `NAME: value`(または `NAME = value`)の行のまとまりで、値はほとんどが 16 進のバイト列である。空行でケースが終わる。AES-128-GCM のケース 1 件は次のとおりである。

```text
KEY: 3881e7be1bb3bbcaff20bdb78e5d1b67
NONCE: dcf5b7ae2d7552e2297fcfa9
IN: 0a2714aa7d
AD: c60c64bbf7
CT: 5626f96ecb
TAG: ff4c4f1d92b0abb1d0820833d9eb83c7
```

| フィールド | 中身 |
|---|---|
| `IN` | 平文 |
| `AD` | 暗号化はしないが認証はする追加データ |
| `CT` | 暗号文 |
| `TAG` | 認証タグ |

ベクターは偽造された署名のように「この入力は拒否しなければならない」ことも示す。

## 3. ファイルとテストの置き場所

<a id="where-the-files-and-tests-live"></a><a id="ファイルとテストの置き場所"></a>

| 項目 | 内容 |
|---|---|
| ベクターファイル | 固定したコミット `dd73e69a4e86fa178a4d19033c691e9b42cc1088` の BoringSSL からコピーした。データだけで、BoringSSL のソースコードは含まない |
| 出どころ、上流のパス、skip の理由 | [`tests/vectors/boringssl/README.md`](../../tests/vectors/boringssl/README.md) |
| 許可したファイル | 取り込みを許可した BoringSSL のベクターファイルの一覧(上の README の表)。以下の「許可したファイル」はこの一覧を指す |
| テスト | `tests/crypto/bssl_*_test.c`。プリミティブの系統ごとに 1 つ。ファイル内のすべてのケースを回し、`just test` の一部として動く |
| 失敗の報告 | ベクターファイル内の行範囲を付けて報告する |

## 4. 結果(2026-10-05)

<a id="how-to-read-the-results-table"></a><a id="結果の表の読み方"></a><a id="results-2026-10-05"></a><a id="結果2026-10-05"></a>

| 列 | 意味 |
|---|---|
| Added | ベクターファイルにあるこのプリミティブのケース数 |
| Pass | 期待どおりの出力を出したか、ベクターが不正と示す入力を拒否した |
| Fail | BoringSSL と食い違った。0 でなければバグである |
| Skip | wired がそのアルゴリズムやその形の入力を実装していないので、実行できなかった。pass として数えない |
| –(ダッシュ) | 固定したコミットから取り込んだファイルのどれにもそのプリミティブのケースがなく、何も実行していない |

| プリミティブ | Added | Pass | Fail | Skip | 備考 |
|---|---|---|---|---|---|
| AES-128-GCM | 74 | 69 | 0 | 5 | skip: NONCE ≠ 12 バイト(API は 96 ビットの nonce のみ) |
| AES-256-GCM | 66 | 64 | 0 | 2 | skip: NONCE ≠ 12 バイト |
| ChaCha20-Poly1305 | 81 | 81 | 0 | 0 | 切り詰めたタグは拒否すべきもので、拒否している |
| X25519 | 527 | 526 | 0 | 1 | Wycheproof 518 件 + `x25519_test.cc` に直接書かれた 8 件(RFC 7748、小さい位数、1,000 回反復)。skip: 1,000,000 回反復のテスト(上流で `DISABLED_`)。低位数 / ゼロの共有秘密は拒否 |
| Ed25519 | 514 | 514 | 0 | 0 | シードからの鍵生成、決定的な署名、検証 |
| ECDSA P-256 | 85 | 85 | 0 | 0 | 検証。`Invalid` のケースは拒否 |
| ECDSA P-384 | 85 | 85 | 0 | 0 | 検証。`Invalid` のケースは拒否 |
| ECDSA P-521 | 88 | 88 | 0 | 0 | 検証(2026-10-10 に追加)。`Invalid` のケースは拒否。生のダイジェストを渡して 521 ビットに切り詰める(71 バイトのダイジェスト 1 件で切り詰めを検査する) |
| ECDSA P-224 / secp224k1 | 91 | 0 | 0 | 91 | 曲線を実装していない |
| HMAC-SHA256 | 5 | 5 | 0 | 0 | SHA-256 のオラクルも兼ねる |
| HMAC-SHA384 | 3 | 3 | 0 | 0 | SHA-384 のオラクルも兼ねる |
| HMAC-SHA512 | 3 | 3 | 0 | 0 | SHA-512 のオラクルも兼ねる(ブロックより長い鍵が 1 件) |
| HMAC-MD5 / SHA1 / SHA224 | 12 | 0 | 0 | 12 | ハッシュを実装していない |
| HKDF | 0 | – | – | – | 固定したコミットの許可したファイルにベクターがない(C++ のテストソースへ移動) |
| SHA-2(ダイジェスト単体) | 0 | – | – | – | 同上。SHA-256/384/512 は HMAC を通じてカバー |
| RSA | 0 | – | – | – | 許可したファイルに RSA のベクターがない |

各プリミティブが TLS のどこで使われるかは、ガイドの次のページにある。

- [X25519 鍵交換](https://hakkadaikon.github.io/wired/guide/ja/tls/x25519/)
- [証明書の読み込み](https://hakkadaikon.github.io/wired/guide/ja/tls/certificates/)
- [SHA-256](https://hakkadaikon.github.io/wired/guide/ja/tls/sha256/)

## 5. テストが失敗しうることの確認

<a id="checking-that-the-tests-can-fail"></a><a id="テストが失敗しうることの確認"></a>

失敗したケースはなく、このオラクルで見つかった未解決の欠陥はない。テストが誤った答えに気づけることを、意図して壊して確かめた。

| 対象 | 壊したもの | 結果 |
|---|---|---|
| AES-128-GCM、Ed25519、ECDSA P-256(P-256 の有効なケース) | 各ベクターセットの期待値を 1 つ一時的に反転 | それぞれちょうど 1 件が失敗(`aes_128_gcm_tests.txt:4-9`、`ed25519_tests.txt:19-22`、`ecdsa_verify_tests.txt:649-654`)。そのあとファイルを元に戻した |
| ECDSA P-521(2026-10-10) | 検証器から、R の x 座標と署名の r を比べる処理を取り除き、無限遠点でない R をすべて受け入れるようにした | 88 件のうち 63 件が失敗。そのあとソースを元に戻した |

## 6. 既知の穴

<a id="known-gaps"></a><a id="既知の穴"></a>

skip にはすべて理由があり、どれも QUIC、HTTP/3、WebTransport、MoQT を弱めない。

| skip | 理由 |
|---|---|
| 96 ビット(12 バイト)でない nonce の AES-GCM | BoringSSL はほかの長さも受け付けるが、wired の API は 96 ビットの nonce しか受け取らないので表現できない。QUIC と TLS 1.3 は常に 96 ビットの nonce を使う |
| ECDSA P-224 と secp224k1 | wired が検証するのは P-256、P-384、P-521 だけである。どちらの曲線も TLS 1.3 のグループや署名方式ではない |
| MD5、SHA-1、SHA-224 の HMAC | wired はこれらのハッシュを実装しない。TLS 1.3 の暗号スイートは SHA-256 か SHA-384 を使い、MD5 と SHA-1 の署名は TLS 1.3 ハンドシェイクで禁止されている |
| HKDF、SHA-2 単体、RSA | 実装して使っているが、許可したファイルに FileTest のベクターがない(HKDF と SHA-2 は C++ のテストソースへ移動)。SHA-256、SHA-384、SHA-512 は HMAC の行で検査する。HKDF と SHA-2 には RFC と FIPS による専用のテストがあり、RSA には生成した署名を使う専用のテストがある。RSA と HKDF は [Wycheproof](wycheproof-vectors.md) とも照合する |
| X25519 の 1,000,000 回反復のテスト | BoringSSL 自身が無効にしている。代わりに 1,000 回反復のケースを実行する |

アルゴリズムの欠落から生じる制約が 1 つある。旧来の RSA-SHA-1 で署名された証明書チェーンを、wired は検証できない。
