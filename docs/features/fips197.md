[ドキュメント](../README.md) › [機能](README.md) › FIPS 197

# FIPS 197: 高度暗号化標準（AES）

仕様の本文(`tasks/specs/fips197.txt`。git には含まない)から抽出した EARS 形式の要件台帳です。各要件には、それを確かめるテストを付けています。チェックがなくテスト行もない項目は、未解決のギャップです。

凡例:

- `[x]`: 挙げたテストで確認済み
- `[~]`: 間接的に確認(専用のテストはなく、evidence 行で確かめ方を説明)
- `[ ]`: まだどのテストでも確認していない

**カバレッジ: テスト済み 12/15、間接 3、未テスト 0。**

## §3 表記法と規約

- [x] F197-001 (§3.4) 実装は、16 バイトの入力配列を `s[r,c] = in[r + 4c]` で 2 次元のステート配列へ写し、最終的なステートを逆の対応で出力配列へ写し戻さなければならない。
  - test: `tests/crypto/aes_test.c` — `test_aes_fips197`
  - test: `tests/crypto/aes_test.c` — `test_aes_appendix_c`
  - gap: この対応はベクターの往復で暗に確かめているだけで、内部のステートの配置を直接は検証していません。

## §4 数学的準備

- [~] F197-002 (§4.1, §4.2) 実装は、GF(2^8) の 2 つのバイトを XOR で加算し、m(x) = x^8+x^4+x^3+x+1 を法として簡約する多項式乗算で乗算しなければならない({02} による乗算には XTIMES を使う)。
  - evidence: `src/crypto/symmetric/aead/aes/aes.c` の `XTIME` が法による簡約を実装しています(`((x << 1) ^ ((x >> 7) * 0x1b))`。m(x) のバイト形式)。`MIX_COLUMNS`/`INV_MIX_COLUMNS` で使うような小さな固定の定数による乗算は、`XTIME` を繰り返して組み立てています。GF(2^8) の乗算だけを確かめる単体テストはなく、`CIPHER()` 全体の既知解テストを通じて間接的に動かしているだけです。
- [x] F197-003 (§4.3) 実装は、MIXCOLUMNS() の数学的な基礎として、GF(2^8) の乗算と XOR を使ってワードに固定行列 [{02},{01},{01},{03}](順方向)を掛けなければならない。
  - test: `tests/crypto/aes_test.c` — `test_aes_mix_columns_matrix`

## §5.1 CIPHER()

- [x] F197-004 (§5.1) 実装は、最初の ADDROUNDKEY、Nr-1 回の完全なラウンド(SUBBYTES、SHIFTROWS、MIXCOLUMNS、ADDROUNDKEY)、MIXCOLUMNS を省いた最終ラウンドの順にステートを変換しなければならない。
  - test: `tests/crypto/aes_test.c` — `test_aes_fips197`
  - test: `tests/crypto/aes_test.c` — `test_aes_appendix_c`
- [x] F197-005 (§5.1.1) 実装は、SUBBYTES() で SBOX の置換表(Table 4)をステートの各バイトに独立に適用しなければならない。
  - test: `tests/crypto/aes_test.c` — `test_aes_fips197`
  - test: `tests/crypto/aes_test.c` — `test_aes_appendix_c`
- [~] F197-006 (§5.1.2) 実装は、SHIFTROWS() でステートの r 行目を左へ r 位置だけ巡回シフトし、0 行目は変えずに残さなければならない。
  - evidence: `src/crypto/symmetric/aead/aes/aes.c` の `shift_rows`/`shift_col` が `t[4c+r] = s[4*((c+r)%4)+r]` を実装しています。既知解テストで端から端まで動かしているだけで、SHIFTROWS 単体の検証はありません。
- [x] F197-007 (§5.1.3) 実装は、MIXCOLUMNS() でステートの各列に固定行列 [{02},{01},{01},{03}] を掛けて混ぜなければならない。
  - test: `tests/crypto/aes_test.c` — `test_aes_mix_columns_matrix`
- [x] F197-008 (§5.1.4) 実装は、ADDROUNDKEY() で各ラウンド鍵(鍵スケジュールの 4 ワード)とステートを XOR で組み合わせなければならない。ADDROUNDKEY() は最初のラウンドの前に 1 回、その後はラウンドごとに 1 回呼び出す。
  - test: `tests/crypto/aes_test.c` — `test_aes_fips197`
  - test: `tests/crypto/aes_test.c` — `test_aes_appendix_c`

## §5.2 KEYEXPANSION()

- [x] F197-009 (§5.2) 実装は、暗号鍵を 4*(Nr+1) 個の鍵スケジュールのワードに拡張しなければならない。最初の Nk ワードは鍵そのものであり、以降の各ワード w[i] は w[i-Nk] に次のいずれかを XOR したものである。i が Nk の倍数なら SUBWORD(ROTWORD(w[i-1])) XOR Rcon[i/Nk]、i+4 が 8 の倍数なら SUBWORD(w[i-1])(AES-256 のみ)、それ以外は w[i-1] そのもの。
  - test: `tests/crypto/aes_test.c` — `test_aes_fips197`
  - test: `tests/crypto/aes_test.c` — `test_aes_appendix_c`
  - test: `tests/crypto/aes_test.c` — `test_aes256_appendix_c3`
  - gap: Nk=4(`schedule_word`)と Nk=8(`aes128_schedule_word256`。i mod 8 = 4 での追加の SUBWORD を含む)の分岐は、暗号化の出力を通じてしか確かめていません。Nk=6 の分岐(AES-192)は提供していません。
- [x] F197-010 (§5.2, Table 5) 実装は、KEYEXPANSION() で 10 個の固定のラウンド定数 Rcon[1..10] = {01,02,04,08,10,20,40,80,1b,36}(それぞれ値を持つのは左端のバイトだけで、下位 3 バイトはゼロ)を使わなければならない。
  - test: `tests/crypto/aes_test.c` — `test_aes_fips197`
  - test: `tests/crypto/aes_test.c` — `test_aes_appendix_c`
  - test: `tests/crypto/aes_test.c` — `test_aes256_appendix_c3`
  - gap: AES-128 は 10 個の定数をすべて、AES-256 は最初の 7 個を使います。暗号化の出力以外で表の値を検証するテストはありません。

## §5.3 INVCIPHER() / EQINVCIPHER()

F197-011 から F197-015(INVCIPHER、INVSHIFTROWS、INVSUBBYTES、INVMIXCOLUMNS、EQINVCIPHER/KEYEXPANSIONEIC)は「対象外」にあります。下を参照してください。

## §6 実装上の考慮事項

- [x] F197-016 (§6.1) 実装は、3 つの鍵長(128、192、256 ビット)のうち少なくとも 1 つをサポートしなければならない。
  - test: `tests/crypto/aes_test.c` — `test_aes_fips197`
  - test: `tests/crypto/aes_test.c` — `test_aes256_appendix_c3`
- [x] F197-017 (§6.2) 実装は、適切に生成された暗号鍵に対して、長さ以外の制限を課してはならない。
  - test: `tests/crypto/aes_test.c` —
    `test_aes_no_key_restriction_beyond_length`
  - test: `tests/crypto/aes_test.c` —
    `test_aes256_no_key_restriction_beyond_length`
  - evidence: `aes128_init`(`src/crypto/symmetric/aead/aes/aes.c`)は、検証の分岐を持たず、鍵のすべてのバイトを無条件にスケジュールします。テストは全ゼロと全 0xff の 16 バイトの鍵(弱い鍵の検査がいちばん拒否しそうな値)を init と encrypt に通し、両方が成功して異なる暗号文を出すことを確かめています。
- [~] F197-018 (§6.5) 実装は、AES を FIPS 承認または NIST 推奨の暗号利用モードと組み合わせてのみ使わなければならない。
  - evidence: `aes128_encrypt`/`aes256_encrypt`(`src/crypto/symmetric/aead/aes/aes.h`)と `src/crypto/symmetric/aead/gcmx86/` の AES-NI のラウンドを呼び出すのは、GCM のモジュール(SP 800-38D のカウンターモード。`gcm_*.c`、`gcmx86_ctr.c`)とヘッダー保護のマスク(`hp.c`、`hp_suite.c`。RFC 9001 5.4.3 の、1 つのサンプルを AES-ECB で暗号化する処理)だけです。これは `src/` を grep して確かめました。ネガティブテストを書いても、この呼び出し箇所の列挙を確かめ直すだけになります。

## 付録 A/B/C: 鍵拡張、暗号化、例示ベクター

- [x] F197-019 (App. A.1, B, C.1) 実装は、128 ビット鍵(ラウンド鍵は付録 A.1 のもの)について、付録 B と付録 C.1 の CIPHER() の既知解ベクターを再現しなければならない。
  - test: `tests/crypto/aes_test.c` — `test_aes_fips197`
  - test: `tests/crypto/aes_test.c` — `test_aes_appendix_c`
- [x] F197-020 (App. A.3, C.3) 実装は、256 ビット鍵(Nk=8、Nr=14)について、付録 C.3 の CIPHER() の既知解ベクターを再現しなければならない。
  - test: `tests/crypto/aes_test.c` — `test_aes256_appendix_c3`

## 対象外

このサーバー SDK が意図して実装しない要件です。カバレッジの分母から除いています。

- (Abstract, §1, §5, Table 3, App. A.2) AES-192(Nk=6、Nr=12)。TLS 1.3 のどの暗号スイートも AES-192 を使いません。AES-256(App. A.3, C.3)は実装済みで(`src/crypto/symmetric/aead/aes/aes.h` の `aes256_*`)、`TLS_AES_256_GCM_SHA384` での QUIC のパケット保護とヘッダー保護の鍵に使っています(`tests/crypto/aes_test.c` の `test_aes256_appendix_c3`、`tests/transport/hp_suite_test.c` の `test_hp_suite`)。
- (§5.3 F197-011, §5.3.1 F197-012, §5.3.2 F197-013, §5.3.3 F197-014, §5.3.5 F197-015) INVCIPHER()、EQINVCIPHER() と、それらを構成するすべての変換(INVSHIFTROWS、INVSUBBYTES、INVMIXCOLUMNS、KEYEXPANSIONEIC)。QUIC は生の AES で復号することがありません。GCM(SP 800-38D)はカウンターモードで順方向の暗号だけを使い、RFC 9001 5.4.3 のヘッダー保護は送信側でも受信側でもサンプルを AES-ECB で*暗号化*します(暗号化とは別にヘッダーを「復号」する操作はありません)。この SDK は AES の復号プリミティブをまったく提供していません。
- (§6.3) パラメーターの拡張(将来の改訂で新しい Nk/Nb/Nr の値を定める場合についての、実装者向けの指針)。標準の実装者に向けた将来の指針であり、本標準のテスト可能な要件ではありません。
- (§6.4) 各種プラットフォームに関する実装上の提案。「実装攻撃から実装を保護することを……検討するべきである」も含みます。本標準はこれを自身の範囲の外に置いています。スカラーの経路は表引きの S-box を使います(`gcmx86` の AES-NI の経路は表引きを使いません)。
- (App. A.2, C.2) AES-192 の鍵拡張と例示ベクター。AES-192 は提供していません(上を参照)。
- (Announcement 8) 輸出規制の順守(「すべての連邦法に従わなければならない」)。法的な告知であり、実装の規則ではありません。
- (Appendix D) 変更履歴(参考)。刊行物の編集の経緯であり、規範的な要件ではありません。
