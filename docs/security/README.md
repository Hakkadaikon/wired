# セキュリティ文書

このページは `docs/security/` の案内図です。監査記録ごとに、何のための記録で、どんなときに開くかを示します。
セキュリティ上の主張の裏付けが要るとき、たとえば「wired は攻撃 X に対して確かめてあるか」「この暗号プリミティブが正しいことはどのテストで示しているか」に答えるときに読んでください。
利用者向けに wired のセキュリティ特性をまとめたものは、こちらではなく [`docs/security.md`](../security.md) から読み始めてください。

## 記録の前提になる 2 つの考え方

**脆弱性台帳** は、wired のようなプロトコルが攻撃されうる既知の手口をすべて並べ、それぞれに判定を付けた一覧です。
項目の出どころは仕様そのもの(攻撃について警告している RFC の段落)、ほかの QUIC / TLS 実装で見つかったバグ(CVE やアドバイザリー)、研究論文、ブラウザー向けサンプルの `npm audit` です。
各項目には次の 3 つの判定のどれかが付きます。

- **fixed**: wired に問題があり、修正済みで、修正をテストで固定している。
- **already safe**: wired にはもともと問題がない。たいていはテストで示しているが、構造上の理由による少数の行では、コードが攻撃されえない理由を Rationale に書いている。
- **not applicable**: 攻撃の対象になる機能やコードパスが wired に存在しない。その理由を項目に記録している。

**第三者のテストベクターによるオラクル** は、他者が書いた期待値と照らして wired の暗号を確かめるものです。
自前のテストはコードを書いた本人が書くので、仕様の読み違いが両方に入り込み、テストがそのまま通ってしまうことがあります。
BoringSSL(Google の TLS ライブラリ)と Project Wycheproof(既知の攻撃入力を集めたもの)は、入力と期待される出力をまとめたファイルを公開しています。
wired はそれを手を加えずに実行するので、結果が食い違えば誤っているのは wired の側です。テストを wired に合わせて書いたせいではありません。

## 文書の一覧

| 文書 | 開くとき | 現状 |
|---|---|---|
| [vuln-ledger.md](vuln-ledger.md) | ある攻撃の種類やアドバイザリーについて、判定とテストを知りたいとき | 840 行、すべて完了: fixed 61、already safe 415、not applicable 364 |
| [feature-gaps.md](feature-gaps.md) | wired にいまない機能を追加しようとしているとき | 26 の機能グループに台帳の 57 行 |
| [boringssl-vectors.md](boringssl-vectors.md) | あるプリミティブについて BoringSSL の判定を知りたいとき | 1634 件: pass 1523、fail 0、skip 111 |
| [wycheproof-vectors.md](wycheproof-vectors.md) | どの攻撃入力が拒否されるかを知りたいとき | 6296 件: 正答 6141(うち 54 件は構造上の正答)、fail 0、skip 155 |

各行の補足:

- **vuln-ledger.md**: 攻撃の種類ごとに 1 行で、出どころ(CVE、RFC の節、論文)、判定、それを固定するテスト、コミットを記録しています。ファイルの書式は `python3 scripts/vulnaudit/ledger_check.py docs/security/vuln-ledger.md` で検査し、このコマンドは行数の合計も出力します。上の判定ごとの件数は各行の Verdict 列から数えたものです。
- **feature-gaps.md**: 機能がないことだけを理由に安全になっている台帳の行です(大半は not applicable で、3 行は存在する部分について already safe)。Encrypted Client Hello、CBC 暗号スイート、失効確認、TLS 1.2 などが該当します。その機能を追加すると該当する行を判定し直すことになるので、追加する前にこの文書を読んでください。
- **boringssl-vectors.md**: BoringSSL の FileTest ベクター(固定したコミット `dd73e69a`)の結果です。対象は AES-GCM、ChaCha20-Poly1305、X25519、Ed25519、ECDSA P-256 / P-384 / P-521、HMAC-SHA256 / 384 / 512 です。skip は、wired が実装していない曲線とハッシュ、96 ビットでない AES-GCM の nonce、それに BoringSSL 自身が無効にしている X25519 の負荷テスト 1 件です。ベクターは `tests/vectors/boringssl/` にあります。
- **wycheproof-vectors.md**: Wycheproof ベクター(C2SP の `testvectors_v1`、固定したコミット `3fa63dd0`)の結果です。対象は同じ AEAD、曲線、署名に加え、RSA PKCS#1 v1.5 / PSS、HMAC-SHA256、HKDF-SHA256 です。wired の API では入力を表現できないため、wired のコードを 1 行も動かさずに拒否扱いになる「invalid」の 54 件も載せています(AES-192 の鍵、96 ビットでない nonce、64 バイトでない Ed25519 署名)。ベクターは `tests/vectors/wycheproof/` にあります。

このディレクトリの外にある関連文書:

- [`docs/features/known-limitations.md`](../features/known-limitations.md): 既知の制約と、意図的に仕様から外れている点のすべてを、カテゴリ別にまとめたもの。
- [`docs/superpowers/specs/2026-09-12-vuln-and-perf-audit-plan.md`](../superpowers/specs/2026-09-12-vuln-and-perf-audit-plan.md): 脆弱性台帳を作るときに使った方法。

## 暗号プリミティブごとの検査

プリミティブごとに、検査の種類は 3 つありえます。RFC や FIPS 規格に載っている入出力の例から作った wired 自前のテスト(「既知解」)、BoringSSL のベクター、Wycheproof のベクターです。
「no」は、そのプリミティブにその種類の検査がないことを示します。理由は表の下の注に書いています。

| プリミティブ | RFC / FIPS のテスト | BoringSSL | Wycheproof |
|---|---|---|---|
| AES-128-GCM | yes | yes | yes |
| AES-256-GCM | no (1) | yes | yes |
| ChaCha20-Poly1305 | yes | yes | yes |
| X25519 | yes | yes | yes |
| Ed25519 | yes | yes | yes |
| ECDSA P-256 | yes | yes | yes |
| ECDSA P-384 | no (1) | yes | yes(SHA-384 と SHA-512) |
| ECDSA P-521 | no (1) | yes | yes(SHA-512) |
| RSA PKCS#1 v1.5 / PSS の検証 | no (1) | no (2) | yes(e = 65537) (5) |
| HMAC-SHA256 / 384 / 512 | yes | yes | SHA256 のみ |
| HKDF-SHA256 | yes | no (3) | yes |
| SHA-256 / 384 / 512 | yes (4) | HMAC 経由 (6) | ECDSA / RSA / HMAC / HKDF 経由 (6) |

- (1) AES-256-GCM、P-384、P-521、RSA にも専用のテストはありますが、期待値は OpenSSL や Python で生成したもので、RFC や FIPS の既知解から取ったものではありません。この穴を第三者のベクターで埋めています。P-521 は証明書チェーンの検証にだけ使います。
- (2) 取り込みを許可した BoringSSL のベクターファイルには、RSA のベクターがありません。
- (3) BoringSSL は HKDF のベクターを C++ のテストソースへ移したため、固定したコミットには HKDF のベクターファイルがありません。
- (4) SHA-512 の FIPS 180-4 既知解は 1 件だけです(空文字列のダイジェスト)。
- (5) e = 65537 は RSA の公開指数としてふつうに使われる値で、wired はこの値だけを検証します。
- (6) 「経由」は、そこにはそのハッシュ専用のベクターがないものの、挙げたプリミティブのどのケースも入力を先にハッシュするので、ダイジェストが誤っていればそれらのケースが失敗する、という意味です。

TLS ハンドシェイクの中で X25519 と SHA-256 が何をしているかは、ガイドの [X25519 鍵交換](https://hakkadaikon.github.io/wired/guide/ja/tls/x25519/) と [SHA-256](https://hakkadaikon.github.io/wired/guide/ja/tls/sha256/) のページを見てください。
