# セキュリティ設計

[ドキュメント](../README.md) › セキュリティ設計


| 項目 | 内容 |
|---|---|
| 目的 | SDK のセキュリティ設計の文書と、その裏付けになる監査の記録の入口 |
| 読む人 | セキュリティ上の主張の裏付けを確かめる人、セキュリティに関わる変更をレビューする人 |
| 前提文書 | なし |
| 関連文書 | [システムコール](../syscalls.md) |

## 1. 文書の一覧


### 1.1 設計

| 文書 | 中身 | 開くとき |
|---|---|---|
| [脅威モデル](threat-model.md) | SDK が検査する性質とアプリケーションに任せる性質、監査台帳の概要、freestanding による攻撃面 | wired を実際のトラフィックの前に置くかを決めるとき |
| [暗号](crypto.md) | AEAD、Key Update、署名、X25519 の検査と、プリミティブごとの検査の種類 | 暗号のコードを変更・レビューするとき |
| [証明書チェーンと X.509](pki.md) | チェーンの検証の順序、X.509 と DER の検査、有効期間とホスト名の検査の分担 | PKI のコードを変更・レビューするとき |
| [プロトコルごとの防御](protocols.md) | QUIC、HTTP/3、WebTransport、MoQT の検査 | プロトコルのコードを変更・レビューするとき |
| [既知の制限](limitations/README.md) | 既知の制約と、意図して仕様から外れている点(層ごと) | 制約を確かめるとき |

### 1.2 監査の記録

| 文書 | 開くとき | 現状 |
|---|---|---|
| [脆弱性台帳](vuln-ledger.md) | ある攻撃の種類やアドバイザリについて、判定とテストを知りたいとき | 856 行、すべて `done`: `fixed` 65、`already-safe` 291、`n/a` 500(2026-11-07) |
| [機能がないために該当しない脆弱性](feature-gaps.md) | wired にない機能を追加するとき | 25 の機能グループに台帳の 51 行 |
| [BoringSSL のテストベクター](boringssl-vectors.md) | あるプリミティブについて BoringSSL の判定を知りたいとき | 1634 件: pass 1523、fail 0、skip 111 |
| [Wycheproof のテストベクター](wycheproof-vectors.md) | どの攻撃入力を拒否するかを知りたいとき | 6296 件: 正答 6141(うち 54 件は構造上の正答)、fail 0、skip 155 |

台帳の書式と行数は `python3 scripts/vulnaudit/ledger_check.py docs/security/vuln-ledger.md` で検査する。判定ごとの件数は各行の判定の列から数える。

## 2. 第三者のテストベクター


wired 自前のテストは、コードを書いた本人が書く。仕様の読み違いがコードとテストの両方に入ると、テストは通る。そこで、他者が書いた期待値と照らして暗号を確かめる(第三者オラクル)。

| 出どころ | 中身 | 固定したコミット | ベクターの置き場所 |
|---|---|---|---|
| BoringSSL | FileTest ベクター。AES-GCM、ChaCha20-Poly1305、X25519、Ed25519、ECDSA P-256 / P-384 / P-521、HMAC-SHA256 / 384 / 512 | `dd73e69a` | `tests/vectors/boringssl/` |
| Project Wycheproof(C2SP の `testvectors_v1`) | 既知の攻撃入力。上と同じ AEAD、曲線、署名に加え、RSA PKCS#1 v1.5 / PSS、HMAC-SHA256、HKDF-SHA256 | `3fa63dd0` | `tests/vectors/wycheproof/` |

wired はベクターを手を加えずに実行する。結果が食い違えば、誤っているのは wired の側である。

プリミティブごとにどの種類の検査があるかは [暗号](crypto.md) の 5 章にある。
