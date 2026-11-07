# 脅威モデル

[ドキュメント](../README.md) › [セキュリティ設計](README.md) › 脅威モデル

| 項目 | 内容 |
|---|---|
| 目的 | SDK が検査するセキュリティ上の性質と、アプリケーションに任せる性質の境界を示す |
| 読む人 | wired を実際のトラフィックの前に置くかを決める人、変更が何を弱めうるかをレビューする人 |
| 前提文書 | [セキュリティ設計](README.md) |
| 関連文書 | [脆弱性台帳](vuln-ledger.md)、[機能がないために該当しない脆弱性](feature-gaps.md)、[既知の制限](limitations/README.md) |

## 1. 範囲

| 区分 | 項目 |
|---|---|
| SDK が検査する | 暗号プリミティブの正しさ、証明書チェーンと署名の検証、鍵共有の入力検証、QUIC・HTTP/3・WebTransport・MoQT のコアのリソースとパーサーの安全性 |
| 呼び出し側が用意する | 証明書の有効期間とホスト名の検査(サーバーの役割)、HTTP/3 のリクエストのレート制限、Retry トークンの有効期間(TTL)、失効確認、MoQT の購読を認可するポリシー |

同じ線引きをアプリケーションの側から書いたものが、ガイドの [SDK とアプリの役割分担](https://hakkadaikon.github.io/wired/guide/ja/concepts/responsibilities/) である。対象外の項目ごとに、アプリケーションが作るものを載せている。

## 2. 検査する性質

| 性質 | 文書 |
|---|---|
| タグとトークンの比較は定数時間 | [暗号](crypto.md)、[プロトコルごとの防御](protocols.md) |
| ECDSA、Ed25519、X25519 の入力を既知の攻撃クラス(ゼロのスカラー、低位数の点、非正規のエンコーディング)に対して検査する | [暗号](crypto.md) |
| 証明書チェーンのトラストアンカーへの連結、CA ビット、名前制約を検査する。DER のパースは境界を検査する | [証明書チェーンと X.509](pki.md) |
| QUIC の増幅攻撃対策、ECN の検証、AEAD の使用上限をイベントループで強制する | [プロトコルごとの防御](protocols.md)、[暗号](crypto.md) |
| MoQT の購読者の認可はオプトイン | [プロトコルごとの防御](protocols.md) |
| `malloc`、`printf`、libc を使わない | 4 章 |

## 3. 監査台帳

セキュリティ設計の各文書の記述は機能の一覧ではなく [脆弱性台帳](vuln-ledger.md) の監査から来ている。台帳の元は CVE データベース、ほかの QUIC/TLS 実装のセキュリティアドバイザリ、RFC の "Security Considerations" の節である。各行は既知の攻撃 1 つを、それが当てはまる(または当てはまらない) wired のコードパスに対応づける。

| 項目 | 値(2026-11-07) |
|---|---|
| 行数 | 856(すべて `done`) |
| `fixed` | 65 |
| `already-safe` | 291 |
| `n/a` | 500 |
| 節ごとの行数 | 台帳の「概要」の表と `python3 scripts/vulnaudit/ledger_check.py docs/security/vuln-ledger.md` の出力 |

判定の意味と行を閉じる条件は台帳の冒頭にある。機能がないことだけを理由に閉じている行(失効確認、ECH、DSA など)は [機能がないために該当しない脆弱性](feature-gaps.md) に挙げる。その機能を追加すると、該当する行は開き直す。

`n/a` の行の多くは、攻撃される仕組みがこの SDK にない。

| 攻撃クラス | ない仕組み |
|---|---|
| use-after-free、double free | ヒープアロケーター(4 章) |
| ハッシュ衝突による DoS | 予測できるハッシュ。`conntable` のハッシュはプロセスごとの CSPRNG シードを鍵にし、表は固定サイズでリサイズしない(V-0004) |

### 3.1 運用者またはデプロイの側の行

次の 3 行は、SDK がプロセスの中では閉じられない穴である。

| 行 | 内容 | SDK の中で閉じない理由 |
|---|---|---|
| V-0324 | 失効確認(RFC 8446 App. C.2、SHOULD) | libc を使わないこの SDK はネットワーククライアントを持たない。CRL の取得や OCSP ステープリングを動かす場所がない |
| V-0300 | Selfie / 外部 PSK のリフレクション | 攻撃には、1 つのエンドポイントが外部の事前共有鍵をクライアントとサーバーの両方の役割で共有していることが要る。SDK には外部 PSK の仕組みがなく、クライアントの役割では ClientHello を受け付けない |
| V-0223 | 自分で ECN-CE を付ける抑制検出のプローブ(RFC 9002 8.3、任意) | プローブは個々のパケットに CE を付ける。それには送信ごとの TOS の `cmsg` が要るが、ソケット層は公開していないので、運用者は有効にできない |

V-0223 のプローブが狙う攻撃は、RFC 9000 13.4.2.1 の下限チェック(`test_ecn_suppressed_counts_fail_validation`)で検出する。そのため、この行は `already-safe` で閉じている。

## 4. freestanding による攻撃面

`src/` は C 標準ライブラリを使わない。悪用される関数がないので、そのバグのクラスがない。

| 項目 | 内容 | 確かめ方 |
|---|---|---|
| libc | `src/` は libc をリンクしない | `-ffreestanding -nostdlib` のビルド(`just ninja`) |
| ない関数 | `malloc`/`free`(固定サイズのバッファーだけを使う)、`printf`/`scanf`、`getenv`/`system`/`exec`、`signal` ハンドラー、libc の文字列関数 | 本番のソースにないことをそれぞれ確認している |
| 台帳 | use-after-free、double free、ヒープアロケーターの混乱のクラスは `n/a` で閉じる | [脆弱性台帳](vuln-ledger.md) |
| 状態の増加 | 最悪のピアに対する接続の状態の増加と、WebTransport のストリームの頻繁な開閉は、固定容量のテーブルで抑える | `test_srvrun_conn_state_growth_bounded_under_worst_case_peer`、`test_srvrun_wt_stream_churn_bounded_by_slot_table` |

SDK が行うカーネル呼び出しは [システムコール](../syscalls.md) にある。
