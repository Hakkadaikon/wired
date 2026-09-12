# 実装プロトコルの脆弱性監査 + 性能計測 + TDD 修正: 進め方

Status: 承認済み(2026-09-12)。決定: 台帳は `docs/security/vuln-ledger.md` で git 管理、性能退行は中央値 3% 超で停止して原因特定(goodput レーンは任意)、同種実装は §2-B の製品リスト + frontend/e2e の npm audit。

## 目的

このリポジトリが実装する全プロトコル/アルゴリズムについて、(1) 関連する脆弱性
(公開 CVE/アドバイザリ、RFC の Security Considerations、学術・業界の攻撃分類)を
網羅的に台帳へ採番し、(2) 各項目を TDD(先に失敗するテスト)で潰す/既に安全なら
テストで固定する/対象外なら理由を書く、(3) 修正前後で性能を同一手順で計測し、
退行を台帳に残す。台帳のチェックボックスが進捗の唯一の真実。

## 0. 前提の事実(確認済み)

- 外部 DB への `curl` は本セッションでは権限拒否。**WebFetch/WebSearch ツールは
  到達可**(NVD 2.0 API、GitHub Advisory API、各社アドバイザリ、RFC 本文)。
  収集は「エージェントが WebFetch で取得 → JSON に正規化して保存」を主経路にし、
  再現用に `scripts/vulnaudit/collect.py`(同じクエリ列を発行する)も置く
  (ネットワーク許可がある環境ではそれで再実行できる)。
- NVD の `keywordSearch=QUIC` は語幹一致で "quickly" まで拾う(1,417 件)。
  **製品 CPE で引く**(`cpeName=cpe:2.3:a:<vendor>:<product>:*:*:*:*:*:*:*:*`)か
  `keywordExactMatch` を付ける。GitHub Advisory API は `keywords` が効かず、
  `ecosystem` + `affects=<パッケージ名>` で引く。
- 既存資産: `docs/security.md`(現状の保証一覧、Psychic Signature 等の既知クラス
  への言及あり)、`fuzz/`(header / qpack / x509 / onertt の 4 ハーネス、`just
  fuzz-ci` 夜間)、`bench/`(benchclient による ttfb/load レーン、sections、
  goodput)、`tasks/fv`(Lean 述語カタログ)、`tasks/loopeng`(TLA+)。

## 1. 対象の棚卸し(プロトコル → ソース → 一次資料)

| 領域 | 一次仕様 | src |
|---|---|---|
| QUIC v1/v2 | RFC 9000, 9001, 9002, 8999, 9287(grease), 9368/9369(v2, compat VN), ack-frequency draft | `transport/*` |
| TLS 1.3 | RFC 8446, 8448(vectors), 7748(X25519), 8422, 8701(GREASE) | `tls/*` |
| 対称暗号/ハッシュ | AES-GCM(SP 800-38D)、ChaCha20-Poly1305(RFC 8439)、SHA-2(FIPS 180-4)、HMAC/HKDF(RFC 2104/5869) | `crypto/symmetric`, `crypto/kdf` |
| 公開鍵 | ECDSA P-256/P-384(FIPS 186-5, RFC 6979)、Ed25519(RFC 8032)、RSA PKCS#1 v1.5/PSS(RFC 8017)、X25519 | `crypto/asymmetric` |
| PKI | X.509(RFC 5280)、名前照合(RFC 6125/9525)、DER(X.690)、PEM | `crypto/pki` |
| HTTP/3・QPACK | RFC 9114, 9204, 9297(Datagram/Capsule), 9220(Extended CONNECT), 9218(priority) | `app/http3`, `app/qpack`, `app/datagram` |
| WebTransport | draft-ietf-webtrans-http3-15, draft-ietf-webtrans-overview | `app/webtransport` |
| MoQT | draft-ietf-moq-transport-19 | `app/moqt` |
| IP/UDP/AF_XDP | RFC 768/791/1071(checksum)、8899(DPLPMTUD)、GSO、XDP | `transport/io` |
| メディア | ISO 14496-12 box 構造 | `app/media/mp4frag` |
| サンプル/フロント | examples/*、frontend(npm)、e2e(npm) | `examples/` |

## 2. 収集の方法(Phase 1)

三系統を全部採る。**過剰抽出は安全、漏れは危険**(迷ったら採る)。

A. **仕様由来の脆弱性クラス**: 上表の各 RFC/draft の Security Considerations を
   段落単位で採番(`S-<RFC>-<n>`)。RFC 9000 は 21 節、9001 は 9 節、9114 は 10 節、
   9204 は 7 節、8446 は付録 E まで。WebFetch で rfc-editor の本文を取り、段落ごとに
   「攻撃/前提/要求される防御」を 1 行化する。
B. **同種実装の CVE/アドバイザリ**(我々にも同じバグクラスが無いかの点検表):
   ngtcp2/nghttp3、quiche(Cloudflare)、quinn、quic-go、msquic、lsquic、picoquic、
   aioquic、s2n-quic、mvfst、xquic、neqo、quicly、Chromium QUIC、nginx HTTP/3、
   HAProxy、Envoy、curl(HTTP/3 部)、OpenSSL/BoringSSL/wolfSSL/mbedTLS/GnuTLS/
   rustls/s2n-tls(TLS 1.3・X.509・RSA/ECDSA/Ed25519)、libsodium(ed25519)、
   mp4 パーサ(FFmpeg mov、GPAC、Bento4)。取得元は NVD(CPE 指定)、GitHub
   Advisory(`affects=`)、各リポジトリの GHSA、OSV(`/v1/vulns/<id>` で補完)。
   期間は 2018 年(QUIC draft 実装期)〜現在。
C. **攻撃分類の文献**: NCC Group「QUIC Hash-DoS」(2025 一斉開示)、「Revisiting
   QUIC attacks」(IJIS 2022)、Rapid Reset(CVE-2023-44487)と HTTP/3 版、
   Loop DoS(CVE-2024-2169)、楽観的 ACK(CVE-2025-4820 quiche 他)、QUIC-LEAK
   (CVE-2025-54939)、Marvin(RSA タイミング)、Minerva(ECDSA タイミング)、
   punycode X.509(CVE-2022-3602/3786)、TLS の Raccoon/ALPACA/SLOTH 類、
   QUIC WG implementations ページの既知問題。

成果物: `tasks/vuln/raw/<source>.json`(取得生データ、取得日時・クエリ付き)→
`scripts/vulnaudit/merge.py` で `tasks/vuln/catalog.json`(正規化: id, source,
product, published, CWE, CVSS, summary, area, bug_class)→ 台帳 v0。
網羅性ゲート: 製品ごとの件数を OpenCVE/GHSA の件数と突き合わせ、RFC は節数と
段落数の突き合わせ(loopeng の 0 段と同じ「採番チェックリスト + トレーサビリティ表」)。

## 3. 台帳(チェックボックス)の設計

置き場は決めの問題(後述の質問 1)。形式:

```
## QUIC transport
- [ ] V-0031 CVE-2025-4820 (quiche) optimistic ACK: 未送信 PN の ACK を受理し cwnd が膨らむ
      ours: transport/recovery/detect/ackrange — verdict: ? — test: — commit: — perf: —
- [x] V-0032 S-9000-21.1 handshake DoS (amplification) …
      verdict: already-safe — test: test_antiamp_budget_before_validation — commit: pinned 1a2b3c4 — perf: n/a
```

- 状態: `[ ]` 未トリアージ / `[~]` 判定済み・テスト計画あり / `[x]` 完了。
- `[x]` の条件(リポの honest-ledger 規範に従う): `fixed`(テスト名 + 修正コミット)、
  `already-safe`(固定テスト名 + コミット)、`n/a`(理由: 該当機能を持たない等)の
  いずれか一つ以上が埋まっていること。テスト名の無い `[x]` は禁止。
- `scripts/vulnaudit/ledger_check.py`: 上の規則を機械検査し、領域別の
  件数(未/判定/完了)と perf 欄の退行を集計する。台帳更新はコミットと同じ手番で行う。

## 4. トリアージと修正(Phase 3〜4、TDD)

各項目で:
1. バグクラス → 我々のコード位置を `grep` で特定(無ければ `n/a`)。
2. 検証層を決める(リポ規範の三層): パーサ/メモリ安全 → **fuzz ハーネス + 単体テスト**;
   プロトコル状態(楽観的 ACK、増幅上限、ストリーム上限、移行、鍵更新、Retry
   トークン)→ **TLA+**(tasks/loopeng に既存モデルあり)で反例を出してから
   テスト; 暗号・パースの数学的性質(定数時間、非正準入力拒否、DER 長さ)→
   **Lean 述語 + ベクタ**、タイミングは `$TMPDIR` で dudect 風の統計検定。
3. TDD: 攻撃入力/性質を表す **失敗するテストを先に書く**(Red)→ 最小修正
   (Green、CCN ≤ 3)→ ゲート → マイクロコミット。コミット件名に CVE/節番号を
   入れる(例 `fix(recovery): reject ACK ranges above the largest sent PN (CVE-2025-4820 class)`)。
   既に通るなら「固定テスト」として `already-safe` で閉じる。
4. fuzz の拡充(第 1 波で先行): 未カバーのパーサに harness を足す —
   TLS ハンドシェイクメッセージ、QUIC 全フレーム種、transport parameters、
   capsule、MoQT control/data、QPACK encoder stream、mp4frag。`fuzz-smoke`(毎コミット)
   と `fuzz-ci`(夜間)に載せ、corpus を蓄積。
5. 各領域の完了時に security 観点のレビュー(diff-review の security レンズ)。

並列化: 領域ごとに explorer(トリアージ)→ coder(修正、自分のファイルのみ)→
integrator(配線・ゲート・コミット)の既存パイプライン。台帳は integrator が
コミットと同じ手番で更新。

## 5. 性能計測の方法(Phase 2 と各波の後)

同一手順・同一機材で「修正前ベースライン → 各波後」を比べる。

| レーン | 何を測るか | 道具 |
|---|---|---|
| ttfb / load | 新規接続 1 リクエストの遅延、ウォーム接続 20 並列の req/s と p50/p95、CPU | `bench/run-lane.sh`(サーバー core 3 固定、クライアント 0,1) |
| goodput | 標準模擬リンクのスループット | `bench/goodput-ci.sh`(docker + tshark が要る: Phase 0 で可否確認) |
| crypto micro | AES-GCM/ChaCha/SHA-256/HKDF/X25519/P-256 verify/Ed25519 verify の ns/op | `bench/micro/`(新設、freestanding ビルドの関数を hosted で回す) |
| per-packet | 受信〜フレーム分岐までの ns/packet(検証追加の直撃箇所) | onertt fuzz 入力を使う microbench(新設) |
| moqt live | 2 窓での余裕・停止・live_dropped | `e2e/run-live-check.mjs --measure`(既存プローブを昇格) |
| footprint | text/data/bss、RSS | `bench/sections.sh`、/proc |

- 各 5 ラウンド以上、中央値と MAD を `tasks/perf/<date>-<label>.json` に保存し、
  markdown の差分表を台帳の perf 欄に転記する。
- 退行判定の予算は決めの問題(質問 2)。暫定: いずれかのレーンで中央値 3% 超の
  悪化は「原因特定してから merge」。セキュリティ修正はホットパス(ACK 処理、
  フレーム分岐)に検査を足すことが多いので、per-packet レーンを必ず見る。
- 最後に `docs/comparison.md` の表を更新(手順は同文書の Run manifest に従う)。

## 6. フェーズと成果物

| Phase | 内容 | 成果物 | 並列 |
|---|---|---|---|
| 0 | 可否確認(docker/tshark、Go、perf 系ツール)、質問 1〜3 の決定 | チェックリスト | — |
| 1 | 収集 A/B/C、正規化、台帳 v0、網羅性ゲート | `tasks/vuln/raw/*`、`catalog.json`、台帳(全 `[ ]`) | 取得元ごとに explorer 並列 |
| 2 | 性能ベースライン | `tasks/perf/baseline.json` + 表 | 1 worker(機材専有) |
| 3 | トリアージ(領域ごと)、verdict と検証層、TLA+/Lean 対象の選定 | 台帳 `[~]`、Gherkin/述語 | 領域ごと並列 |
| 4 | 修正波(fuzz 拡充 → crypto/PKI → QUIC transport → TLS → HTTP3/QPACK → WT/MoQT → IO/メディア)、波ごとに性能再計測 | コミット列、台帳 `[x]`、perf 差分 | coder 並列・integrator 直列 |
| 5 | 最終 security レビュー、`docs/security.md` をテスト裏付き記述に更新、comparison.md 更新、総括 | 文書更新、総括レポート | — |

規模感: 台帳は 150〜400 項目(RFC 由来 ~120、同種実装 CVE ~100〜200、文献 ~30)。
複数セッションにまたがるので、台帳と `tasks/todo.md` を再開の唯一の入口にする
(セッションごとに `[ ]` の先頭から再開)。

## 7. 決めてほしいこと

1. **台帳の置き場**: `docs/security/vuln-ledger.md` として git 管理(監査の
   成果物として残る、推奨)か、規範どおり `tasks/` で非管理か。
2. **性能退行の予算**: 中央値 3% 超で止める(暫定)でよいか。goodput レーン
   (docker + tshark)を必須にするか任意にするか。
3. **同種実装の範囲**: 上記 B の製品リストでよいか。Chromium/nginx/curl の
   ような巨大製品は「QUIC/HTTP3 部分のみ」に絞る。frontend/e2e の npm 依存は
   `pnpm audit` / `npm audit` の結果を別節として台帳に含めるか。

## 対象外(この計画で扱わないもの)

- ペネトレーションテストや実ネットワークでの攻撃再現(ループバック・単体・
  fuzz・モデル検査で代替)。
- 依存ツールチェーン(nix の clang 等)の脆弱性。
- 運用側の責務として `docs/security.md` が明示している項目(証明書の有効期間・
  ホスト名検証の適用、リクエストレート制限、Retry トークン TTL)の実装。
  ただし「SDK として提供すべき機構が欠けている」と判明した項目は台帳に載せる。
