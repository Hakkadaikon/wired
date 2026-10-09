closed (2026-10-09), successor: none (commits 45c637e, 6365599, 9fb08e4, dd951fb)

# guide サンプルと moqt_chat を draft-22 基準へ — 計画 (2026-10-09)

ユーザー指示: guide サンプルと moqt_chat を最新 draft (22) 基準で動作させる。徹底計画 → TDD 実装
→ テスト → commit/push。ドキュメントも全更新。レビューは別のレビュー用 subagent で最大 3 回。
moqt_chat 方針(ユーザー選択): **22 優先 + 19 フォールバック**(protocols で moqt-22 を申し出、
交渉できないブラウザでは現行 draft-19 legacy 経路)。

## 0. 調査で確定した前提(証跡)

- 版選択は WT subprotocol だけ。`moqt-22` 交渉成立で D22 + uni 制御ストリーム組。無交渉は D19 legacy
  (単一 bidi 制御)。`moqtrun.c:282-312`, `moqver.c:47-50`。
- d22 セッションの形: サーバーが uni を開き先頭が SETUP(`AF 00`、型=ストリーム型、1 回だけ)。
  クライアントも自分の uni を開いて SETUP を送る。両 SETUP が揃うまで要求は保留(2048B)。
  要求は 1 要求 1 bidi。GOAWAY はサーバー uni 制御ストリームに来る。
- SETUP / SUBSCRIBE / SUBSCRIBE_OK / PUBLISH / REQUEST_OK / REQUEST_ERROR / GOAWAY / PUBLISH_DONE /
  名前空間系 / データプレーン(SUBGROUP_HEADER, OBJECT_DATAGRAM, FETCH_HEADER)は 19 と 22 でバイト同一。
- 差分(クライアントが触るもの):
  - LOCATION_FILTER 0x21: d19 は Length 付き type 1..4、d22 は Length 無し type 0x00..0x05。
    d19 Largest(2) ≒ d22 NextObject(0x05)。
  - FETCH 0x16: d22 は `RID, NS, Name, Params`、範囲は LOCATION_FILTER(0x03/0x04)。Joining 廃止
    (d22 で Joining 形は PROTOCOL_VIOLATION)。
  - Joining の代替は SUBSCRIBE の FILL_PARAMETERS 0x23(len + 内側 params: LOCATION_FILTER など)。
    fill はサーバー uni の fetch ストリームで届き FETCH_HEADER の RID は SUBSCRIBE の RID、FETCH_OK 無し。
    d19 Relative Joining joiningStart=J ⇔ d22 RelativeStart N=J+1(start = Largest.G+1−N)。
  - FETCH_OK End Location: d19 exclusive(+1)、d22 inclusive。
  - EOR marker 0x20C(timed-out)は d22 のみ。
- ブラウザ: Chromium 141 は `WebTransportOptions.protocols` / `wt.protocol` を
  `--enable-experimental-web-platform-features` 付きでのみ公開(spike で確認: protocol=moqt-22、
  サーバー uni 先頭 `af 00 00 04`)。フラグ無しでは protocols は無視 → legacy d19。
- Go: webtransport-go v0.13.0 の `ApplicationProtocols` で申し出可(wt-session client が既に使用)。
- SDK(src/)の変更は不要の見込み(サーバーは 22 を実装済み)。

## 1. 作業項目

### G. guide サンプル(8 本)
- [x] G-1 `guide/moqtclient/moqtclient.go`: d22 セッション確立ヘルパー
  (`ApplicationProtocols: moqt-22`、クライアント uni SETUP 送信、サーバー uni SETUP 受信)、
  `Request()`(bidi 要求)、d22 FETCH 本体、`Fill` 用 SUBSCRIBE(FILL_PARAMETERS)、
  NextObject フィルタ、inclusive FETCH_OK、0x20C、節番号を d22 に。JoiningFetch 削除。
- [x] G-2 各 `main.c` に `opt.wt_protocols = "moqt-22"`(delivery も含め全 8 本)、コメントの節番号を d22 に。
- [x] G-3 各 `client.go` を d22 形に(SUBSCRIBE は制御ストリームでなく bidi 要求、GOAWAY は uni 制御から、
  data の AcceptUniStream より先に制御 uni を取る)。
- [x] G-4 golden: hub/publish/authorize/live/discovery/delivery/priority-goaway は不変の見込み、
  fetch は joining → fill で変わる(先に期待 golden を書いて Red → 実装で Green)。
- [x] G-5 guide-verify 36/36、snippet-lint、pnpm test。

### C. moqt_chat
- [x] C-1 サーバー `wired_server.c`: `opt.run.wt_protocols` に `wired_moqt_wt_protocols()`
  (22/19/18 受理、無交渉ブラウザは legacy d19 のまま)、HTTP 本文と節コメント更新。
- [x] C-2 `moqtWire.ts`: 版引数で LOCATION_FILTER を 19/22 両形で encode/decode、FILL_PARAMETERS 0x23
  encode、d22 FETCH 本体(使わないなら不要)、0x20C を d22 で受理、節番号は d22 基準 + d19 注記。
- [x] C-3 `moqtClient.ts`: `protocols: ["moqt-22"]` を申し出、`wt.protocol === "moqt-22"` なら d22:
  クライアント uni SETUP、サーバー uni 制御(0x2F00)から GOAWAY、履歴は SUBSCRIBE+fill
  (N = joiningStart+1、fill の RID = SUBSCRIBE RID)。それ以外は現行 d19 経路をそのまま。
- [x] C-4 `moqtScreenClient.ts`(joiningStart 0 → fill N=1)、`page.tsx` 表記。
- [x] C-5 テスト(TDD、先に Red): fakeWebTransport に `protocol` と uni 制御ストリーム/クライアント uni 記録、
  moqtClient.test.ts に d22 系(SETUP 送信、uni GOAWAY、fill SUBSCRIBE バイト、fill ストリーム受信)、
  d19 系は現行テストを維持。moqtWireRequests/moqtWire テストに d22 ベクタ。
- [x] C-6 `testvectors/moqt_golden.json` に d22 ベクタ(NextObject、FILL_PARAMETERS 付き SUBSCRIBE、
  EOR 0x20C)。ベクタはサーバー codec(C)で検証する C テストを追加し、`scripts/gen_moqt_golden.py`
  → `tests/app/moqt_golden.h` 再生成、`just golden-check`。
- [x] C-7 実ブラウザ確認: Playwright Chromium 141 + 実験フラグで moqt_chat サーバーに接続し
  protocol=moqt-22 と chat の送受信・履歴(fill)を確認。不可能ならその理由を記録。

### D. ドキュメント
- [x] D-1 guide en/ja: moqt/{hub,authorize,delivery,discovery,fetch,priority-goaway,publish,live}.mdx、
  concepts/{limits,media-mapping,streams-vs-datagrams}.mdx(節番号 d22、制御ストリーム形、fill)。
- [x] D-2 docs: api-stability.md、arch/rfcs.md、performance/comparison.md、getting-started.md、
  features/draft-moq-transport.md・-22.md、moqt_chat README、e2e シナリオのコメント。

### R. レビュー
- [x] R-1 別 subagent(quic-reviewer + 汎用)でレビュー → 修正、最大 3 回。

## 2. 並列化
- 実装は G と C を別 coder で並列(ファイル重複なし)。ninja は G のみ使用、C はサーバーを clang 直呼びで検証。
- tests/run.c・moqt_golden.h・git はコーディネーターのみ。D は G/C の結果確定後。

## 3. 完了条件
just test / test-fast / ninja / lizard / fmt-check / docs / golden-check / examples build、
guide-verify 36/36、guide pnpm test、frontend vitest + lint、実ブラウザ確認(C-7)、レビュー合格、push。

## 4. 最大並列化の計画(2026-10-09 追記)

計測: nproc 4、MemAvailable 15.4GB、loadavg 0.05。
`safe_parallel = min(nproc-1=3, 15431/700=22, N_independent, 8)` → **CPU を使う(ビルド/テスト実行)エージェントは同時 3 本**。
読み書き中心(ドキュメント編集・レビュー)は CPU をほぼ使わないので、その上に乗せる。

### 独立単位(ファイル集合が重ならないもの)
| ID | 内容 | 触るファイル | 種別 | 依存 |
|---|---|---|---|---|
| W-G | guide サンプル 8 本 + moqtclient.go | guide/snippets/moqt-*, guide/moqtclient | CPU(ninja guide, go, guide-verify) | なし(実行中) |
| W-C | moqt_chat フロント + サーバー + golden JSON | examples/moqt_chat/{frontend/src, wired_server.c, testvectors} | CPU(pnpm/vitest, clang 直) | なし(実行中) |
| W-E | e2e 実行基盤の事前検証(リポジトリは編集しない) | scratchpad のみ | CPU(Chromium) | なし → W-C 完了後に実ブラウザ確認 C-7 へ継続 |
| W-D1 | guide 本文 en/ja: hub, publish, authorize, live, delivery + concepts(limits, media-mapping, streams-vs-datagrams) | guide/src/content/docs/{en,ja}/… | 軽量 | なし(事実は確定済み) |
| W-D2 | guide 本文 en/ja: discovery, priority-goaway, fetch(fetch の golden 依存行はプレースホルダ) | guide/src/content/docs/{en,ja}/moqt/{discovery,priority-goaway,fetch}.mdx | 軽量 | fetch の出力行だけ W-G 待ち |
| W-D3 | moqt_chat README + e2e シナリオ/ライブラリのコメント | examples/moqt_chat/README.md, e2e/** | 軽量 | なし |

### 直列(コーディネーター 1 人だけ)
- tests/run.c、tests/app/moqt_golden.h 再生成(gen_moqt_golden.py)、新 d22 ベクタの C 照合テスト、git add/commit/push。
- ninja のビルドディレクトリは W-G 専有。他は clang 直呼び / 既存バイナリのみ。

### 波(パイプライン)
1. **第 1 波(今)**: W-G, W-C(実行中)+ W-E, W-D1, W-D2, W-D3 を起動 → 計 6 本(CPU 系 3 本)。
2. **第 2 波(完了したものから順次)**: 完了ストリームごとに別のレビュー subagent を即起動(R-G / R-C / R-D)。
   指摘は元のエージェントへ SendMessage で戻して修正(文脈を保持)、各ストリーム最大 3 回。
   並行してコーディネーターが golden.h 再生成 + C 照合テスト + run.c 配線、W-D2 へ fetch の確定出力を渡す、
   W-E が W-C の成果で実ブラウザ確認(C-7)。
3. **第 3 波(直列)**: 全体ゲート(test/test-fast/ninja/lizard/fmt-check/docs/golden-check/examples/guide-verify/
   guide pnpm test/frontend vitest+lint/e2e)→ ストリーム単位のコミット → push。

これ以上は増やさない: 残りの作業(run.c・golden.h・git)は共有資源で直列、W-G 内の 8 snippet は共通の moqtclient.go に
依存するため分割すると同じ基盤を二重に作ることになる。

## 5. 結果(2026-10-09)

- G: guide 8 サンプルを moqt-22 化(45c637e)。guide-verify 36/36、golden 変更は moqt-fetch のみ(joining→fill)。
  レビュー 3 回(R1 FAIL 3 should-fix → R2 FAIL 1 → R3 FAIL 1: publisher の FIRST_OBJECT、上限到達のため
  コーディネーターが修正し guide-verify で確認)。
- C: moqt_chat 22 優先 + 19 フォールバック(9fb08e4)。vitest 610/610。レビュー 2 回(R1 FAIL 2 → R2 PASS、
  nit 3 件はコーディネーターが TDD で修正)。実ブラウザ(Chromium 141): フラグ有り d22 / 無し d19 とも
  チャット送受信と履歴(d22 は fill)PASS(scratchpad/we/final)。
- C-6: d22 ベクタ 3 件をサーバー codec で往復照合(6365599)。
- D: docs/guide 本文/README/e2e コメント(45c637e, dd951fb)。known-limitations に relay の FIRST_OBJECT
  未クリア(src、範囲外)を記録。
- 未実施: 既存 e2e スイート(puppeteer)への実験フラグ追加(ハーネスに引数指定の仕組みがない)。
