# moqt_chat: 実回線で「画像が相手に出ない/画面共有が届かない」の修正

Spec(上位の権威): このファイルの「設計(Spec)」節。

## Context

前回(2026-09-23、main 45d70a3f)で hub に chat track の信頼中継(捨てない中継 + 発行者への credit hold)を入れ、e2e(localhost)では 5MB まで数秒で届くようになった。ところが実配備(自宅 hub、参加者 2 人、実回線)では **≤2MB の画像が 5 分待っても相手に出ず、画面共有も届かない**(受信側コンソールは無出力)。

### 調査で確定した事実
- コンテナは新バイナリ(23:02 ビルド)。ユーザー試験セッション 4.5 分の hub 統計(shutdown 行): `sent=11908 dropped=865(7%) reset=100 open_dropped=0 relay_full=0 rel_stall=0 rel_overflow=0 dg_sent=15039`。終了は exit 0(フォアグラウンド `just up` の Ctrl-C と整合、原因ではない)。
- 同じコンテナ + 本番フロント(Pages、45d70a3f 配備済)に localhost から Chrome 146 ヘッドレス 2 タブで再現試行 → 画面共有 59 フレーム復号、画像 200KB 110ms / 2MB 863ms で**すべて正常**(`.superpowers/repro/report.md`)。
- alias は chat 0..3 / voice 4..7 / screen 10..13 → screen は lossy 経路のまま(alias 誤判定は棄却)。差分監査で lossy/共通経路の挙動変更なし、`credit_hold` の初期化漏れなし。
- e2e/再現と実環境の決定的な差: **購読者向け送信の拒否率 7%・reset 100 回/4.5 分**(e2e・再現は 0/0)。実回線では credit(WT_MAX_DATA)の更新が RTT 分遅れる。

### 根本原因(コードで確認済み)
`src/app/http3/server/srvrun/srvrun.c`:
- `wt_reply_flow_ok`(~:4217)と `wt_open_flow_ok`(~:4110)は、**サーバ自身の送信/open が購読者の WT_MAX_DATA / WT_MAX_STREAMS を超えるとき**、拒否するだけでなく `c->wt_flow_violation[sidx] = 1` を latch する。
- `srvrun_close_wt_flow_violations`(~:3325、毎 step)がその latch を **WT_FLOW_CONTROL_ERROR でのセッション close** に変換する。
- 仕様(draft-ietf-webtrans-http3 §5.3/5.4)は「送信側は相手の上限を超えて送ってはならない(= 拒否して待つ)」「**受信側**が相手の超過を検出したら close」。自分の送信試行を違反として自分のセッションを閉じるのは誤読。導入: 4f582229(2026-07-24)、相手の capsule 適用: 1894c633(2026-09-13)。
- 発火条件: `sent_data` は staging 受理時に加算(`wired_wt_session_note_data_sent`)されるため、hub の「送った」は相手の「受け取った」より最大 staging 分(64KB/stream)先行する。信頼中継は毎 tick 16KB ラウンドを staging が満ちるまで詰めるので、実回線(RTT で credit 更新が遅い)では残 credit < 16KB になりやすく、次の `stream_send` が flow 拒否 → latch → **購読者セッション close**。
- 帰結: 購読者は自動再参加(フロントの backoff、コンソール無出力)→ 添付ストリームは途中から(reliable 経路は late-open しない/lossy fallback は途中から)→ フロントは EOF まで表示しないので**画像は永遠に出ない**。同じセッション上の画面共有ストリームも close で消え、再参加後に再び credit 枯渇 → close の繰り返し → **画面共有が届かない**。lossy 経路でも flow 拒否は busy streak → reset(100 回)として現れており統計と整合。
- 既存テスト `tests/app/srvrun_test.c` ~15048-15106 が現在の「拒否 → latch → close」を pin している(修正で反転)。

### 副次的に見つかった潜在バグ(今回は未発火、`open_dropped=0`)
- `examples/moqt_chat/wired_server.c` `moqt_io_open_uni_stream`(~:176-192)は open payload を 2048B のスタック(`MOQT_SIG_BUF`)に詰めるため、信頼中継の start(header + 初回配送の whole Objects、最大 49152B)が 2048B を超えると全購読者の open が失敗し、reliable 経路は late-open しないので**その添付は全員が丸ごと失う**。
- hub 統計は shutdown 時の合計のみで、ライブ運用で拒否理由(busy/flow)やセッション close 回数が見えない。

### 追加で確定した事実(srvrun 側)
- `wt_flow_violation[]=1` の書き手は `wt_open_flow_ok`(:4118)と `wt_reply_flow_ok`(:4221)の 2 箇所だけ(テスト内の手動セットを除く)。受信側(相手がサーバの上限を超えた)の WT セッション flow 制御は**未実装**で、しかもサーバは WT_MAX_DATA / WT_MAX_STREAMS capsule も SETTINGS の initial max も**一切 advertise していない**(`wtcapsule_encode_max_*` に本番呼び出し無し)。→ latch と close 機構を外しても仕様上失うものは無い(相手が違反しうる上限が存在しない)。QUIC 層の受信 flow 制御は別層(`flowviol.c`)で健在。
- `wired_server_wt_stream_send` の拒否は flow(`stat_wtsend_flow`)も busy(`stat_wtsend_busy`)も同じ `-1`(区別不能)。カウンタは qlog のみ(`--qlog` 時 1 秒毎)、公開 API 無し。`wired_wt_session` は公開 struct で `max_data`/`sent_data` を直接読める(session.h:91-102、srvrun.h 経由で hub からも見える)。
- `sent_data` は staging 受理時(:4155/4198/4238/4374)に加算。
- 現挙動を pin するテスト(`tests/app/srvrun_test.c`): `test_srvrun_wt_open_uni_exceeding_max_streams_refused`(:15076、`wt_flow_violation[0]==1` を断定)、`..._open_bidi_exceeding_max_streams_refused`(:15093)、`..._open_uni_exceeding_max_data_refused`(:15112)、`..._stream_reply_exceeding_max_data_refused`(:15129)、close 機構自体の `test_srvrun_close_wt_flow_violations_resets_session`(:15156)/`..._noop_without_latch`(:15203)。

## 設計(Spec)

### 1. 自分の送信拒否でセッションを閉じない(root cause fix、srvrun)
- `wt_open_flow_ok`(:4110-4120)/ `wt_reply_flow_ok`(:4217-4223)は **拒否のみ**(latch 行を削除)。相手の上限内に収まるまで待つのが送信側の正しい挙動(draft-ietf-webtrans-http3 §5.3/5.4)。
- 書き手が無くなる機構を**削除**(dormant で残さない: 書き手ゼロ、サーバは上限を advertise しないので受信側 enforcement は成立しえず、dead code は本リポの hygiene ゲートで落ちる): `wt_flow_violation[]`(メンバ + doc :460-470)、`srvrun_close_flow_violated_slot`/`srvrun_close_wt_flow_violations`(:3312-3329、呼び出し :3490)、`srvrun_wt_flow_control_code`(:2856、唯一の呼び出しが :3322)。参照する doc コメント :498 / :2954 / :3109 / :3159 / :3914 のアンカーを `srvrun_wt_rx_capsules` 等に書き換え。ゲート: `grep -rn 'wt_flow_violation\|flow_violated\|wt_flow_control_code' src tests` が空。
- テスト(`tests/app/srvrun_test.c`): `CHECK(c->wt_flow_violation[0] == 1)` の 4 本(:15076/:15093/:15112/:15129)を「拒否後も `WIRED_WT_ESTABLISHED`、次 step で RESET/STOP_SENDING 無し」に反転。`==0` を断定する :15069/:15309/:15462 はメンバ削除でコンパイル不能になるので該当 CHECK を削除。close 機構のテスト :15156/:15203 と runner 登録 :18299-18300、節コメント :15048-15053 を削除。新規 1 本(既存 capsule テスト :15296-15309 は open 経路なので重複しない): `wired_server_wt_stream_send` が max_data 到達で -1 → capsule で max_data を上げる → **同じ round** が受理される(中継の実経路「待てば進む」を pin)。

### 2. 信頼中継の drain に session credit の余裕を残す(hub、二次原因)
latch を外しても、信頼中継が毎 tick 16KB を staging が満ちるまで詰めると、購読者セッションの WT_MAX_DATA 残量を添付が独占し、同じセッション上の画面共有(lossy、拒否 8 連続で reset)を飢えさせる。実測の `reset=100` はこれ。
- `wired_moqt_io` 末尾に `usz (*send_budget)(wired_wt_session* s)` を追加(位置指定初期化子はすべて 0 のまま = 無制限、`send_datagram`/`stream_hold` と同じ 0 ガード)。本番実装(wired_server.c、CCN 3): `s->max_data == 0 ? (usz)-1 : (s->max_data > s->sent_data ? s->max_data - s->sent_data : 0)`(`wired_wt_session` の公開フィールド、session.h:101-103)。
- `sent_data` は staging 受理時に加算済みなので、budget は staged 未送信分を既に差し引いている(64KB/stream の追加 reserve は不要)。lossy 画面共有 1 ラウンドの最大は `relay_scratch` = `WIRED_MOQTRUN_RELAY_FRAG_MAX`(512)+ `WIRED_SRVLOOP_WT_BUF_CAP`(49152)+ signal(≤9)。よって `WIRED_MOQTREL_HEADROOM` = `WIRED_MOQTRUN_RELAY_FRAG_MAX + WIRED_SRVLOOP_WT_BUF_CAP + 16`(16 は hub から見えない signal prefix 分)。
- 述語(CCN 2): `static int moqtrun_rel_budget_ok(hub, wt, n) { if (!hub->io.send_budget) return 1; return hub->io.send_budget(wt) >= n + WIRED_MOQTREL_HEADROOM; }`。待ち(CCN 2): `moqtrun_rel_budget_wait` = ok なら 0、そうでなければ `stat_rel_wait++` だけして 1(cursor も stall クロックも動かさない)。`moqtrun_rel_send_round`(現 CCN 3)は「span==0 の FIN 枝」「budget_wait なら return」「`moqtrun_rel_send_span`(fin_flag + 受理判定、CCN 2)」に分割。credit 枯渇が stall 窓を超えて続く購読者は、既存の busy 拒否とまったく同じ経路で lossy fallback へ shed される(QUIC 上は生きているのに WT_MAX_DATA を上げない相手を待ち続けると、ring が塞がり発行者の hold が他の全購読者を巻き込むため)。再試行は `wired_moqt_tick` が毎 step 全 ring を drain するので保証済み。
- fake io に `send_budget` を追加(既定 0 = 無制限)し、テスト 4 本: budget 不足で round を送らず `stat_rel_wait` が増え、budget 回復後に**同じ span** が送られる / headroom 分は常に残る(budget = n + HEADROOM − 1 では送らない、= n + HEADROOM で送る) / `send_budget == 0` なら従来どおり(既存 105+ 本無変更で緑) / budget 不足が stall 窓を超えたら shed、`stat_rel_wait` は deferral 回数。

### 3. open の 2048B 上限撤廃(wired_server.c、潜在バグ)
`wired_server_wt_open_uni_stream` / `wired_server_wt_open_uni` は payload ≤ `SRVRUN_WTSEND_BUF`(65536)を呼び出し中にコピーする(srvrun.c:283-290、srvrun.h:444-450/481-489)。単一スレッド・同期コールバックで再入無し → `static u8 g_open_buf[MOQT_OPEN_BUF]` 1 本で足りる。`#define MOQT_OPEN_BUF (BIG_SIG_MAX + WIRED_MOQTRUN_RELAY_HDR_MAX + WIRED_MOQTRUN_RELAY_FRAG_MAX + WIRED_SRVLOOP_WT_BUF_CAP)` = 9+40+512+49152 = 49713(< 65536 ⇒ 常にコピー、根拠をコメント)。使用箇所は `moqt_io_open_uni_stream`(:185)と `moqt_io_send_uni`(:163)。bidi 制御応答(:96)は 2048 のスタックのまま。srvrun.h:449 の古い「4096 bytes」表記を実値(`SRVRUN_WTSEND_BUF` 65536)に直す(doxygen 対象)。観測は既存 `open_dropped`。

### 4. ライブ観測(wired_server.c)
- `on_step(void* ctx, u64 now_ms)`(:352)に static な `next_ms` を持たせ、10 秒毎に `log_relay_stats` を呼ぶ(CCN 2)。`log_relay_stats` に `const char* label` を足し("moqt relay: " / "moqt relay(10s): ")、書式の複製を避ける。
- 追加項目: `sessions=<live>` `closed=<累計>`(`wired_moqt_on_session` にもカウント用ラッパを噛ませる。close 側は既存 `on_session_close` :173)、`rel_wait`。
- 実配備の `docker logs` だけで「拒否が続いているか」「セッションが落ちているか」が分かる。

### 5. e2e 再現(RTT 注入)
s15 の私製 `joinClient` を `e2e/lib/stabilityClient.mjs` の `joinStabilityClient` に置換(`serverUrl` を localStorage prefs で seed し、`WT_INSTRUMENTATION_SCRIPT` で `window.__wtEvents[].closedAt` を記録済み)。`--jitter-ms`/`--loss-rate` を parse し `startUdpProxy({listenBase: 25433, upstreamPort: 4433, flowCount: 2, profile: {lossRate, seed: 1, jitterBaseMs}})`、各クライアントは `https://127.0.0.1:${proxy.port(i)}/`、`finally` で `proxy.close()`。ケース毎に `__wtEvents.every(e => !e.closedAt)` と `[data-testid="status"]` の `data-status === "connected"` を assert、`elapsedMs` を report に記録。
- **RED の主根拠は srvrun 単体テスト**(§1)。e2e の RED は best-effort: Chrome 146 が WT_MAX_DATA capsule を送る直接証拠は repo に無い(間接: 1894c633 の動機、実配備の flow 拒否は `max_data != 0` を要する、localhost e2e では `wtsend_flow=0`(tasks/call-quality-ledger.md:67))。`--large-bytes=2000000 --jitter-ms=100` で修正前に FAIL しなければ、`--qlog` の metrics `wtsend_flow` を記録して「再現せず(初期 credit が転送を上回る)」と明記し、修正後は GREEN のみを回帰として残す。

## 検証する性質
- セッション credit(max_data/sent_data)× staging × drain の相互作用は、信頼中継に単調な待ち条件を 1 つ足すだけ(修正 1 は「閉じない」だけ)。前回成り立ちを固めた性質(各購読者が受け取る列は連続 prefix で欠落・重複・順序崩れ無し / fin は全バイト送信後のみ / 受理が eventually 起きる購読者には全バイト+fin が届く / 全購読者が drain すれば hold は eventually 解除)はそのまま保たれる。これ以上の保証は不要(YAGNI)。
- TDD: §1 srvrun_test(反転 4 + 再開 1)、§2 moqtrun_test(budget 3 本 + credit 枯渇 shed 1 本)、§5 e2e(s15 に RTT 注入、RED→GREEN)。

### 追加で確定した事実(example/e2e 側)
- `wired_server_wt_open_uni_stream` / `wired_server_wt_open_uni` は payload ≤ `SRVRUN_WTSEND_BUF`(65536)を送信スロットにコピー(srvrun.h:444-450、:481-489。doc の「4096」は古い、実値は srvrun.c:290)。→ `MOQT_SIG_BUF` を 2048 から「signal(≤9)+ `WIRED_MOQTRUN_RELAY_FRAG_MAX`(512)+ `WIRED_SRVLOOP_WT_BUF_CAP`(49152)」以上にすれば、:164 `moqt_io_send_uni`(one-shot、最大 ~49664)と :186 `moqt_io_open_uni_stream`(keep-open open、同上)の両方が救える。単一プロセス・同期呼び出しなのでスタックでなく static 1 本でよい(スタック 50KB を避ける)。:97 の bidi(制御応答、数十 B)は現状維持。
- s15 への RTT 注入: s13 と同じく `startUdpProxy({listenBase, upstreamPort: 4433, flowCount: 2, profile: {lossRate, seed, jitterBaseMs}})`(s13:81-86、udpProxy.mjs:45-65)、クライアントは `https://127.0.0.1:${proxy.port(i)}/` を `data-testid="url"` に入力(s15 は現状 certHash のみ入力、:32)。`runCase`(:177-210)に `elapsedMs` を追加。切断検出は `stabilityClient.mjs:34,132-146` の `WT_INSTRUMENTATION_SCRIPT`(`window.__wtEvents[].closedAt`)を `evaluateOnNewDocument` で注入して assert、UI 側は `[data-testid="status"]` の `data-status` が `connected` のままを assert。

## タスク

順序: Task 1 → (Task 2 ∥ Task 3、別ファイル群) → Task 4 → Task 5 → Task 6。`tests/run.c` 変更は無し(新ファイル無し)。git は直列。

### Task 1: e2e 再現(RED の記録、修正前)
`examples/moqt_chat/e2e/scenarios/s15-image-send.mjs`: §5 のとおり(`joinStabilityClient` に置換、`--jitter-ms`/`--loss-rate`、proxy、`elapsedMs`、close 無し + status badge の assert)。修正前 main で `just e2e-stability s15-image-send --large-bytes=2000000 --jitter-ms=100` を実行し結果を記録(期待: FAIL、`__wtEvents` に close)。再現しなければ `--qlog` の `wtsend_flow` を添えて「再現せず」と記録(RED の主根拠は Task 2 の単体テスト)。既定引数(jitter 0)では従来どおり直結と同等の挙動(proxy 経由でも可)で既存 s15 が PASS すること。

### Task 2: srvrun — 自分の送信拒否でセッションを閉じない(root cause)
§1 のとおり。`src/app/http3/server/srvrun/srvrun.c`(latch 行削除、機構削除、doc アンカー 5 箇所)、`src/app/http3/server/srvrun/srvrun.h`(:449 の「4096」を実値に)、`tests/app/srvrun_test.c`(反転 4、CHECK 削除 3、機構テスト 2 + runner 登録削除、新規 1)。grep ゲート空。三点ゲート + `just docs`。

### Task 3: hub — drain に session credit の余裕(`send_budget`)
§2 のとおり。`src/app/moqt/run/moqtrun.h`(io 末尾 `send_budget` + doc、`stat_rel_wait` + doc)、`src/app/moqt/run/moqtrel.h`(`WIRED_MOQTREL_HEADROOM` + doc)、`src/app/moqt/run/moqtrun.c`(`moqtrun_rel_budget_ok`/`_budget_wait`/`_send_span` 分割)、`tests/app/moqtrun_test.c`(fake io `send_budget` + テスト 4 本)。CCN ≤ 3、既存テスト無変更緑。

### Task 4: wired_server.c — open の 2048B 上限撤廃 + ライブ観測 + 配線
§3・§4 のとおり。`examples/moqt_chat/wired_server.c`: `MOQT_OPEN_BUF` + `static u8 g_open_buf[]`(:163/:185)、`g_moqt_io` 末尾に `moqt_io_send_budget`、`on_step` 10 秒タイマー、`log_relay_stats(label)`、`sessions=/closed=/rel_wait=`、`wired_moqt_on_session` のカウント用ラッパ。`ninja examples/moqt_chat/wired_server` + boot smoke(`--port 14433`、SIGTERM、10 秒行と shutdown 行が出る)。

### Task 5: 三点ゲート・e2e GREEN・回帰
`just test`(単一 TU)、`just ninja` + count、`lizard src --CCN 3 -w`、`just docs`、`just fmt-check`/`just lint`、`just fuzz-smoke`(io テーブル拡張は fuzz ハーネスに影響しうる)。e2e(docker 停止 → 実行 → `docker start`): s15 `--large-bytes=2000000 --jitter-ms=100` PASS(close 無し、`open_dropped=0 rel_stall=0 rel_overflow=0`)、s15 既定 / `--large-bytes=5000000` PASS、s13 `--clients=2 --talk-ms=30000` PASS、s2-chat-longevity / s8-late-join PASS。

### Task 6: 仕上げ
micro-commit(C 側 / e2e 側は別系列)、main へ merge → push → CI 見届け、`tasks/todo-moqt-reliable-relay.md` に追記(epoch 継続)、`tasks/lessons.md` に「送信側の flow 拒否を違反として自セッションを閉じていた / localhost e2e は credit 遅延を隠す(RTT 注入を標準化)」を追記。実配備は `just up-bg` で再ビルドし、ユーザーに再試験を依頼(10 秒統計行で `closed=` が増えないことを確認)。

## 検証(全体)
1. srvrun_test: 反転 4 + 新規 1 が緑、close 機構のコード/テストが消えている(`grep -n wt_flow_violation src tests` が空)。
2. moqtrun_test: budget 3 本緑、既存 105+ 本無変更緑。
3. e2e: Task 1 の RED(修正前)と Task 5 の GREEN(修正後)が同じコマンドで対になっている。`server.log` に `closed=0`(10 秒行)/`open_dropped=0 rel_stall=0 rel_overflow=0`。
4. 三点ゲート + docs + fmt/lint + fuzz-smoke + CI 4 本 success。
5. `examples/moqt_chat/frontend/` 無変更。

## 対象外
- 受信側 WT セッション flow 制御(サーバが上限を advertise していない以上、今は不要)。
- late-join 購読者への添付再送、lossy 経路の設計変更、フロント変更。
