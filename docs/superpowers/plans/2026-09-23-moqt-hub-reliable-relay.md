# MoQT hub: chat track の keep-open 中継を「捨てない」信頼配送にする(添付の大容量送信)

Spec(上位の権威): このファイルの「設計」節。

## Context

moqt_chat の複数添付機能(main 済み)は、1添付を「480→448B チャンク × N オブジェクト」で送る。前回の修正(`bfd131d2`)で「チャンクごとに uni ストリーム」を「1添付=1ストリーム(keep-open)」に変えて 20KB/50KB は通るようになったが、200KB・2MB は届かない。ユーザー体感「画像1枚 20〜30 秒」の根本原因は **hub(`src/app/moqt/run/moqtrun.c`)の keep-open 中継がライブ音声向け設計で、バルク転送を想定していない**こと。実測(`tasks/voice-stability/s15-image-send/server.log`):

| サイズ | 結果 | hub 統計 | 原因(コード) |
|---|---|---|---|
| 20KB / 50KB | PASS | `sent=42 dropped=0` | — |
| 200KB | FAIL(2回とも) | `sent=0` | 最初の配送がヘッダ+途中 Object で終わると `moqtrun_decode_fresh_subgroup`(moqtrun.c:1376-1382)が 0 を返し捨てる。以後の配送はヘッダ無しなので永久に捨てられる |
| 2MB | FAIL | `sent=1740 dropped=8 reset=1` | `moqtrun_relay_forward_one`(1102-1121): 購読者ストリームの前ラウンドが未ACK(`stream_send` が拒否)なら**そのラウンドを捨てる**。8連続で `moqtrun_relay_shed_one` が RESET |

ユーザー承認済みの方針: **A = hub に背圧を入れる**(src/ を変更、chat track の中継は捨てずに待つ。5MB まで回線速度で送れる真の解)。B(クライアント側の並列 one-shot、ヒューリスティック)と C(送信前縮小)は却下。

## 調査で確定した前提(file:line)

- 受信側 credit: `srvrun_grant_stream_credit`(srvrun.c:2420-2431)が毎 step、`wt_slot_credit_ceiling(delivered_len) = delivered_len + WIRED_SRVLOOP_WT_BUF_CAP(49152)` を advertise。アプリから止める手段は無い。呼び出しは 2815/2817(bidi/uni の各 slot)。slot 構造体 `wired_srvloop_wt_stream_slot` / `wired_srvloop_wt_uni_stream_slot`(srvloop.h:290-312, 366-378)に `credit_advertised` がある。
- 送信側: `wired_server_wt_stream_send`(srvrun.c:4357-4374)は **1ストリームにつき1ラウンドだけ in flight**(前ラウンド未ACKなら `srvrun_wtsend_accept_round` が拒否)。payload ≤4096 はコピー、それ超は VIEW(ACK まで caller が保持)。送信スロットはコネクションあたり `WIRED_SRVLOOP_MAX_STREAMS`=40。ACK/スロット解放のコールバックは無い。
- hub の入口 `wired_moqt_on_stream_data`(moqtrun.c:1444-1459)は `void` で即時消費。`wired_moqt_tick(hub, now_ms)`(934-940)は `on_step` から呼ばれ、**イベントごと+最低 25ms 周期**(srvrun.h:292-299)。
- keep-open 中継: `moqtrun_relay_start`(1293-1322, fin 無しの fresh stream)→ `moqtrun_relay_open_all`(open_uni_stream、失敗は `stat_open_drop`)→ 以後 `moqtrun_relay_continue`(1231-1243)→ `moqtrun_relay_normalize`(Object 境界で切り、端数 ≤512B を `frag` に保持)→ `moqtrun_relay_append_all/one`(1156-1181)→ `moqtrun_relay_forward_one`。fin は `stream_fin`/`stream_send(fin)` で伝播、relay entry は fin で解放。
- 相手ごとの one-shot 経路(`moqtrun_relay_object`、fin 付き1ラウンド)は `moqt_io_send_uni` のスタック 2048B が上限(wired_server.c:157-163)。**チャンクは ≤512B/Object を維持**(前回コミット `5f1e46f5` で 448B に固定済み)。
- io テーブル `wired_moqt_io`(moqtrun.h:40-56)は関数ポインタの位置指定初期化。末尾追加なら既存初期化子は壊れない(`send_datagram != 0` ガードの前例 moqtrun.c:1466-1468)。
- track 名: chat=`<id>`、voice=`<id>/audio`、screen=`<id>/screen`。alias は client が PUBLISH で宣言(chat 0..3、voice/screen はそれ以上)。hub 側 `wired_moqtrun_track.own_alias`(moqtrun.h:224)で判別可能。
- 容量: `WIRED_MOQTRUN_MAX_SESSIONS`=32、`MAX_SUBS`=31、`MAX_RELAYS`=4/track、`MAX_TRACKS_PER_PEER`=3。
- テスト: `tests/app/moqtrun_test.c`(3501行)は fake io(`moqtrun_test_stream_send` が `g_stream_send_reject_n`/`_sess` で拒否を注入、`moqtrun_test_record` で送信を記録)。`tests/app/srvrun_test.c` は credit を `stream_credit` で扱う。unity build(`tests/run.c`)に `#include "app/moqt/run/moqtrun.c"`(557行目)。

## 設計(Spec)

### 1. 発行者への背圧: 受信 credit の hold(srvrun)
- slot 構造体に `int credit_hold` を追加(bidi/uni 両方)。`srvrun_grant_stream_credit` の呼び出し側(`srvrun_grant_wt_slot_credit`/`_uni_`)は `credit_hold` なら advertise を**上げない**(advertise は減らせない: RFC 9000 19.10。上げるのを止めるだけ)。
- 公開 API(srvrun.h): `int wired_server_wt_stream_hold(wired_wt_session* s, u64 stream_id, int hold)` — s のコネクションの受信 slot(bidi/uni どちらでも)を stream_id で探し `credit_hold=hold`。1=適用、負=slot 無し。ループ内(コールバック)からのみ呼べる契約は他の `wired_server_wt_*` と同じ。
- 効果: hold 後に発行者が送れるのは advertise 済み残り ≤ `WT_BUF_CAP`(49152)。**hub はこの分を必ず吸収できるサイズの待ち行列を持つ**(下記 2)。

### 2. hub の信頼中継モード(新モジュール `src/app/moqt/run/moqtrel.{h,c}`、prefix `moqtrel_`)
対象: `track->own_alias < hub->reliable_alias_limit` の track(既定 0 = 無効 → 他利用者の挙動不変。moqt_chat の server は 4 を設定)。voice/screen(alias ≥ 4)は**現行の捨てる/RESET 経路のまま**。

状態(hub 全体でプール、`WIRED_MOQTREL_POOL`=4 本、1本 `WIRED_MOQTREL_CAP = 3 * WIRED_SRVLOOP_WT_BUF_CAP`=147456B、静的 576KB):
- `moqtrel_buf`: バイトリング `buf[CAP]`、`head`(reclaim 済み絶対オフセット)、`tail`(書込済み絶対オフセット)、`fin_seen`、`held`(発行者 credit hold 中)、発行者 `(wt, stream_id)`(hold/release 用)。
- 購読者ごと(`WIRED_MOQTRUN_MAX_SUBS`): `sent`(次に送る絶対オフセット)、`inflight_from`(前回受理ラウンドの先頭。`sent` との差が in-flight)、`fin_done`、`last_ok_ms`(最後に `stream_send` が受理された時刻、stall 判定)。
- relay entry(`wired_moqtrun_relay`)に `i32 rel_idx`(-1 = lossy)。

遷移(すべて既存の `moqtrun_relay_*` から分岐、reliable でなければ従来どおり):
- **start**(fresh stream, fin=0, reliable track): プールから1本確保(無ければ `stat_relay_full++` して従来 lossy にフォールバック)。ヘッダ〜whole_end を ring へ append(端数は従来の `frag`)。購読者ストリームは従来どおり `open_uni_stream(header + whole)` で開く。開けた購読者の `sent = tail`, `inflight_from = 0`。
- **continue**(以降の配送): `normalize` した whole を ring へ **append**(捨てない)。append 後 `free < 2*WT_BUF_CAP` なら `io.stream_hold(pub, 1)`, `held=1`。fin は `fin_seen=1`。その後 **drain**。
- **drain**(配送直後と `wired_moqt_tick` の毎回): 各 active sub で `sent < tail` なら、`[sent, min(tail, sent+ROUND_MAX, リング終端))` を `stream_send(view)` する(`WIRED_MOQTREL_ROUND_MAX`=16384。≤4096 はコピー、それ超は VIEW: リング上のバイトは `head` より下でしか再利用しないので ACK まで不動)。受理(=前ラウンド完了の証)なら `inflight_from = sent(旧)`, `sent += n`, `last_ok_ms = now`。拒否なら何もしない(次の tick で再試行、捨てない)。`fin_seen && sent == tail && !fin_done` なら最後のラウンドに fin=1(バイト無しなら `stream_fin`)。受理で `fin_done=1`。
- **reclaim**: `head = min(inflight_from)`(active な sub のうち)。`held && used <= WT_BUF_CAP/2` なら `io.stream_hold(pub, 0)`, `held=0`。
- **stall shed**: `now - last_ok_ms > WIRED_MOQTREL_STALL_MS`(10000)かつ `sent < tail` の sub は従来の `stream_reset` で捨て、`sent = tail`, `fin_done=1`(その sub だけ諦める。他は進む、発行者は止まらない)。
- **sub 離脱**(`on_session_close` 経由で `subs[i].active=0`): reclaim 対象から外れるだけ。
- **発行者離脱**: relay entry と一緒にプール返却。hold は接続ごと消えるので不要。
- **終了**: 全 active sub が `fin_done` → プール返却、relay entry 解放。
- **late open**(中継開始後の購読者): 従来どおりヘッダで開き `sent = tail`(途中からで、その添付は不完全。現状と同じ制約、docs に明記)。
- 統計: `stat_rel_stall`(shed 数)、`stat_rel_overflow`(設計上 0。0 でなければ不変条件違反 = バグ検出用)。

### 3. fresh stream の torn first Object 修正(moqtrun)
`moqtrun_decode_fresh_subgroup` は「ヘッダ+完結 Object 0 個」を **fin=0 なら受理**(whole_end = ヘッダ末尾、端数は frag へ)。fin=1(one-shot)で 0 個は従来どおり捨てる。reliable/lossy 両方に効く(200KB `sent=0` の直接原因)。

### 4. 配線(wired_server.c)
- `g_moqt_io` 末尾に `moqt_io_stream_hold`(= `wired_server_wt_stream_hold`)。
- `wired_moqt_init` 後に `g_hub.reliable_alias_limit = CHAT_ALIAS_LIMIT`(4、コメントで `moqtClient.ts` の `CANDIDATE_PARTICIPANT_IDS` と対応させる)。
- フロントエンドは変更不要(1添付=1ストリーム、448B チャンクのまま)。

## 検証する性質(実装前に確定)

1. **設計段階で成り立ちを固める性質**(発行者の配送は hold により outstanding ≤ BUF、購読者ごとの send 受理/拒否は非決定、reclaim・fin・sub 離脱・stall shed を含めた全遷移で):
   - リングの使用量は常に容量を超えない(hold の閾値 `2*BUF` の正当性)。
   - 各 sub が受け取る列は ring 内容の連続 prefix(欠落・重複・順序崩れ無し)。
   - fin は全バイト送信後にのみ送られる。
   - VIEW 送信中のバイトは reclaim されない。
   - 受理が eventually 起きる sub には全バイト+fin が届く。
   - 全 sub が drain すれば hold は eventually 解除される。
2. コーデックの可逆性等は今回変更しないので、これ以上の保証は不要。
3. TDD: 上記性質を 1:1 で `tests/app/moqtrun_test.c`(fake io の拒否注入+tick 駆動)と `tests/app/srvrun_test.c`(hold で ceiling が上がらない/解除で再 grant)に落とす。

## リポジトリ規約(Global Constraints)

- libc-free / `src/` は `util/*` と `sys` 以外の標準ヘッダ禁止。**CCN ≤ 3**(`lizard src --CCN 3 -w`)。unity build の名前衝突: 新規 non-static は `moqtrel_` prefix、static/typedef/macro も `moqtrel_`/`MOQTREL_` で grep 確認。
- 三点ゲート: `just test-fast`(push 前に一度 `just test`)/ `just ninja` / `lizard src --CCN 3 -w` + obj==src count。`src/**/*.h` の doc コメントを触るので **`just docs`(doxygen WARN_AS_ERROR)も必須**。fmt/lint は nix pin(`just fmt-check`/`just lint`、サンドボックスで無理なら push 後の CI を見届ける)。
- 新ファイル `moqtrel.c` は `tests/run.c` に手で `#include`(production ブロック)、count check。
- 並列: 実装は別ファイルで並列可、`tests/run.c`・git は1人が直列。コミットは conventional micro-commit、C 側/TS 側は別系列(今回 TS 無し)。
- `tasks/todo.md` を新 epoch に使う前に `todo-<epoch>-done.md` へ退避(tasks-ledger.md)。

## タスク

### Task 1: 設計の検証
上記「設計」§2 の状態と遷移を小さな構成(Subs=2, CAP=6, BUF=2, ROUND=2, Bytes=8 程度)で網羅的に確かめ、「検証する性質」の各項目が全遷移で成り立つことを固める。成果: C テストリスト(各性質→テスト名)。

### Task 2: srvrun 受信 credit hold
`src/app/http3/server/srvloop/srvloop.h` の両 slot に `int credit_hold`(claim 時 0 初期化: srvloop.c:58/78/472/565 と同じ箇所)。`srvrun.c` の `srvrun_grant_wt_slot_credit`/`_uni_slot_credit` で `credit_hold` なら return。`srvrun.h` に `wired_server_wt_stream_hold` 宣言+doc(doxygen 形式は隣の `wired_server_wt_stream_fin` に揃える)、`srvrun.c` に実装(slot 検索は `wt_uni_streams[i].stream_id`/`wt_streams[i].stream_id` を走査、CCN 内で bidi/uni を helper 分割)。テスト(`tests/app/srvrun_test.c`): hold 中は delivered が進んでも MAX_STREAM_DATA が出ない / hold 解除の次 step で出る / 未知 stream は負。

### Task 3: fresh stream の torn first Object 受理(moqtrun)
`moqtrun_decode_fresh_subgroup` を「ヘッダ OK なら Object 0 個でも track を返す(whole_end=ヘッダ末尾)」に変え、`moqtrun_dispatch_fresh_stream` で `fin && whole_end==ヘッダ末尾` は従来どおり破棄。テスト: (a) 1回目=ヘッダ+Object 前半(fin=0)→ open が起き frag 保持、2回目=後半+次 Object → 2 Object 分が中継される、(b) fin=1 で 0 個 → 何も送らない(既存挙動)。

### Task 4: `moqtrel` モジュール(新規 `src/app/moqt/run/moqtrel.{h,c}`)
純粋なリング+カーソル管理と drain 判断を、io を関数ポインタで受ける形で実装(hub 構造体に依存しすぎない: `moqtrel_buf`、`moqtrel_append`, `moqtrel_next_round(sub) -> span`, `moqtrel_note_sent/refused`, `moqtrel_reclaim`, `moqtrel_should_hold/release`, `moqtrel_stalled(now)`)。CCN ≤3 で小関数分割。単体テスト `tests/app/moqtrel_test.c`(Task 1 のテストリストのうち ring/カーソル/watermark/wrap-around の性質)。unity 配線は Task 6。

### Task 5: moqtrun への統合
`wired_moqt_hub` に `u64 reliable_alias_limit`(init で 0)、`moqtrel_buf pool[WIRED_MOQTREL_POOL]`、`stat_rel_stall/overflow`。`wired_moqt_io` 末尾に `int (*stream_hold)(wired_wt_session*, u64, int)`(0 ガード)。`moqtrun_relay_start/continue/append_one/forward_one` に reliable 分岐、`wired_moqt_tick` に drain+stall、`on_session_close`/relay 解放でプール返却。テスト(`tests/app/moqtrun_test.c`、Task 1 の残りの性質): 拒否→tick で再送され全バイト順序どおり / watermark で `stream_hold(1)`→drain 後 `(0)` / fin は最後 / 速度差のある 2 sub / sub 離脱で reclaim 進む / stall shed / `reliable_alias_limit=0` なら既存テスト全緑(lossy 不変)。fake io に `stream_hold` 記録を追加。

### Task 6: 配線+三点ゲート(integrator、直列)
`tests/run.c` に `moqtrel.c`/`moqtrel_test.c`/`test_moqtrel()` を追加(grep で着地確認)、count check、`just test`(単一 TU で衝突検出)、`just ninja`、`lizard src --CCN 3 -w`、`just docs`。`wired_server.c` の配線(§4)と `ninja examples/moqt_chat/wired_server` + boot smoke。micro-commit で C 側を連続コミット。

### Task 7: e2e と実測
docker の `moqt_chat-wired_server-1` を止めてから(ポート 4433)`just e2e-stability s15-image-send` を既定 / `--large-bytes=200000` / `--large-bytes=2000000` / `--large-bytes=5000000` で実行し全ケース PASS、`server.log` の `dropped=0 reset=0`、2MB/5MB の所要時間を記録。回帰: s1-voice-clean / s13-screen-longrun / s14-screen-rejoin / s2-chat-longevity / s8-late-join が PASS(voice/screen の lossy 経路不変)。終了後 `docker start`。

### Task 8: 台帳・仕上げ(controller)
`tasks/todo.md` を退避→新 epoch、`tasks/lessons.md` に「hub の中継は drop 設計だった/事前調査で見落とした」を追記。main へ merge → push → CI(Examples/CI/Docs)を見届け。

## 検証(全体)
1. 三点ゲート+count+`just docs` 緑、`just test`(単一 TU)緑。
2. moqtrun/moqtrel/srvrun の新テストが Task 1 の性質と 1:1 で存在し緑。
3. s15: 20KB/200KB/2MB/5MB PASS、`dropped=0 reset=0 frag_dropped=0`。2MB の受信完了が 30 秒を大きく下回る(目標: localhost で数秒以内)。
4. voice/screen の e2e 5 本 PASS。
5. `git diff --stat` で `examples/moqt_chat/frontend/` に変更が無い(フロント無変更)。

## 対象外
- 途中参加者へのバッファ済み添付の再送(late open は従来どおり)。
- 購読者ごとの再送要求(NACK)や MoQT レベルの FETCH。
- voice/screen(lossy)経路の変更。
- クライアント側のチャンクサイズ変更(448B/≤512B Object を維持)。
