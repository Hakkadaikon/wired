# MoQT 画面共有(ウインドウ / 画面全体)実装計画

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** `examples/moqt_chat` の各参加者が `getDisplayMedia`(ウインドウ / 画面全体、ブラウザ標準ピッカー)で自分の画面を配信し、他の全参加者がタイルで見られるようにする。チャット・音声と同じ hub 中継(バイト透過リレー)に乗せる。

**Architecture:** ブラウザ側で VP8 (WebCodecs `VideoEncoder`) にエンコードし、各 `EncodedVideoChunk` を ≤480B の MoQT Object に分割して alias 10..13 の長寿命 uni ストリームで送る(音声 `MoqtVoiceClient` と同形)。C 側のリレー本体(`moqtrun`)はトラック非依存なので無変更。`SRVRUN_WTSEND_BUF` と `WIRED_MOQTRUN_MAX_TRACKS_PER_PEER` の 2 定数だけ変更する。受信側は送信者ごとに再構成器 → `VideoDecoder` → `<canvas>` タイル。

**Tech Stack:** libc-free C(このリポジトリの制約)、TypeScript/Next.js + vitest、WebCodecs/WebTransport(素の DOM API、DI でテスト)、puppeteer e2e。

**Spec:** 本 plan がそのまま spec を兼ねる(直前の brainstorming/plan mode で承認済み)。

## Global Constraints

- `src/` は libc-free: `sys/syscall.h` の型と `util/*.h`(`util/bytes.h`, `util/be.h`, `util/ct.h`, `util/num.h`)のみ。標準ヘッダ禁止。
- `src/` の全関数 CCN ≤ 3(`lizard src --CCN 3 -w` が exit 0)。`&&`, `||`, `?:`, `if`, `for`, `while` は各 +1。
- `tests/run.c` は単一 TU: 新規の non-static / static シンボル名はすべて `grep -rn '<name>' src/ tests/` で一意なことを確認してから追加。
- 新規公開ヘッダメンバ・マクロ・関数には doc comment(`/** */`)必須。
- 内部 API は module token を prefix にする(`moqtrun_*`, `srvrun_*`)。application-facing API は `wired_*`。
- コミットゲート(毎コミット): `just test-fast` が "all tests passed" を出力 AND `just ninja` が exit 0 AND `lizard src --CCN 3 -w` が exit 0、`if A && B && C; then git commit; fi` の形で実行(`| tail && commit` 禁止)。push 前は `just test`、`just fmt-check`、`just docs`、`just lint`、`just fuzz-smoke`(すべて `nix develop` 経由)。
- 並列ワーカーは自分の新規ファイルのみ編集。`git add`/`commit`/`push` 禁止、`tests/run.c`・`examples/moqt_chat/justfile` 編集禁止。integrator(Task 8)のみが wiring とコミットを行う。
- コミットの末尾トレーラー(毎コミット):
  ```
  Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
  Claude-Session: https://claude.ai/code/session_01MUGHRYWD7RZSxw8p3C7GP1
  ```
- alias: chat 0..3, audio 4..7, movie 8, movie/init 9, **screen 10..13**(`3N` オフセット、N=4)。
- チャンクヘッダ codec: `seq u16 | idx u16 | count u16 | flags u8 (bit0=keyframe) | ts u32 (µs)`。キーフレームの idx=0 にだけ続けて `width u16 | height u16 | codec len u8 + bytes`。Object payload ≤ 480 B。
- vp8、`latencyMode: "realtime"`、bitrate ≈ 1 Mbps、2 秒ごとに `encode(frame, {keyFrame:true})` で強制キーフレーム。
- 受信側は「欠けた idx があればフレーム全体を破棄」。キーフレームが揃うまで decoder には渡さない(WaitKey → Decoding の状態機械。decode error は WaitKey へ戻る)。

## Parallelism

Wave 0(直列・最初): Task 1。
Wave 1(並列、Task 1 の後): Task 2, Task 3。
Wave 2(並列、Task 4 単体・Task 4 完了後に Wave 3 着手可): Task 4。
Wave 3(並列、Task 4 の後): Task 5, Task 6。
Wave 4(直列、Task 5+6 の後): Task 7。
Wave 5(直列、integrator): Task 8(ビルドゲート)、Task 9(e2e)。

---

### Task 1: `WIRED_MOQTRUN_MAX_TRACKS_PER_PEER` 2→3

**Files:**
- Modify: `src/app/moqt/run/moqtrun.h`(line 180 の define、line 179/191 の doc comment)
- Modify: `tests/app/moqtrun_test.c`(`test_moqtrun_third_publish_gets_error` を `test_moqtrun_fourth_publish_gets_error` へ改名し、3 本目の成功 PUBLISH を追加してから 4 本目で失敗することを検証)

**Interfaces:**
- 変更後、1 peer あたり chat + audio + screen の 3 トラックを PUBLISH できる。4 本目は既存のエラー経路のまま。

- [ ] **Step 1: テストを先に赤くする**
  `test_moqtrun_third_publish_gets_error` を `test_moqtrun_fourth_publish_gets_error` に改名し、2 本目までの PUBLISH 成功アサーションの後に 3 本目の成功 PUBLISH を追加、4 本目の PUBLISH がエラーになることをアサート。`WIRED_MOQTRUN_MAX_TRACKS_PER_PEER` はまだ 2 のまま実行し、3 本目の成功アサーションが失敗することを確認する(Red)。
- [ ] **Step 2: 定数変更**
  `moqtrun.h` の `WIRED_MOQTRUN_MAX_TRACKS_PER_PEER` を `2` → `3` に変更。隣接する doc comment(peer あたりのトラック数を説明している行)も 3 に合わせて更新。
- [ ] **Step 3: Green 確認**
  `just test-fast` で "all tests passed"、`lizard src --CCN 3 -w` で exit 0 を確認。

---

### Task 2: `SRVRUN_WTSEND_BUF` 4096→65536

**Files:**
- Modify: `src/app/http3/server/srvrun/srvrun.c`(line 286 の define + doc comment)
- Create or modify: `tests/app/srvrun_test.c`(なければ新設し `tests/run.c` への追加は Task 8 の integrator に委ねる — このタスクではテストファイルを作るだけで `tests/run.c` は触らない)

**Interfaces:**
- `SRVRUN_WTSEND_BUF` が 65536 になることで、49664 B(受信窓 49152 + 保持断片 512)を超えるペイロードでも `srvrun_wtsend_arm_id` が copy 経路(view_round にならない)を取れる。

- [ ] **Step 1: テストを先に赤くする**
  新規ユニットテストで、`SRVRUN_WTSEND_BUF` に収まらないサイズ(約 50000 B)のペイロードを `srvrun_wtsend_arm_id` に渡し、`view_round` にならず copy されることをアサートする。定数が 4096 のままでは失敗することを確認(Red)。テスト関数名は `grep -rn` で `tests/` 配下との重複がないことを確認してから追加すること。
- [ ] **Step 2: 定数変更**
  `SRVRUN_WTSEND_BUF` を `4096` → `65536` に変更。doc comment にサイズ根拠(受信窓 49152 + 保持断片 512 を超える必要がある旨)を1行で残す。
- [ ] **Step 3: Green 確認**
  `just test-fast`(このテストファイルを一時的に `tests/run.c` に足さずに単体コンパイルで確認できない場合は、Task 8 の integrator wiring 後に最終確認でよい旨を report に明記)。

---

### Task 3: C リレー本体は無変更、テストのみ追加

**Files:**
- Modify: `tests/app/moqtrun_test.c`

**Interfaces:**
- 既存の `test_moqtrun_peer_publishes_two_tracks`(line 840 付近)を 3 トラック版に拡張、または並置する新規テストを追加。
- 既存の音声長寿命リレー継続テスト(`relays[0]` 周り、line 1770 近辺)を "screen" という名前のトラックで複製し、`WIRED_MOQTRUN_MAX_RELAYS` がトラックごとに独立した枠を持つこと(音声と画面共有が競合しないこと)を検証する。

- [ ] **Step 1: 3 トラック PUBLISH テスト**
  `test_moqtrun_peer_publishes_two_tracks` を参考に、chat + audio + screen の 3 トラックを 1 peer が PUBLISH できることを検証するテストを追加(関数名は `grep -rn` で一意性確認)。
- [ ] **Step 2: screen トラックの長寿命リレーテスト**
  音声の長寿命リレー継続テストを "screen" トラック名で複製し、`relays[]` がトラックごとに独立していることを確認。
- [ ] **Step 3: Green 確認**
  `just test-fast` で "all tests passed"。

---

### Task 4: `moqtScreenWire.ts`(純粋なチャンク符号化、pure TS)

**Files:**
- Create: `frontend/src/lib/moqtScreenWire.ts`
- Create: `frontend/src/lib/__tests__/moqtScreenWire.test.ts`

**Interfaces:**
- `buildScreenSubgroupHeader()`: `buildVoiceSubgroupHeader`(既存)を模倣し SUBGROUP_HEADER 0x70 を組み立てる。
- チャンクヘッダ codec: `seq u16 | idx u16 | count u16 | flags u8 (bit0=keyframe) | ts u32 (µs)`。キーフレームの idx=0 にだけ `width u16 | height u16 | codec len u8 + bytes` を続ける。
- `encodeScreenObjectMessage(...)`: 1 チャンクを MoQT Object(ID delta 0)にエンコード。
- `decodeScreenObjectMessage(...)`: 上記の逆関数。
- フレーム再構成関数(`drainVoiceObjectStream` の形を踏襲): `seq` ごとに idx を集め、`count` 揃ったときだけ完全なフレームを返す。**欠けた idx が 1 つでもあればそのフレーム全体を破棄**(音声の欠落許容とは異なる仕様)。

- [ ] **Step 1: golden round-trip テストを先に書く**
  固定バイト列 → decode → 各フィールドが期待値と一致、および encode(decode(bytes)) == bytes のラウンドトリップをアサート(Red: 実装前なので落ちる)。
- [ ] **Step 2: 欠落チャンクの破棄テストを先に書く**
  3 チャンク中 1 個(idx=1)を与えずに再構成関数へ流し、フレームが一切出力されないことをアサート(Red)。
- [ ] **Step 3: 実装**
  `buildScreenSubgroupHeader`, `encodeScreenObjectMessage`, `decodeScreenObjectMessage`, 再構成関数を実装し Step 1/2 を Green にする。
- [ ] **Step 4: 検証**
  `pnpm vitest run moqtScreenWire` が全件 Green。

---

### Task 5: `moqtScreenClient.ts`(ネットワーク結線)

**Files:**
- Create: `frontend/src/lib/moqtScreenClient.ts`
- Modify: `frontend/src/lib/useMoqtChat.ts`(`onUnknownUniStream` に screen alias 範囲チェックを追加)

**Interfaces:**
- `publishScreenTrack()`: alias `<id>/screen`(index+10)を PUBLISH。
- `subscribeToScreenTrack(id)`: 1 秒リトライループへの追加(既存の chat/audio ポーリングと同じ形)。
- `sendVideoChunk(bytes)`: `sendOpusFrame` と同じ 1 writer・長寿命ストリームで送信(`sendGate` を再利用)。
- `handleIncomingStream(...)`: 受信 uni ストリームのエントリポイント。
- `onUnknownUniStream` の判定順序: movie チェックの後、voice の無条件 `reader.cancel()` フォールバックより**前**に screen alias 範囲(10..13)チェックを挿入する。順序を誤ると画面共有ストリームが voice に食われて cancel される。
- `ownScreenTrackAlias(id)` 等、alias 算術は純粋関数として切り出し単体テスト可能にする。

- [ ] **Step 1: alias 算術の単体テストを先に書く**
  `ownScreenTrackAlias`(index+10 のオフセット計算)を純粋関数として設計し、境界値(id=0..3)のテストを先に書く(Red)。
- [ ] **Step 2: 実装**
  `moqtScreenClient.ts` を `MoqtVoiceClient` の形を模倣して実装。Task 4 の `moqtScreenWire.ts` を利用する。
- [ ] **Step 3: `useMoqtChat.ts` への結線**
  `onUnknownUniStream` に screen alias チェックを追加(movie の後、voice フォールバックの前)。
- [ ] **Step 4: 検証**
  `pnpm vitest run moqtScreenClient` が全件 Green。

---

### Task 6: `screenSharePipeline.ts`(WebCodecs キャプチャ)

**Files:**
- Create: `frontend/src/lib/screenSharePipeline.ts`
- Create: `frontend/src/lib/__tests__/screenSharePipeline.test.ts`

**Interfaces:**
- `micPipeline.ts` と同じ DI 形: `getDisplayMedia`, `VideoEncoderCtor` を注入可能にする。
- `getDisplayMedia({ video: { width: 1280, height: 720, frameRate: 10 }, audio: false })`。
- `VideoEncoder`(codec vp8、bitrate 1 Mbps、2 秒ごとに `encode(frame, {keyFrame:true})` で強制キーフレーム)。
- `output` コールバックで `chunk.copyTo` → ≤480B 分割 → 既存 `sendGate.ts` を再利用(新しい gate は作らない)。
- ブラウザの「共有を停止」でトラックが `ended` → エンコーダ停止 → ストリーム FIN。

- [ ] **Step 1: 偽 VideoEncoder/getDisplayMedia でチャンク数・ヘッダ内容を断言するテストを先に書く**
  DI で注入した偽 `getDisplayMedia`(固定サイズのフレームを返す)と偽 `VideoEncoderCtor`(`output` を同期呼び出しするスタブ)を使い、期待されるチャンク数とヘッダ内容(Task 4 の `moqtScreenWire.ts` の関数を使って decode)をアサート(Red)。
- [ ] **Step 2: 実装**
  `screenSharePipeline.ts` を実装し Step 1 を Green にする。
- [ ] **Step 3: 検証**
  `pnpm vitest run screenSharePipeline` が全件 Green。

---

### Task 7: 受信側再構成 + canvas タイル描画 + UI 結線

**Files:**
- Create: `frontend/src/lib/screenReceivePipeline.ts`(`voiceReceivePipeline.ts` の形、送信者ごと `VideoDecoder` → `drawImage` → `frame.close()`)
- Modify: `frontend/src/lib/useMoqtChat.ts`(`MoqtScreenClient` を chat/voice と独立に結線。画面共有の失敗が chat/voice を巻き込まないこと)
- Modify: `frontend/src/lib/moqtChatStore.ts`(`screenSharing: boolean`, `screenTiles: string[]` を既存の `peers`/`muted` と同じフラットな action パターンで追加)
- Modify: `frontend/src/app/page.tsx`(`ScreenShareToggle` を `MicToggle` と同形で追加、タイル描画を `LivePlayer` の `<video>` ref パターンに倣い `<canvas data-testid="screen-tile-<id>">` で追加)

**Interfaces:**
- `ScreenShareToggle`: `data-testid="screen-toggle"`、Mic と同列にヘッダへ配置。
- `ScreenTiles`: 共有中の送信者ごとに canvas タイル + 名前。自分の共有は小さなプレビュー。
- 受信側状態機械: WaitKey(キーフレーム待ち)→ Decoding。decode error でも WaitKey へ戻る。

- [ ] **Step 1: 状態機械のテストを先に書く**
  `screenReceivePipeline.ts` の WaitKey/Decoding 遷移を、偽 `VideoDecoder`(configure/decode/close をスタブ)で駆動するテストを先に書く: (a) キーフレーム未着時は decode を呼ばない、(b) キーフレーム到着で Decoding へ、(c) decode error で WaitKey に戻る、(d) 以後キーフレームが来れば再度 Decoding へ戻る(Red)。
- [ ] **Step 2: 実装**
  `screenReceivePipeline.ts` を実装し Step 1 を Green にする。
- [ ] **Step 3: UI 結線**
  `useMoqtChat.ts`, `moqtChatStore.ts`, `page.tsx` を編集し、画面共有トグルとタイル描画を結線。画面共有パイプラインのエラーが chat/voice の state に波及しないことをコードレビューで確認できる形にする(try/catch や独立した store slice)。
- [ ] **Step 4: 検証**
  `pnpm vitest run`(フルスイート)、`pnpm tsc --noEmit`。

---

### Task 8: ビルドゲート(integrator)

**Files:**
- Modify: `tests/run.c`(Task 2, Task 3 で新設/変更したテストファイルの `#include` と `test_*()` 呼び出しを追加)
- Modify: `examples/moqt_chat/justfile`(必要なら)

**Interfaces:**
- なし(統合・検証のみ)。

- [ ] **Step 1: wiring**
  Task 2 で新設した `tests/app/srvrun_test.c`(既存なら追記)を `tests/run.c` に `#include` + `test_srvrun();` 呼び出しとして配線。Task 3 で追加したテストが `tests/run.c` 経由で実行されることを確認。
- [ ] **Step 2: count check**
  `[ "$(find src -name '*.c' | wc -l)" = "$(find build/src -name '*.o' | wc -l)" ]` で不一致がないことを確認。
- [ ] **Step 3: 三点ゲート**
  `cd examples/moqt_chat && just build`(SDK ゲート + `ninja examples/moqt_chat/wired_server`)、`just test`(フル)、`lizard src --CCN 3 -w`、`just fmt-check`、`just lint` をすべて実行し Green を確認。
- [ ] **Step 4: コミット**
  ゲートが全て Green のときのみ、`if A && B && C; then git commit; fi` の形でコミット(micro-commit、conventional commit、末尾トレーラー付き)。

---

### Task 9: e2e

**Files:**
- Create: `examples/moqt_chat/e2e/run-screenshare-check.mjs`(`run-live-check.mjs` の 2 ブラウザ構造を踏襲)

**Interfaces:**
- `page.evaluateOnNewDocument` で `navigator.mediaDevices.getDisplayMedia` を `canvas.captureStream()`(オフスクリーン canvas に時刻を描く動画)へ差し替え(headless Chrome の実 getDisplayMedia は不安定なため、`voiceTap.ts` と同じ設置点)。
- 受信側 `window.__wiredScreenTap`(`voiceTap` 形)でフレーム数・サイズを断言。
- 4 参加者 + チャット同時発火のシナリオを流し、`WIRED_SRVLOOP_MAX_WT_UNI_STREAMS 6` が chat+audio+screen 同時開で足りるかを実測する(未確定事項の解消)。

- [ ] **Step 1: e2e スクリプト作成**
  `run-live-check.mjs` を参考に `run-screenshare-check.mjs` を作成。2 ブラウザで画面共有 → 受信側タイルにフレームが描画されることを確認。
- [ ] **Step 2: 負荷シナリオ**
  4 参加者 + チャット同時発火で `WIRED_SRVLOOP_MAX_WT_UNI_STREAMS 6` が不足しないか確認。不足が判明した場合はこの plan には含めず、別タスクとして再計画する旨をログに残す。
- [ ] **Step 3: 実行確認**
  `just e2e-screen`(または同等のコマンド)で実行し Green を確認。

---

## 対象外(YAGNI)

- 音声付き画面共有、複数同時共有の帯域制御、SVC/simulcast、hub の大オブジェクトレーンは対象外。
- Lean による符号化の形式証明は対象外(vitest の golden/property テストで代替)。
