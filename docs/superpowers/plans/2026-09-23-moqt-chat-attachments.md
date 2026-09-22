# moqt_chat: 複数添付(画像/動画/クリップボード) + Send確定フロー + movie配信廃止

Spec: docs/superpowers/specs/2026-09-22-moqt-chat-attachments-design.md

## Context

既存のmoqt_chatは単一画像の即時送信機能(`sendImage`/`moqtImageWire.ts`)のみを持つ。ユーザーから5つの拡張要求があった:

1. 複数画像を1メッセージに添付
2. クリップボードからの画像添付
3. 動画も同様に添付
4. Slack/Discordのように送信前プレビュー→Send確定フロー(添付即送信をやめる)
5. サーバーからのmp4動画配信(`--movie`)機能の全廃止

ユーザー承認済みの設計判断(brainstorming architecturalパスで確認済み):
- テキスト+複数添付は1つの論理メッセージとして送る(別メッセージにしない)
- 動画もトランスコードせず生バイトのままチャンク分割送信、上限は画像と同じ5MB
- 添付上限は1メッセージ4枚まで
- クリップボード添付はテキスト入力欄フォーカス中のpasteイベントのみ(専用ボタンなし)
- ワイヤー設計は「messageIdで紐付け、テキストと各添付を別々のPublish」方式
- プレビューは個別削除可能
- e2eは主要パス(複数添付送信、動画含むケース)のみ新規、クリップボードはunitテストでカバー
- movie機能は`--movie`起動フラグ・`moqtMovieClient.ts`/`moqtLiveClient.ts`・`LivePlayer`を含めて完全削除

受信側の「複数の独立ストリーム(テキスト1本+添付N本)が非同期・任意順序で到着し、messageIdで集約して1メッセージとして確定する」という新しい状態機械は、事前に別途設計検証を行い、安全性・活性ともに反例なしで確認済み。検証で得られた実装上の要点:
- 「揃った瞬間に配信」の判定は、テキスト到着・添付到着それぞれの処理内で同期的に行う(別立ての完了チェック処理は置かない)
- messageId再利用時、古いサイクルの結果は新しいサイクルに汚染されない(Mapが過去を記憶しない設計通りでよい)
- タイムアウト(30秒)で未完了エントリを静かに破棄(既存の`imageFrameReassemblerPush`と同じ無ログdrop方式)

検証済み受け入れシナリオ(このまま失敗テストの元にする):
- テキスト→全添付の順で到着 → ちょうど1回配信
- 添付→テキスト(件数一致)の順で到着 → ちょうど1回配信
- 一部添付が届かずタイムアウト → 配信なしで破棄
- 配信済みmessageIdの再利用 → 新しい独立サイクルとして開始、旧配信は無傷
- 添付0件のテキストのみメッセージ → テキスト到着時点で即配信
- タイムアウト破棄後の遅延到着添付 → 新しい独立サイクルを開始(古いエントリを復活させない)

## 調査で確定した既存コード状況

- `moqtImageWire.ts`(183行)/`moqtImageWire.test.ts`(257行)は今回**全面置き換え**(新規`moqtAttachmentWire.ts`)。exportは`MAX_IMAGE_CHUNK_BYTES`, `IMAGE_CHUNK_MARKER`, `ImageChunk`, `buildImageSubgroupHeader`, `encodeImageChunkMessage`, `decodeImageChunkMessage`, `isImageChunkPayload`, `splitImageIntoChunks`, `ImageFrameReassembler`, `imageFrameReassemblerInit`, `imageFrameReassemblerPush`。
- `moqtClient.ts`(739行)の`classifyChatPayload`(207行目、`"text"|"nickname"|"image"`を返す、呼び出しは711行目1箇所のみ)を`"text"|"nickname"|"attachment"`等に拡張。`#imageReassemblers: Map<string, ImageFrameReassembler>`(278行目)と`#handleImageChunkPayload`(724-738行目)を、messageId+attachmentIdxキーの新集約ロジックに置き換え。`sendImage`/`onImage`はそれぞれ`sendMessage`/`onMessage`に統合(既存のプレーンテキスト`onMessage(participantId, text)`も`attachments: []`を伴う形に統一)。
- `moqtClient.ts`にmovie関連のimportやコードは無い(コメント2箇所のみ、229-230行目)。ここは削除不要。
- `page.tsx`にコンポーネントテストは存在しない(このコードベースの一貫した方針: Reactコンポーネントは直接テストせず、抽出可能な純粋関数のみvitestでテストする。`@testing-library/react`もdevDependenciesに無い)。既存`data-testid`一覧: `author, certHash, chat-form, connect, image-file, live, master-volume, message, message-image, messages, mic-toggle, nickname, ns-toggle, output-device, screen-stalled-own, screen-tile-own, screen-tile-width, screen-toggle, speaking-you, status, text, url`。`message-image`は既存e2e(`s15-image-send.mjs`)が依存しているセレクタなので、新e2eでも同じtestidを画像に使い続ける。動画には新規`message-video`を使う。
- リスト個別削除の既存パターンは`moqtChatStore.ts`の`removeScreenTile`(該当項目をfilterで除去+関連する依存stateもクリア)。添付ドラフト削除もこのパターンを踏襲。
- `moqtScreenClient.ts`が`moqtMovieClient.ts`から`MOVIE_INIT_TRACK_ALIAS`をimportし、`SCREEN_ALIAS_OFFSET = MOVIE_INIT_TRACK_ALIAS + 1n`(現在値10、`CANDIDATE_PARTICIPANT_IDS.length=4`から`2*4+2=10`)を計算している。この数値をハードコードするコードは他に無い(C側もscreenのaliasを関知しない、e2eもTS側のexportを参照するのみ)。**数値10を維持したまま、`moqtMovieClient.ts`への依存だけを切る**(`SCREEN_ALIAS_OFFSET = CANDIDATE_PARTICIPANT_IDS.length * 2 + 2`として独立に再定義)のが最小リスク。
- `wired_server.c`の movie専用コード: `publish_movie()`関数(360-390行目)と定数/グローバル変数ブロック(38-57行目、`MOVIE_MAX`/`MOVIE_GROUP_MS`/`MOVIE_TRACK_ALIAS`/`MOVIE_INIT_TRACK_ALIAS`/`MOVIE_TRACK_NAME`/`MOVIE_INIT_TRACK_NAME`/`g_movie`/`g_movie_layout`/`g_movie_init_wire`)は丸ごと削除可能。共有コード側の編集点は`wired_main()`内453行目の`publish_movie(...)`呼び出し1行のみ削除、176行目のdocコメント内のmovie言及は文言修正。`g_live`/`LIVE_RING`等はscreen-share/voiceとも共有される汎用機構なので**削除対象外**。`wired_server.c`自体はSDKのunity-buildテスト対象外(examples配下の独立バイナリ、C単体テストなし、e2e経由でのみ検証)。
- `Dockerfile`の`COPY assets/movie-live.mp4 /movie.mp4`と`ENTRYPOINT`の`--movie /movie.mp4`引数を削除。`docker-compose.yml`にmovie関連行なし。
- `useMoqtChat.ts`のmovie関連コードは広範囲(22-23, 230, 539-541, 585-612, 660, 875-924, 1011, 1033, 1237-1238, 1257行目付近): import、`videoRef`/`liveRef`、`clearLive`、`shouldStartLive`(純粋関数、テスト対象)、`onUnknownUniStream`内の`MOVIE_INIT_TRACK_ALIAS`/`MOVIE_TRACK_ALIAS`分岐、返り値の`videoRef`。
- `page.tsx`の`LivePlayer`は`<section className="body">`の最初の子要素(701-703行目付近)で、`ScreenTiles`/`MessageList`/`Compose`と並ぶ兄弟。該当行削除のみでレイアウト調整不要。`data-testid="live"`は`run-live-check.mjs`以外どこからも参照されていない。
- 既存e2eシナリオ(s8/s10/s11/s13/s14)はmovie/live機能を一切参照していない(grep確認済み、影響なし)。
- README.mdはmovieについて冒頭紹介文+"What this demonstrates"の4段落+Build and run+e2e+Layoutの計5箇所に言及。冒頭とWhat this demonstratesは実質書き直し、他は該当行削除で足りる。
- `moqtScreenClient.test.ts`/`moqtChatStore.test.ts`はmovie依存の間接的な修正が必要(要確認、実装時に個別対応)。`moqtLiveClient.test.ts`/`moqtMovieClient.test.ts`はファイルごと削除。
- 動画プレビューの技術方針: `<video src={blobURL} muted preload="metadata">` + `loadedmetadata`後に`currentTime`を明示セットしてフレームデコードを強制(Safari/WebKitは無操作だと黒枠のまま)。revokeのタイミングは`<img>`の`onload`と違い`<video>`は`loadeddata`まで待つか、その添付がドラフトから削除されるまでrevokeしない設計にする(Firefoxのモバイル録画mp4で`loadedmetadata`時点のrevokeが既知の問題を起こすため)。React実装は「file単位のuseObjectUrlフック、item削除時にunmountでrevoke」パターン(親でURL mapを手動管理しない)。
- 既存e2e `s15-image-send.mjs`の構造: `joinClient`(loadTest.mjs版から`received`ポーリングを省いた簡易版)、`makePattern`(決定的疑似ランダムバイト列)、`sendImageFromPage`(`waitForSelector`後にFile+DataTransfer+changeイベント)、`waitForReceivedImage(page, previousCount)`(要素数がpreviousCountを超えるまで待つ、送信者自身の楽観エコーとの混同を避けるため)、`runCase`。この構造を多添付・動画・テキストのみケースに拡張する。

## 実装方針

### 1. ワイヤーフォーマット刷新: `moqtAttachmentWire.ts`(新規、`moqtImageWire.ts`を置き換え)

- 既存`moqtImageWire.ts`の全ロジック(チャンク分割・reassembler)を土台に、`messageId`(u32)と`attachmentIdx`(u8, 0-3)を追加。
- マーカーバイト: `0xFD`=添付チャンク、`0xFE`=テキストパート(添付点数を同梱)。既存`0xFF`(旧単一画像マーカー)と`0x00`(ニックネーム)は廃止/維持を精査(旧`0xFF`は新方式に統合されるため削除、ニックネームは維持)。
- テキストパート: `marker(0xFE) | messageId(u32) | attachmentCount(u8) | textLen(u16) | text`。
- 添付チャンク: `marker(0xFD) | messageId(u32) | attachmentIdx(u8) | seq(u32, 常に0) | idx(u16) | count(u16) | (idx=0のみ)mimeType長+mimeType+totalBytes(u32) | data`。
- `splitAttachmentIntoChunks`/reassembler関数群は既存`splitImageIntoChunks`/`imageFrameReassemblerPush`とほぼ同一ロジックをmessageId/attachmentIdx対応に拡張。
- TDD: encode/decode round-trip、境界値(0バイト・480バイト境界・複数チャンク)、マーカー判別の非衝突性(検証済み設計通り)。

### 2. `moqtClient.ts`: メッセージ集約ロジックと送受信API刷新

- `sendMessage(text: string, attachments: {bytes: Uint8Array; mimeType: string}[]): Promise<void>`を新設(`sendImage`/既存の`sendChat`のテキスト送信ロジックを統合)。`messageId`を1つ採番し、テキストパートを1ストリーム、各添付を順にチャンク送信。
- `classifyChatPayload`を`"text"|"nickname"|"attachment-text"|"attachment-chunk"`の4分岐に拡張。
- `#pendingMessages: Map<string, PendingMessage>`(キーは`` `${participant}:${messageId}` ``)を新設。検証済み設計通りの状態遷移(テキスト到着/添付到着それぞれの処理内で同期的に完了判定、タイムアウトsweep)。
- `MoqtChatCallbacks.onMessage`を`(participantId: string, text: string, attachments: ReassembledAttachment[]) => void`に統一。既存プレーンテキストは`attachments: []`で同じコールバックを通す。`onImage`は廃止。
- TDD: 検証済み受け入れシナリオ6件をそのままテストケース化(text-first/attachment-first/timeout/messageId再利用/0添付即配信/タイムアウト後の遅延到着)。

### 3. `moqtChatStore.ts`: 型刷新

- `ChatMessage.attachments: ChatAttachment[]`(`imageDataUrl`/`imageMimeType`を置き換え)。`ChatAttachment = {bytes, mimeType, url}`。
- `imageSendError`を`messageSendError`にリネーム(意味も統一: テキスト/添付問わず送信失敗全般をカバー)。
- 既存`removeScreenTile`パターンに倣い、ドラフト添付の個別削除用ロジックはCompose内のローカルstateで完結させる(storeには持たせない、Composeが送信前の一時状態を持つのはUIローカルの責務)。

### 4. `useMoqtChat.ts`: フック刷新 + movie機能削除

- `sendChat`/`sendImage`を`sendMessage(text, attachments)`1本に統合。
- `moqtChatCallbacks`の`onImage`ハンドラを削除、`onMessage`が添付込みで`store.addMessage`する形に統一。
- movie関連を全削除: import(22-23行目)、`videoRef`/`liveRef`/`clearLive`/`shouldStartLive`、`onUnknownUniStream`のMOVIE分岐、返り値の`videoRef`。

### 5. `page.tsx`: UI刷新

- `Compose`に`draftAttachments: Draft[]`ローカルstateを追加。`Draft = {id, bytes, mimeType, previewUrl, fileName}`。
- ファイル選択: `<input type="file" accept="image/*,video/*" multiple data-testid="attachment-file">`(既存`image-file`から改名、4枚上限・5MB上限を選択時にチェック)。
- クリップボード: テキスト`<input>`の`onPaste`ハンドラで`e.clipboardData.items`からfile種別を抽出、同じ上限チェックを通してdraftへ追加。plainテキストのpasteは妨げない。
- プレビュー行: 画像は`<img>`、動画は`<video muted preload="metadata">`+`loadedmetadata`で`currentTime`セット、各チップに個別削除ボタン(`data-testid="draft-remove"`)。`useObjectUrl`パターンでBlob URL管理。
- Sendボタン: テキストまたは添付いずれかがあれば有効。押下で`onSendMessage(text, draftAttachments)`を呼び、draft/previewUrlをクリア。
- `Message`コンポーネント: `m.attachments`を`<img data-testid="message-image">`/`<video controls data-testid="message-video">`で列挙表示、画像用testidは既存のまま維持(e2e互換のため)。
- `LivePlayer`コンポーネント・`videoRef`関連JSXを削除。

### 6. movie機能のサーバー・インフラ側削除

- `wired_server.c`: `publish_movie()`関数と関連定数/グローバル変数ブロックを削除、`wired_main()`内の呼び出し1行削除、doc内movie言及を文言修正。
- `Dockerfile`: `COPY assets/movie-live.mp4`行と`ENTRYPOINT`の`--movie`引数を削除。
- `assets/movie-live.mp4`削除(`assets/movie.mp4`が他から参照されていないか実装時に確認の上、未参照なら削除)。
- フロント: `moqtMovieClient.ts`/`moqtLiveClient.ts`とそのテストファイルを削除。`moqtScreenClient.ts`の`SCREEN_ALIAS_OFFSET`計算を`moqtMovieClient.ts`依存なしの独立式(`CANDIDATE_PARTICIPANT_IDS.length * 2 + 2`)に書き換え(数値は10のまま不変)。
- e2e: `run-live-check.mjs`削除、justfileの`e2e-live`レシピ削除。
- README.md: 冒頭紹介文とWhat this demonstratesのmovie関連4段落を削除/書き換え、Build and run/e2e/Layoutセクションのmovie言及行を削除。

### 7. テスト(TDD、検証済み受け入れシナリオを橋渡し)

- `moqtAttachmentWire.test.ts`(新規): エンコード/デコードround-trip、reassembler、マーカー非衝突。
- `moqtClient.test.ts`: `sendMessage`のストリーム順序、`classifyChatPayload`4分岐、集約state machineの6シナリオ(text-first/attachment-first/timeout/messageId再利用/0添付即配信/タイムアウト後遅延到着)。
- `moqtChatStore.test.ts`: `ChatMessage.attachments`を持つ`addMessage`、`messageSendError`。movie関連テストの削除/修正。
- `useMoqtChat.test.ts`: `moqtChatCallbacks`の`onMessage`(添付込み)テスト。movie関連(`shouldStartLive`等)テストの削除。
- `moqtScreenClient.test.ts`: `SCREEN_ALIAS_OFFSET`が movie非依存でも同じ数値(10)を返すことの確認(既存テストの調整)。
- Composeのpure-logic部分(paste時のファイル種別フィルタリング、4枚/5MB上限判定)は`page.tsx`から抽出可能なら`src/lib/`配下の純粋関数として切り出しテストする(既存コードベースの「コンポーネント自体はテストしない」方針に従う)。

### 8. e2e

- `s15-image-send.mjs`を拡張(既存の`joinClient`/`makePattern`/`waitForSelector`パターンを踏襲):
  - 複数添付(画像+動画、計2〜4枚)を1メッセージで送信し、受信側で全添付がバイト一致することを検証するケースを追加。
  - テキストのみメッセージ、添付のみメッセージ(テキスト空)のケースも1本のシナリオファイル内でカバー。
  - 動画は`new File([bytes], "test.mp4", {type: "video/mp4"})`で合成(既存パターンがMIME種別を素通しするため画像と同じ経路で動作する)。
  - 既存の`message-image`セレクタは維持、動画は新規`message-video`セレクタで検証。
- クリップボード添付のe2eは行わない(承認済み方針通り、unitテストでカバー)。

## 触るファイル

- 新規 `examples/moqt_chat/frontend/src/lib/moqtAttachmentWire.ts`、`__tests__/moqtAttachmentWire.test.ts`
- 削除 `examples/moqt_chat/frontend/src/lib/moqtImageWire.ts`、`__tests__/moqtImageWire.test.ts`
- `examples/moqt_chat/frontend/src/lib/moqtClient.ts`、`__tests__/moqtClient.test.ts`
- `examples/moqt_chat/frontend/src/lib/moqtScreenClient.ts`(`SCREEN_ALIAS_OFFSET`独立化)、`__tests__/moqtScreenClient.test.ts`
- 削除 `examples/moqt_chat/frontend/src/lib/moqtMovieClient.ts`、`moqtLiveClient.ts`とそれぞれの`__tests__/`
- `examples/moqt_chat/frontend/src/stores/moqtChatStore.ts`、`__tests__/moqtChatStore.test.ts`
- `examples/moqt_chat/frontend/src/hooks/useMoqtChat.ts`、`__tests__/useMoqtChat.test.ts`
- `examples/moqt_chat/frontend/src/app/page.tsx`
- `examples/moqt_chat/e2e/scenarios/s15-image-send.mjs`(拡張)
- 削除 `examples/moqt_chat/e2e/run-live-check.mjs`
- `examples/moqt_chat/wired_server.c`、`Dockerfile`、`justfile`(e2e-liveレシピ削除)
- 削除 `assets/movie-live.mp4`(要: 他未参照確認)
- `examples/moqt_chat/README.md`

## Global Constraints

- `just test-fast`(または`just test`)/`just ninja`/`lizard src --CCN 3 -w` の三点ゲートはC側(`wired_server.c`)を編集した場合のみ必須(SDK `src/`本体は無変更のため通常は影響なしだが、`wired_server.c`はexamples配下でも`.github/workflows/examples.yml`の対象なので、変更したら少なくとも該当exampleのビルドを確認する)。
- `src/`ディレクトリ配下は本タスクでは一切変更しない。`git diff --stat src/`が空であることを最終確認する。
- フロントエンドは`examples/moqt_chat/frontend/`で`npm test -- --run`、`npx tsc --noEmit`、`npx eslint .`、`npm run build`が全てクリーンであること。
- コミットはconventional micro-commit(30-50行単位)。C側とTS側は別コミット系列に分ける。
- 動画・画像とも上限5MB、1メッセージ添付上限4枚(spec/plan記載の通り、実装中に数値を変えない)。
- `message-image`のdata-testidは既存e2e互換のため変更しない。

## タスク分割

### Task 1: `moqtAttachmentWire.ts`新規作成(ワイヤーフォーマット)

`examples/moqt_chat/frontend/src/lib/moqtImageWire.ts`と対応するテストを読み込み、そのロジックを土台に新規`examples/moqt_chat/frontend/src/lib/moqtAttachmentWire.ts`を作成する。TDD(t-wada流: テストリスト→Red→Green→Refactor)で進める。

エクスポートする型/関数:
- 定数: `MAX_ATTACHMENT_CHUNK_BYTES`(既存`MAX_IMAGE_CHUNK_BYTES`と同値を踏襲)、`ATTACHMENT_CHUNK_MARKER = 0xFD`、`TEXT_PART_MARKER = 0xFE`
- 型: `AttachmentChunk`(messageId, attachmentIdx, seq, idx, count, mimeType?, totalBytes?, data)
- `buildAttachmentSubgroupHeader(...)`(既存`buildImageSubgroupHeader`と同じ役割をmessageId/attachmentIdx対応に拡張)
- `encodeAttachmentChunkMessage(chunk: AttachmentChunk): Uint8Array`
- `decodeAttachmentChunkMessage(bytes: Uint8Array): AttachmentChunk`
- `isAttachmentChunkPayload(bytes: Uint8Array): boolean`(先頭バイトが`0xFD`か)
- `splitAttachmentIntoChunks(messageId: number, attachmentIdx: number, mimeType: string, data: Uint8Array): AttachmentChunk[]`
- `encodeTextPartMessage(messageId: number, attachmentCount: number, text: string): Uint8Array`
- `decodeTextPartMessage(bytes: Uint8Array): {messageId: number; attachmentCount: number; text: string}`
- `isTextPartPayload(bytes: Uint8Array): boolean`(先頭バイトが`0xFE`か)
- `AttachmentReassembler`型、`attachmentReassemblerInit()`, `attachmentReassemblerPush(reassembler, chunk): Uint8Array | null`(全チャンク揃ったら結合バイト列を返す、既存`imageFrameReassemblerPush`と同じくタイムアウト30秒で無ログdrop)

ワイヤーフォーマット詳細(plan本文のセクション1参照、逐語):
- テキストパート: `marker(0xFE, 1byte) | messageId(u32, big-endian) | attachmentCount(u8) | textLen(u16, big-endian) | text(UTF-8 bytes)`
- 添付チャンク: `marker(0xFD, 1byte) | messageId(u32) | attachmentIdx(u8, 0-3) | seq(u32, 常に0) | idx(u16) | count(u16) | (idx=0のときのみ) mimeTypeLen(u8) + mimeType(UTF-8) + totalBytes(u32) | data(残りバイト)`
- 1チャンクのdata部最大サイズは既存`MAX_IMAGE_CHUNK_BYTES`と同じ値(既存ファイルを読んで値を確認し、そのまま踏襲すること。変更しない)。

テストリスト(必須、6シナリオ相当をencode/decode roundtripとreassemblerに対応させる):
1. テキストパートのencode→decode roundtrip(空文字、通常文字列、マルチバイトUTF-8)
2. 添付チャンクのencode→decode roundtrip(0バイトdata、1チャンクぴったり、複数チャンクにまたがる境界値)
3. `isAttachmentChunkPayload`/`isTextPartPayload`がお互いを誤判定しない(マーカーバイトの非衝突)こと、既存のニックネームマーカー(`0x00`、既存ファイルで確認)とも衝突しないこと
4. `splitAttachmentIntoChunks`が生成した全チャンクを順不同で`attachmentReassemblerPush`に投入すると最後の1回だけ結合バイト列が返り、それ以外はnullを返す
5. 一部チャンクが欠けたまま30秒経過想定でreassemblerが静かに破棄される(既存`imageFrameReassemblerPush`のタイムアウトテストパターンを踏襲)
6. 同じmessageId+attachmentIdxキーが再利用されても新しいサイクルとして独立に動作する(旧サイクルの残骸が新サイクルに混入しない)

自己レビュー観点: CCN高くならないか(このファイルはTSなのでlizard対象外だが、複雑な分岐は関数分割しておくこと)、既存`moqtImageWire.ts`の実装パターン(バイト操作、DataView使用有無など)を可能な限り踏襲すること。

このタスクでは`moqtImageWire.ts`は削除しない(次のタスクで参照が切り替わってから削除する)。新規ファイル2つ(`moqtAttachmentWire.ts`と`__tests__/moqtAttachmentWire.test.ts`)のみを追加すること。

検証: `cd examples/moqt_chat/frontend && npx vitest run src/lib/__tests__/moqtAttachmentWire.test.ts`が全て green。

### Task 2: `moqtClient.ts`刷新(送受信APIと集約state machine)

前タスクで作成した`moqtAttachmentWire.ts`(パス: `examples/moqt_chat/frontend/src/lib/moqtAttachmentWire.ts`)を使い、`examples/moqt_chat/frontend/src/lib/moqtClient.ts`(739行)を次の通り書き換える。対応する`examples/moqt_chat/frontend/src/lib/__tests__/moqtClient.test.ts`も同時に更新する。TDD(t-wada流)で進める。

現状把握のため、着手前に必ず`moqtClient.ts`全文と`moqtClient.test.ts`全文を読むこと(行数見積もりは調査時点のものなので、実際のコードを正として作業する)。

変更点:
1. `import`を`moqtImageWire.ts`から`moqtAttachmentWire.ts`に切り替え、使う関数を新シグネチャに合わせる。
2. `classifyChatPayload`の返り値を`"text" | "nickname" | "attachment-text" | "attachment-chunk"`の4分岐に拡張(現行の`"text"|"nickname"|"image"`から)。判定は`moqtAttachmentWire.ts`の`isAttachmentChunkPayload`/`isTextPartPayload`を使う。
3. `sendMessage(text: string, attachments: {bytes: Uint8Array; mimeType: string}[]): Promise<void>`を新設。内部で1つの`messageId`(u32、既存コードにインクリメンタルなIDカウンタがあればそれに倣う、無ければ`Date.now()`ベースやモジュールスコープのカウンタ等、既存コードの採番パターンを踏襲)を採番し、テキストパートを1回Publish、各添付を`splitAttachmentIntoChunks`でチャンク化して順にPublish。既存`sendImage`/テキスト送信ロジック(該当箇所を検索して特定)をこの1関数に統合し、古い`sendImage`は削除する。
4. `#pendingMessages: Map<string, PendingMessage>`を新設(キーは`` `${participantId}:${messageId}` ``)。`PendingMessage`型は概ね`{text?: string; attachmentCount: number; attachments: Map<number, Uint8Array | AttachmentReassembler>; receivedAt: number}`のような形(実装しながら最小構成を決めてよい)。
   - テキストパート受信時: `PendingMessage`が無ければ作成、`text`と`attachmentCount`をセット。**その場で**(別立ての完了チェック関数を作らず、この処理の中で同期的に)「添付が全部揃っているか」を判定し、揃っていれば即座に`onMessage`を呼んで`pendingMessages`からエントリを削除。添付が0件なら即配信。
   - 添付チャンク受信時: 対応する`AttachmentReassembler`に`attachmentReassemblerPush`し、結合バイト列が返ってきたら`PendingMessage.attachments`に格納。**その場で**「テキストが届いていて、かつ添付が全部揃っているか」を判定し、揃っていれば即座に`onMessage`を呼んでエントリを削除。
   - どちらの処理も、揃っていなければ何もせず次のストリームを待つ。
   - messageId再利用時は新しいMapエントリとして自然に独立する(古いエントリを明示的に探して破棄する処理は不要、Mapが過去を記憶しない設計のまま)。
   - タイムアウト(30秒)は`moqtAttachmentWire.ts`側の`AttachmentReassembler`が個別チャンク単位で処理する設計なので、`PendingMessage`自体の掃除は「一定時間経過したエントリを定期的にsweepする」既存パターンがコード内にあれば踏襲し、無ければテキストパート/添付チャンクの受信処理の中で`receivedAt`が30秒超過した古いエントリを見つけ次第(同じ処理のついでに)破棄するだけでよい(YAGNI、専用のタイマー/setIntervalは新設しない)。
5. `MoqtChatCallbacks.onMessage`のシグネチャを`(participantId: string, text: string, attachments: {bytes: Uint8Array; mimeType: string}[]) => void`に統一する。既存の`onImage`コールバックは削除。プレーンテキストメッセージも同じ`onMessage`を通す(`attachments: []`)。
6. 呼び出し元(`classifyChatPayload`の呼び出し箇所、既存コードで1箇所)の分岐をtext/nickname/attachment-text/attachment-chunkの4パターンに書き換える。

テストリスト(検証済み受け入れシナリオ6件、`moqtClient.test.ts`に追加/書き換え):
1. テキスト→全添付の順で到着 → `onMessage`がちょうど1回呼ばれる
2. 添付→テキスト(件数一致)の順で到着 → `onMessage`がちょうど1回呼ばれる
3. 一部添付が届かずタイムアウト相当の時間が経過 → `onMessage`が呼ばれない(配信なしで破棄、`pendingMessages`からエントリが消えていることも確認)
4. 配信済みmessageIdの再利用 → 新しい独立サイクルとして`onMessage`が呼ばれ、旧配信の結果(1回目の呼び出し引数)に影響がないこと
5. 添付0件のテキストのみメッセージ → テキスト到着時点で即座に`onMessage`が呼ばれる
6. タイムアウト破棄後に遅延到着した添付チャンク → 新しい独立サイクルとして扱われる(古いエントリを復活させて誤配信しないこと)

さらに:
7. `classifyChatPayload`の4分岐がそれぞれ正しく判定されるテスト
8. `sendMessage`が正しい順序でPublish(テキストパート1回、各添付をチャンク分割してPublish)を呼ぶことを確認するテスト(既存の`sendImage`/`sendChat`相当のテストがあればそのパターンを踏襲)

自己レビュー観点: 既存`sendChat`(または相当関数)のPublish周りのエラーハンドリング・リトライ有無を確認し、`sendMessage`統合後も落とさないこと。`onImage`を参照している他ファイル(`useMoqtChat.ts`等)がこの時点でコンパイルエラーになるのは想定内(次タスクで対応)、`moqtClient.ts`と`moqtClient.test.ts`の範囲内でテストが通ることを確認すればよい。

検証: `cd examples/moqt_chat/frontend && npx vitest run src/lib/__tests__/moqtClient.test.ts`が全てgreen。

### Task 3: `moqtImageWire.ts`削除 + `moqtChatStore.ts`型刷新

このタスクは2つの作業を含む(同一ファイル群への小さい変更のため1タスクにまとめた)。

**3a. `moqtImageWire.ts`削除**
`examples/moqt_chat/frontend/src/lib/moqtImageWire.ts`と`examples/moqt_chat/frontend/src/lib/__tests__/moqtImageWire.test.ts`を削除する。削除前に`grep -rn "moqtImageWire" examples/moqt_chat/frontend/src/`を実行し、Task 2で`moqtClient.ts`のimportが既に切り替わっていることを確認してから削除すること(他に参照が残っていたら、このタスクの範囲でその参照も新wireに切り替える)。

**3b. `moqtChatStore.ts`型刷新**
`examples/moqt_chat/frontend/src/stores/moqtChatStore.ts`と対応するテスト`examples/moqt_chat/frontend/src/stores/__tests__/moqtChatStore.test.ts`を読み、以下を変更する:
- `ChatMessage`型の`imageDataUrl`/`imageMimeType`(該当フィールドを検索して特定)を`attachments: ChatAttachment[]`に置き換える。`ChatAttachment = {bytes: Uint8Array; mimeType: string; url: string}`という型を新設(`url`はBlob URL、呼び出し側で生成してstoreに渡す想定)。
- `imageSendError`(該当ステートを検索して特定)を`messageSendError`にリネームする。意味も統一: テキスト/添付問わず送信失敗全般をカバーするエラーとして扱う(既存の使われ方を確認し、テキスト送信時のエラーも同じフィールドを使うよう呼び出し元判断が必要ならこのタスクで対応、ただし呼び出し元の実際の書き換えはTask 4で行うのでここでは型と store 内のロジックのみでよい)。
- `addMessage`(または相当する追加関数)が`attachments`配列を受け取れるようにシグネチャを更新する。
- 個別削除パターン(`removeScreenTile`、該当箇所を検索)はこのタスクでは新設しない(添付ドラフト削除はCompose内のUIローカルstateで完結させる設計なので、storeの変更範囲外)。

テストリスト:
1. `addMessage`が`attachments`配列(0件、1件、4件)を正しく格納する
2. `messageSendError`のセット/クリアが動作する(既存`imageSendError`のテストがあれば名前を変えて踏襲)
3. 既存のmovie関連テスト(あれば)がこのタスクの変更で壊れていないか確認し、壊れていれば最小修正する(movie機能自体の削除はTask 6の範囲、ここでは型変更による副作用のみ対応)

自己レビュー観点: `moqtChatStore.ts`を参照する他ファイル(`useMoqtChat.ts`, `page.tsx`)はこの時点でコンパイルエラーになるのは想定内(Task 4, 5で対応)。store単体のテストが通ることを確認すればよい。

検証: `cd examples/moqt_chat/frontend && npx vitest run src/stores/__tests__/moqtChatStore.test.ts src/lib/__tests__/`(moqtImageWire.test.tsが消えていること、他は全てgreenであること)。

### Task 4: `useMoqtChat.ts`刷新(API統合 + movie機能削除)

`examples/moqt_chat/frontend/src/hooks/useMoqtChat.ts`と対応するテスト`examples/moqt_chat/frontend/src/hooks/__tests__/useMoqtChat.test.ts`を全文読んでから着手する(行数はplan調査時点の見積もりなので実コードを正とする)。

**API統合:**
- `sendChat`/`sendImage`(該当関数を検索)を`sendMessage(text: string, attachments: {bytes: Uint8Array; mimeType: string}[]): Promise<void>`1本に統合し、`moqtClient.ts`(Task 2で刷新済み)の`sendMessage`を呼ぶ。
- `moqtChatCallbacks`の`onImage`ハンドラを削除。`onMessage`ハンドラが`text`と`attachments`を受け取り、`store.addMessage`(Task 3で刷新済みシグネチャ)を呼ぶよう統一する。Blob URL生成(`URL.createObjectURL`)はここで各添付ごとに行い、`ChatAttachment.url`にセットする。

**movie機能の全削除:**
- movie関連の`import`文を削除(`moqtMovieClient`/`moqtLiveClient`関連、該当箇所を検索)。
- `videoRef`/`liveRef`/`clearLive`/`shouldStartLive`を削除。
- `onUnknownUniStream`(または相当のハンドラ、該当箇所を検索)内のMOVIE系トラックエイリアス分岐を削除。
- フックの返り値オブジェクトから`videoRef`を削除。

削除にあたり、`grep -n "movie\|Movie\|MOVIE\|live\|Live\|LIVE" examples/moqt_chat/frontend/src/hooks/useMoqtChat.ts`を実行し、該当箇所を漏れなく洗い出してから着手すること(ただし`liveRef`等`live`という文字列が偶然他の意味で使われている箇所があれば誤削除しないよう文脈を確認する)。

テストリスト:
1. `onMessage`コールバックが添付込みで呼ばれたとき`store.addMessage`が正しい引数(text, attachments)で呼ばれる
2. `sendMessage`フックが`moqtClient.sendMessage`を正しく呼ぶ
3. movie関連テスト(`shouldStartLive`等、該当テストを検索)を削除する
4. 既存のテキストのみ送信・受信のテストがあれば、新API(`attachments: []`)に合わせて更新し green を維持する

自己レビュー観点: `page.tsx`はこの時点でコンパイルエラーになるのは想定内(Task 5で対応)。フック単体のテストが通ることを確認すればよい。movie削除がこのフックのテキスト/添付送受信ロジックに副作用を与えていないか(共有していた状態やeffectが無いか)を確認すること。

検証: `cd examples/moqt_chat/frontend && npx vitest run src/hooks/__tests__/useMoqtChat.test.ts`が全てgreen。

### Task 5: `page.tsx`刷新(UI: 複数添付プレビュー + Send確定フロー + movie UI削除)

`examples/moqt_chat/frontend/src/app/page.tsx`全文を読んでから着手する。Task 4で刷新済みの`useMoqtChat.ts`が返す`sendMessage`/添付込み`ChatMessage`を使う。

**Compose刷新:**
- `Compose`コンポーネントに`draftAttachments: Draft[]`ローカルstate(`useState`)を追加。`Draft = {id: string; bytes: Uint8Array; mimeType: string; previewUrl: string; fileName: string}`。
- ファイル選択inputを`<input type="file" accept="image/*,video/*" multiple data-testid="attachment-file">`に変更(既存`data-testid="image-file"`から改名)。選択時に4枚上限・5MB上限(既存の画像上限チェックロジックを検索して踏襲、数値は変えない)を超えるファイルは追加を拒否し、エラー表示する(既存のエラー表示パターン、`messageSendError`または同等のローカルUIエラーstateを使う)。
- クリップボード添付: テキスト入力用`<input>`(該当要素を検索、`data-testid="text"`)に`onPaste`ハンドラを追加。`e.clipboardData.items`を走査し、`item.kind === "file"`かつ`item.type`が`image/*`または`video/*`のものだけを抽出、同じ上限チェックを通してdraftへ追加。plainテキストのpasteイベント(`item.kind === "string"`)はブロックしない(`preventDefault`を呼ばない)。
- 上限判定・ファイル種別フィルタリングロジックは純粋関数として`examples/moqt_chat/frontend/src/lib/`配下(既存のlib構成に倣い新規ファイル、例: `attachmentValidation.ts`)に抽出し、`page.tsx`からimportして使う。対応するテスト`examples/moqt_chat/frontend/src/lib/__tests__/attachmentValidation.test.ts`をTDDで先に書く(このコードベースの「コンポーネント自体はテストしない、純粋関数だけテストする」方針に従うため必須)。
- プレビュー行: `draftAttachments`を列挙し、`mimeType`が`image/*`なら`<img src={previewUrl}>`、`video/*`なら`<video src={previewUrl} muted preload="metadata">`を表示。動画は`onLoadedMetadata`で`e.currentTarget.currentTime = 0.1`等をセットしてフレームデコードを強制する(Safari/WebKit対策)。各チップに個別削除ボタン`data-testid="draft-remove"`を付け、押下で該当draftのみを`draftAttachments`からfilterで除去する(`removeScreenTile`パターン踏襲)。Blob URLの生成/revokeは「file単位のuseObjectUrlフック」を新設し(`examples/moqt_chat/frontend/src/hooks/`配下、例: `useObjectUrl.ts`)、削除時のunmountでrevokeする。
- Sendボタン: テキストまたは`draftAttachments`いずれかが1件以上あれば活性化。押下で`onSendMessage(text, draftAttachments.map(d => ({bytes: d.bytes, mimeType: d.mimeType})))`(Task 4の`sendMessage`)を呼び、成功したら`text`と`draftAttachments`をクリアする。

**Message表示刷新:**
- `Message`コンポーネント(該当箇所を検索)が`m.attachments`を列挙し、`mimeType`が`image/*`なら`<img data-testid="message-image">`(既存testid維持)、`video/*`なら`<video controls data-testid="message-video">`(新規testid)で表示する。

**movie UI削除:**
- `LivePlayer`コンポーネントの定義と、`<section className="body">`内でのレンダリング箇所を削除する(該当箇所を検索、plan調査時点で701-703行目付近とされているが実コードを正とする)。`videoRef`を使うJSXも削除。

テストリスト(純粋関数部分のみ、コンポーネント自体はテストしない):
1. `attachmentValidation.ts`: ファイルサイズが5MB以下/超過での合否判定
2. `attachmentValidation.ts`: 既存添付数+新規選択数が4件以下/超過での合否判定
3. `attachmentValidation.ts`: `image/*`・`video/*`以外のMIMEタイプを拒否する判定(clipboard item由来のフィルタリングロジックと共有できるならそのようにする)

自己レビュー観点: 既存e2e (`s15-image-send.mjs`)が依存する`data-testid`(`image-file`→`attachment-file`への改名を含む、e2e側はTask 8で追随)との整合を意識すること。`npx tsc --noEmit`がこの時点でclean(全タスクの中でこのタスクが最後のUI層なので、ここでmovie関連の型エラーも含め完全に解消される想定)。

検証: `cd examples/moqt_chat/frontend && npx vitest run src/lib/__tests__/attachmentValidation.test.ts && npx tsc --noEmit && npx eslint . && npm run build`が全てclean。

### Task 6: movie機能のサーバー・インフラ側削除

以下をまとめて1タスクとする(いずれもmovie削除という単一目的の小さい独立編集のため)。

**6a. `wired_server.c`**
`examples/moqt_chat/wired_server.c`全文を読んでから着手する。`publish_movie()`関数と、movie専用の定数/グローバル変数ブロック(`MOVIE_MAX`/`MOVIE_GROUP_MS`/`MOVIE_TRACK_ALIAS`/`MOVIE_INIT_TRACK_ALIAS`/`MOVIE_TRACK_NAME`/`MOVIE_INIT_TRACK_NAME`/`g_movie`/`g_movie_layout`/`g_movie_init_wire`、該当箇所を検索)を削除する。`wired_main()`内の`publish_movie(...)`呼び出し1行を削除する。doc内のmovie言及コメントを、movie機能が存在しない前提の文言に修正する。`g_live`/`LIVE_RING`等、screen-share/voiceと共有される汎用機構は削除対象外(残すこと)。

**6b. `Dockerfile`**
`examples/moqt_chat/Dockerfile`の`COPY assets/movie-live.mp4 /movie.mp4`行と、`ENTRYPOINT`の`--movie /movie.mp4`引数を削除する。

**6c. `assets/movie-live.mp4`削除**
削除前に`grep -rn "movie-live.mp4\|movie\.mp4" examples/moqt_chat/ --include="*.c" --include="*.md" --include="*.mjs" --include="Dockerfile" --include="justfile"`を実行し、他に未対応の参照が残っていないか確認してから削除する。

**6d. `moqtScreenClient.ts`のSCREEN_ALIAS_OFFSET独立化**
`examples/moqt_chat/frontend/src/lib/moqtScreenClient.ts`と対応するテスト`examples/moqt_chat/frontend/src/lib/__tests__/moqtScreenClient.test.ts`を読む。`moqtMovieClient.ts`からの`MOVIE_INIT_TRACK_ALIAS`importと`SCREEN_ALIAS_OFFSET = MOVIE_INIT_TRACK_ALIAS + 1n`の計算を削除し、`SCREEN_ALIAS_OFFSET = CANDIDATE_PARTICIPANT_IDS.length * 2 + 2`(既存の`CANDIDATE_PARTICIPANT_IDS`を参照、該当箇所を検索)として独立に再定義する。**数値は10のまま変わらないこと**を既存テストまたは新規アサーションで確認する。

**6e. `moqtMovieClient.ts`/`moqtLiveClient.ts`削除**
`examples/moqt_chat/frontend/src/lib/moqtMovieClient.ts`、`moqtLiveClient.ts`とそれぞれの`__tests__/moqtMovieClient.test.ts`、`__tests__/moqtLiveClient.test.ts`を削除する。削除前に`grep -rn "moqtMovieClient\|moqtLiveClient" examples/moqt_chat/frontend/src/`を実行し、6dの修正後は参照が残っていないことを確認する。

**6f. e2e/justfile**
`examples/moqt_chat/e2e/run-live-check.mjs`を削除する。`examples/moqt_chat/justfile`内の`e2e-live`レシピ(該当箇所を検索)を削除する。

**6g. README.md**
`examples/moqt_chat/README.md`を読み、冒頭紹介文とWhat this demonstratesセクションのmovie関連4段落を削除/書き換え、Build and run/e2e/Layoutセクションのmovie言及行を削除する。jp-writer的な日本語散文ではなく英語READMEの体裁を維持すること(既存ファイルの言語・文体をそのまま踏襲)。

検証: `grep -rni movie examples/moqt_chat/ --include="*.c" --include="*.ts" --include="*.tsx" --include="*.md" --include="*.mjs" --include="Dockerfile" --include="justfile" | grep -v node_modules | grep -v /out/ | grep -v /.next/`が空であること。`cd examples/moqt_chat/frontend && npx vitest run && npx tsc --noEmit`が全てgreen(この時点でTask 1-6全ての変更が揃っているはず)。C側は`just build`(リポジトリルートから)を実行して`src/`が無変更でビルド影響がないことを確認、加えて可能であれば`examples/moqt_chat/wired_server.c`単体を対象コンパイラでシンタックスチェックする(このexampleにC単体テストは無いため、実行確認はTask 8のe2eに委ねる)。

### Task 7: `s15-image-send.mjs`拡張(e2e)

`examples/moqt_chat/e2e/scenarios/s15-image-send.mjs`全文を読んでから着手する。既存の`joinClient`/`makePattern`/`sendImageFromPage`/`waitForReceivedImage`/`runCase`パターンを踏襲し、以下のケースを同一ファイル内に追加する:

1. **複数添付(画像+動画混在)ケース**: 画像2枚+動画1〜2枚(計2〜4枚)を1メッセージで送信。`data-testid="attachment-file"`(Task 5で改名済み)に対し`multiple`選択で複数Fileを一度にセットする(既存`sendImageFromPage`をベースに複数File対応へ拡張、関数名も実態に合わせて構わない)。動画は`new File([bytes], "test.mp4", {type: "video/mp4"})`で合成する(既存の`makePattern`で決定的疑似ランダムバイト列を生成)。受信側で全添付が`data-testid="message-image"`/`data-testid="message-video"`それぞれ期待数だけ表示され、バイト列が一致することを検証する(バイト一致検証は既存の画像ケースの検証方法を踏襲、`src`のdata URLやBlobから読み出して比較する既存パターンがあればそれに倣う)。
2. **テキストのみメッセージケース**: 添付なしでテキストのみ送信し、受信側にテキストが表示されることを確認する。
3. **添付のみメッセージケース**(テキスト空): テキスト無しで添付のみ送信し、受信側に添付が表示されることを確認する。

`waitForReceivedImage`相当の待機ヘルパーは、複数添付・複数種別に対応できるよう拡張する(例: 期待する`message-image`件数と`message-video`件数をそれぞれ受け取り、両方が閾値を超えるまで待つ)。既存の「送信者自身の楽観エコーとの混同を避けるため要素数がpreviousCountを超えるまで待つ」設計は維持する。

クリップボード添付のe2eはこのタスクの範囲外(承認済み方針通りunitテストのみでカバー済み、Task 5で対応済み)。

検証: 実サーバーを起動した上で(`examples/moqt_chat/justfile`の該当レシピ、またはこのタスク実行環境で可能な方法で)`node examples/moqt_chat/e2e/scenarios/s15-image-send.mjs`(または該当のjustfileレシピ経由)を実行し、追加した3ケース全てがPASSすること。実サーバー起動が実行環境の制約で不可能な場合は、その旨と理由をDONE_WITH_CONCERNSとして明記し、コード自体は既存パターンに忠実であることの自己レビューで代替する。

### Task 8: 全体整合性の最終確認(コーディネーターが実施、実装タスクではない)

このタスクはコーディネーター(あなた、controller)自身が最終チェックとして行う。implementer subagentへの委任は不要。内容は最終review前のセルフチェック:

1. `cd examples/moqt_chat/frontend && npm test -- --run && npx tsc --noEmit && npx eslint . && npm run build` が全てclean
2. `git diff --stat src/`(リポジトリルートから)が空であること
3. `grep -rni movie examples/moqt_chat/`(node_modules/out/.next除く)が空であること
4. 既存の他e2eシナリオ(s2, s8, s10, s11, s13, s14のうち主要な2〜3本)がmovie削除の影響を受けずgreenのままであることを実行確認

このタスクは実装ではなくコーディネーターの検証ステップなので、SDDのタスクループ(implementer dispatch → task review)には乗せない。最終whole-branch reviewの前に済ませる。

## 検証(全体)

1. `npm test -- --run`(vitest)で新規/変更テストと既存テストが全て通ること。
2. `npx tsc --noEmit`、`npx eslint .`、`npm run build`がクリーンであること。
3. `just build`(リポジトリルート、movie削除後もexamplesがビルド成功すること)。
4. `grep -rni movie examples/moqt_chat/`(node_modules/out/.next除く)が空になること。
5. 拡張した`s15-image-send.mjs`を実サーバーに対して実行し、複数添付(画像+動画混在)・テキストのみ・添付のみの各ケースで受信側バイト一致を確認する(PASS)。
6. 既存の他e2eシナリオ(s2, s8, s10, s11, s13, s14)がmovie削除の影響を受けず green のままであること(念のため主要な2〜3本を実行して確認)。
7. `git diff --stat src/`が空であること(SDK coreは無変更)。

## 対象外

- 画像/動画の圧縮・リサイズ・EXIF除去等の高度処理。
- 送信中のキャンセル機能。
- アップロード進捗バー(チャンク数以上の細粒度表示)。
- クリップボードのe2eカバレッジ(unitテストのみ)。
- `clipboard.read()`による明示的貼り付けボタン(pasteイベントのみ対応)。
</content>
