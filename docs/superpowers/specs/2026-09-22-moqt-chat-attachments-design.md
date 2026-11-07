# moqt_chat: 複数添付の作成(画像/動画/クリップボード)と動画配信の削除

[ドキュメント](../../README.md) › superpowers › moqt_chat: 複数添付の作成(画像/動画/クリップボード)と動画配信の削除

| 項目 | 内容 |
|---|---|
| 目的 | moqt_chat の複数添付の作成と動画配信の削除の設計書 |
| 読む人 | コントリビューター |
| 前提文書 | なし |
| 関連文書 | [実装計画](../plans/2026-09-23-moqt-chat-attachments.md) |

状態: 承認済みの設計(2026-09-22)。実装計画はこの仕様のあとに続く。

<a id="目的"></a>
## 1. 目的

moqt_chat の画像 1 枚の送信機能(出荷済み: `sendImage`、`moqtImageWire.ts`、`MoqtChatClient.sendImage`/`onImage`)を、汎用の添付付きメッセージ作成の流れに広げる。

1. 1 通の送信メッセージに複数のファイル(最大 4 個)を添付できる。
2. 既存のファイル選択ボタンに加えて、テキスト入力にフォーカスがある状態でクリップボードから貼り付けてファイルを添付できる。
3. 動画ファイルも画像と同じ方法で添付でき、生のバイト列のまま送る(クライアント側でのトランスコードや圧縮はしない)。
4. ファイルを添付しても、すぐには送らない。送信前の下書きにプレビュー(画像/動画はサムネイル、それ以外はファイル名のチップ)付きで積み、1 個ずつ取り除けるようにする。
   - ユーザーが Send を押した時点で、テキスト(あれば)と残っているすべての添付を、1 つの論理メッセージとしてまとめて送る。
5. サーバー側の `--movie` による MP4 のライブ配信機能と、それを使うフロントエンドを丸ごと削除する。隠すのではなく、取り除く。
   - サーバー側: wired_server.c の `publish_movie`、Dockerfile の `--movie` フラグ、`assets/movie-live.mp4`。
   - フロントエンド: `moqtMovieClient.ts`、`moqtLiveClient.ts`、`LivePlayer`、`videoRef` の配線。

添付は引き続き既存の chat の Object チャネルに載せる(新しい MOQT の Track は作らず、動画配信の削除以外にサーバーの変更はない)。出荷済みの画像機能と同じ、固定ルーム・同じ Track Alias の設計を、下の「添付のワイヤーフォーマット」のとおりに広げたものである。

<a id="対象外明示出荷済みの画像機能で削った範囲に合わせる"></a>
## 2. 対象外(明示。出荷済みの画像機能で削った範囲に合わせる)

- 画像/動画の圧縮、リサイズ、EXIF の除去はしない。
- アップロードの進捗バーは、チャンク数からすでに分かる添付ごとの全体の割合表示(UI の節を参照)以上のものは作らない。バイト単位の細かな進捗は出さない。
- 送信中の取り消しはしない。
- 永続化しない: 添付はどこ(サーバーでもクライアントでも)のディスクにも書かない。出荷済みの画像機能と同じで、変更はない。
- clipboard-read() のボタンは作らない。クリップボードからの入口は貼り付けだけ。
- ファイル種別ごとのアイコンライブラリは作らない。
  - 添付されてしまった画像/動画以外の MIME 型は、汎用のファイル名チップで扱う。
  - ファイル選択は accept フィルターで画像/動画に絞るが、貼り付けには同じ絞り込みがかからない(Compose の節を参照)。

<a id="添付のワイヤーフォーマットmoqtattachmentwiretsmoqtimagewirets-を置き換える"></a>
## 3. 添付のワイヤーフォーマット(`moqtAttachmentWire.ts`、`moqtImageWire.ts` を置き換える)

出荷済みのチャンク形式を一般化し、次の 2 つを運ぶ。

- (a) `messageId`: 独立した複数の Object/ストリームを 1 つの論理チャットメッセージにまとめられるようにする。
- (b) `attachmentIdx`: 1 つのメッセージ内の複数の添付が受信側の再組み立ての状態でぶつからないようにする。

<a id="テキスト部"></a>
### 3.1 テキスト部

MoQT の Object 1 個(出荷済みの `buildChatObjectMessage` と同じ、ストリーム 1 本に Object 1 個の形)。ペイロードは次のとおり。

```
marker (1 byte, 0xFE — distinct from the image-chunk marker 0xFF and the
        nickname marker's leading 0x00; see Marker Disambiguation below)
messageId (u32 BE)
attachmentCount (u8)      -- how many attachment parts to expect, 0..4
textLen (u16 BE)
text (UTF-8 bytes, textLen bytes)   -- "" when the message is attachments-only
```

<a id="添付のチャンク部"></a>
### 3.2 添付のチャンク部

チャンクごとに MoQT の Object 1 個(出荷済みの画像チャンクと同じ形)。ペイロードは次のとおり。

```
marker (1 byte, 0xFD — distinct from 0xFF/0xFE/nickname's 0x00)
messageId (u32 BE)
attachmentIdx (u8)        -- 0..3, this attachment's position in the message
seq (u32 BE)              -- unused cross-message; kept for symmetry with
                              the shipped format's per-attachment identity,
                              always 0 in this design (one attachment is one
                              logical "frame" — messageId+attachmentIdx is
                              the real key, seq is vestigial and fixed at 0
                              rather than removed, to reuse
                              splitImageIntoChunks's exact chunk-splitting
                              logic unchanged)
idx (u16 BE)               -- chunk index within this attachment
count (u16 BE)             -- total chunks for this attachment
(idx===0 only) mimeType length (u8) + mimeType (UTF-8) + totalBytes (u32 BE)
data (remaining bytes)
```

<a id="マーカーの見分け方"></a>
### 3.3 マーカーの見分け方

chat の Object チャネルには、先頭バイトのマーカーが 4 種類ある。

- `0x00`: ニックネーム。
- `0xFD`: 添付のチャンク。
- `0xFE`: 添付付きのテキスト。
- `0xFF`: 旧来の単独の画像チャンク。互換の経路が必要なときだけ残す(下の「移行」を参照)。
- マーカーなし: 通常のチャットのテキスト。先頭バイトは有効な UTF-8 のどれかで、RFC 3629 §3 の先頭バイトの表により 0xFD/0xFE/0xFF にはなりえない。チャットのテキストは NUL で始まらないので、0x00 も構造上ありえない。

`classifyChatPayload`(moqtClient.ts)には分岐を 2 つ足し、今と同じくマーカーのバイトを先に見る順にする。

<a id="移行についての注記"></a>
### 3.4 移行についての注記

出荷済みの `moqtImageWire.ts`/`IMAGE_CHUNK_MARKER=0xFF` による画像 1 枚の経路は、この形式に置き換わる。

この仕様の範囲(二重書き込みではなく完全な置き換え)に従い、`moqtImageWire.ts` は削除し、`moqtClient.ts` の `sendImage`/`onImage` は添付付きの `sendMessage`/`onMessage` に置き換える(API の節を参照)。

ワイヤーの後方互換シムは作らない。これは単一リポジトリのデモアプリで、別にデプロイされた古いクライアントを支える必要がないためである。

<a id="受信側の集約状態機械検証済みの設計検証の節を参照"></a>
## 4. 受信側の集約(状態機械。検証済みの設計。「検証」の節を参照)

`MoqtChatClient` に `#pendingMessages: Map<string, PendingMessage>` を加える。キーは `` `${participant}:${messageId}` `` である(messageId だけでは全体で一意にならない。出荷済みの `#imageSeq` と同じく送信者ごとのカウンターだからである)。

```
PendingMessage = {
  text: string | undefined       -- set once the text part arrives
  attachmentCount: number | undefined  -- set once the text part arrives
                                     (attachmentCount travels on the text
                                     part, not derivable from chunks alone)
  attachments: (ReassembledAttachment | undefined)[]  -- length
                                     attachmentCount once known, filled in
                                     as each attachment's chunks complete
  attachmentReassemblers: Map<attachmentIdx, ImageFrameReassembler>
  firstSeenAt: number            -- Date.now() at creation, for timeout
}
```

遷移は次のとおり。
- テキスト部が届き、保留エントリがない: エントリを作り、`text`/`attachmentCount` を設定し、`firstSeenAt = now` とする。
- テキスト部が届き、保留エントリがある(添付が先に届いていた): 既存のエントリに `text`/`attachmentCount` を埋める。`firstSeenAt` はリセットしない。
- 添付のチャンクが届き、保留エントリがない: `text = undefined`、`attachmentCount = undefined`、`firstSeenAt = now` でエントリを作り、そのチャンクを attachmentIdx ごとの新しい `ImageFrameReassembler` に入れる。
- 添付のチャンクが届き、保留エントリがある: その attachmentIdx の再組み立て器に入れる(添付ごとのチャンク完了判定は既存のもので、出荷済みの `imageFrameReassemblerPush` から変えない)。
- ある添付の再組み立てが完了: 結果を `attachments[attachmentIdx]` に格納する。
- 完了判定(上の各遷移のあとに毎回実行): `text !== undefined` かつ `attachmentCount !== undefined` かつ `attachments` の `[0, attachmentCount)` のすべてのインデックスが埋まっていれば、次を行う。
  - 完成した `{text, attachments}` で `onMessage` を呼び、保留エントリを削除する。
- タイムアウト: 定期的な掃除(間隔は計画で決める。例: 5 秒ごと)で、`firstSeenAt` から 30 秒を超えた保留エントリを通知せずに捨てる(コールバックなし。出荷済みの再組み立て器が通知せずに捨てる慣習に合わせる)。
  - 保留エントリは際限なく増えることはない。ルームの人数は 4 人が上限(`CANDIDATE_PARTICIPANT_IDS`)で、実際には各送信者が同時に組み立て途中にできるメッセージは 1 つだけである(送信の経路は、配送が終わるまで次の `sendMessage` 呼び出しを待たせる。API の節を参照)。
  - データ構造そのものには同時数の上限を設けない(承認済みの設計判断どおり YAGNI)。

検証する状態機械はこれである。対象の交互実行は、テキストが先か添付が先か、添付の完了順はどれでも、タイムアウトと到着の競合を含む、あらゆる到達可能なものである。検証では、それぞれが次のどちらかになるかを問う。

- (a) 組み上がった内容でちょうど 1 回 `onMessage` を呼ぶ。
- (b) タイムアウトして `onMessage` を呼ばずに捨てる。

2 回呼ぶことも、欠けたまま呼ぶことも、保留エントリをいつまでも残すこともないかも確かめる。

<a id="クライアント側の送信-apimoqtclientts"></a>
## 5. クライアント側の送信 API(`moqtClient.ts`)

`sendImage`/`onImage` を次で置き換える。

```ts
interface AttachmentInput { bytes: Uint8Array; mimeType: string }
async sendMessage(text: string, attachments: AttachmentInput[]): Promise<void>
```

`MoqtChatCallbacks` の `onImage` は次で置き換える。
```ts
onMessage(participantId: string, text: string, attachments: ReassembledAttachment[]): void
```
既存の `onMessage(participantId, text)` のシグネチャも互換性を壊す形で変わる。

出荷済みのテキストだけの経路は同じコールバックを attachments: [] で通るようになり、テキストだけのメッセージと添付付きのメッセージが 1 つの経路にまとまる。`onNickname` は別のまま変えず、引き続き専用のマーカーで運ぶ。

`sendMessage` の内部の順序: `messageId = this.#messageSeq++` を割り当て、先にテキスト部を送り(ストリーム 1 本)、続いて各添付のチャンクを順に送る(チャンクごとにストリーム 1 本。1 つの添付の中ではチャンクを 1 つずつ待つ。出荷済みの `sendImage` と同じ規律)。

添付どうしは続けて送ってかまわない。出荷済みの「チャンクを同時に送らない」決まりを添付をまたいで広げる必要はない。チャンクのストリームはそれぞれ独立しており、受信側は到着順に関係なく messageId+attachmentIdx をキーにするからである。

<a id="ストアの形moqtchatstorets"></a>
## 6. ストアの形(`moqtChatStore.ts`)

```ts
export type ChatAttachment = {
  bytes: Uint8Array;      // never persisted; kept only for the Blob URL's
                           // underlying data and revoked with it
  mimeType: string;
  url: string;             // URL.createObjectURL(...) result
};

export type ChatMessage = {
  id: number;
  senderId: string;
  text: string;
  at: number;
  own: boolean;
  failed?: boolean;
  attachments: ChatAttachment[];  // replaces imageDataUrl/imageMimeType;
                                    // [] for a plain text message
};
```

`imageDataUrl`/`imageMimeType` のフィールドは取り除く(追加ではなく移行である。ワイヤーフォーマットが完全な置き換えであることに合わせる)。`addMessage` のシグネチャの形は変わらない(`Omit<ChatMessage, "id">`)。

`imageSendError` は `messageSendError` に改名する(型は引き続き `string | null` + セッター)。テキストだけ、添付だけ、両方を含むもののどの送信失敗も、`sendChat` の既存の失敗経路と同じように扱うようになるためである。

これに伴い、`sendChat` と `sendImage` は 1 つの `sendMessage` フックのコールバックにまとまり(UI の節を参照)、失敗の出口は 2 つではなく 1 つになる。

<a id="uipagetsx"></a>
## 7. UI(`page.tsx`)

<a id="compose-が状態を持つdraftattachments"></a>
### 7.1 `Compose` が状態を持つ(`draftAttachments`)

```ts
type Draft = { id: string; bytes: Uint8Array; mimeType: string; previewUrl: string; fileName: string };
```

- ファイル選択の `<input type="file" accept="image/*,video/*" multiple data-testid="attachment-file">`: `multiple` により、1 回の選択で複数のファイルを選べる。
  - 下書き済みのものと合わせて合計 4 個が上限のまま。
  - 上限を超えたファイルは 5MB の上限と同じ `onAttachmentError`/サイズ系の Notice で捨て、メッセージは "up to 4 attachments"。
- テキストの `<input>` の `onPaste` の貼り付けハンドラー: `e.clipboardData.items` を走査し、`kind === "file"` の項目ごとに `getAsFile()` を呼んで下書きに加える(ファイル選択の経路と同じく 4 個/5MB の上限を適用)。
  - 貼り付け全体に `preventDefault()` はかけない。ファイルの項目を実際に見つけて処理したときだけ既定の動作を抑えるので、入力欄へのテキストの貼り付けには影響しない。
- 各下書きは入力欄の上の新しい行にプレビューのチップを描画する。
  - 画像は `<img>`、動画は `<video muted>` の最初のフレームのポスター(ブラウザー標準のポスター描画を使い、サムネイルは生成しない)、それ以外はファイル名のチップである。
  - 各チップには削除(×)ボタン(`data-testid="draft-remove"`)があり、押すとその `previewUrl` を revoke して `draftAttachments` から外す。
- `Send` ボタン(これまでの Enter だけの暗黙の送信から名前を付けたもの。テキスト入力での Enter による送信は既存の動作どおり残る)は、テキストがあるか、下書きの添付が 1 個以上あれば有効になる(これまではテキストのみ)。
  - 送信時は `onSendMessage(text, draftAttachments)` を呼び、`draft` と `draftAttachments` の両方を空にする(その前にすべての `previewUrl` を revoke する)。

<a id="message-コンポーネント"></a>
### 7.2 `Message` コンポーネント

`m.text` を(空でなければ)今と同じく描画し、続けて `m.attachments[i]` ごとに `<img>` / `<video controls>` を 1 つずつ描画する。

- 画像の MIME 型には `data-testid="message-image"`。既存の e2e シナリオのセレクターが動くようにそのまま残す。
- 動画の MIME 型には `data-testid="message-video"`。

それぞれにアンマウント時に revoke する `useEffect` を付ける(今と同じパターンで、単位がメッセージごとから添付ごとに変わる)。

<a id="動画配信の削除"></a>
## 8. 動画配信の削除

- `wired_server.c`: `publish_movie`、動画の Track の定数(`MOVIE_MAX`、`g_movie` など)、`--movie` の CLI 引数の処理、動画の Group のペース配分やタイマーのコードを削除する。削除後、このファイルで `movie` を grep しても何も出ないこと。
- `Dockerfile`: `COPY assets/movie-live.mp4` の行と、ENTRYPOINT の `--movie /movie.mp4` 引数を取り除く。
- `assets/movie-live.mp4`(と、ほかから参照されていなければ `assets/movie.mp4`。計画で確かめる)をリポジトリから削除する。
- フロントエンド: `moqtMovieClient.ts`、`moqtLiveClient.ts` とそれらのテストファイルを削除する。
  - `LivePlayer`、`videoRef`、そして `useMoqtChat.ts` の `onUnknownUniStream` ハンドラーと `moqtClient.ts` にある `MOVIE_INIT_TRACK_ALIAS`/`MOVIE_TRACK_ALIAS` の分岐(動画用の Alias 定数がそこにあれば。計画で確かめる)を取り除く。
- e2e: `run-live-check.mjs` と justfile の `just e2e-live` レシピを削除する。
- これは `src/app/moqt/run/*.c` に隣接する変更で(`src/` ではなく wired_server.c)、SDK のコア(`src/`)には手を入れない。
  - なくなるのは example のサーバーバイナリ自身の `--movie` 機能だけである。
  - 出荷済みの画像機能と同じ規律で、計画の検証の節で `src/` に差分がないことを確かめる。

<a id="検証の層"></a>
## 9. 検証の層

1. 状態遷移/並行性: 対象。上の受信側の集約の状態機械(テキストと添付の到着の交互実行、タイムアウトの競合、Map 内で送信者ごとに複数の保留メッセージ)。
   - 実装の前に検証する。
   - 結果(安全と確かめた交互実行と、検証で必要になった設計の修正)は、この仕様の上の集約の節と、計画から導くテストリストにそのまま反映する。
2. Lean で扱うべき重要なアルゴリズム: 対象外。チャンクのエンコード/デコードと再組み立ては、出荷済みで TDD でカバー済みの `moqtImageWire.ts` のパターンを広げたもので、往復テストで確かめられる。
   - 出荷済み機能の TDD の往復テストがすでに覆っている範囲を超える、新しい暗号上の性質や網羅的な分類の性質はない。
3. TDD への橋渡し: 状態機械で安全と確かめた交互実行(または検証で必要になった修正)を、`moqtAttachmentWire.test.ts` と `moqtClient.test.ts` の集約テストのテストリストにする。
   - 交互実行や境界のケースごとに 1 テストである。
   - ケース: テキストが先、添付が先、組み立て途中のタイムアウト、別々の送信者からの同時の複数保留メッセージ、添付 0 個のテキストだけのメッセージ、添付 4 個のメッセージ。

<a id="テストの範囲"></a>
## 10. テストの範囲

- 単体(vitest、TDD)は次のとおり。
  - ワイヤーのエンコード/デコードの往復(`moqtAttachmentWire.test.ts`)
  - 集約の状態機械(`moqtClient.test.ts`。検証済みの設計に基づく)
  - ストアの形(`moqtChatStore.test.ts`)
  - `page.tsx` から純粋関数として切り出せる範囲での Compose の下書き/貼り付け/削除のロジック(貼り付け項目の絞り込み、上限の適用)
  - useMoqtChat の配線(`moqtChatCallbacks` の添付付き `onMessage` から `store.addMessage` への変換)
- e2e(Puppeteer。出荷済みの `s15-image-send.mjs` のパターンに合わせる): 主な経路を覆う新しいシナリオを 1 つ作る。
  - テキスト + 添付 2 個(画像を 1 個以上、動画を 1 個以上)のメッセージを送り、受信側でバイト単位で同一であることを確かめる。
  - 同じシナリオファイルで、テキストだけの場合と添付だけの場合も確かめる。
  - クリップボードからの貼り付けは e2e では扱わない(承認済みの判断どおり)。代わりに、貼り付けハンドラーの純粋なロジックを vitest の単体テストで確かめる。
- 動画配信の削除: 削除したコードにテストは要らない。
  - 計画の検証の手順で、`examples/moqt_chat/` の下で `grep -rn movie`(大文字小文字を区別しない)がこの仕様とコミット履歴以外に何も返さないこと、既存の e2e/単体のスイート(動画のテストを除いたもの)が緑のままであることを確かめる。

<a id="移行互換性"></a>
## 11. 移行/互換性

不要である。単一リポジトリのデモで、出荷済みの画像 1 枚のワイヤーフォーマットが変わらないことに依存する、外部にデプロイされたクライアントはない。出荷済み機能のファイル(`moqtImageWire.ts`、そのテスト、`sendImage`/`onImage` メソッド)は置き換え、新しい形式と並べて残すことはしない。
