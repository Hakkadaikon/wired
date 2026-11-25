# フロントエンド

[wired](../../README.md) › [moqt_chat](README.md) › フロントエンド

| 項目 | 内容 |
|---|---|
| 目的 | moqt_chat のフロントエンドの使い方、開発、デプロイ、カメラと動画の送信、Nostr のログインを示す |
| 読む人 | フロントエンドを動かす・変更するコントリビューター |
| 前提文書 | [moqt_chat](README.md)、[サーバー](server.md) |
| 関連文書 | [MoQT の使い方](wire.md)、[e2e テスト](e2e.md) |

## 1. 構成

| 項目 | 内容 |
|---|---|
| フレームワーク | Next.js と React。スタイルシートは独自のもの |
| 出力 | `output: "export"`(`next.config.ts`)。静的ファイルだけを出力し、配信に Node のサーバーを使わない |
| デプロイ先 | GitHub Pages だけ |

## 2. ルームに入る

1. サーバーを起動し、ログからフィンガープリントを写す([サーバー 2.2](server.md#22-自己署名の証明書のフィンガープリント))。
2. ルームのリンク(`?room=<id>&host=<pubkey>`)でページを開く。リンクがなければ、ルームを作る(2.1 節)。
3. "Server URL" にサーバーの URL、"Certificate hash (SHA-256)" にフィンガープリントを入れる。
4. "Participant ID" で `user1`〜`user4` から 1 つ選び、接続する。
5. ブラウザーのマイクの許可を承認する。

接続すると音声の送信が始まる。マイクのトグルで消音できる。別の参加者 ID のタブ(またはプライベートウィンドウ)を開くと、2 つのタブの間でチャットできる。

ページの URL に `?ns=0` を付けると、RNNoise のノイズ抑制を切った状態で始まる。e2e のハーネスはこれを使う。

### 2.1 ルームを作る、リンクで入る

ルームはページの URL で決まる(`roomLink.ts`)。ビルドの設定は要らない。

| URL | 参加の画面 |
|---|---|
| `room` も `host` もない | "Create room" と、参加の条件("Open" か "Login required"。既定は "Open")を出す。押せるのは Nostr でログインし、kind 0 のプロフィールに `nip05`(`name@domain` の形)があるときだけで、ログインした公開鍵がホストになる。`nip05` がなければ "A NIP-05 address is required to create a room" を出す。押すと、16 バイトの乱数(`crypto.getRandomValues`)を base64url にした 22 文字のルーム ID を作り、`history.replaceState` で URL に `room` と `host` を足す。そのあとは下の行と同じ |
| `room` と `host` が正しい | "Joining room <ルーム ID>" と、共有のリンク `<ページの URL>?room=<id>&host=<hex>`("Copy share link" で写す)を出し、ふだんどおり参加できる |
| どちらかが不正 | "Invalid room link: ..." を出す。"Join" は押せず、接続しない。"Create room" は出る |

ルーム ID は base64url の 22 文字で、16 バイトを表す形(最後の文字が `A`、`Q`、`g`、`w` のどれか)だけを受け付ける。`host` は 64 桁の小文字の hex か npub で、npub は hex に直す。共有のリンクにはページの URL のほかの引数(`?relays=` など)を入れない。

ルームは名前空間 `wired/moqt_chat/<room>` と NIP-53 の space の座標 `30312:<host>:<room>` を決める([MoQT の使い方](wire.md) 3 節、5.3 節)。クライアントは自分のルームの名前空間だけを使い、ハブもセッションをそのルームの名前空間に閉じ込める([MoQT の使い方](wire.md) 2.3 節)。

ページはどの接続でも、"Server URL" に `?room=<id>&host=<hex>` を足した URL に WebTransport でつなぐ(`roomAuth.ts` の `roomSession`)。ハブの CONNECT の `:path` に、ルームとホストが入る。Nostr でログインしていれば、接続のたびに NIP-98 のイベントを拡張機能に署名させ、SETUP の AUTHORIZATION TOKEN で送る([MoQT の使い方](wire.md) 2.1 節)。トークンは 1 回しか使えないので、作成、参加、自動の再参加のどれでも署名し直す。署名を拒まれたとき(拡張機能がない場合を含む)は接続が失敗し、"Could not connect" に理由を出す。自動では試し直さず、"Join" か "Rejoin" を押すと署名からやり直す。ログインしていなければトークンを送らない。"Open" のルームにはそのまま入れ、"Login required" のルームはハブが `unauthorized` で断る。ルームを作ったページは、ログインした鍵がルームの `host` と同じときだけ、接続のたびにイベントへ `nip05` と `["wired-room", <id>, "open" か "auth"]` を入れる。"Leave" か最終画面でこの作成の情報を捨てる。トークンは 1 KiB までで、超える長さの "Server URL" では署名を頼まずに接続をやめる([MoQT の使い方](wire.md) 2.1 節)。

`nip05` は kind 0 から読むだけで、ページは `/.well-known/nostr.json` を取りに行かない。NIP-05 を確かめるのはハブの側(nip05d)で、問い合わせ先の制限(SSRF の対策)もそちらが受け持つ(tasks/moqt-chat-rooms.md の P4)。

ハブがセッションを閉じたときの理由が下の表のトークンなら、ページは自動で再参加せず、"Room closed" の画面に表のメッセージを出す。参加の前(SETUP を断られたとき)も参加の後も同じである。この画面が出た時点で "Leave" と同じ後片付けをする。セッションを閉じ、マイク、カメラ、画面共有を止め、上の操作の列を消す。見出しにフォーカスを移すので、スクリーンリーダーは画面が変わったことを読み上げる。"← Back" で参加の画面に戻る。理由のない終わり方(ネットワークが切れた、ハブが落ちた)は、これまでどおり自動で再参加する。

| 理由 | 画面のメッセージ |
|---|---|
| `malformed-auth` | The hub could not read this client's sign-in token. |
| `expired-auth` | The sign-in token was too old when the hub checked it. Check this computer's clock. |
| `unauthorized` | The hub refused the sign-in. This room may need a Nostr login. |
| `nip05-unverified` | Your NIP-05 address could not be verified, so the room was not created. |
| `room-full` | The room is full: it holds 4 participants. |
| `id-taken` | Someone in this room already uses your participant ID. Pick another one and join again. |
| `no-room-slots` | The hub has no free room. Try again later. |
| `no-such-room` | This room does not exist. Check the link; the hub may have restarted. |
| `room-ended` | The room has ended. |
| `replaced` | Your participant ID was taken over by a newer session of your Nostr key. |

ルームは作ってから 5 時間で終わる(`ROOM_LIFETIME_S`。終わらせるのはハブ)。ホストは live の meeting(kind 30313)に `ends`(作った時刻 + 5 時間)を入れ、ルームの見出しは状態の横に残り時間("4:59:12 left")を 1 秒ごとに出す。`ends` が過ぎたとき、または今から 5 時間 5 分(時計のずれの分)より先のときは出さない。ルームを作ったページでないホスト(作ったあとに再読み込みした場合など)は、その meeting の開始から数える。"Login required" のルームの space(kind 30312)は `status` を `private` にする。作ったページでないホストはモードを知らないので `open` を送る。ハブはモードも作成の時刻もクライアントに知らせないので、再読み込みしたホストの残り時間と space の `status` は正しくないことがある。

`id-taken` だけは終わりの画面をすぐには出さない。一覧で見かけた ID と試した ID を飛ばして、次の空いている ID で参加し直し、「user2 is in use in this room: joined as user3」のように知らせる(`roomStatus.tsx` の `useIdTakenRetry`)。4 つすべてを試しても入れないときに、終わりの画面を出す。試した ID の記録は、接続が保たれたときと部屋が変わったときに消す。入り直しでは退出の後片付けをせず、セッションだけを差し替える。ハブの SETUP を 5 秒待っても来なければ、接続を閉じて通常の再接続に移る(`moqtClient.ts` の `HUB_SETUP_TIMEOUT_MS`)。

ハブはトークンを確かめ、上の理由のトークンで閉じる([サーバー](server.md) 5 節)。1 つのハブは 3 つのルームに 4 人ずつを受け入れる([サーバー](server.md) 3 節)。

### 2.2 Nostr でログインする

参加の画面の右上にある紫の "Log in with Nostr" を押すと、NIP-07 の拡張機能(nos2x、Alby など)の `window.nostr` から公開鍵を受け取る。秘密鍵はページに渡らず、署名は拡張機能が行う。拡張機能は document_end で注入されるので、ページは最大 1.5 秒待つ。失敗は「拡張機能がない」「拒否された」「公開鍵が不正」を分けて表示する。ログイン後は同じ場所にアイコンと名前と "Log out" が出て、ルームの画面では上の操作の列の右端にアイコンと名前が出る。"Log out" でログインをやめる。

| 項目 | 動作 |
|---|---|
| 送信 | ログイン中、添付のないテキストは NIP-53 の kind 1311 のイベントとして拡張機能が署名し、チャットの Track の Object で送る。タグは space の `a`(root)と、meeting が live のときはその `a` である([MoQT の使い方](wire.md) 5.3)。送る前に、拡張機能が返したイベントの署名、公開鍵、本文、kind、`a` タグを確かめる。1 つでも違えば送らず、送信の失敗として表示する。添付付きのメッセージは従来の形式で送る。ルームのほかのイベント(presence、space、meeting、リアクション、削除)も同じように確かめてから送る(`signOwnEvent`) |
| 受信 | Nostr のイベントの Object は、id と BIP-340 の署名を `verifyEvent` で確かめる。kind 1311 で space の `a` タグを持つものだけを表示し、不正なものは捨てる。拡張機能のない参加者も従来の形式で送受信でき、Nostr のメッセージも見える |
| 送り手の表示 | 1 行目に kind 0 のプロフィールの `display_name`(NIP-24。なければ非推奨の `displayName`)を太字で、2 行目に `@` と `name` を灰色で小さく出す。`display_name` がなければ 1 行目に `name` だけを、どちらもなければ短い npub だけを出す。名前は 64 文字までで、長ければ末尾を省略し、テキストとして表示する。完全な npub はツールチップに出す。時刻はイベントの `created_at` を右上に出す。本文は名前から半行あけて始まる |
| 検証の印 | 投稿の下に ✓ を出す。マウスを重ねるかキーボードで選ぶと「Verified Nostr event: id and BIP-340 signature checked」を出す。名前や従来のニックネームで Nostr の送り手になりすませないよう、検証したイベントにだけ付く |
| ルームの一覧 | 参加者の Nostr の公開鍵は、その参加者の Track に届いた検証済みのイベントのうち、`["wired-participant", <その参加者の ID>]` を持つものの公開鍵とする。チャットの Track ならライブのもの、presence の Track なら 3 分以内のもの(fill でもよい)である。ほかの人のイベントを運び直しても対応付かない。そのため、まだ投稿していない人も参加してすぐに名前で出る。対応する参加者は一覧にアイコンと `display_name`(なければ `name`、なければ短い npub)で出る。自分で名乗れるニックネームからは対応付けない |
| アイコン | kind 0 の `picture` を名前の左に小さく出す。`https:` の URL(2048 文字まで)だけを使い、`referrerpolicy="no-referrer"` で読み込む。`picture` がない、不正、読み込めないときは、公開鍵から色を決めた丸を代わりに出す |
| 古いクライアント | この機能より前のビルドは、Nostr のメッセージをその参加者からの生の JSON の 1 行として表示する |
| 元のイベント | Nostr のメッセージの右下の "⋯" で、Object で運ばれたイベントの JSON(検証済みと id)を投稿の下に開く。"Copy raw" は受け取った文字列をそのまま写す |
| ルームの座標 | NIP-53 の meeting space `30312:<host>:<room>`。ルームのリンクの `host` と `room` で決まる(2.1 節)。space の名前(`room` タグ)は `Room <ルーム ID の先頭 6 文字>`、meeting の題は `Open session` |
| ホスト | ルームのリンクの `host` の公開鍵でログインした人。参加すると space(kind 30312)と live の meeting(kind 30313。`ends` 付き、2.1 節)を送り、参加者が変わると meeting を更新し、"Leave" で ended を送る |
| ルームの見出し | メッセージの上に space の名前(届く前は `Room <ルーム ID の先頭 6 文字>`)、meeting の題、状態(LIVE、ENDED など)、live の meeting に `ends` があれば残り時間を出す。meeting が届いていなければ "No meeting announced" を、ハブが Nostr の Track を拒んだときは "Room events unavailable: the hub refused the Nostr tracks" を出す |
| 挙手 | ログイン中は上の操作の列に "Raise hand"(`aria-pressed`)が出る。押すと `hand` 付きの presence を送り、一覧の自分と、ほかの人の画面のその人に "HAND" の札が出る。送れなければ押す前に戻す。presence は 60 秒ごとに送り直し、3 分より古いものは使わない。札は 30 秒ごとに古さを確かめ直す |
| リアクション | Nostr の投稿の ✓ の右に、内容ごとの数(`+ 1` など)を出す。ログイン中は "React" で `+`、❤️、😂、🎉 を開き、選ぶと kind 7 を送る。数の札を押すと同じ内容を送る。自分が送った内容のボタンは押せなくなる。同じ人の同じ内容は 1 回だけ、1 人 4 種類まで数え、数は 999 で止める。従来の形式の投稿には付かない |
| 削除 | 自分の Nostr の投稿の "⋯" の左に "Delete" が出る。押すと kind 5 を送り、投稿は全員の画面で「<名前> deleted this message」(自分の投稿なら「You deleted this message」)の行になり、行の高さは保たれる。削除の作者と投稿の作者が違えば従わない。ハブの履歴には元のイベントが残る |

#### プロフィールのリレー

プロフィール(kind 0)は、参加の画面の "Profile relays" の一覧から読む。1 行に 1 つの `wss://` の URL を書く(`ws://` は localhost だけ)。重複を除き、10 個までを使い、参加の設定と一緒に localStorage に保存する。"Reset relays to defaults" で既定に戻す。

既定のリレーは `wss://relay-jp.nostr.wirednet.jp`、`wss://yabu.me`、`wss://r.kojira.io`、`wss://relay.damus.io`、`wss://relay.primal.net`(`DEFAULT_NOSTR_RELAYS`)である。ページの URL の `?relays=a,b` は一覧より優先し、`?relays=` は 1 つも使わない(e2e はこれで公開のリレーにつながない)。

公開のリレーは読むだけである。送るのは kind 0 の REQ だけで、EOSE か 3 秒で閉じる。EVENT も AUTH も送らない。チャットのイベントはハブだけを通る。

捨て鍵を使う参加者 1 人がすべてのブラウザーに公開のリレーへの問い合わせを繰り返させないよう、問い合わせを絞る(`ProfileResolver`)。

| 項目 | 値 |
|---|---|
| まとめ方 | 300 ms の間に現れた公開鍵を 1 つの REQ(`authors: [...]`)にまとめる。1 つの REQ に 50 人まで |
| 頻度 | 1 分に 6 REQ まで。超えた分は次の 1 分に回す |
| キャッシュ | 256 人まで(古いものから捨てる)。見つからなかったときと失敗は、5 分たつかリレーの一覧が変わると問い合わせ直す |

ログインするか Nostr のメッセージが届くと、ページはこれらの公開のリレーに WebSocket でつなぎ、送り手の公開鍵を問い合わせる。リレーの運用者には、接続元の IP アドレスと、このルームで話した人の公開鍵が見える。

アイコンを出すと、ブラウザーは参加者がプロフィールに書いたホストから画像を取りに行く。そのホストには、メッセージを見た人の IP アドレス、ブラウザーの種類、画像を表示した時刻が見える。そのホストの Cookie も送られうる。

## 3. 開発とデプロイ

| 用途 | 方法 | URL |
|---|---|---|
| 開発 | `just dev-frontend`(`pnpm dev`)。ホットリロードする | `http://localhost:3000/` |
| 静的エクスポート | `just build-frontend`(`pnpm build`)。`frontend/out/` に出力する | — |
| 公開 | `.github/workflows/docs.yml` が `main` への push ごとにビルドし、GitHub Pages にデプロイする | `https://hakkadaikon.github.io/wired/moqt_chat/` |

`http://localhost` はスキームによらず secure context なので、開発サーバーからも WebTransport で接続できる。

GitHub Pages のサイトはルートに Doxygen の API リファレンス、`/guide/` にガイド、`/moqt_chat/` にこのフロントエンドを置く。ビルドでは `NEXT_PUBLIC_BASE_PATH=/wired/moqt_chat` を渡す。GitHub Pages は静的ファイルだけを配信するので、`wired_server` は別のホストで動かす。自己署名の証明書のフィンガープリントは UTC の日が変わると変わるので、公開ページからも毎回入れる。

## 4. フォーマット、リント、単体テスト

| コマンド | `frontend/` での同じコマンド | 動作 |
|---|---|---|
| `just check-frontend` | `pnpm check` | `biome ci --error-on-warnings`。フォーマット、リント、import の順序を書き換えずに検査する。警告も失敗にする |
| `just fix-frontend` | `pnpm fix` | Biome のフォーマットと安全な修正をその場で当てる |
| `just test-frontend` | `pnpm test` | vitest の単体テスト。`testvectors/moqt_golden.json` で固定する |

Biome の設定は `frontend/biome.json` にある。recommended のルールに、Next.js、React、テストのドメインを足す。フォーマッターは Biome の既定(タブ、ダブルクォート、80 桁)を使う。

1 か所に合わないルールは、その行だけ `// biome-ignore lint/<group>/<rule>: <reason>` で止める。設定は緩めない。

## 5. カメラと動画

画面の Video の欄から、参加者の `<id>/camera` の Track(Track Alias 18 + 添字)に 1 つの映像を送る。画面共有と同時に送れる。

| 項目 | 動作 |
|---|---|
| Camera | ブラウザーの既定のカメラを送る |
| Background | `None`、`Blur`、`Image`。MediaPipe の selfie segmenter で人物を切り出し、アプリの WebGL2 のシェーダーで、ぼかしたフレームか同梱の画像に重ねてからエンコードする |
| Video file | 同梱の mp4(または選んだローカルの mp4)を、カメラの代わりにループで送る。映像だけを送り、音声は送らず再生もしない |

背景を変えてもカメラは再起動しない。背景を選んでいるときは、合成したフレームだけを送る。segmenter の読み込み中や切り出しの失敗時は、フレームを送らない。

カメラと動画ファイルは 1 つの Track を共有する。一方を送っている間にもう一方を選ぶと、Track を終えずに送る元を切り替える。送っている方をもう一度押すと止まる。

受け取る側はカメラのタイルに表示する。タイルは、送る側が止めたときか、フレームが届かなくなったときに消える。エンコーダーは画面共有と同じ VP8 のパイプラインである。

### 5.1 同梱のファイル

すべてアプリと同じ Origin から配信し、CDN は使わない。

| ファイル | 出所 |
|---|---|
| `public/mediapipe/selfie_segmenter.tflite` | MediaPipe の selfie segmenter(Apache-2.0)。`storage.googleapis.com/mediapipe-models/image_segmenter/selfie_segmenter/float16/latest/selfie_segmenter.tflite`、sha256 `191ac9529ae506ee0beefa6b2c945a172dab9d07d1e802a290a4e4038226658b` |
| `public/mediapipe/vision_wasm_internal.{js,wasm}` | `predev` と `prebuild` が `@mediapipe/tasks-vision`(Apache-2.0、`pnpm-lock.yaml` で固定)から写す。コミットしない |
| `public/worklets/rnnoise-sync.js` | `predev` と `prebuild` が `@jitsi/rnnoise-wasm` から写す。コミットしない |
| `public/videos/sample.mp4` | `ffmpeg -f lavfi -i mandelbrot=size=480x270:rate=15 -t 8 -c:v libx264 -profile:v baseline -pix_fmt yuv420p` で作る |
| `public/backgrounds/default.jpg` | `ffmpeg -f lavfi -i gradients=size=1280x720:c0=0x1d4e89:c1=0x3fa7d6:x0=0:y0=0:x1=1280:y1=720:nb_colors=2 -frames:v 1 default.jpg` で作る |
