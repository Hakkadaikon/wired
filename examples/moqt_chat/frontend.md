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
2. フロントエンドのページを開く。
3. "Server URL" にサーバーの URL、"Certificate hash (SHA-256)" にフィンガープリントを入れる。
4. "Participant ID" で `user1`〜`user4` から 1 つ選び、接続する。
5. ブラウザーのマイクの許可を承認する。

接続すると音声の送信が始まる。マイクのトグルで消音できる。別の参加者 ID のタブ(またはプライベートウィンドウ)を開くと、2 つのタブの間でチャットできる。

ページの URL に `?ns=0` を付けると、RNNoise のノイズ抑制を切った状態で始まる。e2e のハーネスはこれを使う。

### 2.1 Nostr でログインする

参加の画面の右上にある紫の "Log in with Nostr" を押すと、NIP-07 の拡張機能(nos2x、Alby など)の `window.nostr` から公開鍵を受け取る。秘密鍵はページに渡らず、署名は拡張機能が行う。拡張機能は document_end で注入されるので、ページは最大 1.5 秒待つ。失敗は「拡張機能がない」「拒否された」「公開鍵が不正」を分けて表示する。ログイン後は同じ場所にアイコンと名前と "Log out" が出て、ルームの画面では上の操作の列の右端にアイコンと名前が出る。"Log out" でログインをやめる。

| 項目 | 動作 |
|---|---|
| 送信 | ログイン中、添付のないテキストは NIP-53 の kind 1311 のイベント(`tags: [["a", <ルームの座標>]]`)として拡張機能が署名し、チャットの Track の Object で送る。送る前に、拡張機能が返したイベントの署名、公開鍵、本文、kind、`a` タグを確かめる。1 つでも違えば送らず、送信の失敗として表示する。添付付きのメッセージは従来の形式で送る |
| 受信 | Nostr のイベントの Object は、id と BIP-340 の署名を `verifyEvent` で確かめる。kind 1311 でルームの `a` タグを持つものだけを表示し、不正なものは捨てる。拡張機能のない参加者も従来の形式で送受信でき、Nostr のメッセージも見える |
| 送り手の表示 | 1 行目に kind 0 のプロフィールの `display_name`(NIP-24。なければ非推奨の `displayName`)を太字で、2 行目に `@` と `name` を灰色で小さく出す。`display_name` がなければ 1 行目に `name` だけを、どちらもなければ短い npub だけを出す。名前は 64 文字までで、長ければ末尾を省略し、テキストとして表示する。完全な npub はツールチップに出す。時刻はイベントの `created_at` を右上に出す。本文は名前から半行あけて始まる |
| 検証の印 | 投稿の下に ✓ を出す。マウスを重ねるかキーボードで選ぶと「Verified Nostr event: id and BIP-340 signature checked」を出す。名前や従来のニックネームで Nostr の送り手になりすませないよう、検証したイベントにだけ付く |
| ルームの一覧 | 参加者の Nostr の公開鍵は、その参加者のチャットの Track でライブに初めて届いた検証済みのイベントの公開鍵とする。対応する参加者は、一覧にアイコンと `display_name`(なければ `name`、なければ短い npub)で出る。自分で名乗れるニックネームからは対応付けない |
| アイコン | kind 0 の `picture` を名前の左に小さく出す。`https:` の URL(2048 文字まで)だけを使い、`referrerpolicy="no-referrer"` で読み込む。`picture` がない、不正、読み込めないときは、公開鍵から色を決めた丸を代わりに出す |
| 古いクライアント | この機能より前のビルドは、Nostr のメッセージをその参加者からの生の JSON の 1 行として表示する |
| 元のイベント | Nostr のメッセージの右下の "⋯" で、Object で運ばれたイベントの JSON(検証済みと id)を投稿の下に開く。"Copy raw" は受け取った文字列をそのまま写す |
| ルームの座標 | `NEXT_PUBLIC_NOSTR_ROOM_A`(既定 `30311:<64 桁の 0>:wired-moqt-chat`)。kind 30311 のルームのイベントはまだ公開していない |

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
