# フロントエンド

[wired](../../README.md) › [moqt_chat](README.md) › フロントエンド

| 項目 | 内容 |
|---|---|
| 目的 | moqt_chat のフロントエンドの使い方、開発、デプロイ、カメラと動画の送信を示す |
| 読む人 | フロントエンドを動かす・変更するコントリビューター |
| 前提文書 | [moqt_chat](README.md)、[サーバー](server.md) |
| 関連文書 | [MoQT の使い方](wire.md)、[e2e テスト](e2e.md) |

## 1. 構成

| 項目 | 内容 |
|---|---|
| フレームワーク | Next.js と React。スタイルシートは 1976 年の NASA Graphics Standards Manual を手本にした独自のもの |
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
