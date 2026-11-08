# e2e テスト

[wired](../../README.md) › [moqt_chat](README.md) › e2e テスト

| 項目 | 内容 |
|---|---|
| 目的 | moqt_chat の e2e テストの実行方法とシナリオの一覧を示す |
| 読む人 | サーバーかフロントエンドを変更し、ブラウザーを通して確かめるコントリビューター |
| 前提文書 | [サーバー](server.md)、[フロントエンド](frontend.md) |
| 関連文書 | [MoQT の使い方](wire.md) |

## 1. 準備

1. `cd examples/moqt_chat`
2. `just e2e-setup` を 1 回実行する。Node の依存、puppeteer の Chrome for Testing、最小のコンテナにない共有ライブラリ(`e2e/fetch-chrome-libs.sh`)を入れる。

## 2. レシピ

次の 3 つのレシピは `just build` と `just build-frontend` を先に実行する。

| コマンド | 動作 |
|---|---|
| `just e2e-load --clients=4 --messages=10 --max-loss-rate=0` | `e2e/run.sh`。サーバーと静的なフロントエンドを起動し、ヘッドレスの Chrome の参加者にチャットのメッセージを送らせ、損失と遅延を判定する |
| `just e2e-stability <id> [args]` | `e2e/run-stability.sh`。`e2e/scenarios/<id>.mjs` のシナリオを 1 つ実行する。結果は `tasks/voice-stability/<id>/` に出力する |
| `just e2e-screen [--load]` | `e2e/run-screenshare-check.mjs`。1 人が偽の画面を共有し、もう 1 人がフレームをデコードできるかを確かめる。`--load` では 4 人が同時に共有する |

### 2.1 `e2e-load` の引数

| 引数 | 既定値 | 内容 |
|---|---|---|
| `--clients=N` | 3 | 参加者の数。上限は `MAX_CLIENTS`(4、参加者 ID の数) |
| `--messages=N` | 5 | 参加者ごとのメッセージの数 |
| `--max-loss-rate=R` | 1 | 損失率の上限。1 は判定しない |
| `--max-p95-ms=N` | なし | 遅延の 95 パーセンタイルの上限 |

`e2e-load` が判定するのはチャットだけである。音声の中身は判定しない。

### 2.2 ポート

すべての e2e は `WIRED_E2E_PORT`(既定 4433)で待ち受け・接続し、自分が起動したハブだけを止める。サーバーは SO_REUSEPORT で bind するので、同じポートで別のハブが動いているとパケットを取り合う。ハブが動いているホストでは空いているポートを渡す。

```sh
WIRED_E2E_PORT=14833 just e2e-stability s21-sigterm-goaway
```

### 2.3 Chrome のバージョン

`run-stability.sh` は、`CHROME_PATH` が未設定で `~/.cache/puppeteer/chrome/linux-146.0.7680.153/` に Chrome があるとき、それを使う。Chrome 150 以降はこのサーバーの証明書のハッシュの固定(`serverCertificateHashes`)で `CERTIFICATE_VERIFY_FAILED` になる。

## 3. 安定性のシナリオ

`just e2e-stability <id>` で実行する。

| id | 確かめること |
|---|---|
| `s1-voice-clean` | 4 人のルーム、損失のないネットワークで音声の品質の基準をすべて満たす |
| `s2-chat-longevity` | 2 人が 120 件ずつ送り、1 つの接続で単方向ストリームが 100 本を超えてもチャットを失わない |
| `s3-voice-loss` | 4 人のルーム、UDP プロキシでランダムにパケットを落とし、音声の基準とチャットの損失 0 を満たす(`--loss-rate=0.01` など) |
| `s4-voice-outage-reconnect` | 3 人のうち 1 人の通信が途切れ、その間にブラウザーが落ちても、再参加して音声が戻る |
| `s5-reconnect-churn` | 3 人のうち 1 人がブラウザーの強制終了と再参加を繰り返しても、毎回音声のデコードが戻る |
| `s5b-server-restart` | 通話中にサーバーを SIGKILL して再起動し、クライアントが切断を 3 秒以内に検出して再接続する |
| `s6-voice-soak` | 2 人の音声だけを長時間流す。既定 5 分(`--talk-ms=1500000` で 25 分) |
| `s7-idle-mute` | 全員が 45 秒消音したあとも接続が残り、音声が戻る |
| `s8-late-join` | 3 人の通話に 4 人目が入り、接続から 2 秒以内に最初の音声をデコードする |
| `s9-survivor-hears-rejoin` | 2 人のうち 1 人が落ちて戻り、残った側が戻った側の音声をデコードする |
| `s10-voice-chat-longevity` | 4 人のルームで、チャットを流しながら 60 秒を超えて話す |
| `s11-voice-chat-longrun` | `s10` の長時間版(既定 5 分)。手で実行する |
| `s12-hub-restart-autorejoin` | ハブの SIGKILL と再起動のあと、ページが自分で再参加する |
| `s13-screen-longrun` | 4 人全員が画面を共有し、軽いパケットの損失の下で数分続く |
| `s14-screen-rejoin` | 画面共有の最中に抜けて戻った参加者に、共有とチャットが見える |
| `s15-image-send` | 添付ファイルとテキストのワイヤーの形式を、実際の接続で確かめる |
| `s16-history-join` | 後から入った参加者に、チャットの履歴が届く |
| `s17-video-join-keyframe` | 画面共有の途中から見た参加者が、次のキーフレームを待たずにデコードする |
| `s18-discovery` | 参加者の一覧が、ポーリングではなく名前空間の発見に従う |
| `s19-origin-403` | `WIRED_ALLOWED_ORIGINS` にない Origin からの CONNECT が 403 になる |
| `s20-attachment-1mb` | 1 MB の画像がハブをバイト単位で一致して通る |
| `s21-sigterm-goaway` | SIGTERM でハブが GOAWAY を送り、クライアントが移る |
| `s22-camera` | カメラ、背景のぼかしと画像、mp4、途中参加、停止を Chrome の偽のカメラで確かめる |
| `s23-voice-stream` | データグラムが使えないとき、音声を単方向ストリームで送って届く |

## 4. そのほかの確認

ローカルのサーバーを使うものは、先に `just build build-frontend` を実行する。

| コマンド | 動作 |
|---|---|
| `./e2e/run-voice.sh --clients=4` | 4 人のチャットと音声の負荷テスト |
| `node e2e/run-prod-screenshare-check.mjs --server-url=... --cert-hash=...` | 公開中のフロントエンドと、運用者が起動済みのサーバーで画面共有を測る。前提はファイルの先頭のコメントにある |
| `cd e2e && npm test` | ハーネスの指標の計算の単体テスト(`node --test test/*.test.mjs`) |
