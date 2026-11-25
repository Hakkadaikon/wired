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

### 2.4 RNNoise

e2e は既定で RNNoise を切って(`?ns=0`)参加する。伝送の基準(損失・ジッター・PLC)をワークレットの CPU から切り離すためである。本番の既定(RNNoise を有効)で確かめるときは `E2E_RNNOISE=1` を付ける。

```sh
E2E_RNNOISE=1 just e2e-stability s9-survivor-hears-rejoin
```

4 コアのマシンで 4 人のシナリオを流すと、伝送の損失が 0 でも PLC の基準で落ちることがある。4 つのワークレットが CPU を取り合うためで、2 人のシナリオで判定する。

### 2.3 Chrome のバージョン

`run-stability.sh` は、`CHROME_PATH` が未設定で `~/.cache/puppeteer/chrome/linux-146.0.7680.153/` に Chrome があるとき、それを使う。Chrome 150 以降はこのサーバーの証明書のハッシュの固定(`serverCertificateHashes`)で `CERTIFICATE_VERIFY_FAILED` になる。

### 2.5 ルーム

ハブはルームを必ず確かめる([サーバー](server.md) 5 節)。`run-scenario.mjs` は毎回、次を起動してからハブを `--public-url https://localhost:<port> --nip05 <nip05d>` で起動する(`e2e/lib/roomsE2e.mjs`)。

| 部品 | 内容 |
|---|---|
| NIP-05 のフィクスチャ | ループバックの HTTPS(`openssl` で作る自己署名の証明書)。`Host` が `k<n>.e2e.test` なら `{"names":{"user":<試験用の鍵 n の公開鍵>}}` を返す |
| nip05d | `run-stability.sh` がビルドし、`-allow-host 127.0.0.1:<フィクスチャのポート>` で起動する。このフラグは e2e 専用で、ふだんの SSRF の制限はそのまま残る([nip05d](nip05d/README.md)) |
| NIP-07 の模擬 | `nostrE2e.mjs` の `nostrLogin`。署名は Node が試験用の鍵(`keyOf(n)`、32 バイトすべて n)で行う |
| プロフィールのリレーの模擬 | 作成者のページだけ、`window.WebSocket` を差し替え、kind 0(`nip05` = `user@k<n>.e2e.test`)を返す。ドメインを鍵ごとに分けるのは、ハブがドメインごとに 1 つのルームしか作らせないためである |

ルームを作るのは `stabilityClient.mjs` の `createRoomClient(opts, n, mode)` である。鍵 n でログインし、"Create room" を押して接続し、ハブのログに `moqt room: live` が出るまで待つ。`client.link` が参加者の使うリンクになる。ページの URL に `room` のないシナリオ(s1〜s23)は、最初の参加者が鍵 9 で既定のルームを作り(`args.mjs` の `defaultRoom`)、残りの参加者はそこに入る。

`e2e-load`、`run-voice.sh`、`e2e-screen` も同じように、最初の参加者が既定のルームを作る(`roomsE2e.mjs` の `defaultRoomJoin`)。`run.sh` と `run-voice.sh` は `node e2e/lib/roomsE2e.mjs` でフィクスチャと nip05d を起動し、ハブのフラグを受け取る。

ハブを再起動するとルームが消える。s5b では作成者が新しいページで既定のルームを作り直してから、ゲストが入る。s12 と s21 では、作成者のタブが同じルームを作り直す。ゲストはそれより先に着けば `no-such-room` の画面から手で参加し直す(`roomsE2e.mjs` の `guestBack`)。

既定のルームはハブの寿命(5 時間)で終わる。長時間のシナリオ(s6、s11、s13)は `--room-lifetime 86400` を渡す。

`run-prod-conncheck.mjs` と `run-prod-screenshare-check.mjs` は運用中のハブにルームを作れないので、`--page-url` にルームのリンク(`?room=<id>&host=<hex>`)を渡す。
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
| `s24-nostr-chat` | NIP-07 の模擬の拡張機能でログインした 2 人が kind 1311 のメッセージを交わし、互いの短い npub で表示され、ルームの一覧にも出る。拡張機能のない 1 人も従来の形式で送受信できる。投稿に検証の印が付き、"⋯" で元のイベントを開閉できる。user1 がルームを作る。`?relays=` で公開のリレーにはつながない |
| `s25-nostr-room` | NIP-53 の meeting space。ホスト(user1)とゲスト(user2)が模擬の拡張機能でログインする。ゲストにホストの space の名前、meeting の題と LIVE が出て、投稿の前からホストが一覧に名前で出る(presence)。ゲストの挙手がホストに見え、ゲストの `+` がホストの投稿に `Like: 1` と数えられ、ホストの削除でゲストの画面の投稿が削除の行になる。最後にホストが退出すると、ハブがホストの 30313(ended)でルームを終え、ゲストは `room-ended` の終わりの画面を出す。ルームは user1 が自分の試験用の鍵で作る。`--shots=<dir>` で画面を保存する |
| `s26-rooms` | 1 つのハブの 2 つのルームが混ざらない。2 つの場合を順に確かめる。1 つ目は user1 と user2 がルーム A に、user3 と user4 がルーム B に入る。2 つ目は両方のルームに user1 と user2 が入る(同じ参加者 ID)。どの参加者も同じルームの相手を一覧に出してそのメッセージを受け取り、接続を保つ。別のルームのメッセージは出ず、1 つ目の場合は別のルームの参加者も出ない。各ルームの最初の参加者がホストの鍵でルームを作る。ホストの退出でルームが終わるのを待ってから、2 つ目の場合を流す |

| `s27-room-admission` | 入室の規則と終わりの画面。作成で `live` になり、参加でき、同じ参加者 ID は `id-taken`、5 人目は `room-full`、別のホストのリンクは `unauthorized`、Login required のルームへのログインなしの参加は `unauthorized`(ログインすれば入れる)、3 つのルームがあるときの 4 つ目の作成は `no-room-slots` |
| `s28-room-timers` | 短くした時間でルームが終わる。1 人だけ(`alone`)、全員が去ってからの猶予(`empty`。そのあとリンクで来た参加者は `room-ended`)、寿命(`lifetime`)。メンバーは `room-ended` の終わりの画面を出す |
| `s29-room-nip05` | nip05d が動いていればルームが開き、止めたあとの作成は 3 秒後に `nip05-unverified` で終わる。その間も、すでに開いているルームの 2 人は接続を保ち、メッセージが届く |

ハブが SETUP の時点でセッションを閉じたとき(`room-full`、`no-such-room`、`no-room-slots`)に Chrome 146 のレンダラーが SEGV で落ちる問題は、ハブが入室を決めるまで自分の SETUP を送らず、クライアントがハブの SETUP を待ってからリクエストを開くことで直した。いま残る失敗は Chrome のブラウザープロセスの起動の失敗で、ハーネスは 1 回だけ起動をやり直す(`stabilityClient.mjs` の `launchChrome`)。

`malformed-auth`、`expired-auth`、`server-busy` は、このフロントエンドからは起こせない。フロントエンドは拡張機能が返したイベントの `created_at` が頼んだ値と違えば送らない(`nostr.ts` の `signOwnEvent`)ので、Node の署名で時刻をずらしても `expired-auth` にはならない。ハブの単体テスト(`tests/app/chatroom_test.c`)とフロントエンドの単体テストで確かめる。

## 4. そのほかの確認

ローカルのサーバーを使うものは、先に `just build build-frontend` を実行する。

| コマンド | 動作 |
|---|---|
| `./e2e/run-voice.sh --clients=4` | 4 人のチャットと音声の負荷テスト |
| `node e2e/run-prod-screenshare-check.mjs --server-url=... --cert-hash=...` | 公開中のフロントエンドと、運用者が起動済みのサーバーで画面共有を測る。前提はファイルの先頭のコメントにある |
| `cd e2e && npm test` | ハーネスの指標の計算の単体テスト(`node --test test/*.test.mjs`) |
