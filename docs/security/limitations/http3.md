# 既知の制限: HTTP/3 と WebTransport

[ドキュメント](../../README.md) › [セキュリティ設計](../README.md) › [既知の制限](README.md) › HTTP/3 と WebTransport

| 項目 | 内容 |
|---|---|
| 目的 | WebTransport、HTTP/3、QPACK の制限を示す |
| 読む人 | `src/app/` を変更するコントリビューター、サーバーを本番に入れる人 |
| 前提文書 | [既知の制限](README.md) |
| 関連文書 | [容量の上限](capacity.md)、[RFC 9114 の台帳](../../features/rfc9114.md)、[RFC 9204 の台帳](../../features/rfc9204.md) |

## 1. WebTransport

### 1.1 制御ストリームの滞留に上限がある

影響: 大きな制御フレームを送る相手。

相手の制御ストリームのうち未解析の分は、`WIRED_SRVLOOP_CTRL_BUF_CAP`(512 バイト)に収まる必要がある。それより大きいフレームや欠落があると、H3_EXCESSIVE_LOAD で接続を閉じる。

参照: `priority_ctrl.c`

### 1.2 接続ごとの未送信のブロードキャストデータグラム

影響: データグラムをまとめてブロードキャストするアプリケーション。

接続は 1200 バイトまでのデータグラムを `SRVRUN_DG_PENDING_Q`(4)個までキューに入れる。キューが埋まっていると、いちばん新しいものを断る。

参照: `SRVRUN_DG_PENDING_Q`

### 1.3 セッション確立前のデータグラムのバッファリングには限りがある

影響: セッションの確立前にデータグラムを送るクライアント。

`WIRED_WT_BUFFERED_DATAGRAM_CAP`(256)バイトまでのデータグラムを `WIRED_WT_MAX_BUFFERED_DATAGRAMS`(4)個保持する。それより長いものは切り詰めずに丸ごと捨てる。

参照: `WIRED_WT_BUFFERED_DATAGRAM_CAP`(ponytail)

### 1.4 データグラムのリングのスロットとブロードキャストの緊急度

影響: 緊急度の混ざった HTTP Datagram を送るアプリケーション。

- 別のワーカースレッドへ複製したブロードキャストは緊急度を失い、既定値(3)でキューに入る。
- リングは接続ごとの輻輳ウィンドウとペーシングレートに合わせて送り出す。接続が止められている項目は待ち、その間にほかの接続の項目が先に出る。
- `datagram_first` がない場合、ストリームがペーサーを空にし続けている接続は、リングのデータグラムを最大 max(2 x 平滑化 RTT, 25 ミリ秒) 保留し、そのあとはデータグラムをストリームより先に送る。

参照: `srvrun_dgring_send_best`、`srvrun_dgring_overdue`、`srvrun_broadcast_registered`(shortcut)

### 1.5 MAX_DATA は制御ストリームのバイトを数えない

影響: 通常の大きさではなし。

MAX_DATA は接続全体のフロー制御の上限である。この上限で数えるのは、WT のストリーム、ストリーミングで受けるリクエストの body、CONNECT ストリームのカプセル、相手の QPACK エンコーダーストリームである。制御ストリームとバッファーに入れたリクエストのバイトは、最初の 10 MB(`STP_DEFAULT_MAX_DATA`)の範囲で扱う。

参照: `srvrun_grant_conn_credit`(ponytail)

### 1.6 同時 WT セッション数

影響: 1 つの接続で多くのセッションを開くクライアント。

| 上限 | 値 |
|---|---|
| 接続あたり | `WIRED_SRVRUN_MAX_WT_SESSIONS`(2。`-D` で変えられるビルド時の設定で、最小 2) |
| 全接続 | `SRVRUN_MAX_WT_SESSIONS_GLOBAL`(`WIRED_CONNTABLE_CAP` と同じ。既定は 4、interop のイメージでは 64) |
| 新しいセッション | 接続ごとに 1 秒あたり `SRVRUN_MAX_WT_SESSIONS_PER_WINDOW`(10) |

参照: これらのマクロ

### 1.7 サーバーから開くストリームが止められたら、呼び出し側が再試行する

影響: サーバー側からストリームを開くアプリケーション。

相手のストリームの上限に達すると、開く関数(`wired_server_wt_open_uni` とその仲間)は -1 を返す。WT_STREAMS_BLOCKED を送るのは、原因がストリーム数のときだけである。再試行は呼び出し側が行い、同じ開き方が成功するようになると `wired_srvrun_opt.wt_on_stream_credit` で通知する。

参照: `srvrun_wt_streams_blocked_owed`、`srvrun_credit.c`

### 1.8 WT の双方向ストリームは順に始まる必要がある

影響: パケットの順序が入れ替わるクライアント。

クライアントの双方向ストリームはオフセット 0 のバイトで種類を判定する。それより先に届いた断片はリクエストのスロットに入る。そのストリームがあとで WebTransport(0x41 の合図)だと分かっても、断片は WT のストリームへ移さず、リクエストのスロットを解放して捨てる。相手は ACK 済みのバイトを再送しないので、WT のストリームはその欠落で止まる。

参照: `srvloop_wt_slot_for`、`wt_drop_overtaken`、`wired_srvloop_slot_for`

### 1.9 HTTP/2 上の WebTransport と、カプセルだけの WebTransport はない

影響: HTTP/3 を使えないクライアント。

HTTP/2 上の WebTransport と、HTTP/1.x や HTTP/2 上の HTTP Datagram は実装していない。レート制限のヘッダーも、仲介者によるフロー制御の表し直しもない。

参照: [draft-webtrans-http3.md](../../features/draft-webtrans-http3.md)、[rfc9297.md](../../features/rfc9297.md) の対象外

### 1.10 `h3_tunnel_relay` は状態を切り替えるだけ

影響: CONNECT のトンネルを使うアプリケーション。

トンネルの生のバイトの中継(h3 の DATA フレームの上で行う)は、アプリケーションが行う。

参照: `h3_tunnel_relay`(ponytail)

### 1.11 カプセルだけで送る HTTP Datagram への代替はない

影響: QUIC DATAGRAM に対応していない経路。

QUIC DATAGRAM があることを前提にしている。

参照: [rfc9297.md](../../features/rfc9297.md)

## 2. HTTP/3 と QPACK

QPACK は HTTP/3 のヘッダー圧縮である。最近送ったヘッダーの動的テーブルを持てて、そのテーブルは専用のエンコーダーストリームとデコーダーストリームで更新する。

### 2.1 オリジンサーバーとしてだけ動く

影響: プロキシやプッシュが必要なアプリケーション。

TCP への CONNECT のプロキシ(RFC 9220 の Extended CONNECT だけはある)も、サーバープッシュ(PUSH_PROMISE、push ID の優先度)もない。クライアント役は [対象外と予定なし](scope.md) にある。

参照: [rfc9114.md](../../features/rfc9114.md)、[rfc9218.md](../../features/rfc9218.md)、[rfc9220.md](../../features/rfc9220.md)

### 2.2 QPACK の動的テーブル: リクエストはすべて使い、レスポンスは `:status` だけに使う

影響: レスポンスヘッダーの帯域と、エンコーダーストリームが早い段階で失われた相手。

| 方向 | 動的テーブルの使い方 |
|---|---|
| リクエスト | クライアントの動的テーブルを 2016 バイトまで使える。テーブルの更新を待つ必要のあるリクエストは、待たずに失敗する |
| レスポンス | 静的テーブルに項目のない `:status` だけに使う。クライアントがそれを確認応答してから使う |

デコーダー側の動作は次のとおりである。

- 容量 2016(`QPACK_DYN_MAX_CAPACITY`)と `SETTINGS_QPACK_BLOCKED_STREAMS 0` を広告する。
- 相手のエンコーダーストリームを適用し、ID 11 で開いたデコーダーストリームで Section Acknowledgment、Stream Cancellation、Insert Count Increment を送る。そのため、アプリケーションの最初の単方向ストリームは 15 になる。
- ストリームを止めない。未受信の挿入を必要とするセクションは `QPACK_DECOMPRESSION_FAILED` になる。
- エンコーダーストリームはそのストリームのクレジットと同じ 48 KB の窓で組み立て直し、消費した分だけクレジットを与え直す。
- ストリームの種類を示すバイトより先に届いたバイトは、種類の分からない単方向ストリームが 1 本だけの間は保持する(種類が分かっているストリームは保持しない)。2 本が同時に失われると、2 本目の先に届いたバイトは捨てる。それがエンコーダーストリームなら以後の挿入は適用されず、相手のエンコーダーは静的テーブルと、それまでに確認応答した項目だけで動く。
- body をアプリケーションへストリーミングするリクエスト(`on_body`)のトレーラーセクションは、確認応答せずに読み飛ばす。そこからの参照は接続が続く間固定されたままになる。
- 確認応答のキューは 1 ステップ分を保持し、項目を捨てるのは相手がデコーダーストリームにクレジットを与えないときだけである。
- 欠落の先に届いた(順序が入れ替わって届いた)デコーダー命令は捨て、そのストリームの読み取りはエラーを出さずに欠落の所で止まる(`qpackenc_decrx_feed`、shortcut)。

エンコーダー側の動作は次のとおりである。

- サーバー自身のエンコーダーテーブルは min(相手の容量, 2016) を使う(`QPACKENC_LOCAL_CAP`。`-DQPACKENC_LOCAL_CAP=0` でビルドすると無効)。
- レスポンスのほかのフィールドは静的テーブルかリテラルのままで、リテラルの名前と値は短くなるときにハフマン符号化する。
- 挿入するのは、そのレスポンスのフィールドセクションができあがり、命令がエンコーダーストリームの送信リングに収まるときだけである。そうでなければそのフィールドはリテラルで送る。
- 追い出すのは、すべての挿入が確認応答され、保留中のセクションがないときだけである。取り消されたストリームのセクションは保留のまま残るので、一度取り消しがあるとテーブルは追い出しをしなくなる。

参照: [rfc9204.md](../../features/rfc9204.md)、[rfc7541.md](../../features/rfc7541.md)

### 2.3 HTTP の意味論はアプリケーションが扱う

影響: すべての HTTP アプリケーション。

SDK はトレーラー、`Date`、条件付きリクエストと範囲リクエスト、コンテンツネゴシエーション、TRACE を扱わない。フィールドの値はそのままアプリケーションへ渡す。

参照: [rfc9110.md](../../features/rfc9110.md) の対象外

### 2.4 レスポンスの body の上限

影響: 大きなレスポンスを返すハンドラー。

固定のレスポンスの行は `WIRED_SRVRUN_RESP_MAX`(16384 バイト)から 640 バイトのヘッダー領域(`SRVRUN_RESP_HDR_ROOM`)を引いた分を保持するので、1 回あたりの body は 15744 バイトである。それより大きい body は `srvbigbuf` の行(大きなレスポンス用のバッファープール)かストリーミングを使う([大きなボディのストリーミング](https://hakkadaikon.github.io/wired/guide/ja/h3/streaming/))。

この配列全体は `WIRED_CONNTABLE_CAP` 接続 x 40 レスポンススロット(`SRVRUN_RESP_SLOTS`)x 16 KiB の BSS である。

| 構成 | 大きさ |
|---|---|
| 既定の 4 接続 | 約 2.5 MiB |
| interop のイメージの 64 接続 | 40 MiB |
| `--cores N` | 上の値 x ワーカーの数 |

低レベルのハンドラーの body の上限は `WIRED_SRVLOOP_BODY_MAX`(1024)である。

参照: `WIRED_SRVRUN_RESP_MAX`、`WIRED_SRVLOOP_BODY_MAX`(ponytail)

### 2.5 リクエストのバッファーは `BODYWIN_CAP`(10240)まで

影響: `on_body` のないハンドラーへリクエストの body を送るクライアント。

バッファーに入れるリクエストが FIN のないまま窓を埋めると、413 か 431 で応答する。FIN があとの空のフレームで来る場合(「window stuck」)も同じである。窓を超えたバイトはストリームのクレジットも超えているので、FLOW_CONTROL_ERROR で接続を閉じる。大きな body には `on_body` を使う([POST ボディのストリーミング](https://hakkadaikon.github.io/wired/guide/ja/h3/post-body/))。

参照: `route_window_stuck`(ponytail)

### 2.6 リクエストのスロットは 8000 オクテットのリクエストターゲットに合わせた大きさ

影響: メモリの予算。

RFC 9110 4.1 は少なくとも 8000 オクテットの URI を受け付けることを推奨している。そのため、次の 3 つはそれぞれ 10240 バイトである。

- フィールドセクションの上限(`WIRED_H3_MAX_FIELD_SECTION`)
- リクエストの窓(`BODYWIN_CAP`)
- リクエストストリームのクレジット(`STP_DEFAULT_STREAM_DATA_REMOTE`)

リクエストのスロットは復号用の作業領域、窓、その折り返し用のバッファー、窓の受信ビットマップを持ち、以前の 2048 バイトのときより約 25 KB 大きい。接続あたり 40 個のリクエストスロット(`WIRED_SRVLOOP_MAX_STREAMS`)があるので、接続(`WIRED_CONNTABLE_CAP`)ごとに約 1 MB 増える。

| 構成 | サーバー環境(1 つのサーバーループの静的メモリ)ごとの増分 |
|---|---|
| 既定の 4 接続 | 約 4 MB |
| interop のイメージの 64 接続 | 65 MB |
| `srvthreads` | ワーカーごとに環境を 1 つ割り当てるので、上の値 x ワーカーの数 |

参照: `body_window.h`、`control_settings.h`

### 2.7 中断の再送テーブルは固定長

影響: なし。

ストリームの中断は RESET_STREAM か STOP_SENDING のフレームである。`SRVRUN_RST_RETX` は、接続が追跡できるストリームごとに中断を 1 つ保持する(104)。1 RTT の間にそれより多くの中断が確認応答されないままになると、超えた分は 1 回だけ送り、再送しない(RFC 9000 13.3)。

参照: `srvrun_rst_keep`(ponytail)

### 2.8 不正なリクエストには応答せず中断する

影響: 不正な HEADERS を送るクライアント。

| 状況 | 動作 |
|---|---|
| HEADERS フレーム全体からリクエストを組み立てられない | FIN を待たずに H3_MESSAGE_ERROR と STOP_SENDING でリセット。その前に 400 は送らない(RFC 9114 4.1.2 の MAY)。適合性の検査ツールが期待するリセットになる |
| HEADERS フレームが揃う前に終わった | H3_REQUEST_INCOMPLETE |
| 復号した行が復号用の作業領域からあふれる(広告した SETTINGS_MAX_FIELD_SECTION_SIZE を超える) | 431 で応答(RFC 9114 4.2.2) |
| 1 行のフィールドが復号用の作業領域全体より大きい、またはデコーダーが解釈できない | QPACK_DECOMPRESSION_FAILED でリセット(RFC 9204 7.4) |

どの場合もスロットと双方向ストリームのクレジットは返す。受信の途中で相手がリセットしたリクエストストリームや、データがまだスロットを取る前にリセットされたリクエストストリームも同じ扱いである。

参照: `connect_headers_complete`、`route_note_incomplete_append`、`h3reqdrive_line_fail`、`reset_request_stream`、`srvrun_abort_incomplete_reqs`、`srvrun_free_reset_reqs`

### 2.9 グレースフルシャットダウンは tick の回数で区切る

影響: SIGTERM でサーバーを止める運用者。

サーバーは GOAWAY を送り、閉じる前に最大 `SRVRUN_DRAIN_TICKS`(25)x 200 ミリ秒(約 5 秒)待つ。ハンドラーを設定する前に届いた SIGTERM は既定の動作になる(GOAWAY は送らない)。運用の手順は guide の「[SIGTERM によるグレースフルストップ](https://hakkadaikon.github.io/wired/guide/ja/ops/shutdown/)」にある。

参照: `srvrun_drain_tick`(ponytail)

### 2.10 スピンの待ち時間は回数で決める

影響: 何もしていないビジーポーリングのループ(眠らずにソケットをポーリングするループ)の CPU 使用量。

時間に基づく待ち時間の延長はない。使える時計がミリ秒の粒度しかないためである。

参照: `srvpoll_backoff_pause_n`(ponytail)

### 2.11 受信のまとめ数

影響: 多くの相手から受けるときのスループット。

サーバーは `recvmmsg` の 1 回の呼び出しで最大 `SRVRUN_RX_BATCH`(16)個のデータグラムを読み、環境ごとに 32 KB の領域を使う。

参照: `SRVRUN_RX_BATCH`(ponytail)

### 2.12 アイドルタイムアウトと追い出しの猶予は固定

影響: 長くアイドルなクライアント。

`WIRED_SRVRUN_IDLE_MS` は 30000、`WIRED_SRVRUN_EVICT_GRACE_MS` は 1000 である。

参照: これらのマクロ
