# 既知の制限: 容量の上限

[ドキュメント](../../README.md) › [セキュリティ設計](../README.md) › [既知の制限](README.md) › 容量の上限

| 項目 | 内容 |
|---|---|
| 目的 | 固定長のテーブルとバッファーの上限と、超えたときの動作を示す |
| 読む人 | 上限を変えるコントリビューター、サーバーを本番に入れる人 |
| 前提文書 | [既知の制限](README.md) |
| 関連文書 | guide の「[現在の上限](https://hakkadaikon.github.io/wired/guide/ja/concepts/limits/)」 |

## 1. 対象

上限はすべて固定長のテーブルとバッファーで、ほとんどは BSS に置く。上限を変えるには、定数を変えてビルドし直す。guide の「現在の上限」はアプリケーションから見える上限を扱う。この文書は残りの上限と、超えたときの動作を加える。

値は 2026-10-15 に `#define` と照合した。guide の値と異なる場合(`WIRED_MOQTRUN_MAX_TRACKS_PER_PEER`、`WIRED_MOQTRUN_MAX_REQS` など)は、この文書の値が今の値である。

## 2. MoQT ハブ

| 定数 | 値 | 制限する対象 | 超えたときの動作 |
|---|---|---|---|
| `WIRED_MOQTRUN_MAX_SESSIONS` | 32 | ハブあたりのセッション数 | 空きスロットなし。raw では INTERNAL_ERROR で切断 |
| `WIRED_MOQTRUN_MAX_SUBS` | 31 | Track あたりの購読者数 | 購読者の空きスロットなし |
| `WIRED_MOQTRUN_MAX_FILTER_RANGES` | 4 | リクエストあたりの Range Filter の範囲数 | REQUEST_ERROR INVALID_FILTER |
| `WIRED_MOQTRUN_MAX_REQ_UPDATES` | 4 | 未応答の REQUEST_UPDATE | TOO_MANY_REQUEST_UPDATES(d19 以降) |
| `WIRED_MOQTRUN_IMPL_MAX` | 64 | MOQT_IMPLEMENTATION のバイト数 | 値を切り詰め |
| `WIRED_MOQTRUN_HOLD_BUF` | 2048 | SETUP の前に保持するバイト数 | リクエストを EXCESSIVE_LOAD でリセット、Object を破棄 |
| `WIRED_MOQTRUN_EARLY_BUF` | 2048 | 上流の SUBSCRIBE_OK より前の SUBGROUP のバイト数 | ストリームを破棄 |
| `WIRED_MOQTRUN_GOAWAY_URI_MAX` | 8192 | GOAWAY の URI(仕様の最大) | `wired_moqt_goaway` が -1 を返す |
| `WIRED_MOQTRUN_MAX_RELAYS` | 4 | Track あたりで同時に中継するパブリッシャーのストリーム数 | ストリームを中継せず、購読者は受け取れない |
| `WIRED_MOQTRUN_MAX_NAME` | 64 | Track Name のバイト数 | 拒否(PUBLISH。ハブが所有する publish は 0 を返す) |
| `WIRED_MOQTRUN_MAX_NS` | 128 | 符号化した名前空間のバイト数 | PUBLISH で名前空間を拒否 |
| `WIRED_MOQTRUN_MAX_TRACKS_PER_PEER` | 5 | 1 つのセッションが公開する Track 数 | PUBLISH を拒否 |
| `WIRED_MOQTRUN_MAX_REQS` / `_PER_SESSION` | 128 / 32 | リクエストストリーム | リクエストストリームを EXCESSIVE_LOAD でリセット |
| `WIRED_MOQTRUN_MAX_RDV` / `_RDV_PER_SESSION` | 16 / 4 | ランデブーの保留 | SUBSCRIBE を EXCESSIVE_LOAD で拒否 |
| `WIRED_MOQTRUN_RDV_MAX_MS` | 1500 | ランデブーの保留時間 | 保留がタイムアウト(逸脱) |
| `WIRED_MOQTRUN_MAX_UP` | 16 | 上流を待つもの | 待機を EXCESSIVE_LOAD で拒否 |
| `WIRED_MOQTRUN_MAX_FETCHES`(+ fetch_waits) | 8 (+8) | 処理する FETCH とフィル | REQUEST_ERROR INTERNAL_ERROR |
| `WIRED_MOQTRUN_UPFETCH_BUDGET_MS` | 2000 | 上流 FETCH のレッグの時間 | レッグが終わる |
| `WIRED_MOQTRUN_RELAY_FRAG_MAX` | 16384 | 分断された Object を丸ごと保持する大きさ | それより大きいペイロードはそのまま流す |
| `WIRED_MOQTRUN_TRACK_PROPS_MAX` | 96 | 転送する Track Properties | 空にして転送 |
| `WIRED_MOQTRUN_RESET_AFTER_BUSY` | 8 | lossy な経路で拒まれた回数 | 購読者のストリームをリセット |
| `WIRED_MOQTRUN_GOAWAY_GRACE_MS` | 1000 | 終了時の猶予 | 確認応答の有無にかかわらず 1 秒後にセッションを閉じる |
| `WIRED_MOQTRUN_PUBDONE_WAIT_MS` | 2000 | PUBLISH_DONE のあとの待ち時間 | 残りのストリームをリセット |
| `WIRED_MOQTRUN_SSTS_SETS` | 8 | 切り替えセット | SWITCHING_SET_ASSIGNMENT を INTERNAL_ERROR で拒否 |
| `MOQSSTS_MAX_MEMBERS` | 4 | 切り替えセットあたりのメンバー数 | SWITCHING_SET_ASSIGNMENT を INTERNAL_ERROR で拒否 |
| `MOQCTL_SSTS_MAX_ALGS` | 4 | SSTS_ALGORITHMS の ID | 超えた ID は保持も送信もしない |
| `WIRED_MOQTSW_SOFT_WAIT_MS` | 4000 | Soft の切り替えの待ち時間 | 古い Track を諦める |
| `WIRED_MOQTREL_POOL` | 4 | 信頼リング | 以降の信頼 Track は lossy な経路を使う |
| `WIRED_MOQTREL_CAP` | 3 x `WIRED_SRVLOOP_WT_BUF_CAP` | リングの大きさ | リングが一周する |
| `WIRED_MOQTREL_STALL_MS` | 10000 | 遅い購読者を待つ時間 | 遅い購読者を外す(リセット) |
| `WIRED_MOQTREL_MAX_SUBS` / `_MARKS` | 31 / 8 | リングのカーソル / 到着マーク | 購読者にカーソルがない / 配送のタイムアウトが早く発火することがある |
| `MOQCACHE_OBJ_MAX` | 65472 | キャッシュする Object のペイロード | それより大きい Object はキャッシュしない |

用語は [既知の制限: MoQT](moqt.md#1-用語) にある。

## 3. WebTransport、HTTP/3、QUIC

| 定数 | 値 | 制限する対象 | 超えたときの動作 |
|---|---|---|---|
| `WIRED_WT_MAX_BUFFERED_DATAGRAMS` / `_CAP` | 4 / 256 | セッション確立前のデータグラム | 長いデータグラムを破棄 |
| `WIRED_SRVRUN_MAX_WT_SESSIONS` | 2 | 接続あたりの WT セッション数 | セッションを拒否 |
| `SRVRUN_WTSEND_BUF` | 131072 | WT の送信スロットあたりの一時置き場のバイト数 | それより大きいペイロードは呼び出し側が所有するビューのまま |
| `SRVRUN_DG_PENDING_Q` | 4 | 接続ごとにキューに入れるブロードキャストデータグラム | いちばん新しいものを拒否 |
| `WIRED_SENDSESS_LOG` | 128 | 送信セッションあたりの未確認応答のスライス | 送ったパケットを追跡できず、あとで失われたように見える。cwnd の成長が止まる |
| `WIRED_SRVRUN_RESP_MAX` | 16384 | 固定のレスポンス 1 回分 | それより大きい body には bigbuf かストリーミングが必要 |
| `WIRED_SRVLOOP_BODY_MAX` | 1024 | 低レベルのハンドラーの body | body を上限で切る |
| `SRVRUN_RX_BATCH` | 16 | `recvmmsg` 1 回あたりのデータグラム | 次のまとめで読む |
| `WIRED_SRVLOOP_MAX_STREAMS` | 40 | リクエストのスロット | ストリームを破棄 |
| `WIRED_SRVLOOP_MAX_WT_STREAMS` / `_UNI_STREAMS` | 24 / 9 | WT の双方向 / 単方向のスロット | それより多く開く相手はストリームの上限を破る(STREAM_LIMIT_ERROR) |
| `WIRED_SRVLOOP_WT_BUF_CAP` | 49152 | スロットごとの受信の窓 | フロー制御で相手を止める |
| `WIRED_SRVLOOP_MAX_RX_DATAGRAMS` / `_RX_DATAGRAM_CAP` | 256 / 1200 | 受信データグラムのキュー | データグラムを破棄 |
| `BODYWIN_CAP` | 10240 | リクエストの body の窓 | 413/431 か FLOW_CONTROL_ERROR |
| `WIRED_SRVLOOP_CTRL_BUF_CAP` | 512 | 制御ストリームの滞留 | H3_EXCESSIVE_LOAD |
| `SRVRUN_RST_RETX` | 104 | ACK を待つ中断 | 超えた分は 1 回だけ送る |
| `SRVRUN_RAW_CLOSE_REASON_MAX` | 1148 | raw の切断理由のバイト数 | 理由を切り詰める(到達しない: メッセージは 1024 以下) |
| `WIRED_CONNTABLE_CAP` | 4(interop のイメージでは 64) | QUIC の接続 | 新しい接続を受け入れない |
| `ZERORTT_SEEN_CAP` | 4096 | 0-RTT の指紋 | 最も古いものを追い出す |
| `WIRED_RECVMMSG_MAX` | 64 | UDP のまとめ数 | まとめ数を上限で切る |

送信側の 2 つのバッファーの大きさの理由は次のとおりである。

| 定数 | 理由 |
|---|---|
| `SRVRUN_WTSEND_BUF` | サーバーから送る WT の送信スロット(接続あたり `SRVRUN_WT_SEND_SLOTS` = 40 個)それぞれの一時置き場。この大きさまでのペイロードは中へ複製するので、呼び出しから戻った時点で呼び出し側のバッファーは空く。それより大きいペイロードは送り終わるまで呼び出し側のメモリ(ビュー)のままである。大きさは WT の受信の窓 1 つ分(49152)と、保持する中継の断片(16384)の和で、画面共有のフレームのような窓いっぱいの中継するペイロードも複製される |
| `WIRED_SENDSESS_LOG` | 1 つの送信セッション(レスポンスか WT の送信スロット)が、確認応答を待つ間に追跡する送信済みスライスの数。interop runner のリンクの帯域遅延積 1 つ分(約 35 スライス)を超える大きさにしている。埋まると送信済みのパケットが送信中の計上から漏れ、あとで失われたように見えるので、輻輳ウィンドウの成長が止まる |
