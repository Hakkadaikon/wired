# MoQT(experimental)

[ドキュメント](../README.md) › [参照資料](README.md) › MoQT(experimental)

| 項目 | 内容 |
|---|---|
| 目的 | `wired.h` から呼べる MoQT の公開面と、その任意の設定を一覧にする |
| 読む人 | MoQT のハブと io テーブルを変更するコントリビューター |
| 前提文書 | [参照資料](README.md) |
| 関連文書 | [バージョニングの方針](api-versioning.md)、[MoQT の Track 切り替え](../features/moqt-track-switching.md) |

## 1. 区分

MoQT の公開面は丸ごと experimental で、Stable API と Low-level / internal API のどちらの表にも載せない。MoQ Transport は IETF のドラフトで、名前、デフォルト、ワイヤー上の振る舞いはドラフトに従い、非推奨期間なしにどのコミットでも変わりうる。前提条件はヘッダーのコメントにある。

`src/app/moqt/` は MoQT を 14 のモジュールで実装する。`cache`、`ctl`、`data`、`dgram`、`fetch`、`kvp`、`ns`、`qraw`、`run`、`sess`、`ssts`、`tstat`、`ver`、`vi` である。セッションは draft-ietf-moq-transport-18、-19、-22 のうち、ピアが WebTransport のサブプロトコル(`moqt-18`、`moqt-19`、`moqt-22`)として提示したものを話す。

`src/wired.h` は、MoQT のヘッダー(`run/moqtrun.h`、`qraw/moqrawio.h`、`data/moqdata.h`、`dgram/moqdg.h`)と、ライブメディア用の `media/mp4frag/mp4frag.h` と `platform/clock/mono.h` をインクルードする。`wired_moqt_init` などに 2 つ目のインクルードは要らない。

| 語 | 意味 |
|---|---|
| ハブ(`wired_moqt_hub`) | パブリッシャーと購読者の間で Track を転送するリレー |
| io テーブル(`wired_moqt_io`) | トランスポート上で送信、open、close するためにハブが呼ぶ関数ポインターの表 |

ハブの使用例は [MoQT ハブ](https://hakkadaikon.github.io/wired/guide/ja/moqt/hub/) にある。

## 2. ハブと io テーブルの任意の設定

どれも `run/moqtrun.h` にあり、省略できる。デフォルト(0 または未設定)の動作は 2.1 節にある。

| Name | Role |
|---|---|
| `wired_moqt_cache_attach` | FETCH が使う Group 単位の Object キャッシュ用のアリーナをハブに渡す |
| `wired_moqt_goaway` | すべてのセッションに MoQT の GOAWAY を送り、タイムアウト後に閉じる |
| `wired_moqt_on_session_draining` | ピアがセッションを drain したら GOAWAY の手順を始める |
| `wired_moqt_on_stream_reset` | ピアがストリームの 1 つをリセットしたことをハブに伝える |
| `wired_moqt_hub.authorize_namespace`, `authorize_ns_ctx`, `wired_moqt_authorize_ns_fn` | 名前空間のリクエストに対する任意の認可関数。0 ならすべて許可 |
| `wired_moqt_hub.authorize_publish`, `authorize_pub_ctx` | PUBLISH に対する任意の認可関数。0 ならすべて許可 |
| `wired_moqt_hub.no_implementation` | 1 ならハブの SETUP から MOQT_IMPLEMENTATION オプションを省く。0 なら `wired/0` を送る |
| `wired_moqt_io.close_session`, `stream_reply_open`, `stream_priority`, `stream_stop` | `wired_moqt_io` の末尾に追加された操作 |
| `wired_moqt_io.stream_sched` | Object のストリームの送信クラスを全項目まとめて設定する操作 |
| `wired_moqt_io.est_kbps` | 接続の配送レートの推定値を報告する操作 |

### 2.1 各設定の動作

| 設定 | 動作 |
|---|---|
| キャッシュ | アリーナは呼び出し側が所有する。ないと、FETCH はすべての範囲を unknown として報告する |
| GOAWAY | 任意の New Session URI とタイムアウトを運ぶ。タイムアウトが過ぎると、ハブは PUBLISH_DONE を送り、GOAWAY_TIMEOUT でセッションを閉じる |
| Drain | `wired_moqt_on_session_draining` は `wired_srvrun_opt.wt_on_session_draining` と同じ形である。ピアの WT_DRAIN_SESSION が、そのセッションの GOAWAY の手順を始める |
| ストリームのリセット | そのストリームが運んでいたリクエストや FETCH を取り消す |
| 認可関数 | `authorize_namespace` は PUBLISH_NAMESPACE と SUBSCRIBE_NAMESPACE を対象にする。`authorize_publish` は `wired_moqt_authorize_fn` 型で、Full Track Name とトークンを受け取る。リレーはこれで、パブリッシャーがほかの誰かになりすましていないかを確かめる。どのドラフトもこの確認を求めている。使用例は [購読者の認可](https://hakkadaikon.github.io/wired/guide/ja/moqt/authorize/) にある |
| io テーブルの操作 | `close_session`、`stream_reply_open`、`stream_priority`、`stream_stop` は、それぞれ `wired_server_wt_close_session`、`wired_server_wt_stream_reply_open`、`wired_server_wt_stream_priority`、`wired_server_wt_stream_stop` と同じ形である |
| io テーブルの操作が 0 のとき | `close_session` は何も閉じない。`stream_reply_open` はリクエストごとのストリームを開かない。`stream_priority` はデフォルトの urgency を保つ。`stream_stop` は、ハブが振り分けられない受信側のデータストリームを読まずに流れるままにする |
| `stream_sched` | `wired_server_wt_stream_schedule` と同じ形で、`wired_moqraw_io` が設定する。設定すると、Object のストリームについて `stream_priority` の代わりに使う。0 のときハブは `stream_priority` を使う |
| `est_kbps` | `wired_server_wt_est_kbps` と同じ形で、`wired_moqraw_io` はこれをその関数に設定する。0 のとき、SSTS の予算(5 章)は上限値だけで決まる |

## 3. ドラフトのバージョンの選択

`wired_moqt_wt_protocols`(`ver/moqver.h`)は、サーバーが提示するサブプロトコルのリストを `wired_srvrun_opt.wt_protocols` 用に書き出す。

| 条件 | ネゴシエートするドラフト |
|---|---|
| `wt_protocols` が未設定、または単一の文字列 `"moqt-19"` | draft-19 だけ |
| ピアが WebTransport のサブプロトコルを送らない | draft-19 の制御ストリームの振る舞い |
| ガイドの MoQT のサンプル(`wt_protocols = "moqt-22"`、クライアントは `moqt-22` を提示) | draft-22 |
| `examples/moqt_chat`(リスト全体を提示) | `moqt-22` を提示できるブラウザー(WebTransport の `protocols` オプション)は draft-22、提示できないブラウザーは draft-19 |

## 4. raw QUIC 上の MoQT

MoQT は HTTP/3 や WebTransport を使わずに QUIC の上で直接動く(draft-ietf-moq-transport-22 6.2.2、-18/-19 3.1.4-5)。クライアントは ALPN で MoQT を選ぶ。この接続には CONNECT リクエストがないので、SDK は接続全体を表す暗黙のセッションを 1 つ与える。下の名前はすべてデフォルトが 0 か未設定で、その場合は WebTransport だけになる。

| Name | Role |
|---|---|
| `wired_srvboot_id.raw_alpns` | `h3`/`hq-interop` のほかにサーバーが選んでよい raw の ALPN。0 = オフ |
| `wired_srvrun_opt.raw_on_session`, `raw_session_ctx`, `wired_rawq_on_session` | raw の ALPN の接続ごとに、ハンドシェイクの確定時に一度呼ばれる |
| `wired_server_session_is_raw` | raw QUIC のセッションなら 1、WebTransport のセッションなら 0 |
| `wired_moqraw_io` (`qraw/moqrawio.h`) | `wired_server_wt_*` の上に作った `wired_moqt_io` |
| `wired_moqt_on_session_raw` (`run/moqtrun.h`) | ハブの `raw_on_session` コールバック |
| `wired_moqt_hub.raw_policy` (a `moqraw_policy`) | raw セッションの PATH と AUTHORITY に対する任意の確認 |
| `WIRED_MOQTRUN_CLOSE_MALFORMED_PATH`, `WIRED_MOQTRUN_CLOSE_MALFORMED_AUTHORITY` | セッションのクローズコード 0x9 と 0x1A |

| 対象 | 動作 |
|---|---|
| `raw_alpns` | `"moqt-22 moqt-19 moqt-18"` のような空白区切りのリストで、サーバーの優先順に並べ、h3 と hq-interop より先に置く(RFC 7301 3.2)。`alpn_client_order` を 1 にすると、クライアントの順序で選ぶ |
| `raw_on_session` | 接続の暗黙のセッションとネゴシエートされた ALPN を、そのストリームのバイトより前に受け取る。その後のセッションは WebTransport のセッションと同じ `wt_on_*` のコールバックを通る。0 なら raw のセッションは報告しない |
| raw と WebTransport の違い | raw のセッションでは、`wired_server_wt_close_session` がそのコードで QUIC の CONNECTION_CLOSE(0x1d)を送る。ストリームのリセットは WebTransport の対応付けを経ずにコードを運ぶ。データグラムは quarter-stream-id(セッションのストリーム ID を 4 で割った値)を持たない |
| `wired_moqraw_io` | ストリームを開く操作に WebTransport のストリームシグナルを加えるのは、WebTransport のセッションの場合だけである。raw セッションのストリームには何も付かない。`send_uni2` は 0 で、必要なアプリケーションが設定する |
| `wired_moqt_on_session_raw` | `wired_rawq_on_session` と同じ形である。`raw_on_session` として渡し、ハブを `raw_session_ctx` にする。ALPN の `moqt-NN` がドラフトを決める。制御ストリームは方向ごとに 1 本ずつの単方向ストリームの組である。PATH と AUTHORITY の Setup Option は、正しい形式なら受け入れ、そうでなければ MALFORMED_PATH(0x9)か MALFORMED_AUTHORITY(0x1A)でセッションを閉じる。GOAWAY は空の New Session URI を運び、満杯のハブは INTERNAL_ERROR でセッションを閉じる |
| `raw_policy` | 正しい形式の値に対する、任意の `accept_path` と `accept_authority` のフックである。拒否すると INVALID_PATH(0x8)か INVALID_AUTHORITY(0x19)でセッションを閉じる。`wired_moqt_init` のデフォルトである 0 は、正しい形式の値をすべて受け入れる |

## 5. Track 切り替え(moqtail 互換、draft-22 のみ)

Track 切り替えは、購読者が購読し直さずに Track のバリエーション(高レートと低レートのエンコードなど)の間を移る拡張である。draft-ietf-moq-transport-22 にもほかのどのドラフトにもない。バージョンの更新も非推奨期間もなしに、どのコミットでも丸ごと削除されうる。moqtail のコードポイントを使い、検証はプロセス内だけで、第三者の実装との相互運用性は確かめていない。仕組みは [MoQT の Track 切り替え](../features/moqt-track-switching.md) にある。

すべてデフォルトでオフである。これらのフィールドを設定しないハブでは、パラメーター SWITCH_FROM(0x24)と SWITCHING_SET_ASSIGNMENT(0x41)は PROTOCOL_VIOLATION でセッションを閉じる。

| Name | Role |
|---|---|
| `wired_moqt_hub.switch_track` (`run/moqtrun.h`) | 1 なら draft-22 のセッションで SWITCH_FROM を有効にする |
| `wired_moqt_hub.ssts_algs`, `ssts_alg_n` (`run/moqtrun.h`) | ハブが告知する SSTS(送信側の Track 切り替え)のアルゴリズム ID。`ssts_alg_n` が 0 なら SSTS は無効 |
| `wired_moqt_hub.ssts_cap_kbps` (`run/moqtrun.h`) | デフォルトのアルゴリズムの予算の上限(kbps)。0 = 上限なし |
| `WIRED_MOQTSW_SOFT_WAIT_MS` (`run/moqtswitch.h`, include it yourself) | ソフトな SWITCH_FROM をあきらめるまでの時間(4000 ms) |
| `WIRED_MOQTRUN_SSTS_SETS` (`run/moqtss.h`) | 購読者のセッションごとの切り替えセットの数(8) |
| `WIRED_MOQTRUN_MAX_TRACKS_PER_PEER` (`run/moqtrun.h`) | 1 つのピアが同時に PUBLISH できる Track の数(5) |
| `MOQCTL_PARAM_SWITCH_FROM`, `MOQCTL_PARAM_SWITCHING_SET_ASSIGNMENT`, `MOQCTL_OPT_SSTS_ALGORITHMS`, `MOQCTL_SWITCH_HARD` / `_SOFT`, `MOQCTL_ERR_INVALID_SWITCH`, `MOQCTL_ERR_UNSUPPORTED_EXTENSION`, `MOQCTL_DONE_SWITCHED`, `MOQCTL_SSTS_ALG_DEFAULT` / `_BACKPRESSURE`, `MOQCTL_SSTS_MAX_ALGS`, `moqctl_switchfrom`, `moqctl_ssa` (`ctl/moqctl.h`) | コーデックの定数と値の構造体 |
| `moqssts_*` / `MOQSSTS_*` (`ssts/moqssts.h`) | SSTS の純粋なアルゴリズム。SDK 内部向けで、安定性の約束はない |

| 対象 | 動作 |
|---|---|
| `switch_track` | `wired_moqt_init` のデフォルトである 0 のとき、ハブは SWITCH_FROM に対して PROTOCOL_VIOLATION でセッションを閉じる |
| `ssts_algs` | 呼び出し側が所有するリストで、ハブより長く生きていなければならない。ハブはこれを draft-22 の SETUP で Setup Option 0x09 として送る。エントリは最大 `MOQCTL_SSTS_MAX_ALGS`(4)個 |
| `ssts_cap_kbps` | デフォルトのアルゴリズム(0)の予算は、この上限と接続の配送レートの推定値(`wired_moqt_io.est_kbps`。`wired_moqraw_io` はこれを `wired_server_wt_est_kbps` に設定する)のうち小さいほう |
| `WIRED_MOQTSW_SOFT_WAIT_MS` | `run/moqtswitch.h` は `wired.h` がインクルードしないので、値を使うにはこのヘッダーを直接インクルードする |
| `WIRED_MOQTRUN_SSTS_SETS` | これを超える割り当ては INTERNAL_ERROR で拒否する |
| `WIRED_MOQTRUN_MAX_TRACKS_PER_PEER` | ピアがほかの Track と並べて低レートのバリエーションとカメラを PUBLISH できるよう 5 にしてある。この値でピアの表の大きさが決まる |
| コードポイント | SWITCH_FROM はパラメーター 0x24、SWITCHING_SET_ASSIGNMENT は 0x41、SSTS_ALGORITHMS は Setup Option 0x09、INVALID_SWITCH はエラー 0x32、UNSUPPORTED_EXTENSION はエラー 0x33、SWITCHED は done コード 0x3。`moqctl_*` は SDK 内部向けの名前だが、独自のクライアントを作るにはコードポイントが要るので載せている |
| SSTS のアルゴリズム | default は 0、backpressure は 0xff01 |
