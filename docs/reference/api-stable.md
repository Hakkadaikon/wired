# Stable API

[ドキュメント](../README.md) › [参照資料](README.md) › Stable API

| 項目 | 内容 |
|---|---|
| 目的 | アプリケーション向けで、互換性を壊す変更を避ける関数と、その前提条件を一覧にする |
| 読む人 | Stable API を変更するコントリビューター |
| 前提文書 | [参照資料](README.md) |
| 関連文書 | [Low-level / internal API](api-lowlevel.md)、[バージョニングの方針](api-versioning.md) |

この文書の関数は下にある QUIC や TLS の状態機械を知らなくても呼べる。どれも 1 つの仕事を丸ごとこなすか、呼び出し順のルールを持たない純粋関数である。

たいていのアプリケーションが使うのは次の 4 つである。WebTransport のアプリケーションは `wired_server_broadcast_datagram` を加えた 5 つを使う。

| 関数 | 用途 | ガイド |
|---|---|---|
| `wired_srvdriver_parse`、`wired_srvdriver_run` | コマンドラインのフラグを解析してサーバーを動かす | [サーバーのフラグ](https://hakkadaikon.github.io/wired/guide/ja/quic/server-flags/) |
| `wired_srvrun_handler` | リクエストのコールバック | [サーバーのフラグ](https://hakkadaikon.github.io/wired/guide/ja/quic/server-flags/) |
| `wired_certreload_load_or_selfsigned` | 本物の証明書を読み込む | [証明書のホットリロード](https://hakkadaikon.github.io/wired/guide/ja/ops/cert-reload/) |

## 1. サーバーを動かす

| Function | Role |
|---|---|
| `wired_srvdriver_parse`, `wired_srvdriver_run` | 推奨の入口。ドライバーのフラグを解析し、4 つのドライバーのどれかを動かす |
| `wired_server_run` | 完結した単一プロセスのサーバーを、kill されるまで動かす |
| `wired_server_run_opt` | `wired_server_run` に `wired_srvrun_opt` のオプトイン設定を加えたもの |
| `wired_server_run_id` | 呼び出したワーカーの run が使っている identity(起動時のコピー。証明書のリロードで更新される) |
| `wired_srvrun_handler` (struct) | 自分のコールバックとそのコンテキスト。run 系の関数に渡す |

### 1.1 `wired_srvdriver_parse` と `wired_srvdriver_run`

`wired_srvdriver_parse` はドライバーのフラグ(`--port`、`--workers`、`--ifindex`、`--cores`、`--pin-core` ほか。ヘッダーを参照)を読む。`--workers` と `--cores` の併用のような矛盾する組み合わせは拒否する。

`wired_srvdriver_run` は 4 つのドライバー(単一プロセス、fork したワーカー、AF_XDP、スレッド)から 1 つを選ぶ。ドライバーの仕組みは [I/O ドライバー](../architecture/io-drivers.md) にある。

### 1.2 `wired_srvrun_opt`

| メンバー | 内容 |
|---|---|
| busy-polling、AF_XDP ドライバー、WebTransport のコールバック、`on_step` | オプトインの設定。`on_step` はループのステップごとのコールバック |
| `wt_origin_check` | WebTransport セッションを Origin で受け入れるかを決める。origin ヘッダーがないリクエストでは空の `origin` ビューを受け取る |
| `wt_on_session_draining` | ピアがセッションの CONNECT ストリームで WT_DRAIN_SESSION を送ったときに呼ばれる |
| `wt_on_stream_credit`(`wired_wt_on_stream_credit` 型)、`wt_stream_credit_ctx` | `wired_server_wt_open_*` がクレジット不足で -1 を返したあと、同じ open が成功するようになった時点で一度だけ呼ばれる |
| `datagram_first` | 1 なら、送信パスごとにキューに積んだ DATAGRAM をストリームのデータより先に送る。デフォルトの 0 ではストリームのデータが先(RFC 9221 §5.1) |

`opt` は 0 であってはならない。すべての設定がデフォルトなら、`wired_server_run` と同じに動く。

### 1.3 `wired_srvrun_handler`

末尾の 3 つのメンバーは省略でき、0 のままなら無効である。

| メンバー | 型 | 内容 |
|---|---|---|
| `http` | `wired_http_handler` | `wired_http_exchange` を埋めてステータスを選び、`WIRED_HTTP_MAX_FIELDS`(8)個までのレスポンスヘッダーを加える |
| `on_body` | `wired_srvloop_on_body` | レスポンダーが動く前に、リクエストの body を届いた順にチャンク単位で受け取る。0 なら、body 全体を先にバッファーに溜める |
| `on_body_abort` | `wired_srvloop_on_body_abort` | `on_body` へストリーミング中の body が fin なしで終わったときに一度だけ呼ばれる |

`on_body_abort` が呼ばれるのは、クライアントがストリームをリセットしたとき、レスポンスが始まる前に止めたとき、接続が終わったときである。ストリーム ID とクライアントのエラーコード(接続が終わったときは `H3_REQUEST_CANCELLED`)を受け取る。`on_body` に渡される `req` はその呼び出しの間だけ有効である。

`wired_http_field` は内部の `qpack_field`(`wired_span` 2 つ。名前、値の順)の typedef で、レイアウトはその構造体に従う。

## 2. コールバックの中から使う WebTransport

| Function | Role |
|---|---|
| `wired_server_broadcast_datagram` | 生きている全 WebTransport セッションへ QUIC DATAGRAM をキューに積む |
| `wired_server_wt_open_uni`, `wired_server_wt_open_bidi` | サーバーから WebTransport の単方向 / 双方向ストリームを開く |
| `wired_server_wt_stream_reply` | クライアントが開いた双方向ストリームで返信する |
| `wired_server_wt_stream_inflight` | 送ったストリームのペイロードがまだ使われているか |
| `wired_server_wt_drain_session` | セッションを畳むようピアに頼む |
| `wired_server_wt_stream_priority` | 送ったストリームの urgency を設定する |
| `wired_server_wt_stream_schedule`, `wired_wt_sched` (struct) | 送ったストリームの送信クラスを全項目まとめて設定する |
| `wired_server_wt_occupancy`, `wired_wt_occupancy` (struct) | 開いているセッションとストリームのスナップショット |
| `wired_wt_ref` (struct), `wired_wt_ref_of`, `wired_wt_ref_get` | ステップをまたいでセッションを保持する。開いている間はそのセッションに解決し、古くなったら 0 になる |

どれもサーバー自身のループの中、つまりコールバックの中からだけ呼べる。スレッドセーフでもシグナルセーフでもない。

使い方は [WebTransport のデータグラム](https://hakkadaikon.github.io/wired/guide/ja/wt/datagram/) と [サーバーが開いたストリームを閉じずに保つ](https://hakkadaikon.github.io/wired/guide/ja/wt/open-streams/) にある。

### 2.1 古いセッション

`wired_wt_session*` は、セッションのコールバックからクローズのコールバックまで有効である。クローズのあと、サーバーはその領域を後続のセッション(別のピアのものかもしれない)に再利用する。それ以降も持ち続けたポインターは、新しいセッションを指す。

ステップをまたいでセッションを持つには `wired_wt_ref_of(s)` を保持し、使うときに `wired_wt_ref_get` で解決する。セッションが閉じると 0 を返し、新しいセッションがその領域を使っても 0 のままである。

セッションを受け取るほかの呼び出しも、もう開いていないセッションのポインターは受け付けない。ただし、再利用されたセッションと本来のセッションを区別できるのは ref だけである。ステップをまたいで持つストリーム ID はセッションの ref と組にし、ref を解決して返ったセッションとともに渡す(ストリーム ID は接続ごとに振り直される)。

### 2.2 ペイロードの寿命

open と reply の呼び出しは 128 KiB(131072 バイト。送信スロットのステージングバッファー)までのペイロードをコピーする。呼び出しが戻った時点でバッファーを解放できる。

それより大きいペイロードは呼び出し側のメモリへのビューとして保持され、`wired_server_wt_stream_inflight` が 0 を返すまで生きている必要がある。

| `wired_server_wt_stream_inflight` の戻り値 | 条件 |
|---|---|
| 1 | ストリームの送信スロットが `stream_id` をまだ保持している(未 ACK のバイトがある、またはストリームが追記のために開いている) |
| 0 | スロットが解放された、または `stream_id` がこのセッションでサーバーが送ったストリームを一度も指していない |

### 2.3 個々の呼び出し

| 項目 | 内容 |
|---|---|
| ストリームシグナル | open の呼び出しに渡すペイロードは、WebTransport のストリームシグナルの接頭辞で始まっていなければならない |
| Drain | `wired_server_wt_drain_session` は、ループの次のステップでセッションの CONNECT ストリームに WT_DRAIN_SESSION を送る。送るのはセッションごとに最大 1 回で、繰り返し呼ぶと送り直さずに 1 を返す。セッションがもう生きていないとき、または drain を持たない raw QUIC のセッションのときは 0 を返す |
| Urgency | `wired_server_wt_stream_priority` は RFC 9218 の urgency を 0 から 7 で受け取る(デフォルト 3)。値が小さいほど先に送る。各送信パスは送信できるストリームのうち最も urgency の高いものだけを扱い、同じ urgency のストリームは交互に送る。urgency が 7 を超えるとき、または開いている送信スロットのない ID には負の値を返す |
| 占有状況 | `wired_server_wt_occupancy` は、呼び出したループで開いているセッションとクライアントが開いたストリームを、コンパイル時の容量とともに報告する。ある時点のスナップショットで、`wired_srvrun_env_wt_usage` の累計とは別である |

`wired_server_wt_stream_schedule` は、3 つのキーを持つ `wired_wt_sched` を受け取る。エラーは `wired_server_wt_stream_priority` と同じである。

| キー | 内容 |
|---|---|
| `urgency` | 上と同じく階層を選ぶ |
| `fine` | 同じ urgency の中でストリームを並べる。小さいほうが先 |
| `flow` | 0 以外のとき、同じ値を共有するストリームを決まった順序に並べる。その flow の送信可能なストリームのうち、(`order`, `tie`)が最小のものだけが送る。flow 0 は順序を課さない |

各送信パスでは、参加するストリームがそれぞれ 1 スライスずつ送る。2 つのセッションが接続を共有するときは、各セッションがパスごとに同じ数のスライスを送り(draft-ietf-webtrans-http3-16 §8)、各セッションが持てる送信スロットは半分までである。

### 2.4 まだ区分していない `wired_server_wt_*`

同じヘッダーには、どちらの区分にもまだ入れていない呼び出しがある。ループの中だけというルールは同じで、前提条件はそれぞれのヘッダーのコメントにある。

- `wired_server_wt_stream_reply_open`
- `wired_server_wt_stream_send`
- `wired_server_wt_stream_fin`
- `wired_server_wt_stream_hold`
- `wired_server_wt_stream_reset`
- `wired_server_wt_stream_stop`
- `wired_server_wt_send_datagram_to`
- `wired_server_wt_close_session`
- `wired_server_wt_est_kbps`
- `wired_server_wt_exporter`
- `wired_server_broadcast_datagram_ring`
- `wired_server_wt_send_datagram_prio`
- `wired_server_broadcast_datagram_prio`

2 つの `_prio` の呼び出しは 0(最も急ぐ)から 7 までの urgency を受け取る(RFC 9221 §5.1)。キューに積んだデータグラムは urgency の高い順に、同じ urgency の中では呼び出し順に出ていく。`_prio` の付かない呼び出しは 3 を使う。

## 3. リクエストとレスポンス

| Function | Role |
|---|---|
| `wired_h3req_path` | リクエストの `:path` を 1 つの `wired_span` で返す |
| `wired_http_req_header` | 小文字の名前でリクエストヘッダーを探す |
| `wired_http_reply_text` (`srvrun/httpx.h`) | ステータス、`text/plain`、body のテキストを 1 回の呼び出しで設定する |
| `wired_http_add_field` (`srvrun/httpx.h`) | 2 つの C 文字列からレスポンスヘッダーを 1 つ追加する。フィールドの表が満杯のとき 0 を返す |

`wired_http_req_header` は名前を完全一致で照合する。`cookie` は全部の断片を `"; "` でつないで返し、それ以外の繰り返されたヘッダーは最初の 1 つを返す。

`cookie`、`origin`、`wt-available-protocols` 以外のヘッダーは最初の `WIRED_H3REQDRIVE_MAX_HDRS`(32)個しか保持しない。戻り値はリクエストの中を指すビューで、リクエストのほかのビューと同じ間だけ生きている。

1 つのバッファーより大きいレスポンスの body はラウンドに分けて作り、次のチャンクを埋めるためにレスポンダーをもう一度呼ぶ([大きな body のストリーミング](https://hakkadaikon.github.io/wired/guide/ja/h3/streaming/))。

2 回目以降のラウンドで見えるリクエストはコピーで、ビューとヘッダー用の余地は 512 バイトである。コピーに収まらなかったヘッダーは、そこでは見つからない。

## 4. 証明書

| Function | Role |
|---|---|
| `wired_certreload_load` | PEM の証明書チェーンと P-256 の鍵を、呼び出し側が所有する領域へ読み込む |
| `wired_certreload_load_or_selfsigned` | 同上。パスが設定されていなければ既存の identity を保つ |
| `wired_pem_next` | PEM ブロックを 1 つデコードする。繰り返せば full-chain のファイルを順にたどれる |
| `wired_eckey_p256_priv` | DER(SEC1 または PKCS#8)から P-256 の秘密鍵を取り出す |

`wired_certreload_load` に渡す領域はそこから作った identity より長く生きていなければならない。`wired_certreload_load_or_selfsigned` は、パスが設定されているのに読み込めなかったとき、自己署名証明書へ切り替えずに診断メッセージを出して終了する。

使い方は [証明書の読み込み](https://hakkadaikon.github.io/wired/guide/ja/tls/certificates/) と [証明書のホットリロード](https://hakkadaikon.github.io/wired/guide/ja/ops/cert-reload/) にある。

## 5. ソケット、ファイル、コーデック

| Function | Role |
|---|---|
| `wired_udp_socket`, `wired_udp_bind`, `wired_udp_send`, `wired_udp_recv`, `wired_udp_recvfrom`, `wired_udp_close`, `wired_udp_addr` | QUIC の状態を持たない、素の UDP ソケットの呼び出し |
| `wired_fio_read`, `wired_fio_append`, `wired_fio_write_new`, `wired_fio_mkdir` | ファイル全体の読み込み、追記、置き換え。ディレクトリの作成 |
| `wired_fio_open`, `wired_fio_size`, `wired_fio_pread`, `wired_fio_close` | チャンク単位のファイルアクセス。open、サイズ取得、オフセット指定の読み込み、close |
| `wired_fio_read_span` | `wired_span` を返す `wired_fio_read`(エラー時は長さ 0) |
| `wired_header_parse`, `wired_header_build_long` | QUIC パケットヘッダーのうちバージョンに依存しない部分を解析・構築する |

UDP の呼び出しは、普通のソケットプログラムが使う順序ならどの順でも動く。ファイルの呼び出しはシステムコールを直接呼び、プロトコルの状態を持たない。examples は大きな静的ファイルを丸ごと読み込まずにストリーミングするためにチャンク単位の呼び出しを使う。

## 6. テキスト、整形、ログ

| Function | Role |
|---|---|
| `wired_log_str`, `wired_log_ts`, `wired_fmt_u64`, `WIRED_LOG` | stderr への任意のトレース。どこで呼んでもよい |
| `wired_snprintf`, `wired_vsnprintf`, `wired_dprintf` | libc を必要としない printf 互換のフォーマッター |
| `wired_obuf_printf` | `wired_obuf` へ printf 形式で追記する |
| `wired_span_eq`, `wired_span_eq_cstr`, `wired_span_cstr`, `wired_span_to_cstr`, `WIRED_SPAN_ARG` | バイトのビューを比較、構築、コピーアウトする |
| `wired_span_find` | ビューの中で指定したバイトが最初に現れる位置。なければ -1 |
| `wired_cstr_eq`, `wired_cstr_append`, `wired_span_strip_lead`, `wired_obuf_put` | C 文字列とバッファーの小さなヘルパー |
| `wired_hex_encode`, `wired_dump_hex`, `wired_dump_text` | ビューを 16 進にエンコードする。ビューを fd へ 16 進かテキストで書き出す |

| 対象 | 内容 |
|---|---|
| フォーマッター | `%d %i %u %x %X %p %s %c %% %f` をフラグ、幅、精度、長さ修飾子つきで扱う。独自の拡張 `%H` はバイト列を小文字の 16 進で出力し、`"%.*H"` はバイト数とポインター(`WIRED_SPAN_ARG` が展開する組)を受け取る。C99 との違いは `common/fmt/fmt.h` にある |
| `wired_dprintf` | write(2) だけを呼ぶ |
| `wired_obuf_printf` | `len` の位置から追記し、最大 `cap - len - 1` バイトを書き、追記したバイト数を返す |
| span と C 文字列のヘルパー | `common/bytes/text/text.h` にある。`wired_span_eq` は定数時間ではないので、秘密の値の比較には使えない。`wired_span_to_cstr` と `wired_cstr_append` は収まるように切り詰め、`wired_obuf_put` は `cap` で切る。`WIRED_SPAN_ARG` は `"%.*s"` が必要とする 2 つの引数に展開される |

## 7. デモ用の identity

| Function | Role |
|---|---|
| `wired_srvboot_demo`, `wired_srvboot_demo_keys` (`srvboot/srvdemo.h`) | サンプルとテスト用の固定のデモ identity。本番では使わない |
| `wired_srvboot_cert_sha256`, `wired_srvboot_log_fingerprint` (`srvboot/srvdemo.h`) | リーフ証明書の SHA-256。生の値か、ログに出した値 |

デモの identity は連番パターンの鍵と自己署名証明書を使うので、誰でも再現できる。証明書のハッシュは、ブラウザーが `serverCertificateHashes` に期待する値である。フィンガープリントはコロン区切りでログに出る。

`wired_srvboot_cert_sha256` と `wired_srvboot_log_fingerprint` はプロセス全体で 1 つの作業用サーバーを共有するので、再入可能ではない。

## 8. セッション再開と 0-RTT

| Name | Role |
|---|---|
| `wired_srvboot_id.ticket_key` | セッションチケットの鍵のシード。0 = 再開なし |
| `wired_srvboot_id.early_data` | 1 = 再開した接続で 0-RTT を受け入れる。0(デフォルト)= 1-RTT としてのみ再開する |

0-RTT はオプトインである。0-RTT のデータはリプレイされうるので、RFC 8446 Appendix E.5 は、アプリケーションが求めない限り 0-RTT を有効にすることを禁じている。

`ticket_key` だけで有効になるのは再開で、0-RTT ではない。`early_data = 1` の前提は、クライアントが早期に送りうるすべてのリクエストが 2 回処理されても問題ないことである。

`early_data = 1` でも、SDK は次の場合に 0-RTT を断り、接続を 1-RTT として再開する。チケットが早期データを告知するのは、0-RTT が有効なときだけである。

- リプレイされたチケット
- チケットの経過時間が古い
- 別の ALPN や暗号スイートで発行されたチケット
- raw QUIC の ALPN
- HelloRetryRequest のあとに続く ClientHello

## 9. アドレス検証トークン

| Name | Role |
|---|---|
| `wired_srvkeys_set_token_key` (`srvkeys/srvkeys.h`) | Retry / NEW_TOKEN のトークンのシード。サーバーの起動前に呼ぶ。呼ばなければプロセスごとのランダムなシードになる |

## 10. クライアント証明書と相互 TLS

| Name | Role |
|---|---|
| `wired_srvboot_id.client_auth` | `WIRED_CLIENT_AUTH_OFF`(0、デフォルト)、`_OPTIONAL` または `_REQUIRED` |
| `wired_srvboot_id.client_ca` | クライアント証明書のチェーンがたどり着くべきトラストストア(`castore`) |
| `wired_http_exchange.peer_cert` | 検証済みのクライアントのリーフ証明書の DER。なければ空 |
| `wired_castore_init`, `wired_castore_add` (`crypto/pki/trust/castore/castore.h`) | `client_ca` のストアを作る。呼び出し側の `castore_entry` 配列に結び付け、CA 証明書の DER を 1 つずつ追加する |

| 項目 | 内容 |
|---|---|
| フェイルクローズ | `client_auth` がオフ以外なのに `client_ca` がないと、すべての接続の初期化が失敗する。チェーンはストアまで 1 段ずつつながり、現在の時刻で有効でなければならない。リーフが鍵の用途を列挙しているなら `clientAuth` を許していなければならない。必須モードでは、証明書を送らないクライアントを `certificate_required` で閉じる |
| 再開なし | クライアント認証が有効だと、提示された PSK と 0-RTT は無視し、セッションチケットも発行しない。どの接続でもクライアントは鍵を毎回証明する |
| 寿命 | 何もコピーしない。`castore`、その `castore_entry` 配列、`wired_castore_add` に渡したすべての CA の DER バッファーは、サーバーがハンドシェイクのたびに読むビューである。3 つとも、サーバーが動いている間生きている場所(`main` の中か static)に置く。`wired_server_run` より前に戻るヘルパー関数の中には置けない。`peer_cert` は接続の中を指すビューで、ハンドラーの呼び出しの間だけ有効で、最初のラウンドでだけ設定される |

## 11. アイドルタイムアウト

| Name | Role |
|---|---|
| `wired_srvboot_id.idle_timeout_ms` | サーバーが告知する max_idle_timeout(ms)。0 = 30 秒 |
| `wired_server_idle_timeout_ms` | 接続でネゴシエートされたアイドルタイムアウト(ms)。ClientHello を処理するまではサーバー自身の値を返す |

接続は `idle_timeout_ms` とクライアントの max_idle_timeout のうち小さいほうでアイドルタイムアウトする(RFC 9000 10.1)。クライアントの値が 0 か値がない場合は、サーバーの値だけが効く。SDK は PTO 3 回分より短い時間で接続をアイドルタイムアウトさせない。
