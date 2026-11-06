[ドキュメント](../README.md) › [機能](README.md) › draft-ietf-webtrans-http3-16

# draft-ietf-webtrans-http3-16: WebTransport over HTTP/3

仕様の本文(`tasks/specs/draft-ietf-webtrans-http3-16.txt`。git には含まない)から抽出した、サーバー側の EARS 形式の要件台帳です。各要件には、それを確かめるテストを付けています。チェックがなくテスト行もない項目は、未解決のギャップです。2026-10 時点の状況です。

凡例:

- `[x]`: 挙げたテストで確認済み
- `[~]`: 間接的に確認(専用のテストはなく、evidence 行で確かめ方を説明)
- `[ ]`: まだどのテストでも確認していない

**カバレッジ: テスト済み 74/81、間接 7、未テスト 0。**

## §3.1 WebTransport に対応した HTTP/3 接続の確立

- [x] WTH3-001 (§3.1) サーバーは、値 1 の SETTINGS_WT_ENABLED 設定を送ることで、WebTransport over HTTP/3 のサポートを示さなければならない。
  - test: `tests/app/h3settings_control_settings_test.c` —
    `test_h3settings_control_settings_advertises_wt`
  - test: `tests/app/h3settings_build_test.c` —
    `test_h3settings_build_h3_datagram_and_wt_enabled`
- [x] WTH3-002 (§3.1) WebTransport を設定していない構成では、サーバーは SETTINGS_WT_ENABLED を送らず、既定値の 0 のままにしなければならない。
  - test: `tests/app/h3settings_build_test.c` —
    `test_h3settings_build_h3_datagram_and_wt_disabled`
  - test: `tests/app/h3settings_control_settings_test.c` —
    `test_h3settings_control_settings_advertises_wt`
- [x] WTH3-003 (§3.1) サーバーは、SETTINGS_ENABLE_CONNECT_PROTOCOL 設定を含め、RFC 9220 に記述された Extended CONNECT をサポートしなければならない。
  - test: `tests/app/h3settings_build_test.c` —
    `test_h3settings_build_connect_protocol`
  - test: `tests/app/connect_test.c` — `test_connect_protocol_negotiation`
- [x] WTH3-004 (§3.1) サーバーは、値 1 の SETTINGS_H3_DATAGRAM 設定を送ることで、HTTP/3 データグラムのサポートを示さなければならない。
  - test: `tests/app/h3settings_build_test.c` —
    `test_h3settings_build_h3_datagram_and_wt_enabled`
  - test: `tests/app/h3settings_control_settings_test.c` —
    `test_h3settings_control_settings_advertises_wt`
- [x] WTH3-005 (§3.1) WebTransport を設定した構成では、サーバーは QUIC データグラムのサポートを示すために、0 より大きい値の max_datagram_frame_size トランスポートパラメーターを送らなければならない。
  - test: `tests/tls/server_tp_test.c` —
    `test_server_tp_datagram_frame_size`
- [x] WTH3-006 (§3.1) サーバーは、RESET_STREAM_AT 拡張を有効にするために、空の reset_stream_at トランスポートパラメーターを送らなければならない。
  - test: `tests/tls/server_tp_test.c` — `test_server_tp_reset_stream_at_empty`
- [x] WTH3-007 (§3.1) WebTransport に必要な設定・パラメーターのどれかについて正しい値を持たない SETTINGS またはトランスポートパラメーターを受け取った場合、サーバーは確立済みのものと新たに届くものを含むすべての WebTransport セッションを不正な形式として扱わなければならない。
  - test: `tests/app/srvrun_wtsess_test.c` —
    `test_srvrun_wt_settings_h3_datagram_required`
  - test: `tests/app/srvrun_wtsess_test.c` —
    `test_srvrun_wt_no_datagram_tp_malformed`
  - test: `tests/app/srvrun_wtsess_test.c` —
    `test_srvrun_wt_h3_token_requires_reset_stream_at`
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_wt_held_connect_rejected_after_settings`
  - evidence: クライアントが SETTINGS_H3_DATAGRAM=1、0 でない max_datagram_frame_size、さらに `webtransport-h3` トークンの場合は reset_stream_at(draft-07 の `webtransport` トークンはこれより前のもの)を送っていなければ、CONNECT は H3_MESSAGE_ERROR でリセットされます(RFC 9114 4.1.2、`srvrun_wt_peer_ok`)。クライアントの SETTINGS より前にセッションは確立できず(WTH3-009)、2 つ目の SETTINGS フレームは接続エラーになるので、CONNECT ごとのこの検査は確立済みのセッションにも及びます。
- [x] WTH3-008 (§3.1, §7.1) WebTransport のドラフト版では、相手がサポートするバージョンを識別できるように、サーバーはサポートする各ドラフト版のコードポイントで SETTINGS_WT_ENABLED を送らなければならない。
  - test: `tests/app/h3settings_build_test.c` —
    `test_h3settings_build_h3_datagram_and_wt_enabled`
  - evidence: 組み立てた SETTINGS は draft-02 (0x2b603742) と現行 (0x2c7cf000、-16 §9.2) の両方のコードポイントを同じフレームに載せます。
- [x] WTH3-009 (§3.1, §7.1) WebTransport のドラフト版では、サーバーはクライアントの SETTINGS を受け取るまで、届いた WebTransport リクエストを処理してはならない。
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_wt_connect_before_client_settings_held`
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_wt_two_held_connects_each_processed_once`
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_wt_connect_after_client_settings_establishes`
  - evidence: 先に届いた CONNECT は拒否せずに応答を返さないまま保留し、クライアントの SETTINGS が届いた時点で処理します。

## §3.2 新しいセッションの作成

- [x] WTH3-010 (§3.2) 新しい WebTransport セッションを作るために、サーバーは `:protocol` 擬似ヘッダーフィールドが "webtransport-h3"(または実際に使われている draft-07 の "webtransport" トークン)であることを求めなければならない。
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_wt_connect_establishes_session`
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_wt_connect_webtransport_token`
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_plain_connect_no_protocol_no_wt_session`
- [x] WTH3-011 (§3.2) WebTransport の CONNECT リクエストの `:scheme` フィールドは https でなければならない。
  - test: `tests/app/srvrun_wtsess_test.c` —
    `test_srvrun_wt_connect_http_scheme_malformed`
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_wt_connect_missing_scheme_no_session`
- [x] WTH3-012 (§3.2) WebTransport の CONNECT リクエストには `:authority` と `:path` の両方の値を設定しなければならない。これらのフィールドは求める WebTransport サーバーのリソースを識別する。
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_wt_connect_missing_authority_no_session`
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_wt_connect_missing_path_no_session`
  - test: `tests/app/srvrun_test.c` — `test_srvrun_wt_accept_records_path`
- [x] WTH3-013 (§3.2) リクエストが Origin ヘッダーを含む場合、サーバーは Origin ヘッダーを検証し、指定されたオリジンがそのサーバーへのアクセスを許可されていることを確かめなければならない。
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_wt_origin_check_allowed_establishes`
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_wt_origin_check_disallowed_403`
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_wt_origin_check_absent_empty_span`
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_wt_origin_check_unset_unchanged`
  - evidence: アプリケーションの `wired_srvrun_opt.wt_origin_check` コールバックが Origin ごとに可否を決めます(ヘッダーがないときは空のスパンとして渡されます)。存在するが空の Origin は、コールバックより前に 403 で拒否します。コールバックを設定していないときは、形式の正しさの検査だけを行います。
- [x] WTH3-014 (§3.2) Origin の検証に失敗した場合、サーバーはステータスコード 403 で応答するべきである。
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_wt_connect_origin_malformed_403`
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_wt_origin_check_disallowed_403`
- [x] WTH3-015 (§3.2) すべての検査に通った場合、サーバーは 2xx 系のステータスコードで応答してセッションを受け入れてもよい。
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_wt_connect_establishes_session`
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_wt_connect_origin_ok_establishes`
- [x] WTH3-016 (§3.2) 対象のリソースが WebTransport をサポートしない場合、サーバーはステータスコード 405 で応答するべきである。
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_wt_resource_check_405_no_session`
  - evidence: アプリケーションが `wired_wt_resource_check` コールバックを登録します(`srvrun_wt_resource_decide`)。このコールバックはセッションを確立する前にすべての Extended CONNECT について呼ばれます。コールバックが "not found" を報告すると、本文のない 405 レスポンスを組み立て、リクエストはアプリケーションのハンドラーには届きません。
- [x] WTH3-017 (§3.2) サーバーから見ると、WebTransport セッションは 2xx レスポンスを送った時点で確立する。
  - test: `tests/app/wt_session_test.c` —
    `test_close_from_established`
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_wt_connect_establishes_session`
- [x] WTH3-018 (§3.2) サーバーは、リダイレクトを示す 3xx レスポンスで応答してもよい。
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_wt_resource_check_redirect_3xx_with_location`
  - evidence: 同じ `wired_wt_resource_check` コールバック(WTH3-016)が、Location の値とともに 3xx ステータスを報告できます。`srvrun_reject_wt_redirect` は、Location ヘッダーを Literal Field Line With Literal Name で載せたリダイレクトレスポンスを組み立てます。
- [~] WTH3-019 (§3.2) 0-RTT を受け入れる場合、サーバーは WebTransport に関する初期のフロー制御の SETTINGS の値を、前のセッションでネゴシエートした値より小さくしてはならない。
  - evidence: サーバーの SETTINGS_WT_INITIAL_* の値はコンパイル時の定数(`DEFAULT_WT_INITIAL_*`、control_settings.c)なので、セッションをまたいで下がることはありません。`h3settings_zerortt_compatible` も「下げない」規則を検査しますが、`tests/app/h3settings_control_settings_test.c` にあるその WebTransport 向けのテスト関数は `tests/run.c` から呼ばれていません。
  - gap: 再開用のチケットを発行したときに送った設定を保存する場所がなく、実際の 0-RTT の受け入れ経路で `prior` 引数に渡す値を用意できません(9114-066 と同じギャップ)。
- [x] WTH3-020 (§3.2) サーバーが 2xx レスポンスを送ると、"webtransport-h3" アップグレードトークンについてカプセルプロトコルがネゴシエートされる。
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_wt_connect_establishes_session`
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_wt_close_session_capsule_received`
  - vuln: V-0496
- [~] WTH3-075 (§3.2) サーバーは、セッションを受け入れる 2xx レスポンスを送るまで CONNECT ストリームで受け取ったバイトをカプセルとして処理してはならず、セッションを拒否した場合はそれらを破棄しなければならない。
  - evidence: カプセルの受信カーソルは、`srvrun_start_wt` がセッションを確立したときにだけ有効になり(`srvrun_wt_capsule_arm`)、リクエストの HEADERS の直後から始まります(`tests/app/srvrun_test.c` — `test_srvrun_wt_capsule_start_skips_connect_headers`)。2xx より前、または拒否した CONNECT でカプセルを送るテストはありません。

## §3.3 アプリケーションプロトコルのネゴシエーション

- [x] WTH3-021 (§3.3) クライアントが CONNECT リクエストに WT-Available-Protocols ヘッダーフィールドを含める場合、サーバーはクライアントのリストからちょうど 1 つの要素を選び、成功のレスポンスに WT-Protocol フィールドとして含めてもよい。
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_wt_negotiate_picks_first_client_choice`
- [x] WTH3-022 (§3.3) 自身のリストとクライアントの提示に共通のサブプロトコルがないとき、サーバーは WT-Protocol ヘッダーフィールドを含めてはならず、それでもセッションを受け入れてもよい。
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_wt_negotiate_no_common_no_header`
- [x] WTH3-023 (§3.3) WT-Available-Protocols ヘッダーフィールドがないとき、サーバーは WT-Protocol フィールドを含めてはならず、セッションの確立には影響しない。
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_wt_negotiate_absent_offer_no_header`
- [x] WTH3-024 (§3.3) WT-Available-Protocols ヘッダーフィールドが String 以外の型の値を持つ(またはほかの理由で有効な Structured Field の List でない)場合、サーバーはそのフィールド全体を無視しなければならない。
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_wt_negotiate_bad_syntax_no_header`
- [x] WTH3-076 (§3.3) サーバーは、WT-Available-Protocols のリストの要素に付いたパラメーターをすべて無視しなければならない。
  - test: `tests/app/sfield_test.c` — `test_sfield_parameters_are_skipped`

## §3.4 優先度付け

- [~] WTH3-026 (§3.4) WebTransport の CONNECT リクエストとレスポンスは Priority ヘッダーフィールドを含んでもよく、クライアントは PRIORITY_UPDATE フレームを送って優先度を変えてもよい。
  - evidence: PRIORITY_UPDATE フレームのコーデック(`tests/app/priupdate_test.c`)は任意の element_id を扱えるので、CONNECT ストリームの ID も扱えます。確立済みの WebTransport の CONNECT ストリームに対して PRIORITY_UPDATE を送るテストはありません。サーバー側では、アプリケーションが `wired_server_wt_stream_priority` で WebTransport のストリームごとに RFC 9218 の urgency を設定でき、送信ポンプは urgency の値が小さいものから送ります(`tests/app/srvrun_test.c` — `test_srvrun_wt_priority_lower_urgency_first`、`test_srvrun_wt_priority_blocked_urgent_does_not_starve`)。`wired_server_wt_stream_schedule` は、2 つ目のクラスキーとフローごとの順序を加えます(`test_srvrun_wt_sched_better_class_first`、`test_srvrun_wt_sched_one_slice_per_pass`)。

## §4 WebTransport の機能 / セッション ID

- [x] WTH3-027 (§4) セッション ID は、QUIC の可変長整数の方式でエンコードしなければならない。
  - test: `tests/app/wtwire_test.c` — `test_wtwire_signal_put_uni`
  - test: `tests/app/wtwire_test.c` — `test_wtwire_qsid_put`
- [x] WTH3-028 (§4) クライアントは CONNECT リクエストを送った直後から、楽観的にそのセッションでストリームを開いたりデータグラムを送ったりしてもよい。サーバー側では、CONNECT リクエストを受け取った直後から、ストリームを開くこととデータグラムを送ることができる。
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_wt_open_uni_streams_payload_on_wire`
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_wt_open_bidi_allocates_ids_and_holds_view`
- [x] WTH3-029 (§4) セッション ID は、常にクライアントが開始した双方向ストリームに対応しなければならない。
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_wt_connect_client_bidi_id_establishes_session`
- [x] WTH3-030 (§4) 単方向ストリーム、双方向ストリーム、データグラムで、クライアントが開始した双方向ストリームの ID に対応しないセッション ID を受け取った場合、サーバーは H3_ID_ERROR エラーコードで接続を閉じなければならない。
  - test: `tests/app/srvrun_wtsess_test.c` —
    `test_srvrun_wt_non_client_bidi_session_id_closes`
  - evidence: データグラムの Quarter Stream ID は必ず 4 の倍数に対応するので、そのような ID を運べるのは WT ストリームのヘッダーだけです。クライアントが開始した双方向ストリームでない ID の CONNECT は、そもそもクライアントが開けません(それでも H3_ID_ERROR になります。`test_srvrun_wt_connect_non_client_bidi_id_rejected`)。
- [x] WTH3-031 (§4) 閉じたセッションに対応するセッション ID は、それ自体を、クライアントが開始した双方向ストリームかどうかの検査で無効と見なしてはならない。閉じたセッションのデータは、エンドポイントがセッション終了の規則に従って扱う。
  - test: `tests/app/srvrun_wtsess_test.c` —
    `test_srvrun_wt_closed_session_id_not_an_id_error`
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_wt_foreign_stream_id_rejected`

## §4.2 単方向ストリーム

- [x] WTH3-032 (§4.2) WebTransport の HTTP/3 単方向ストリームの型は 0x54 とし、その後ろに可変長整数のセッション ID、さらにその後ろにユーザーが指定したストリームデータが続かなければならない。
  - test: `tests/app/wtwire_test.c` — `test_wtwire_signal_put_uni`
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_wt_uni_stream_data_delivered_on_offer`

## §4.3 双方向ストリーム

- [x] WTH3-033 (§4.3) サーバーは、サーバーが開始する各 WebTransport 双方向ストリームの先頭のバイトとして、可変長整数でエンコードしたシグナル値 0x41 を送り、その後ろにセッション ID を続けなければならない。
  - test: `tests/app/wtwire_test.c` — `test_wtwire_signal_put_bidi`
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_wt_open_bidi_allocates_ids_and_holds_view`
- [x] WTH3-034 (§4.3) 実装は、クライアントが開始した WebTransport 双方向ストリームの先頭のバイトにあるクライアントのシグナル値 0x41 を認識しなければならない。
  - test: `tests/app/srvloop_test.c` —
    `test_srvloop_wt_bidi_stream_not_request`
  - test: `tests/app/srvloop_test.c` — `test_srvloop_wt_bidi_stream_reassembled`
- [x] WTH3-035 (§4.3) WT_STREAM のシグナル値 (0x41) を、リクエストストリームのまさに先頭のバイト以外の場所で、HTTP/3 ストリームのフレーム型として受け取った場合、サーバーはそれを H3_FRAME_ERROR 型の接続エラーとして扱わなければならない。
  - note: デコードしたリクエストストリームのフレーム型(バッファー付きのパーサーと、ストリーミングされるボディのウィンドウ)で検査し、DATA のペイロードのバイトは検査しません(issue #212)。
  - test: `tests/app/h3reqdrive_test.c` —
    `test_reqdrive_wt_signal_frame_after_headers`
  - test: `tests/app/body_window_test.c` —
    `test_bodywin_wt_signal_frame_error`
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_wt_signal_frame_after_headers_closes`
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_on_body_wt_signal_frame_error`
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_body_bytes_like_wt_signal_served`
  - test: `tests/app/srvloop_test.c` —
    `test_srvloop_wt_signal_offset_zero_opens_wt`

## §4.4 データストリームのリセット

- [x] WTH3-036 (§4.4) サーバーは、WebTransport のデータストリームに対する RESET_STREAM または STOP_SENDING をアプリケーションに伝えなければならず、自身が送るリセット・停止のそれぞれでアプリケーションのエラーコードを受け付けなければならない。
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_wt_reset_mapped_delivers_app_error_code`
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_wt_stream_reset_sends_reset_and_frees_slot`
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_wt_stream_stop_sends_stop_sending`
- [x] WTH3-037 (§4.4) ストリームに対する WebTransport のアプリケーションエラーコードは、WT_APPLICATION_ERROR の範囲にマッピングしなければならない。0x00000000 は 0x52e4a40fa8db に、0xffffffff は 0x52e5ac983162 に対応し、0x1f*N+0x21 の形の予約済みコードポイントは飛ばす。
  - test: `tests/app/wterrmap_test.c` — `test_wterrmap`
- [x] WTH3-038 (§4.4) WebTransport の実装は、WebTransport のデータストリームをリセットするとき、Reliable Size を少なくとも WebTransport ヘッダーのサイズにした RESET_STREAM_AT フレームを使わなければならない。
  - test: `tests/app/srvrun_wtflow_test.c` —
    `test_srvrun_wt_reset_stream_at_covers_header`
  - test: `tests/app/srvrun_wtflow_test.c` —
    `test_srvrun_wt_reset_stream_at_fallbacks`
  - test: `tests/tls/sdrv_test.c` —
    `test_sdrv_recv_client_hello_reset_stream_at`
  - evidence: reset_stream_at トランスポートパラメーターを広告した相手にだけ送り(draft-ietf-quic-reliable-stream-reset-09 3。ネゴシエートしていない 0x24 を送ると Chrome の接続が切れます)、それ以外には RESET_STREAM を送ります(`test_srvrun_wt_abort_frames_match_stream_type`)。ヘッダーのバイトは STREAM フレームとして同じ保持中のパケットに載るので、送信スロットを解放したあとも ACK されるまで再送されます。クライアントが開始したストリームでは、サーバー側の半分にヘッダーがないので、RESET_STREAM でリセットします(Reliable Size 0 と同等。rsr-09 4)。
- [x] WTH3-039 (§4.4) サーバーは、既知のセッションに結びついたストリームのリセットのエラーコードを、そのセッションを持つアプリケーションへそのまま渡さなければならない。
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_wt_reset_mapped_delivers_app_error_code`
  - test: `tests/app/srvrun_wtsess_test.c` —
    `test_srvrun_wt_reset_stream_at_delivers_reset`(相手の
    RESET_STREAM_AT もリセットとして扱う。フレームは aiomoqt から取り込んだもの)
- [x] WTH3-040 (§4.4) WT_APPLICATION_ERROR の範囲外のエラーコードを持つ RESET_STREAM または STOP_SENDING フレームを受け取った場合、実装はそれをアプリケーションのエラーコードのないストリームのリセットとしてアプリケーションへ渡すべきである。
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_wt_reset_unmapped_delivers_no_app_error_code`

## §4.5 データグラム

- [x] WTH3-041 (§4.5) WebTransport のデータグラムのペイロードは、HTTP Datagram Payload フィールドに手を加えずに入れ、Quarter Stream ID フィールドの直後に置いて送らなければならない。
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_wt_send_datagram_to_prefixes_qsid`

## §4.6 受信したストリームとデータグラムのバッファリング

- [x] WTH3-043 (§4.6) WebTransport のエンドポイントは、ストリームとデータグラムを、確立したセッションに結びつけられるまでバッファーに保持するべきである。
  - test: `tests/app/wt_session_test.c` —
    `test_stream_buffered_then_established`
  - test: `tests/app/wt_session_test.c` —
    `test_datagram_buffered_then_established`
- [x] WTH3-044 (§4.6) リソースの枯渇を避けるために、エンドポイントはバッファーに保持するストリームとデータグラムの数を制限しなければならない。
  - test: `tests/app/wt_session_test.c` —
    `test_stream_buffer_limit_rejects_overflow`
  - test: `tests/app/wt_session_test.c` —
    `test_datagram_buffer_limit_drops_overflow`
- [x] WTH3-045 (§4.6) バッファーに保持するストリームの数を超えたとき、ストリームは WT_BUFFERED_STREAM_REJECTED エラーコードの RESET_STREAM と STOP_SENDING の一方または両方を送って閉じなければならない。
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_wt_bidi_stream_buffer_full_sends_reset`
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_wt_uni_stream_buffer_full_sends_reset`
- [x] WTH3-046 (§4.6) バッファーに保持するデータグラムの数を超えたとき、データグラムは破棄しなければならない。
  - test: `tests/app/wt_session_test.c` —
    `test_datagram_buffer_limit_drops_overflow`

## §4.7 HTTP/3 の GOAWAY フレームとの関係

- [~] WTH3-047 (§4.7) GOAWAY を送ったとき、サーバーは GOAWAY のストリーム ID 以上のストリームで、新しい WebTransport セッションのための CONNECT リクエストを受け入れてはならない。
  - evidence: `srvrun_start_resp` は、送った GOAWAY の ID 以上のリクエストストリームを、メソッドの振り分けより前に H3_REQUEST_REJECTED で拒否します。そのため WebTransport の CONNECT も同じ経路を通ります(`tests/app/srvrun_test.c` — `test_srvrun_goaway_id_past_largest_accepted`、GET で駆動)。GOAWAY を超える CONNECT を送るテストはありません。
- [x] WTH3-048 (§4.7) HTTP/3 の GOAWAY フレームは、すべての WebTransport セッションの終了処理を始めるようにアプリケーションへ伝える合図でもある。1 つのセッションだけを終了するには、どちらのエンドポイントも WT_DRAIN_SESSION カプセルを送れる。
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_send_wt_drain_seals_capsule_on_connect_stream`
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_send_wt_drain_all_skips_inactive_slot`
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_wt_drain_session_sends_once`
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_wt_drain_rx_notifies_app`
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_wt_drain_rx_with_value_closes`
  - evidence: GOAWAY を送ると、`srvrun_send_wt_drain_all` が有効な各 WebTransport セッションに WT_DRAIN_SESSION カプセルを送り、各セッションの `wired_wt_session_drain` による ESTABLISHED->DRAINING の遷移を起こします。`wired_server_wt_drain_session` は 1 つのセッションを最大 1 回ドレインします。相手の WT_DRAIN_SESSION は `wt_on_session_draining` でアプリケーションに届き、値を持つ DRAIN はセッションを不正な形式として閉じます。
- [x] WTH3-049 (§4.7) WT_DRAIN_SESSION カプセルを送った、または受け取ったあとも、エンドポイントはそのセッションを使い続け、新しい WebTransport ストリームを開いてもよい(ドレインは通知にすぎず、セッションを終わらせるものではない)。
  - test: `tests/app/wt_session_test.c` —
    `test_drain_is_advisory_not_terminal`
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_wt_drain_one_session_leaves_others_untouched`

## §4.8 鍵素材エクスポーターの使用

- [x] WTH3-050 (§4.8) サーバーは、ラベル "EXPORTER-WebTransport" と、WebTransport Exporter Context 構造体をシリアライズしたコンテキストを使って、指定した WebTransport セッションの TLS エクスポーターを導出できなければならない。
  - test: `tests/app/srvrun_wtflow_test.c` —
    `test_srvrun_wt_exporter_matches_tls_exporter`
  - test: `tests/app/srvrun_wtflow_test.c` —
    `test_srvrun_wt_exporter_sha384_suite`
  - test: `tests/app/srvrun_wtflow_test.c` —
    `test_srvrun_wt_exporter_refusals`
  - test: `tests/tls/keyschedule_test.c` —
    `test_keyschedule_exporter_secret_matches_oneshot`

## §5.1 フロー制御の使用のネゴシエーション

- [x] WTH3-051 (§5.1, §8) サーバーは、0 でない SETTINGS_WT_INITIAL_MAX_STREAMS_UNI、SETTINGS_WT_INITIAL_MAX_STREAMS_BIDI、SETTINGS_WT_INITIAL_MAX_DATA を送ってフロー制御を有効にしなければならない。
  - test: `tests/app/h3settings_control_settings_test.c` —
    `test_h3settings_control_settings_advertises_wt`
  - evidence: サーバーは 2^60 / 2^60 / 2^62-1 を送ります(`DEFAULT_WT_INITIAL_*`、control_settings.c)。テストは、広告した各値が 0 でない上限として受け入れられることと、1000 本のストリームがその範囲に収まることを確かめます。クライアントも 0 でない値を送れば、フロー制御は有効になります(`srvrun_wt_seed_limits`)。
- [x] WTH3-052 (§5.1) フロー制御が有効でないときに、接続上で 2 つ以上の WebTransport セッションを受け取った場合、サーバーは超過した CONNECT ストリームを H3_REQUEST_REJECTED でリセットしなければならない。
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_second_wt_connect_rejected_when_flow_control_disabled`
  - vuln: V-0503, V-0509
- [x] WTH3-053 (§5.1) フロー制御が有効でない場合、サーバーは受け取ったフロー制御のカプセルをすべて無視しなければならない。
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_wt_max_data_capsule_ignored_when_flow_control_disabled`
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_wt_max_streams_capsule_ignored_when_flow_control_disabled`
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_wt_streams_blocked_ignored_when_flow_control_disabled`
  - vuln: V-0505

## §5.2 同時セッション数の制限

- [x] WTH3-054 (§5.2) サーバーは、リソースの過剰な消費を防ぐために、H3_REQUEST_REJECTED または HTTP ステータスコード 429 を使って、届く WebTransport セッションの頻度を制限するべきである。
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_wt_reject_at_session_limit`
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_wt_session_creation_rate_limited`
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_second_wt_connect_rejected_429`
  - test: `tests/app/srvrun_test.c` — `test_srvrun_wt_occupancy_counts_open`
  - evidence: `wired_server_wt_occupancy` が開いているセッションの数と上限を返すので、アプリケーションは上限に達する前に負荷を減らせます。
  - vuln: V-0506
- [x] WTH3-055 (§5.2) フロー制御が有効でない間、サーバーは届く WebTransport セッションを同時に 2 つ以上受け入れてはならない。
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_second_wt_connect_rejected_when_flow_control_disabled`
  - vuln: V-0503, V-0509

## §5.3 セッション内のストリーム数の制限

- [x] WTH3-056 (§5.3) WT_MAX_STREAMS カプセルは、WebTransport セッション内のストリーム数の上限を定めなければならず、単方向ストリームと双方向ストリームで別々の型を持つ。
  - test: `tests/app/wtcapsule_test.c` —
    `test_wtcapsule_max_streams_bidi_roundtrip`
  - test: `tests/app/wt_session_test.c` —
    `test_flow_control_max_streams_bidi_enforced`
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_wt_rx_max_streams_capsules_raise_limits`
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_wt_rx_max_streams_capsule_via_dispatch_raises_limit`
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_wt_initial_max_streams_from_settings`
- [x] WTH3-057 (§5.3) エンドポイントは、相手が設定した現在のストリーム数の上限を超えてストリームを開いてはならない。
  - test: `tests/app/wt_session_test.c` —
    `test_flow_control_max_streams_bidi_enforced`
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_wt_open_uni_exceeding_max_streams_refused`
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_wt_open_bidi_exceeding_max_streams_refused`
- [~] WTH3-058 (§5.3) 広告した Maximum Streams の値を超えることになるストリームをセッションについて受け取った場合、エンドポイントは WT_FLOW_CONTROL_ERROR エラーコードで WebTransport セッションを閉じなければならない。
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_wt_refused_stream_reset_and_credited`
  - evidence: このサーバーは方向ごとに 2^60 本のストリームを広告し(WTH3-051)、自分の WT_MAX_STREAMS でそれを下げることもないので、届くストリームが上限を超えることはなく、受信側で閉じる処理は起こりえません。実際に届くストリームを制限しているのは固定サイズのストリーム表です。それを超えたストリームは H3_REQUEST_REJECTED でリセットし、QUIC のストリームのクレジットを返します。
- [x] WTH3-059 (§5.3, §5.6.3) ストリームを開きたいが、相手が設定したセッション単位のストリーム数の上限のために開けないとき、サーバーは WT_STREAMS_BLOCKED カプセルを送るべきである。
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_wt_open_uni_blocked_sends_streams_blocked`
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_wt_open_bidi_blocked_sends_streams_blocked`
  - test: `tests/app/wtcapsule_test.c` —
    `test_wtcapsule_streams_blocked_roundtrip`
- [x] WTH3-069 (§5.6.2) 受け取った WT_MAX_STREAMS の値が、その方向のセッションの現在のストリーム数の上限を増やさない(同じ値か減少)か、2^60 を超える場合、サーバーは WT_FLOW_CONTROL_ERROR エラーコードで WebTransport セッションを閉じなければならない。
  - test: `tests/app/wt_session_test.c` —
    `test_flow_control_max_streams_equal_value_rejected`
  - test: `tests/app/wt_session_test.c` —
    `test_flow_control_max_streams_decreasing_rejected`
  - test: `tests/app/wt_session_test.c` —
    `test_flow_control_max_streams_over_ceiling_rejected`
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_wt_nonincreasing_flow_control_capsule_closes_session`
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_wt_max_streams_over_ceiling_closes_session`
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_wt_initial_max_streams_from_settings`
- [x] WTH3-070 (§5.6.3) 受け取った WT_STREAMS_BLOCKED の値が 2^60 を超える場合、サーバーは WT_FLOW_CONTROL_ERROR エラーコードで WebTransport セッションを閉じなければならない。
  - test: `tests/app/wt_session_test.c` — `test_streams_blocked_ceiling`
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_wt_streams_blocked_over_ceiling_closes_session`
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_wt_streams_blocked_within_ceiling_is_noop`

## §5.4 データ量の制限

- [x] WTH3-060 (§5.4) WT_MAX_DATA カプセルは、WebTransport セッション内で送れるデータ量の上限を定めなければならない。
  - test: `tests/app/wtcapsule_test.c` — `test_wtcapsule_max_data_roundtrip`
  - test: `tests/app/wt_session_test.c` — `test_flow_control_max_data_enforced`
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_wt_rx_max_data_capsule_via_dispatch_unblocks_send`
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_wt_rx_max_data_capsule_via_on_step_raises_max_data`
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_wt_initial_max_data_from_settings`
- [x] WTH3-077 (§5.6.4) サーバーは、相手が広告した Maximum Data の値を超えて、セッションのストリームで Stream Body のデータを送ってはならない。
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_wt_open_uni_exceeding_max_data_refused`
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_wt_stream_reply_exceeding_max_data_refused`
- [~] WTH3-061 (§5.4) WT_MAX_DATA の上限を超える Stream Body のデータを受け取った場合、エンドポイントは WT_FLOW_CONTROL_ERROR エラーコードで WebTransport セッションを閉じなければならない。
  - evidence: このサーバーは 2^62-1 バイトを広告し(WTH3-051)、それを下げることもないので、受け取るデータが上限を超えることはなく、受信側で閉じる処理は起こりえません。受け取るデータは代わりに QUIC のストリームと接続のクレジットで制限されます。
- [x] WTH3-062 (§5.4, §5.6.5) データを送りたいが、セッション単位のフロー制御のために送れないとき、サーバーは WT_DATA_BLOCKED カプセルを送るべきである。
  - test: `tests/app/srvrun_wtflow_test.c` —
    `test_srvrun_wt_data_limited_send_emits_data_blocked_once`
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_wt_open_uni_blocked_by_data_limit_sends_data_blocked`
- [x] WTH3-063 (§5.4) WT_MAX_STREAM_DATA または WT_STREAM_DATA_BLOCKED カプセルを受け取った場合、サーバーはそれをセッションエラーとして扱わなければならない。
  - test: `tests/app/srvrun_wtsess_test.c` —
    `test_srvrun_wt_stream_level_flow_capsule_session_error`
  - evidence: セッションは WT_FLOW_CONTROL_ERROR(このセッションエラーのコードをドラフトは定めていない)と CONNECT ストリームの FIN で閉じます。
- [x] WTH3-071 (§5.6.4) 受け取った WT_MAX_DATA の値が、セッションの現在のデータ量の上限を増やさない(同じ値か減少)場合、サーバーは WT_FLOW_CONTROL_ERROR エラーコードで WebTransport セッションを閉じなければならない。
  - test: `tests/app/wt_session_test.c` —
    `test_flow_control_max_data_equal_value_rejected`
  - test: `tests/app/wt_session_test.c` —
    `test_flow_control_max_data_decreasing_rejected`
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_wt_nonincreasing_flow_control_capsule_closes_session`
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_wt_initial_max_data_from_settings`

## §5.6 フロー制御のカプセル

- [~] WTH3-078 (§5.6) フロー制御が有効な間、サーバーはデータを消費したりストリームを閉じたりするのに合わせて WT_MAX_DATA と WT_MAX_STREAMS のカプセルを送るべきであり、それらを送る前に WT_DATA_BLOCKED や WT_STREAMS_BLOCKED のカプセルを待ってはならない。
  - evidence: サーバーは WT_MAX_DATA/WT_MAX_STREAMS を送りません。代わりに、相手が使い切れない事実上無制限の初期上限(2^60 本のストリーム、2^62-1 バイト。WTH3-051)を広告するので(`tests/app/h3settings_control_settings_test.c` — `test_h3settings_control_settings_advertises_wt`)、クレジットを更新して送る必要は生じません。

## §6 セッションの終了

- [x] WTH3-064 (§6) CONNECT ストリームが(正常にまたは突然に)閉じたとき、または WT_CLOSE_SESSION カプセルを送るか受け取ったときに、WebTransport セッションは終了したと見なさなければならない。
  - test: `tests/app/wt_session_test.c` — `test_close_from_established`
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_connect_stream_reset_closes_wt_session`
- [x] WTH3-065 (§6) セッションが終了したと知ったとき、エンドポイントはそのセッションに結びついたすべてのストリームについて、WT_SESSION_GONE エラーコードで送信側をリセットし、受信側の読み取りを中止しなければならない。WT_SESSION_GONE はプロトコルレベルの HTTP/3 エラーコードであり、そのままの値で送り、WebTransport のアプリケーションエラーコードの範囲にはマッピングしない。また、エンドポイントは新しいデータグラムを送ったり、新しいストリームを開いたりしてはならない。
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_connect_stream_reset_resets_owned_wt_bidi_stream`
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_connect_stream_reset_resets_owned_wt_uni_stream`
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_connect_stream_reset_leaves_other_sessions_streams`
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_wt_send_datagram_to_requires_send_side_open`
  - evidence: CONNECT ストリームが閉じると、`srvrun_reset_wt_streams_for_session` が、閉じるセッションが持つすべての WT の双方向・単方向ストリーム(`wt_session_slot` で追跡)を WT_SESSION_GONE でリセットします。データグラムの送受信はそれとは別にセッションの状態で制限されます(9297-007/008)。
- [x] WTH3-066 (§6) 詳しいエラーメッセージ付きでセッションを終了するために、アプリケーションは 32 ビットの Application Error Code と最大 1024 バイトのエラーメッセージを運ぶ WT_CLOSE_SESSION (0x2843) カプセルでそのメッセージを渡してもよい。
  - test: `tests/app/wtcapsule_test.c` — `test_wtcapsule_close_roundtrip`
  - test: `tests/app/wtcapsule_test.c` —
    `test_wtcapsule_close_encode_rejects_long_message`
- [x] WTH3-067 (§6) WT_CLOSE_SESSION カプセルを送るとき、サーバーは直ちに CONNECT ストリームで FIN を送らなければならない。
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_send_wt_close_seals_capsule_with_fin`
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_wt_close_session_latches_pending`
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_drain_wt_close_pending_closes_session`
  - evidence: 公開 API の `wired_server_wt_close_session` がクローズの要求を保持し、`srvrun_drain_wt_close_pending` が WT_CLOSE_SESSION カプセルを CONNECT ストリームの最後の送信として封じるので、その後ろに FIN が続きます。カプセルは CONNECT ストリーム上の HTTP/3 DATA フレームの中で運ばれます(RFC 9297 3.2。[rfc9297.md](rfc9297.md) の 9297-024 を参照)。送信側は webtransport-go と照らし合わせて確かめました。
- [x] WTH3-079 (§6) WT_CLOSE_SESSION カプセルを受け取ったとき、サーバーはそれへの応答として CONNECT ストリームを閉じるかリセットしなければならない。
  - test: `tests/app/srvrun_close_test.c` —
    `test_srvrun_close_peer_capsule_fins_connect`
  - test: `tests/app/srvrun_close_test.c` —
    `test_srvrun_close_peer_fin_fins_connect`
  - test: `tests/app/srvrun_close_test.c` —
    `test_srvrun_close_peer_capsule_and_fin_one_fin`
  - test: `tests/app/srvrun_close_test.c` —
    `test_srvrun_close_bad_capsule_resets_no_fin`
  - evidence: `srvrun_wt_connect_fin` は、このサーバーの側をストリームの現在の終端での FIN で 1 回だけ閉じます(クローズの本体が不正なときは、代わりにストリームをリセットします。WTH3-072)。ループバックでのみテストしており、moq-playa との相互接続性のケース(`transport.closed`)はまだ再実行していません。
- [x] WTH3-080 (§6) WT_CLOSE_SESSION カプセルのあとに CONNECT ストリームで追加のストリームデータを受け取った場合、サーバーはコード H3_MESSAGE_ERROR でそのストリームをリセットしなければならない。
  - test: `tests/app/srvrun_wtsess_test.c` —
    `test_srvrun_wt_data_after_close_same_frame_resets`
  - test: `tests/app/srvrun_wtsess_test.c` —
    `test_srvrun_wt_data_after_close_later_frame_resets`
  - test: `tests/app/srvrun_wtsess_test.c` —
    `test_srvrun_wt_fin_after_close_no_reset`
  - evidence: クローズのあとに監視する CONNECT ストリームは接続ごとに 1 本です(`wired_srvloop_wt_watch`)。その間に別のセッションが閉じると、監視の対象はそちらに置き換わります。
- [x] WTH3-068 (§6) WT_CLOSE_SESSION カプセルなしで CONNECT ストリームを正常に終了することは、エラーコード 0 と空のエラー文字列を持つ WT_CLOSE_SESSION カプセルで終了することと意味の上で同じでなければならない。
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_connect_stream_reset_closes_wt_session`
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_other_stream_reset_does_not_close_wt_session`
- [x] WTH3-072 (§6) 受け取った WT_CLOSE_SESSION カプセルの Application Error Message が 1024 バイトを超えるか、有効な UTF-8 でない場合、サーバーはエラーコード H3_MESSAGE_ERROR で CONNECT ストリームをリセットしなければならない(WTH3-064 により、これでセッションも終了する)。
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_wt_close_message_too_long_resets_and_closes`
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_wt_close_message_invalid_utf8_resets_and_closes`
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_wt_close_message_at_max_len_closes_session`
  - test: `tests/app/wtcapsule_test.c` — `test_wt_utf8_valid_ascii`
  - test: `tests/app/wtcapsule_test.c` —
    `test_wt_utf8_invalid_truncated_sequence`
- [x] WTH3-073 (§6) アプリケーションが渡した WT_CLOSE_SESSION の Application Error Message を 1024 バイトの上限に切り詰めるとき、サーバーは上限以下で最後の UTF-8 の文字全体の境界で切り詰めなければならず、マルチバイトの並びを分割してはならない。
  - test: `tests/app/wtcapsule_test.c` —
    `test_wt_utf8_truncate_len_backs_off_before_split_sequence`
  - test: `tests/app/wtcapsule_test.c` —
    `test_wt_utf8_truncate_len_keeps_sequence_ending_at_cap`
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_wt_close_session_truncates_at_utf8_boundary`
- [x] WTH3-081 (§6) WT_CLOSE_SESSION を送り、QUIC 接続を閉じるつもりのとき、サーバーは CONNECTION_CLOSE を送る前に、すべての CONNECT ストリームが相手によって閉じられるまで待つべきである。
  - test: `tests/app/srvrun_wtflow_test.c` —
    `test_srvrun_wt_shutdown_waits_for_connect_close`
  - test: `tests/app/srvrun_wtflow_test.c` —
    `test_srvrun_wt_shutdown_wait_ends_on_reset_or_closing`
  - evidence: グレースフルシャットダウン(srvrun_loop)では、GOAWAY のドレインのあとにすべての生きているセッションに WT_CLOSE_SESSION を送り、相手がそれらの CONNECT ストリームを閉じるまで(上限は SRVRUN_WT_CLOSE_TICKS)処理を続けてから、H3_NO_ERROR の CONNECTION_CLOSE を送ります。エラーによるクローズは即座のままです。

## §8 セキュリティに関する考慮事項

- [x] WTH3-082 (§8) サーバーは、届くストリームやデータグラムの数など、WebTransport の機能の使用状況を追跡し、その使用に上限を設けるべきである。
  - test: `tests/app/srvrun_test.c` — `test_srvrun_wt_usage_counters_exposed`
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_wt_stream_churn_bounded_by_slot_table`
  - vuln: V-0494, V-0512
- [x] WTH3-083 (§8) サーバーは、接続を共有する各セッションに送信とストリームを開くためのリソースを妥当な割合で配る公平性の仕組みを実装するべきである。
  - test: `tests/app/srvrun_wtflow_test.c` —
    `test_srvrun_wt_fair_pass_equal_per_session`
  - test: `tests/app/srvrun_wtflow_test.c` —
    `test_srvrun_wt_open_capped_per_session`
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_wt_sched_equal_flows_share`
  - evidence: 各送信パスで、送れるストリームを持つすべてのセッションが同じ数のスライス(それらのセッションの送れる数の最小値)を送り、自分のストリームの間で順に回します。1 つのセッションが持てるのは、接続の内部処理が空けている送信スロット表のうち、均等に分けた分までです。

## §9.5 HTTP/3 エラーコードの登録

- [x] WTH3-074 (§9.5) WT_BUFFERED_STREAM_REJECTED と WT_SESSION_GONE は IANA の "HTTP/3 Error Code" レジストリに登録された HTTP/3 レベルのエラーコードであり、サーバーはそれらをそのままの値で送らなければならず、WebTransport のアプリケーションエラーコードの範囲にマッピングしてはならない。
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_wt_bidi_stream_buffer_full_sends_reset`
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_connect_stream_reset_resets_owned_wt_bidi_stream`

## 対象外

このサーバー SDK が実装しない、クライアントだけ・中継者だけの要件と参考情報の要件です。カバレッジの分母から除いています。

- (§2.1.1) QPACK の静的な展開と Huffman 復号のサポート。RFC 9204 の台帳で追跡しています。
- (§2.1.2) draft-ietf-webtrans-http2 が定義する、カプセルを使って 1 本のストリームの上で WebTransport を運ぶプロトコル("webtransport" HTTP/2 アップグレードトークンの変種)と、この文書のプロトコルを優先する SHOULD。この文書のネイティブなストリームへの対応付けとは別のプロトコルであり、HTTP/3 専用というこの SDK の範囲の外です。
- (§3.1) クライアントの義務: 1 より大きい SETTINGS_WT_ENABLED を H3_SETTINGS_ERROR として扱うこと、サーバーの設定より前にセッションを試みないこと、ドラフトのコードポイントを送ること、サーバーの要件が満たされないときにセッションを確立しないこと、任意の WT_REQUIREMENTS_NOT_MET でのクローズ。クライアントの動作です。
- (§3.2) ブラウザーのクライアントが Origin を送る義務、3xx のリダイレクトに自動で従わないこと、再開時の SETTINGS がフロー制御の値を下げたときに H3_SETTINGS_ERROR で閉じること。クライアントの動作です。
- (§3.3) アプリケーションプロトコルのネゴシエーションを必須とするサーバーが、適切な WT-Available-Protocols のない、または不正な形式の WT-Available-Protocols を持つリクエストを拒否すること。この SDK が提供しない任意(MAY)の厳格モードです。ネゴシエーションはオプトインで、拒否はしません。
- (§3.3) クライアント側での WT-Available-Protocols ヘッダーの組み立てと、不正な WT-Protocol のレスポンスに対する WT_ALPN_ERROR でのセッションのクローズ。クライアントの動作です。
- (§3.4) 同じ接続上のほかのセッションやリクエストと比べて WebTransport セッションの優先度を決めるときの、エンドポイント間のやり取りに関する懸念。定性的な指針であり、直接テストできるサーバーの動作ではありません。
- (§4.1) "Pooling" トランスポートプロパティーで、本当のプーリングのサポートの代わりにクォータのヘッダーを使う方法。任意(MAY)の補足であり、この SDK では、すでに確かめているセッション数の上限の動作(WTH3-052/054/055)とは別のコード経路として実装していません。
- (§4.3) クライアントが開く双方向ストリームで 0x41 のシグナルを送るクライアントの義務。クライアントの動作です(サーバーの認識は WTH3-034)。
- (§4.4) 中継者が RESET_STREAM/STOP_SENDING を同じフレーム型とエラーコードで転送すること。中継者の動作です。
- (§4.6) クライアントが CONNECT を送る前にサーバーの SETTINGS を待つこと。クライアントの動作です(サーバー側の保留は WTH3-009)。
- (§4.7) GOAWAY を受け取ったクライアントが、新しいセッションのために新しい接続を開くこと。クライアントの動作です。
- (§5.1) フロー制御が有効でないときに、クライアントが 2 つ以上のセッションを試みないこと。クライアントの動作です(サーバー側の拒否は WTH3-052)。
- (§5.2) クォータの方針を伝えるレート制限のヘッダーフィールド(I-D.ietf-httpapi-ratelimit-headers)。この SDK が実装しない別のドラフトです。
- (§5.6.1-§5.6.5) 中継者に固有の、フロー制御のカプセルの消費と表現し直しの動作。この SDK はエンドポイントであり、WebTransport の中継者ではありません。
- (§7) 現在ネゴシエートしているドラフトのコードポイントより先の、将来の WebTransport のバージョンに関する考慮事項。将来に向けた指針であり、このドラフト自身の実装への要件ではありません。
- (§8) クライアント側でのセッション数の自主的な制限と、不審な動きに対する任意(MAY)の H3_EXCESSIVE_LOAD でのクローズ。クライアントの動作、または任意の要件です。`H3_EXCESSIVE_LOAD` は定義されています(RFC 9114)が、ここでは使っていません。
