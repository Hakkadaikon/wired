[ドキュメント](../README.md) › [機能](README.md) › draft-ietf-moq-transport-22

# draft-ietf-moq-transport-22: Media over QUIC Transport

仕様の本文(`tasks/specs/draft-ietf-moq-transport-22.txt`。git には含まない)から抽出した、この SDK の MOQT サブセットについての EARS 形式の要件台帳です。対象のサブセットは、WebTransport 上の単一の中央ハブリレーで、SETUP、GOAWAY、PUBLISH(PUBLISH_STATE_NOTIFY を含む)、SUBSCRIBE(型付きの LOCATION_FILTER、FORWARD、優先度、OBJECT_DELIVERY_TIMEOUT を含む)、fill fetch ストリーム(FILL_PARAMETERS)、Range Filter、SUBSCRIBE・FETCH・名前空間リクエスト・送信者自身の PUBLISH に対する REQUEST_UPDATE、TRACK_STATUS、FETCH(Group 単位のキャッシュから応答)、PUBLISH_NAMESPACE(プレフィックスとして)/ SUBSCRIBE_NAMESPACE、SUBSCRIBE_TRACKS(ハブが始める PUBLISH または PUBLISH_SKIPPED)、PUBLISH_DONE、Subgroup ストリームと Object Datagram での Object の配送を実装します。ピアが WebTransport のサブプロトコル `moqt-22` をネゴシエートすると、セッションは draft-22 で動きます。データプレーン(SUBGROUP_HEADER、OBJECT_DATAGRAM、Object の本体、パディング)は draft-19 とバイト単位で同一です。このファイルには draft-22 に存在する要件だけを載せます(draft-19 には無いもの、draft-19 と書き方が違うものもあり、各項目の注記を参照)。draft-19 と文言まで同じ要件は、その台帳の文言とテストの参照を流用しています。このファイルは、draft-22 だけを読む人が別のドラフトの台帳と見比べなくて済むように置いています。各要件には、それを確かめるテストを付けています。チェックがなくテスト行もない項目は、未解決のギャップです。2026-10 時点の状況です。

ハブはすべてのセッション、Track、キャッシュを 1 つのプロセスのメモリに持ちます。`examples/moqt_chat` と同じように、単一プロセスで動かしてください(`--workers`、`--cores`、AF_XDP の振り分けは使わない)。

凡例:

- `[x]`: 挙げたテストで確認済み
- `[~]`: 間接的に確認(専用のテストはなく、evidence 行で確かめ方を説明)
- `[ ]`: まだどのテストでも確認していない

**カバレッジ: テスト済み 224/259、間接 34、未テスト 1。**

## SS8.1 可変長整数

- [x] MQ22-001 実装は、MOQT の可変長整数を、先頭バイトの上位から続く 1 のビットの数でエンコード長(1〜9 バイト)を決め、残りのビットと後続のバイトにネットワークバイトオーダーで値が入っているものとしてデコードしなければならない。
  - test: `tests/app/moqvi_test.c` — `test_moqvi_decode_official_examples`
  - test: `tests/app/moqvi_test.c` — `test_moqvi_decode_zero_all_lengths`
  - test: `tests/app/moqvi_test.c` — `test_moqvi_decode_nine_byte_padded`
- [x] MQ22-002 実装は、64 ビット符号なし整数のすべて(0〜2^64-1)を MOQT の可変長整数エンコーディングでエンコードしなければならない。
  - test: `tests/app/moqvi_test.c` — `test_moqvi_encode_official_examples`
  - test: `tests/app/moqvi_test.c` — `test_moqvi_encode_boundaries`
- [x] MQ22-003 実装は、可変長整数を、値を表せる最小のバイト数でエンコードしなければならない。
  - test: `tests/app/moqvi_test.c` — `test_moqvi_roundtrip`
  - test: `tests/app/moqvi_test.c` — `test_moqvi_encode_official_examples`
- [x] MQ22-004 可変長整数が必要最小より多いバイト数でエンコードされている場合、実装はそれでも正しい値にデコードしなければならない(最小でないエンコーディングも有効)。
  - test: `tests/app/moqvi_test.c` — `test_moqvi_decode_zero_all_lengths`
  - test: `tests/app/moqvi_test.c` — `test_moqvi_decode_nine_byte_padded`
- [x] MQ22-005 可変長整数のエンコード長が利用できるバイト数を超える場合、実装は入力の終わりを越えて読まず、デコードをデータ不足として報告しなければならない。
  - test: `tests/app/moqvi_test.c` — `test_moqvi_decode_truncated`
- [x] MQ22-006 実装は、可変長整数を自身のエンコード長を越えてバイトを消費せずにデコードし、入力の後続のバイトに手を付けずに残さなければならない。
  - test: `tests/app/moqvi_test.c` — `test_moqvi_decode_ignores_trailing`
- [x] MQ22-007 出力先のバッファーが値のエンコード長を収めるには小さすぎる場合、実装はバッファーの終わりを越えて書かず、エンコードを失敗させなければならない。
  - test: `tests/app/moqvi_test.c` — `test_moqvi_put_too_small`

## SS8.2 Location 構造

- [x] MQ22-008 実装は、Location を連続する 2 つの可変長整数(Group, Object)としてエンコード・デコードしなければならない。
  - test: `tests/app/moqctl_test.c` —
    `test_moqctl_location_roundtrip_and_order`
- [x] MQ22-009 実装は、2 つの Location A と B を、A.Group < B.Group であるか、A.Group == B.Group かつ A.Object < B.Object であるときに限り A < B となるように比較しなければならない。
  - test: `tests/app/moqctl_test.c` —
    `test_moqctl_location_roundtrip_and_order`

## SS8.3 Key-Value-Pair 構造

- [x] MQ22-010 実装は、Key-Value-Pair の Type を、直前までの累積 Type に Delta Type を足した値(最初のペアでは 0 に足す)としてデコードしなければならない。
  - test: `tests/app/moqkvp_test.c` — `test_moqkvp_take_even_num`
  - test: `tests/app/moqkvp_test.c` — `test_moqkvp_take_delta_accumulates`
- [x] MQ22-011 Key-Value-Pair の累積 Type が 2^64-1 を超える場合、実装はプロトコル違反を報告しなければならない。
  - test: `tests/app/moqkvp_test.c` — `test_moqkvp_take_type_overflow`
- [x] MQ22-012 実装は、Type が奇数の Key-Value-Pair の Value を Length バイトとして、Type が偶数のペアの Value を 1 つの可変長整数としてデコードしなければならない。
  - test: `tests/app/moqkvp_test.c` — `test_moqkvp_take_even_num`
  - test: `tests/app/moqkvp_test.c` — `test_moqkvp_take_odd_raw`
- [x] MQ22-013 Key-Value-Pair の Length フィールドは 2^16-1 バイトを超えてはならない。それより大きい長さを受信した場合、実装はプロトコル違反を報告しなければならない。
  - test: `tests/app/moqkvp_test.c` — `test_moqkvp_take_len_65535_accepted`
  - test: `tests/app/moqkvp_test.c` — `test_moqkvp_take_len_65536_violation`
  - vuln: V-0799
- [x] MQ22-014 Key-Value-Pair の Value が、実装の理解する Type で定められたシリアライズの形に合わない場合、実装はプロトコル違反とは区別したフォーマットエラーを報告しなければならない。
  - test: `tests/app/moqtrun_ssts_test.c` —
    `test_moqtrun_ssts_setup_malformed_closes`
  - test: `tests/app/moqctl_test.c` —
    `test_moqctl_params_auth_token_malformed_kvfmt`
  - note: 1 つ目のテストは、既知の Setup Option の値がデコードできないときにセッションを KEY_VALUE_FORMATTING_ERROR で閉じます。2 つ目のテストは、デコードできない Token 構造が、単なる違反ではなくフォーマットエラーに分類されることを示します(SS8.9)。
- [x] MQ22-015 実装は、Key-Value-Pair の Delta Type や Type が偶数の Value に最小のエンコード長を、デコードの条件として課してはならない(最小でないエンコーディングも有効)。
  - test: `tests/app/moqkvp_test.c` — `test_moqkvp_take_nonminimal_delta`
  - test: `tests/app/moqkvp_test.c` — `test_moqkvp_take_nonminimal_even_value`
- [x] MQ22-016 Key-Value-Pair が自身の既知のバイト境界の内側で途切れている場合、実装は入力を消費せずにデータ不足として報告し、閉じるかどうかの判断を呼び出し側に任せなければならない。
  - test: `tests/app/moqkvp_test.c` — `test_moqkvp_take_truncated_insufficient`
- [x] MQ22-017 実装は、Key-Value-Pair を呼び出し側が与えたバイト境界を越えて読まずにデコードし、Type の順序を保ったままラウンドトリップできる Key-Value-Pair のリストをエンコードしなければならない。
  - test: `tests/app/moqkvp_test.c` — `test_moqkvp_roundtrip`

## SS8.4 Track と Object のプロパティ

- [x] MQ22-240 (SS8.4, SS7.7, SS10.7-10.9) リレーは、自身が解釈しない Track と Object の Properties を、変更・追加・削除・統合を一切せずにそのまま転送しなければならない。Immutable Properties と、Prior Group/Object ID Gap のプロパティも含む。
  - test: `tests/app/moqtrun_sub_test.c` —
    `test_moqtrun_sub_include_properties_1_forwards`
  - test: `tests/app/moqtrun_upfetch_test.c` —
    `test_moqtrun_upfetch_reencode`
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_object_relay_preserves_bytes`
  - note: 1 つ目のテストは、パブリッシャーの Track Properties を SUBSCRIBE_OK へバイト単位でそのまま中継します。2 つ目のテストは、再エンコードしても Object の Properties が保たれることを確かめます。キャッシュがそれを保存していることは、キャッシュから応答する FETCH の経路(MQ22-214)を通じてしか示していません。

## SS8.5 Reason Phrase 構造

- [x] MQ22-018 実装は、Reason Phrase を、可変長整数の Length と、それに続く Length バイトの UTF-8 としてデコードしなければならない。
  - test: `tests/app/moqctl_test.c` — `test_moqctl_reason_boundary`
  - vuln: V-0800
- [~] MQ22-019 Reason Phrase の Length が 1024 バイトを超える場合、実装はプロトコル違反でセッションを閉じなければならない。
  - evidence: コーデックは VIOLATION を返します(`test_moqctl_reason_boundary`)。リクエストのデコードに失敗するとハブは PROTOCOL_VIOLATION で閉じます(`test_moqtrun_fillfix_malformed_subscribe`、`test_moqtrun_setup_malformed_closes`)が、この条件を起こすハブのテストはありません。

## SS8.7 Track Namespace 構造

- [x] MQ22-020 実装は、Track Namespace を、可変長整数のフィールド数と、それに続くその数の長さ付き Track Namespace Field としてデコードしなければならない。
  - test: `tests/app/moqctl_test.c` — `test_moqctl_ftn_decode_basic`
- [~] MQ22-021 Track Namespace Field の Length が 0 の場合、実装はプロトコル違反でセッションを閉じなければならない。
  - evidence: コーデックは VIOLATION を返します(`test_moqctl_ns_field_len_zero_rejected`)。リクエストのデコードに失敗するとハブは PROTOCOL_VIOLATION で閉じます(`test_moqtrun_fillfix_malformed_subscribe`、`test_moqtrun_setup_malformed_closes`)が、この条件を起こすハブのテストはありません。
- [~] MQ22-022 Track Namespace の Track Namespace Field が 32 個を超える場合、実装はプロトコル違反でセッションを閉じなければならない。
  - evidence: コーデックは VIOLATION を返します(`test_moqctl_ns_fields_32_accept_33_reject`)。リクエストのデコードに失敗するとハブは PROTOCOL_VIOLATION で閉じます(`test_moqtrun_fillfix_malformed_subscribe`、`test_moqtrun_setup_malformed_closes`)が、この条件を起こすハブのテストはありません。
- [~] MQ22-023 Full Track Name(Track Namespace と Track Name)が 4096 バイトを超える場合、実装はプロトコル違反でセッションを閉じなければならない。
  - evidence: コーデックは VIOLATION を返します(`test_moqctl_ftn_4096_accept_4097_reject`)。リクエストのデコードに失敗するとハブは PROTOCOL_VIOLATION で閉じます(`test_moqtrun_fillfix_malformed_subscribe`、`test_moqtrun_setup_malformed_closes`)が、この条件を起こすハブのテストはありません。
- [x] MQ22-024 実装は、Track Namespace Field と Track Name を、バイト列の完全一致で比較しなければならない。
  - test: `tests/app/moqctl_test.c` — `test_moqctl_ftn_eq_exact_bytes`

## SS12.1 不正な Track

- [~] MQ22-025 購読者が Malformed Track を検出した場合、実装はそのパブリッシャーからのその Track に対応する購読を取り消さなければならない。
  - evidence: デコード時の違反(未知の Object Status、累積 Object ID のオーバーフロー。MQ22-114/MQ22-130a を参照)に加えて、リレーは次を検出します。#4(その Group の最新の END_OF_GROUP Object より後の Object)、#5(END_OF_TRACK Object より後の Object)、#1(同じ Group と Subgroup ID の最新の Subgroup ヘッダーと Publisher Priority が異なる Subgroup ストリーム)、#7(キャッシュが Subgroup ストリームから得て保持している Object に対するデータグラム。Track は両方のモードを混ぜてよいので、同じ Object の場合だけを数える)。検出すると、すべての購読を PUBLISH_DONE MALFORMED_TRACK で終え、その Track の fetch ストリームを MALFORMED_TRACK でリセットし、パブリッシャーのリクエストを取り消し、きっかけになった Object はキャッシュしません。未対応のもの: 購読の経路での #6(ペイロードが異なる重複した Object。Object ごとにキャッシュを引く必要がある)と、#2/#3(FIN をまたぐ Subgroup の最終 Object)。
  - test: `tests/app/moqtrun_done_test.c` —
    `test_moqtrun_pubdone_malformed_after_end_of_track`
  - test: `tests/app/moqtrun_done_test.c` —
    `test_moqtrun_pubdone_malformed_after_end_of_group`
  - test: `tests/app/moqtrun_done_test.c` —
    `test_moqtrun_pubdone_malformed_resets_fetch`
  - test: `tests/app/moqtrun_done_test.c` —
    `test_moqtrun_pubdone_malformed_prio_mismatch`
  - test: `tests/app/moqtrun_done_test.c` —
    `test_moqtrun_pubdone_malformed_mode_change`

## SS2.4.3/6.5 予約済みの名前空間 / セッションレベルの Track

- [x] MQ22-028 リクエストが参照する Track Namespace の最初のフィールドが 1 つのピリオドである場合、実装はそれを DOES_NOT_EXIST で拒否しなければならない。
  - test: `tests/app/moqtrun_sub_test.c` — `test_moqtrun_reserved_ns_rejected`
  - test: `tests/app/moqtrun_ns_test.c` — `test_moqtrun_ns_reserved_rejected`
  - test: `tests/app/moqtrun_sub_test.c` — `test_moqtrun_other_dot_ns_served`
  - note: `moqtrun_ns_reserved`(台帳 10-1)は、最初のフィールドがちょうど `.` か `.session` である PUBLISH、SUBSCRIBE、PUBLISH_NAMESPACE、SUBSCRIBE_NAMESPACE を DOES_NOT_EXIST で拒否します。それ以外の `.` で始まるフィールドは、通常の名前空間と同じように扱います。この判定はバージョンに依存しません。

- [x] MQ22-221 (SS6.5) リクエストが名指す Track Namespace の最初のフィールドが `.session` である場合、ハブ(セッションレベルの Track を 1 つも定義しない)はそれを REQUEST_ERROR DOES_NOT_EXIST で拒否し、決してほかのセッションへ転送してはならない。
  - test: `tests/app/moqtrun_sub_test.c` — `test_moqtrun_reserved_ns_rejected`
  - test: `tests/app/moqtrun_ns_test.c` — `test_moqtrun_ns_reserved_rejected`

## SS3.1.3.1 未知の Track Alias

- [x] MQ22-226 (SS3.1.3.1) 実装は、接続のフロー制御のクレジットを、どのデータストリームよりも先に制御ストリームへ割り当てなければならない。
  - test: `tests/app/moqtrun_drain_test.c` — `test_moqtrun_prio_control_first`
    (ハブの制御ストリームは urgency 2 で、リクエストストリームの 3、Object ストリームの 4..7 より上)
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_wt_priority_conn_credit_to_urgent`(WT の送信パスは、接続の最後のクレジットをより緊急度の高いクラスに渡す)

## SS3.6 プレフィックスによる Track の購読

- [~] MQ22-225 (SS3.6, SS3.1) アプリケーションが名前空間の認可関数を設定している構成では、ハブはすべての SUBSCRIBE_TRACKS をそれに見せ、拒否されたら REQUEST_ERROR UNAUTHORIZED で応答しなければならない。これにより、ハブはそのコンテンツの認可を受けていない購読者へ PUBLISH を決して送らない。
  - evidence: SUBSCRIBE_TRACKS は、PUBLISH_NAMESPACE と SUBSCRIBE_NAMESPACE と同じ `moqtrun_disc_verdict` を通ります(`moqtrun_row.c`)。`test_moqtrun_ns_authorization` が確かめているのは、この 2 つの名前空間リクエストだけです。

## SS3.7 理解が必須の Track プロパティ

- [x] MQ22-222 (SS3.7) PUBLISH が Mandatory Track Property(型 0x4000-0x7FFF。このハブは一切理解しない)を含む場合、ハブは REQUEST_ERROR UNSUPPORTED_EXTENSION で応答し、その Track を転送してはならない。
  - test: `tests/app/moqtrun_sub_test.c` — `test_moqtrun_sub_publish_mandatory_refused`
- [x] MQ22-223 (SS3.7) 上流の SUBSCRIBE_OK が Mandatory Track Property を含む場合、ハブはその購読を取り消し、保留中の下流の SUBSCRIBE のそれぞれに REQUEST_ERROR UNSUPPORTED_EXTENSION で応答しなければならない。
  - test: `tests/app/moqtrun_upsub_test.c` — `test_moqtrun_upsub_ok_mandatory_refused`
- [x] MQ22-224 (SS3.7) Object が Mandatory Track Property を Object Property として含む場合、ハブはその Track を不正なもの(SS12.1)として扱わなければならない。
  - test: `tests/app/moqtrun_done_test.c` — `test_moqtrun_pubdone_malformed_mandatory_obj_prop`

## SS6.2 セッションの確立

- [x] MQ22-248 (SS6.2) サーバーは、`moqt-22` を(自身が話すそれ以前のドラフトとともに)WT-Available-Protocols と ALPN で提示し、ネゴシエートしたトークンが `moqt-22` のセッションを draft-22 の意味論で動かさなければならない。
  - test: `tests/app/moqver_test.c` — `test_moqver_find_each_token`
  - test: `tests/app/moqver_test.c` — `test_moqver_offer`
  - test: `tests/app/moqtrun_raw_test.c` — `test_moqtrun_raw_ver_from_alpn`
- [~] MQ22-247 (SS6.2) サーバーは、MOQT を運ぶ接続で QUIC DATAGRAM 拡張をサポートし、ネゴシエートしなければならない。
  - evidence: `test_server_tp_datagram_frame_size`(`tests/tls/server_tp_test.c`)は、サーバーが max_datagram_frame_size を広告できることを示します。MOQT の運用でそれを有効にするのは設定の問題で、ここでは確かめていません(RFC 9221 の台帳を参照)。

## SS6.3 セッションの初期化

- [x] MQ22-029 サーバーは、単方向の制御ストリームを 1 本開き、最初のメッセージとして SETUP を送信しなければならない。
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_token_session_opens_uni_ctl`
  - test: `tests/app/moqtrun_test.c` — `test_moqtrun_client_uni_ctl_accepted`
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_refused_uni_ctl_open_retries`
  - note: WT のトークンが空のセッション(サブプロトコルを提示しないクライアント。たとえば WebTransport の `protocols` に対応していないブラウザー)は、以前のドラフトと同じ双方向の制御ストリーム 1 本を使い続けます(`test_moqtrun_empty_token_keeps_bidi_ctl`)。
- [x] MQ22-030 両方のエンドポイントが SETUP を送信し受信したら、セッションは Established にならなければならない。
  - test: `tests/app/moqtrun_test.c` — `test_moqtrun_client_uni_ctl_accepted`
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_token_requests_held_until_established`
- [x] MQ22-031 双方向のリクエストストリームは、First-type のメッセージ(TRACK_STATUS, SUBSCRIBE, PUBLISH, FETCH, PUBLISH_NAMESPACE, SUBSCRIBE_NAMESPACE, SUBSCRIBE_TRACKS)のいずれかで始まらなければならない。そうでない場合、実装はプロトコル違反でセッションを閉じなければならない。
  - test: `tests/app/moqtrun_sub_test.c` —
    `test_moqtrun_req_bad_first_message_closes`
- [x] MQ22-032 Object を含む単方向ストリームや双方向のリクエストストリームが、両方の制御ストリームで SETUP が済む前に届く場合、ハブはそれをバッファーに入れ、SETUP が済んでから処理しなければならない。
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_token_requests_held_until_established`
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_token_object_stream_held_until_established`
- [x] MQ22-033 SETUP がまだ済んでおらず、リクエストストリームをバッファーに入れられない場合、ハブはそれをリセット(EXCESSIVE_LOAD)しなければならない。
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_token_unbufferable_request_reset`
- [~] MQ22-034 ピアは、自身の SETUP の後、ハブの SETUP を待たずにリクエストをパイプライン化してもよい。
  - evidence: ハブはセッションが開いたときに自身の SETUP を送信し、クライアントの SETUP が届くとすぐにそのクライアントのリクエストを処理します(`test_moqtrun_token_requests_held_until_established`)。パイプライン化そのものはセッションモデル(`test_moqsess_pipeline_before_peer_setup`)でしか固定しておらず、ハブはそのモデルを使っていません。
- [x] MQ22-035 セッションの存続中に制御ストリームがトランスポート層で閉じられた場合、実装はプロトコル違反でセッションを閉じなければならない。
  - test: `tests/app/moqtrun_test.c` — `test_moqtrun_ctl_fin_violates`
  - test: `tests/app/moqtrun_test.c` — `test_moqtrun_ctl_reset_violates`
- [x] MQ22-036 同じピアが 2 本目の制御ストリームを開いた場合、実装はプロトコル違反でセッションを閉じなければならない。
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_second_ctl_stream_violates`
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_on_session_twice_is_idempotent`

## SS12.2/12.5 セッション終了とストリームリセットのエラーコード(使っている一部)

- [~] MQ22-037 実装は、セッション終了のエラーコード表のうち自身が使う項目(NO_ERROR, INTERNAL_ERROR, PROTOCOL_VIOLATION, INVALID_REQUEST_ID, DUPLICATE_TRACK_ALIAS, KEY_VALUE_FORMATTING_ERROR, INVALID_PATH, GOAWAY_TIMEOUT, INVALID_AUTHORITY)を認識しなければならない。
  - evidence: これらのコードは、コーデックでラウンドトリップさせるのではなく、呼び出し箇所で `#define` として使っています(moqctl.h/moqsess.h)。表全体を列挙する専用のテストはありませんが、各コードはそれぞれの違反の箇所で動いています(このファイル全体にある sess/data/ctl の望ましくない動作の項目を参照)。draft-22 はセッションのコード 0x15(VERSION_NEGOTIATION_FAILED。未割り当て)を削除しています。受信側は未知のコードをもともと普通の切断として扱うので、ワイヤー上は安全です(対象外を参照)。

## SS6.4.1 単方向ストリームの型

- [x] MQ22-038 実装は、単方向ストリームの先頭の可変長整数を、SETUP (0x2F00)、FETCH_HEADER (0x05)、SUBGROUP_HEADER (0b0XX1XXXX)、PADDING (0x132B3E28) のいずれかに分類しなければならない。
  - test: `tests/app/moqdata_test.c` — `test_moqdata_classify_golden`
- [x] MQ22-039 エンドポイントが未知の単方向ストリームの型を受信した場合、実装はプロトコル違反でセッションを閉じなければならない。
  - test: `tests/app/moqtrun_sess_test.c` — `test_mtss_unknown_uni_closes`
  - test: `tests/app/moqtrun_sess_test.c` — `test_mtss_padding_stream_kept`
- [x] MQ22-040 実装は、単方向ストリームを、途切れた先頭の型フィールドを越えてバイトを消費せずに分類し、代わりに分類をデータ不足として報告しなければならない。
  - test: `tests/app/moqdata_test.c` — `test_moqdata_classify_truncated`

## SS6.6 終了

- [x] MQ22-041 サーバーは、WebTransport で運ぶ MOQT セッションを、CLOSE_WEBTRANSPORT_SESSION の仕組みで閉じなければならない。
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_ctl_unknown_type_closes_session`
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_ctl_over_max_closes_session`
  - test: `tests/app/moqtrun_sub_test.c` —
    `test_moqtrun_req_bad_first_message_closes`
  - evidence: ハブは、io テーブルの `close_session` 操作(本番では `wired_server_wt_close_session`)を通じて、ドラフトの終了コードで閉じます。WT_CLOSE_SESSION カプセルそのものは WebTransport の台帳で確かめています。

## SS6.6.1 セッションの移行 / SS9.2 GOAWAY(セッションのライフサイクル)

- [x] MQ22-042 GOAWAY を送信または受信したエンドポイントは、セッションを開いたまま、エンドポイントが終了しつつあることを示すエラーで新しいリクエストを拒否してもよい。
  - test: `tests/app/moqtrun_drain_test.c` —
    `test_moqtrun_goaway_late_rejected`
- [x] MQ22-043 制御ストリームで GOAWAY を受信したエンドポイントは、自分から新しいリクエストを始めてはならない。ただし、GOAWAY だけを理由にセッションを閉じることはしない。
  - test: `tests/app/moqtrun_upfetch_test.c` —
    `test_moqtrun_upfetch_upsub_skips_goaway`
- [x] MQ22-044 ピアが GOAWAY のタイムアウト内にセッションを閉じない場合、送信側は GOAWAY_TIMEOUT でセッションを閉じなければならない。
  - test: `tests/app/moqtrun_drain_test.c` —
    `test_moqtrun_goaway_timeout_flush_then_close`
- [x] MQ22-045 サーバーが New Session URI Length が 0 でない GOAWAY を受信した場合、実装はプロトコル違反でセッションを閉じなければならない。
  - test: `tests/app/moqtrun_drain_test.c` — `test_moqtrun_peer_goaway_uri`
- [x] MQ22-046 同じ制御ストリームが GOAWAY を 2 回以上受信した場合、実装はプロトコル違反でセッションを閉じなければならない。
  - test: `tests/app/moqtrun_drain_test.c` — `test_moqtrun_peer_goaway_twice`
- [x] MQ22-047 GOAWAY を制御ストリームではなくリクエストストリームで受信する場合、実装はセッションを閉じずにそれを受け入れなければならない。ただし、同じリクエストストリームで 2 回目の GOAWAY を受信したら、やはりプロトコル違反として扱わなければならない。
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_goaway_on_request_stream_produces_no_reply`
  - test: `tests/app/moqtrun_sub_test.c` —
    `test_moqtrun_req_second_goaway_closes`
  - test: `tests/app/moqtrun_upfetch_test.c` —
    `test_moqtrun_upfetch_two_goaways`
  - note: GOAWAY のワイヤー上のレイアウトは draft-19 から変わっていません(draft-18 と違い、末尾の Request ID フィールドはない。`docs/features/draft-moq-transport-18.md` の MQ18-048a を参照)。

## SS7 リレー(SS7.x の転送の規律)

- [x] MQ22-048 リレーは、複数の Object を運ぶストリームで受信した Object を購読者へ転送するとき、その順序を入れ替えたり Object を落としたりしてはならない。
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_object_relay_to_subscriber`
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_object_relay_two_subscribers_two_objects`
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_relay_forwards_bytes_as_they_arrive`
- [x] MQ22-049 リレーは、Object を転送するとき、Object のヘッダーのフィールドやペイロードを変更してはならない。
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_object_relay_preserves_bytes`
- [x] MQ22-050 リレーは、下流の SUBSCRIBE への応答として SUBSCRIBE_OK を送信する前に、Established の上流の購読を持っていなければならない。
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_subscribe_matching_publish_replies_ok`
  - test: `tests/app/moqtrun_upsub_test.c` —
    `test_moqtrun_upsub_ok_after_upstream`
- [x] MQ22-051 どのパブリッシャーも PUBLISH していない Track への SUBSCRIBE をリレーが受信した場合、実装は、その Track の名前空間またはそのプレフィックスを PUBLISH_NAMESPACE した(購読者以外の)セッションへ、上流の SUBSCRIBE を送信しなければならない(SS7.6)。送信はその場で行うか、保留した SUBSCRIBE では PUBLISH_NAMESPACE が届いたときに行う。上流の購読が Established になったら SUBSCRIBE_OK を、上流がエラーを返したらそのコードで REQUEST_ERROR を応答する。そのようなパブリッシャーがいない(かつ RENDEZVOUS_TIMEOUT もない)場合は、REQUEST_ERROR DOES_NOT_EXIST を応答しなければならない。
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_subscribe_without_publish_replies_error`
  - test: `tests/app/moqtrun_upsub_test.c` —
    `test_moqtrun_upsub_ok_after_upstream`,
    `test_moqtrun_upsub_error_relayed`,
    `test_moqtrun_upsub_hold_then_announce`,
    `test_moqtrun_upsub_own_namespace`, `test_moqtrun_upsub_prefix`,
    `test_moqtrun_upsub_cross_draft`
  - note: 上流の SUBSCRIBE は Full Track Name ごとに 1 つで、最初に一致した告知元へ送ります。ただし `multi_publisher` が有効なら、一致するパブリッシャーのそれぞれ(後から告知したものも含む)へ 1 つずつ送ります(MQ22-229)。下流の誰も必要としなくなった上流の購読は取り消します(`test_moqtrun_upsub_last_cancel_cancels_upstream`)。上流がパブリッシャー側で終わったときは、下流の購読を終えずに、別の告知元を待ちます(MQ22-208〜MQ22-212)。
- [~] MQ22-052 複数の購読者が同じ Track を要求するとき、リレーはその Track についての認可済みの購読を集約し、上流からの 1 つの Object を一致する下流の購読者すべてへ転送してもよい。
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_chat_object_relays_to_all_three_subscribers`
  - test: `tests/app/moqtrun_upsub_test.c` —
    `test_moqtrun_upsub_two_share_one`
- [x] MQ22-208 ハブの上流の購読がパブリッシャー側で終わったとき(PUBLISH_DONE GOING_AWAY または INTERNAL_ERROR、ハブの SUBSCRIBE ストリームのリセット、パブリッシャーのセッションの切断。ハブ自身による切断(GOAWAY のドレインの期限切れ、プロトコル違反)も含む)、リレーは下流の各購読を、終わった時点から最大 `WIRED_MOQTRUN_RDV_MAX_MS` の間(延長はしない)保持し、その待機中にまだ試していない一致する告知元の 1 つへ SUBSCRIBE を送信しなければならない。待っている購読者自身のセッションは、その購読者については除外し、ほかにまだ試していない告知元が残っていないときに限ってほかの購読者のために問い合わせる(SS7.6, SS7.6.1)。その SUBSCRIBE が拒否されるかリセットされたら次へ進み、あるセッションがその Track を覆う新しい PUBLISH_NAMESPACE を送ると、そのセッションは再び候補になる。最初の SUBSCRIBE_OK で、待っているすべての購読を、すでに持っている Track Alias と状態(待機中に受けた REQUEST_UPDATE も含む)のまま付け直す。スイッチングセットのメンバーは付け直しのときにそのセットを離れるので、待機中にスイッチングセットを割り当てる REQUEST_UPDATE は拒否する(UNSUPPORTED_EXTENSION。その後、そのリクエストの唯一の PUBLISH_DONE は UPDATE_FAILED)。
  - test: `tests/app/moqtrun_repath_test.c` —
    `test_moqtrun_repath_takeover`, `test_moqtrun_repath_each_end`,
    `test_moqtrun_repath_hub_closes`,
    `test_moqtrun_repath_late_announce`, `test_moqtrun_repath_failover`,
    `test_moqtrun_repath_ender_skipped`,
    `test_moqtrun_repath_untry_covering`, `test_moqtrun_repath_own_announce`,
    `test_moqtrun_repath_prefers_outsider`,
    `test_moqtrun_repath_ends_again`, `test_moqtrun_repath_update`
  - test: `tests/app/moqtrun_ssts_test.c` —
    `test_moqtrun_ssts_repath_member`,
    `test_moqtrun_ssts_repath_rejoin_refused`
  - note: `multi_publisher` が無効なら、上流は 1 つの Track につき一度に 1 つです(MQ22-229)。有効なら一致するパブリッシャーすべてを購読し、パブリッシャーが去った購読は、待たずに別のパブリッシャーの購読へまとめます。
- [x] MQ22-209 新しい経路を待っている購読には、2 回目の SUBSCRIBE_OK も REQUEST_ERROR も送ってはならない(SS3.1: 1 つのリクエストに応答は 1 つ)。一方、同じ Track への新しい SUBSCRIBE には、保留中の上流から引き続き応答しなければならない(購読者自身のセッションへの上流には決して乗せない。RENDEZVOUS_TIMEOUT があれば期限まで待ち続ける。ハブが閉じようとしているセッションへの上流や、そのセッション上の告知元も使わない)。待機中にすでに試した告知元しか残っていなければ、すぐに DOES_NOT_EXIST を応答する。
  - test: `tests/app/moqtrun_repath_test.c` —
    `test_moqtrun_repath_takeover`, `test_moqtrun_repath_refusal_hidden`,
    `test_moqtrun_repath_fresh_rides`, `test_moqtrun_repath_fresh_dne`,
    `test_moqtrun_repath_fresh_own_upstream`,
    `test_moqtrun_repath_fresh_own_upstream_rt`,
    `test_moqtrun_repath_fresh_closing_upstream`
- [x] MQ22-210 期限までに新しい経路が Established にならない場合、リレーは待っている各購読に、元の終了のステータス(GOING_AWAY または INTERNAL_ERROR。リセットやセッションの切断では INTERNAL_ERROR)の PUBLISH_DONE をちょうど 1 回送信しなければならない。SUBSCRIBE がまだ保留中でも送信し、その SUBSCRIBE は取り消す。待機中、リクエストストリームにはほかに何も送らない。その Stream Count は、付け直しの前後を通じて、ハブがその購読のために開いたすべてのストリームを数える。待つ余地がなければ PUBLISH_DONE はすぐに送る。SWITCH_FROM の古い側、新しい経路の SUBSCRIBE_OK で付け直せない待機者(その SUBSCRIBE_OK の時点)でも同じで、購読者自身の GOAWAY のドレインが尽きたときは GOING_AWAY で送る。
  - test: `tests/app/moqtrun_repath_test.c` —
    `test_moqtrun_repath_silent_wait`, `test_moqtrun_repath_expiry`,
    `test_moqtrun_repath_expiry_status`, `test_moqtrun_repath_done_once`,
    `test_moqtrun_repath_stream_count`, `test_moqtrun_repath_drain_flush`,
    `test_moqtrun_repath_deadline_beats_pending`,
    `test_moqtrun_repath_deadline_fixed`, `test_moqtrun_repath_new_closes`,
    `test_moqtrun_repath_no_room`, `test_moqtrun_repath_table_full`,
    `test_moqtrun_repath_session_share`,
    `test_moqtrun_repath_own_announce`, `test_moqtrun_repath_names_wrapped`
  - test: `tests/app/moqtrun_switch_test.c` —
    `test_moqtrun_switch_old_side_no_wait`,
    `test_moqtrun_switch_waiting_new_released`
- [x] MQ22-211 上流の PUBLISH_DONE がそれ以外のステータスの場合と、Malformed Track(SS12.1)の場合は、下流の購読をそのステータスですぐに終えなければならない。ほかの告知元には問い合わせない。
  - test: `tests/app/moqtrun_repath_test.c` —
    `test_moqtrun_repath_final_status`, `test_moqtrun_repath_malformed`
- [x] MQ22-212 待機中に去った購読は、決して付け直してはならず、PUBLISH_DONE も受け取らない。誰も待たなくなった上流の SUBSCRIBE は取り消し、取り消したものへの応答は無視し、Established になった新しい上流は、そのパブリッシャーが名前空間を取り下げても残す。
  - test: `tests/app/moqtrun_repath_test.c` —
    `test_moqtrun_repath_leave`, `test_moqtrun_repath_all_leave`,
    `test_moqtrun_repath_stale_ok`, `test_moqtrun_repath_one_upstream`,
    `test_moqtrun_repath_withdraw_keeps`

- [x] MQ22-228 (SS7.6, SS7.2, SS5.1.3, SS9.20.3, SS9.20.4) リレーの上流の SUBSCRIBE は、パラメーターを 1 つも持ってはならない。つまり一時停止させず(FORWARD の既定値は 1)、Subscriber Priority、Group Order、配送タイムアウトを下流の購読から写さない。
  - test: `tests/app/moqtrun_upsub_test.c` —
    `test_moqtrun_upsub_ok_after_upstream`
- [x] MQ22-229 (SS7.6) リレーは、Track に一致するすべてのパブリッシャー(Established の上流の購読と、その Track を覆うすべての PUBLISH_NAMESPACE)へ SUBSCRIBE を送信しなければならない。
  - test: `tests/app/moqtrun_mpub_test.c` —
    `test_moqtrun_mpub_subscribes_every_announcer`,
    `test_moqtrun_mpub_dedup_streams`, `test_moqtrun_mpub_dedup_datagrams`,
    `test_moqtrun_mpub_publisher_leaves`,
    `test_moqtrun_mpub_subscriber_cancel`, `test_moqtrun_mpub_one_refuses`,
    `test_moqtrun_mpub_late_announcer`, `test_moqtrun_mpub_two_publish`
  - note: `wired_moqt_hub.multi_publisher` が有効なときの動作です(examples/moqt_interop が設定する。既定の 0 では、moqt_chat が求めるとおり 1 つの名前につきパブリッシャーは 1 つで、最も新しいセッションが持つ)。重複の除去は、Subgroup ストリーム(Group, Subgroup)とデータグラム(Group, Object)を単位に、ハブ全体で 64 エントリの窓で行います。最初のパブリッシャーが途中で残した Subgroup を、もう一方の捨てた複製から補うことはしません。モデル: tasks/loopeng/MoqtMultiPub(#149)。
- [x] MQ22-227 (SS7.2, SS7.6) パブリッシャーの PUBLISH が購読を一時停止させ(FORWARD 0)、下流の購読者が一時停止していない場合、リレーは REQUEST_UPDATE FORWARD 1 でそれを再開させなければならない。
  - test: `tests/app/moqtrun_upsub_test.c` —
    `test_moqtrun_upsub_publish_resumed`
  - note: PUBLISH のときと、下流の各 SUBSCRIBE / REQUEST_UPDATE のときに確かめます。従来の単一の双方向制御ストリーム上の PUBLISH は再開させません。
- [x] MQ22-230 (SS9.20.6, SS7.6) SUBSCRIBE が、パブリッシャーのいない Track に対して 0 でない RENDEZVOUS_TIMEOUT を持つ場合、ハブはそれを(最大 `WIRED_MOQTRUN_RDV_MAX_MS` の間)保留し、パブリッシャーが現れたら SUBSCRIBE_OK で応答し(その購読者の SUBSCRIBE_TRACKS が受け取るはずの PUBLISH は、あわせて送らない)、期限が来たら REQUEST_ERROR TIMEOUT で応答しなければならない。パラメーターがないか 0 なら、すぐに DOES_NOT_EXIST で応答し、続けて FIN を送る。
  - test: `tests/app/moqtrun_rdv_test.c` — `test_moqtrun_rdv_s2_timeout`
  - test: `tests/app/moqtrun_rdv_test.c` — `test_moqtrun_rdv_s3_zero_is_dne`
  - test: `tests/app/moqtrun_rdv_test.c` — `test_moqtrun_rdv_s4_resolve`
  - test: `tests/app/moqtrun_rdv_test.c` — `test_moqtrun_rdv_s6_clamp`
  - test: `tests/app/moqtrun_rdv_test.c` —
    `test_moqtrun_rdv_s12_subtracks_skips_held`

## SS9 制御メッセージ: 共通の外枠

- [x] MQ22-053 実装は、すべての制御メッセージを Message Type(varint)+ Message Length(16 ビット)+ Message Body としてエンコード・デコードしなければならない。
  - test: `tests/app/moqctl_test.c` — `test_moqctl_peek_type_setup`
  - test: `tests/app/moqctl_test.c` — `test_moqctl_setup_roundtrip`
- [x] MQ22-054 実装は、Message Type の表のうち自身が実装する項目を認識しなければならない: SETUP (0x2F00)、GOAWAY (0x10)、SUBSCRIBE (0x3)、SUBSCRIBE_OK (0x4)、PUBLISH (0x1D)、PUBLISH_DONE (0xB)、REQUEST_OK (0x7)、REQUEST_ERROR (0x5)、(draft-22 で新設の)PUBLISH_STATE_NOTIFY (0x22。MQ22-182 を参照)。
  - test: `tests/app/moqctl_test.c` — `test_moqctl_peek_type_setup`
  - test: `tests/app/moqctl_test.c` — `test_moqctl_setup_roundtrip`
  - test: `tests/app/moqctl_test.c` — `test_moqctl_subscribe_roundtrip`
  - test: `tests/app/moqctl_test.c` — `test_moqctl_subscribe_ok_roundtrip`
  - test: `tests/app/moqctl_test.c` — `test_moqctl_publish_roundtrip`
  - test: `tests/app/moqctl_test.c` — `test_moqctl_publish_done_roundtrip`
  - test: `tests/app/moqctl_test.c` — `test_moqctl_request_ok_roundtrip`
  - test: `tests/app/moqctl_test.c` — `test_moqctl_request_error_roundtrip`
  - test: `tests/app/moqctl_test.c` — `test_moqctl_goaway_roundtrip`
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_ctl_publish_state_notify_d22_only`
  - evidence: FETCH (0x16。draft-22 の本体のレイアウト。MQ22-131 を参照)、FETCH_OK (0x18)、TRACK_STATUS (0xD)、REQUEST_UPDATE (0x2)、PUBLISH_NAMESPACE (0x6。プレフィックスの意味論。MQ22-182a を参照)、SUBSCRIBE_NAMESPACE (0x50)、NAMESPACE (0x8)、NAMESPACE_DONE (0xE) は、それぞれ専用のコーデック(fetch/、ns/、tstat/)がエンコード・デコードし、どれもゴールデンベクターで固定しています。
- [x] MQ22-055 エンドポイントが未知の Message Type を受信した場合、実装は呼び出し側がセッションを閉じられるように、それを区別して報告しなければならない。
  - test: `tests/app/moqctl_test.c` — `test_moqctl_peek_type_unknown`
- [x] MQ22-056 実装は、外枠の先読みでは本体をデコードしない既知の Message Type(REQUEST_UPDATE、FETCH、TRACK_STATUS、PUBLISH_NAMESPACE、SUBSCRIBE_NAMESPACE、SUBSCRIBE_TRACKS など)を、まったく未知の型と区別しなければならない。これにより、呼び出し側はセッションを閉じる代わりに、それを振り分けるか NOT_SUPPORTED で応答できる。現在のハブは、SUBSCRIBE_TRACKS(MQ22-193)を含めてこれらすべてに応答する。
  - test: `tests/app/moqctl_test.c` —
    `test_moqctl_peek_type_known_unimplemented`
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_unknown_first_type_gets_not_supported`
- [x] MQ22-057 制御メッセージの宣言された Length が、実際に利用できる Message Body の長さと一致しない場合、実装はそのメッセージを完全なものとして扱ってはならない(本体の終わりを越えて読み違えるのではなく、データ不足として報告する)。
  - test: `tests/app/moqctl_test.c` — `test_moqctl_peek_type_length_mismatch`
  - test: `tests/app/moqctl_test.c` — `test_moqctl_peek_type_truncated`
- [x] MQ22-058 実装は、全体の長さが 2^16-1 バイトまでの制御メッセージをサポートしなければならない。
  - test: `tests/app/moqctl_test.c` — `test_moqctl_peek_type_max_len_field`
- [~] MQ22-231 (SS9) 制御メッセージの本体を型に従って解析したとき、宣言された Message Length でちょうど終わらない(フィールドが途中で切れている、またはバイトが余る)場合、実装は PROTOCOL_VIOLATION でセッションを閉じなければならない。
  - evidence: FETCH と名前空間のコーデックは、本体が途中で切れているかバイトが余っていると VIOLATION を返します(`test_moqfetch_length_mismatch`、`test_moqns_length_mismatch`)。ハブは、デコードに失敗した FETCH の本体(`test_moqtrun_fetch_malformed_closes`。未知の Fetch Type)で PROTOCOL_VIOLATION で閉じます。Length と本体が食い違うメッセージを送るハブのテストはありません。

## SS6.4.2.1 Request ID

- [~] MQ22-059 サーバーは、1 から始めて、自身が始める新しいリクエストごとに 2 ずつ増やした奇数の Request ID を生成しなければならない。
  - test: `tests/app/moqtrun_upsub_test.c` —
    `test_moqtrun_upsub_ok_after_upstream`
  - evidence: テストは、上流の SUBSCRIBE の Request ID が奇数であることを確かめています。開始値 1 と +2 の刻み(`request_id_next`、moqtrun.h)は確かめていません。クライアントの偶数 ID の規則はクライアントだけのものです。
- [x] MQ22-060 エンドポイントが受信した Request ID の最下位ビットが送信者にとって正しくない場合、実装は INVALID_REQUEST_ID でセッションを閉じなければならない。
  - test: `tests/app/moqtrun_sess_test.c` — `test_mtss_rid_parity_closes`
- [x] MQ22-061 エンドポイントが重複した Request ID を受信した場合、実装は INVALID_REQUEST_ID でセッションを閉じなければならない。
  - test: `tests/app/moqtrun_sess_test.c` — `test_mtss_rid_duplicate_closes`
  - test: `tests/app/moqtrun_sess_test.c` — `test_mtss_rid_out_of_order_ok`
  - test: `tests/app/moqtrun_sess_test.c` — `test_mtss_rid_window_slides`

## SS9.20 メッセージのパラメーター

- [x] MQ22-062 実装は、Message Parameters を、Type Delta(varint。直前の Parameter Type からの累積)と、それに続く Value としてデコードしなければならない。Value のエンコーディング(uint8、varint、Location、長さ付きのバイト列、Track Namespace)は Type ごとに決まっている。
  - test: `tests/app/moqctl_test.c` — `test_moqctl_params_forward_roundtrip`
  - test: `tests/app/moqctl_test.c` —
    `test_moqctl_params_delivery_timeout_decode`
- [~] MQ22-063 パラメーターは Type の昇順にシリアライズしなければならない。累積の Parameter Type が 2^64-1 を超える場合、実装はプロトコル違反でセッションを閉じなければならない。
  - evidence: コーデックは VIOLATION を返します(`test_moqctl_params_type_overflow_violation`)。リクエストのデコードに失敗するとハブは PROTOCOL_VIOLATION で閉じます(`test_moqtrun_fillfix_malformed_subscribe`、`test_moqtrun_setup_malformed_closes`)が、この条件を起こすハブのテストはありません。
- [x] MQ22-064 エンドポイントが未知の Message Parameter の Type を受信した場合、実装はプロトコル違反でセッションを閉じなければならない。
  - test: `tests/app/moqctl_test.c` —
    `test_moqctl_params_unknown_type_violation`
  - test: `tests/app/moqtrun_fillfix_test.c` —
    `test_moqtrun_fillfix_malformed_subscribe`
- [~] MQ22-065 送信者が 1 つのメッセージで同じ Parameter Type を繰り返した場合、実装はプロトコル違反でセッションを閉じなければならない。
  - evidence: コーデックは VIOLATION を返します(`test_moqctl_params_duplicate_type_violation`)。リクエストのデコードに失敗するとハブは PROTOCOL_VIOLATION で閉じます(`test_moqtrun_fillfix_malformed_subscribe`、`test_moqtrun_setup_malformed_closes`)が、この条件を起こすハブのテストはありません。
- [x] MQ22-066 Message Parameter が、それが現れたメッセージ以外のメッセージの型のために定義されたものである場合、実装はプロトコル違反でセッションを閉じなければならない。
  - test: `tests/app/moqtrun_upd_test.c` — `test_moqtrun_upd_bad_and_control`
  - test: `tests/app/moqctl_test.c` — `test_moqctl_params_scope_violation`
  - note: パラメーターの型の大半で、draft-22 で許されるメッセージの集合は draft-19 と異なります(PUBLISH_OK は EXPIRES だけに狭まり、PUBLISH は 5 つのパラメーターが増え、PUBLISH_STATE_NOTIFY と「FILL_PARAMETERS の内側」が新しい文脈になる)。`draft19-vs-22-diff.md` の §5.2 を参照。
- [x] MQ22-067 SUBSCRIBE、PUBLISH_OK、FETCH の Message Parameters は、パブリッシャーが送信する Object のペイロードを変えさせてはならない。
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_object_relay_preserves_bytes`
  - evidence: moqtrun.c は、Object のペイロードを組み立てるときにパラメーターの値を一切参照しません。relay-preserves-bytes のテストはペイロードが端から端まで同一であることを示しますが、パラメーターを変えてこの保証だけを切り出してはいません。

## SS9.20.3/9.20.4 SUBGROUP_DELIVERY_TIMEOUT / OBJECT_DELIVERY_TIMEOUT

- [x] MQ22-068 実装は、Message Parameter の SUBGROUP_DELIVERY_TIMEOUT (0x06) と OBJECT_DELIVERY_TIMEOUT (0x02) を varint としてデコードし、値 0 をタイムアウトなしとして扱わなければならない。
  - test: `tests/app/moqctl_test.c` —
    `test_moqctl_params_delivery_timeout_decode`
- [x] MQ22-069 ハブは、自身の SUBSCRIBE_OK / REQUEST_OK / PUBLISH_DONE の応答に配送タイムアウトのパラメーターを入れて送信してはならない(損失のない単一ハブのサブセットは配送タイムアウトを設定しない)。
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_subscribe_ok_carries_no_timeout_param`
- [x] MQ22-070 0 でない SUBGROUP_DELIVERY_TIMEOUT または OBJECT_DELIVERY_TIMEOUT パラメーターを持つ SUBSCRIBE は、受け入れて適用しなければならない。
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_subscribe_nonzero_timeout_accepted`
  - test: `tests/app/moqtrun_upd_test.c` — `test_moqtrun_timeout_accepted`
  - test: `tests/app/moqtrun_sub_test.c` —
    `test_moqtrun_sub_subgroup_timeout_min`
- [ ] MQ22-070a OBJECT_DELIVERY_TIMEOUT の時計は、Object のヘッダーの最後のバイトを受信した(または渡された)時点から始めなければならない(draft-19 では最初のペイロードのバイトから始まる点が異なる)。
  - gap: 裁定 4-11(コントローラー、2026-10-04): このハブは Object をひとまとまりでデコードし、ヘッダーの終わりとペイロードの始まりを区別する境界のタイムスタンプを持たないので、draft-19 と draft-22 の違いはこの実装では観測できません(どちらのバージョンでもタイミングの値は同じになり、ここにバージョンの分岐を入れてもデッドコードになる)。タイムスタンプの取得元そのものには本物のバグがありました(リングの経路が `born_ms` ではなく追記の完了時に刻んでいた)。これは `born_ms` を `moqtrun_rel_take` まで通して直しました。この修正はバージョンに依存せず、draft-22 の文言に固有のものではありません。

- [x] MQ22-245 (SS5.2) SUBGROUP_DELIVERY_TIMEOUT が 0 でない場合、ハブは上流の Subgroup ストリームが FIN したときにタイマーを始め、タイマーが切れた時点で下流のストリームが「all data committed」に達していなければ、そのストリームをリセットしなければならない。
  - test: `tests/app/moqtrun_sub_test.c` —
    `test_moqtrun_sub_subgroup_timeout_after_fin`
  - note: 中継したストリームの上流の FIN で起動します(最初の配送で丸ごと送った一度きりのストリームでは起動しない)。「committed」は、トランスポートのすべて確認応答済みの合図(`wired_moqt_io.stream_inflight`)です。

## SS9.20.18 FORWARD パラメーター

- [x] MQ22-071 実装は、FORWARD パラメーター(Type 0x10)を、値が 0(転送しない)または 1(転送する)の uint8 としてエンコード・デコードし、省略時は 1 としなければならない。
  - test: `tests/app/moqctl_test.c` — `test_moqctl_params_forward_roundtrip`
- [x] MQ22-072 PUBLISH で FORWARD=0 を送ったパブリッシャーは、購読者が REQUEST_UPDATE で Forward State(名前が "paused" に変わった)を一時停止でない状態にするまで、Object を 1 つも送信してはならない。購読への Object の転送は、その Forward State で制御する。
  - test: `tests/app/moqtrun_misc_test.c` —
    `test_moqtrun_misc_pub_forward0_then_update`
  - test: `tests/app/moqtrun_sub_test.c` —
    `test_moqtrun_sub_reattach_keeps_state`
  - note: draft-22 は、PUBLISH_OK で許されるパラメーターから FORWARD を外しています(購読者は代わりに REQUEST_UPDATE を使わなければならない。MQ22-095 を参照)。実装側の制御そのもの(購読の Forward State)は変わっていません。

## SS9.20.12-9.20.17 Range Filter、FILL_PARAMETERS、LARGEST_OBJECT の規則

- [x] MQ22-241 (SS9.20.12) PRIORITY_FILTER をデコードした値が 255 を超える場合、ハブはそのリクエストを REQUEST_ERROR INVALID_FILTER で拒否しなければならない。
  - test: `tests/app/moqtrun_sub_test.c` — `test_moqtrun_sub_rngf_value_checks`
- [x] MQ22-242 (SS9.20.13, SS9.20.14) OBJECT_PROPERTY_FILTER または TRACK_PROPERTY_FILTER が奇数の Property Type を名指す場合、ハブはそのリクエストを REQUEST_ERROR INVALID_FILTER で拒否しなければならない。
  - test: `tests/app/moqtrun_sub_test.c` — `test_moqtrun_sub_rngf_value_checks`
- [x] MQ22-243 (SS9.20.15) FILL_PARAMETERS が自身の表にないパラメーター(表にあるのは FILL_TIMEOUT、SUBSCRIBER_PRIORITY、LOCATION_FILTER、GROUP_ORDER と、Object に対する 4 つの Range Filter)を含む場合、ハブは PROTOCOL_VIOLATION でセッションを閉じなければならない。
  - test: `tests/app/moqtrun_sess_test.c` — `test_mtss_fill_unlisted_param_closes`
  - test: `tests/app/moqtrun_fillfix_test.c` — `test_moqtrun_fillfix_malformed_subscribe`
- [~] MQ22-244 (SS9.20.17, SS7.4) リレーは、上流のパブリッシャーの LARGEST_OBJECT と、上流の購読で受信した最大の Location のうち大きいほうを、LARGEST_OBJECT として報告しなければならない。
  - test: `tests/app/moqtrun_sub_test.c` —
    `test_moqtrun_sub_republish_resets_largest`
  - test: `tests/app/moqtrun_sub_test.c` — `test_moqtrun_sub_ok_largest`
  - evidence: テストは、PUBLISH の LARGEST_OBJECT(`moqtrun_track_seed_largest`)と受信した Object を扱っています。上流の SUBSCRIBE_OK が運ぶ値は確かめていません。

## SS9.1 SETUP

- [x] MQ22-073 実装は、SETUP の Setup Options を、メッセージのペイロード全体にわたる Key-Value-Pair のリストとしてエンコード・デコードしなければならない。
  - test: `tests/app/moqctl_test.c` — `test_moqctl_setup_roundtrip`
- [x] MQ22-074 エンドポイントは、認識できない Setup Option を、未知のものの重複も含めて無視しなければならない。
  - test: `tests/app/moqctl_test.c` —
    `test_moqctl_setup_unknown_option_ignored`
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_setup_unknown_options_ignored`
- [~] MQ22-075 送信者は、そのオプションが複数のインスタンスを明示的に許していない限り、1 つのメッセージで同じ Setup Option の Type を繰り返してはならない。
  - evidence: `moqctl_setup_encode` は、PATH/AUTHORITY/MOQT_IMPLEMENTATION をそれぞれ高々 1 回しか書かない作りになっています。エンコーダーに重複を入れて、デコード時に拒否されることを確かめるテストはありません(デコードは、繰り返された既知のオプションについて最後に見た値を保持するだけで、これは KVP 層自身の重複を許すモデルと一致する)。

## SS9.1.1/9.1.2 AUTHORITY / PATH / MOQT_IMPLEMENTATION

- [x] MQ22-076 実装は、Setup Option の PATH (0x01) と AUTHORITY (0x05) をバイト列の値としてデコードしなければならない。
  - test: `tests/app/moqctl_test.c` — `test_moqctl_setup_path_option_decode`
- [x] MQ22-077 WebTransport を使っている間に PATH または AUTHORITY オプションを受信した場合、実装はそれぞれ INVALID_PATH または INVALID_AUTHORITY でセッションを閉じなければならない。ネイティブ QUIC では、不正なものを MALFORMED_PATH または MALFORMED_AUTHORITY で閉じる。
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_setup_path_closes_invalid_path`
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_setup_authority_closes_invalid_authority`
  - test: `tests/app/moqtrun_raw_test.c` —
    `test_moqtrun_raw_same_setup_on_wt_closes`
  - test: `tests/app/moqtrun_raw_test.c` — `test_moqtrun_raw_malformed_closes`
- [x] MQ22-078 実装は、Setup Option の MOQT_IMPLEMENTATION (0x07) を UTF-8 のバイト列の値としてデコードしなければならない。
  - test: `tests/app/moqctl_test.c` — `test_moqctl_setup_roundtrip`

## SS9.1.4 AUTHORIZATION TOKEN Setup Option

- [x] MQ22-232 (SS9.1.4) クライアントの SETUP が、Alias Type が DELETE または USE_ALIAS の AUTHORIZATION TOKEN オプションを含む場合、サーバーは PROTOCOL_VIOLATION でセッションを閉じなければならない。キャッシュの上限を超えた REGISTER は USE_VALUE として扱い、決して AUTH_TOKEN_CACHE_OVERFLOW にはしない。
  - test: `tests/app/moqtrun_sess_test.c` — `test_mtss_setup_token_alias`

## SS9.2 GOAWAY(ワイヤー形式)

- [x] MQ22-079 実装は、GOAWAY を Type (0x10) + Length + New Session URI Length + New Session URI + Timeout としてエンコード・デコードしなければならない(draft-19 から変更なし。draft-18 と違い、末尾の Request ID フィールドはない)。
  - test: `tests/app/moqctl_test.c` — `test_moqctl_goaway_roundtrip`
- [~] MQ22-080 New Session URI Length が 8192 バイトを超える場合、実装はプロトコル違反でセッションを閉じなければならない。
  - evidence: コーデックは VIOLATION を返し(`test_moqctl_goaway_uri_boundary`)、デコードに失敗した GOAWAY は PROTOCOL_VIOLATION で閉じます(`test_moqtrun_peer_goaway_uri`。不正な GOAWAY)。長すぎる URI を送るハブのテストはありません。

## SS9.3 REQUEST_OK

- [x] MQ22-082 実装は、REQUEST_OK を Type (0x7) + Length + Number of Parameters + Parameters + Track Properties(メッセージの残りのバイト)としてエンコード・デコードしなければならない。
  - test: `tests/app/moqctl_test.c` — `test_moqctl_request_ok_roundtrip`
- [x] MQ22-083 Track Properties が空でなければならない REQUEST_OK の変種(PUBLISH_OK など)が、空でない Track Properties を含む場合、実装はプロトコル違反でセッションを閉じなければならない。
  - test: `tests/app/moqtrun_sess_test.c` — `test_mtss_publish_ok_props_closes`
  - evidence: このうちハブが受信しうるのは PUBLISH_OK だけです。ハブは REQUEST_UPDATE、SUBSCRIBE_NAMESPACE、PUBLISH_NAMESPACE を送信しません。
- [x] MQ22-083a OK が Track Properties を運ぶリクエストで INCLUDE_PROPERTIES=0 が送られる場合、実装は Track の実際のプロパティにかかわらず、空の Track Properties を末尾に出さなければならない。
  - test: `tests/app/moqtrun_sub_test.c` —
    `test_moqtrun_sub_include_properties_0_empty_tail`
  - test: `tests/app/moqctl_test.c` —
    `test_moqctl_params_include_properties_range`
  - evidence: INCLUDE_PROPERTIES=1(または省略。これが既定)のとき、SUBSCRIBE_OK はパブリッシャーの Track Properties(最大 `WIRED_MOQTRUN_TRACK_PROPS_MAX` バイト)を運びます。
  - test: `tests/app/moqtrun_sub_test.c` —
    `test_moqtrun_sub_include_properties_1_forwards`

## SS9.4 REQUEST_ERROR

- [x] MQ22-084 実装は、REQUEST_ERROR を Type (0x5) + Length + Error Code + Retry Interval + Error Reason + 省略可能な Redirect としてエンコード・デコードしなければならない。
  - test: `tests/app/moqctl_test.c` — `test_moqctl_request_error_roundtrip`
  - test: `tests/app/moqctl_test.c` —
    `test_moqctl_request_error_redirect_roundtrip`
- [~] MQ22-085 Redirect 構造は、Error Code が REDIRECT のときにだけ存在しなければならない。
  - test: `tests/app/moqctl_test.c` —
    `test_moqctl_request_error_redirect_roundtrip`
  - evidence: テストは、Redirect 付きの REDIRECT をラウンドトリップさせています。ほかのコードで Redirect がないことは `moqtrun_queue_request_error` の作りで保証していて、確かめてはいません。
- [x] MQ22-086 サーバーが Connect URI Length が 0 でない Redirect を受信した場合、実装はプロトコル違反でセッションを閉じなければならない。
  - test: `tests/app/moqtrun_sess_test.c` — `test_mtss_publish_error_redirect_closes`
  - test: `tests/app/moqtrun_upsub_test.c` — `test_moqtrun_upsub_redirect_uri_closes`
  - test: `tests/app/moqtrun_upfetch_test.c` — `test_moqtrun_upfetch_error_redirect_uri_closes`
  - evidence: ハブは名前空間を対象とするリクエストを送信しないので、Track Name の規則を当てはめる REQUEST_ERROR はありません。
- [x] MQ22-087 実装は、自身が使う REQUEST_ERROR のコードを認識しなければならない: INTERNAL_ERROR、NOT_SUPPORTED、GOING_AWAY、INVALID_FILTER、UNINTERESTED、DOES_NOT_EXIST、UNAUTHORIZED、REDIRECT。
  - test: `tests/app/moqctl_test.c` —
    `test_moqctl_unknown_error_normalizes_to_internal`
  - note: draft-22 は INVALID_JOINING_REQUEST_ID (0x32) を削除しています(Joining FETCH そのものが削除されたので意味がない。MQ22-132 を参照)。いずれにせよ、未知のコードは INTERNAL_ERROR に正規化します。
- [x] MQ22-088 エンドポイントが認識できない REQUEST_ERROR のコードを受信した場合、実装はセッションを閉じずに、それを INTERNAL_ERROR として扱わなければならない。
  - test: `tests/app/moqctl_test.c` —
    `test_moqctl_unknown_error_normalizes_to_internal`

## SS9.6 SUBSCRIBE / SS9.7 SUBSCRIBE_OK

- [x] MQ22-089 実装は、SUBSCRIBE を Type (0x3) + Length + Request ID + Track Namespace + Track Name + Number of Parameters + Parameters としてエンコード・デコードしなければならない。
  - test: `tests/app/moqctl_test.c` — `test_moqctl_subscribe_roundtrip`
- [x] MQ22-090 購読が成功したら、パブリッシャーは SUBSCRIBE_OK をちょうど 1 つ応答しなければならない。
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_subscribe_matching_publish_replies_ok`
  - test: `tests/app/moqtrun_sub_test.c` —
    `test_moqtrun_req_subscribe_answered_on_its_stream`
- [x] MQ22-091 実装は、SUBSCRIBE_OK を Type (0x4) + Length + Track Alias + Number of Parameters + Parameters + Track Properties としてエンコード・デコードしなければならない。許されるパラメーターは EXPIRES と LARGEST_OBJECT だけである(draft-19 より狭い)。
  - test: `tests/app/moqctl_test.c` — `test_moqctl_subscribe_ok_roundtrip`
- [x] MQ22-092 実装が同じ SUBSCRIBE または PUBLISH への 2 つ目の応答(SUBSCRIBE_OK、PUBLISH_OK、REQUEST_ERROR)を受信した場合、実装はプロトコル違反でセッションを閉じなければならない。
  - test: `tests/app/moqtrun_misc_test.c` —
    `test_moqtrun_misc_pub_second_ok_closes`
  - test: `tests/app/moqtrun_misc_test.c` —
    `test_moqtrun_misc_pub_error_after_ok_closes`
- [~] MQ22-093 パブリッシャーが SUBSCRIBE を REQUEST_ERROR で拒否した場合、その購読には Object を 1 つも送信してはならない。
  - evidence: 拒否した SUBSCRIBE は購読を作らない(`test_moqtrun_subscribe_without_publish_replies_error`、`test_moqtrun_sub_ns_must_match`)ので、そこへ何も中継しようがありません。その後に Object を送るテストはありません。
- [x] MQ22-093a ピアは、同じ Track への同時の購読を、それぞれ固有の Request ID で複数持ってもよい(draft-18 とは異なる。`docs/features/draft-moq-transport-18.md` の MQ18-094a を参照)。
  - test: `tests/app/moqtrun_upd_test.c` —
    `test_moqtrun_sub_duplicate_reanswered_d19_d22`
  - note: `moqtrun_sub_held_reply` は `MOQVER_CAP_DUP_SUBSCRIPTION` で分岐し、このビットは d19/d22 にはありません。台帳 4-2 を参照。

## SS9.8 PUBLISH

- [x] MQ22-094 実装は、PUBLISH を Type (0x1D) + Length + Request ID + Track Namespace + Track Name + Track Alias + Number of Parameters + Parameters + Track Properties としてエンコード・デコードしなければならない。
  - test: `tests/app/moqctl_test.c` — `test_moqctl_publish_roundtrip`
- [~] MQ22-094a PUBLISH は、パブリッシャーの初期の購読のパラメーター(OBJECT_DELIVERY_TIMEOUT、SUBGROUP_DELIVERY_TIMEOUT、EXPIRES、LARGEST_OBJECT、FORWARD、SUBSCRIBER_PRIORITY、LOCATION_FILTER、GROUP_ORDER)を運ばなければならない(draft-19 では、代わりに PUBLISH_OK が購読者のパラメーターを運ぶ点が異なる)。
  - evidence: `moqctl_publish` のワイヤーのデコーダーは、汎用の `params` フィールドをすでに運んでいます(19/22 でバイト単位で同一)。ギャップはハブの振る舞いだけにあります。`moqtrun_handle_publish` は受信した PUBLISH から LARGEST_OBJECT だけを読み、FORWARD/優先度/フィルター/タイムアウトは適用しません。これは draft-19 の台帳ですでに未解決の同じギャップと一致します(`draft-moq-transport.md` の「未実装」の節と、台帳 4-7 の裁定を参照。裁定は、このハブの常に転送し優先度を持たない振る舞いが、観測できる違反なしに draft-22 の MAY を満たすとしている)。
- [x] MQ22-095 PUBLISH から始まった購読が成功したら、購読者は PUBLISH_OK(EXPIRES だけを運ぶ REQUEST_OK)をちょうど 1 つ応答しなければならず、その後に REQUEST_UPDATE を続けて購読者が制御するパラメーターを設定してもよい(draft-19 では、それらのパラメーターが PUBLISH_OK そのものに載る点が異なる)。
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_publish_replies_request_ok`
  - test: `tests/app/moqtrun_misc_test.c` —
    `test_moqtrun_misc_pub_forward0_then_update`
  - test: `tests/app/moqtrun_vgate_test.c` — `test_moqtrun_vgate_update_kinds`
  - test: `tests/app/moqtrun_misc_test.c` — `test_moqtrun_misc_stray_update`
  - note: 送信者自身の PUBLISH ストリーム上の REQUEST_UPDATE は、どのドラフトでも受け入れます(18/19 の SS10.9 と 22 の SS9.5 は、どちらも PUBLISH を挙げている)。以前の draft-22 専用の機能ビットは削除しました(台帳 12-6)。SS9.5 の 2 つの場合(制御ストリーム、TRACK_STATUS ストリーム)の外にあるものは、PROTOCOL_VIOLATION でセッションを閉じます(台帳 12-17、`MOQVER_CAP_UPDATE_STRAY_CLOSE`)。
- [~] MQ22-096 パブリッシャーは、PUBLISH から始まった購読で、PUBLISH_OK を受信する前に Object を送信し始めてもよい。
  - evidence: ハブは PUBLISH にすぐに応答し、その後に続く Object を中継します(`test_moqtrun_object_relay_to_subscriber`)。Object が REQUEST_OK より先に届く場合を固定するテストはありません。
- [~] MQ22-097 購読者が PUBLISH を REQUEST_ERROR UNINTERESTED で拒否した場合、購読は Object を 1 つも送信せずに終了しなければならない。
  - evidence: ハブが送った PUBLISH への REQUEST_ERROR はそのスロットを解放します(`test_subtracks_publish_error_frees_slot`)。その後に Object を送るテストはありません。
- [x] MQ22-097a 認可されていないピアが、配信を許されていない名前空間を PUBLISH しようとした場合、実装はそれを REQUEST_ERROR UNAUTHORIZED で拒否しなければならない。これは、リレーが購読する側だけでなく配信する側の名前空間も認可することを求める、draft-22 の SS15.3.3「Preventing Impersonation」の要件に対応する。
  - test: `tests/app/moqtrun_upd_test.c` —
    `test_moqtrun_publish_requires_authorization`
  - note: `moqtrun_publish_refused` は、以前からある `moqtrun_subscribe_refused` と対になるものです。`docs/security/vuln-ledger.md` に記した V-0839 のギャップを閉じます。台帳 4-14a と、コミット `041b9ef4` の一連のコミットを参照。
  - vuln: V-0793, V-0839

## SS9.9 PUBLISH_DONE

- [x] MQ22-098 実装は、PUBLISH_DONE を Type (0xB) + Length + Status Code + Stream Count + Error Reason としてエンコード・デコードしなければならない。Stream Count が「不明」であることを表す番兵の値は 2^64-1(9 バイトの varint)で、draft-19 の 2^62-1 とは異なる。
  - test: `tests/app/moqctl_test.c` — `test_moqctl_publish_done_roundtrip`
  - note: wired の PUBLISH_DONE の Stream Count は現在つねに正確な数です(台帳 3-9/10-3: `MOQTRUN_DONE_STREAMS_UNKNOWN` はコードベースから完全に削除した)。そのため、どちらのバージョンでもハブがこの番兵を出すことはありません。意味があるのはピアの PUBLISH_DONE をデコードするときだけで、このハブは今のところ、ログ出力以外には自身の fill や購読の管理にそれを使っていません。
- [x] MQ22-099 送信者は、その購読のために開いたすべてのデータストリーム(そのために開いた fill fetch ストリームも含む。draft-22 で新設。MQ22-186 を参照)を閉じるまで、PUBLISH_DONE を送信してはならない。
  - test: `tests/app/moqtrun_done_test.c` —
    `test_moqtrun_pubdone_waits_open_stream`
  - test: `tests/app/moqtrun_drain_test.c` —
    `test_moqtrun_done_resets_streams_first`
  - test: `tests/app/moqtrun_fill_test.c` — `test_moqtrun_fill_counts_in_done`
  - test: `tests/app/moqtrun_fill_test.c` —
    `test_moqtrun_fill_done_waits_for_held`
  - test: `tests/app/moqtrun_done_test.c` —
    `test_moqtrun_pubdone_count_after_supersede`
- [x] MQ22-100 購読は、PUBLISH_DONE を送り、購読の双方向ストリームを閉じることで終了しなければならない。その後、送信者は購読の状態を破棄してもよい。
  - test: `tests/app/moqtrun_done_test.c` — `test_moqtrun_pubdone_fin_after`
  - test: `tests/app/moqtrun_done_test.c` — `test_moqtrun_pubdone_one_sub`
- [~] MQ22-101 購読者が応答を送る前に PUBLISH_DONE が届いた場合、購読者は FIN を送る前に、後回しにした PUBLISH_OK をちょうど 1 つ送らなければならない。
  - evidence: ハブはすべての PUBLISH にすぐに応答するので、応答していない PUBLISH を抱えることはありません。この規則は購読のモデル(`test_moqsub_publish_done_before_response_defers_ok`)でしか固定していません。
- [x] MQ22-102 実装は、自身が使う PUBLISH_DONE のステータスコードを認識しなければならない: INTERNAL_ERROR、TRACK_ENDED、GOING_AWAY。Location Filter の終わりがもはや購読を終了させないので(MQ22-137a を参照)、draft-22 は SUBSCRIPTION_ENDED (0x3。未割り当て)を削除している。
  - test: `tests/app/moqctl_test.c` —
    `test_moqctl_unknown_error_normalizes_to_internal`
  - note: いずれにせよ未知の PUBLISH_DONE のコードは INTERNAL_ERROR に正規化するので、この削除はワイヤー上は安全です。
- [~] MQ22-103 パブリッシャーが購読のためにデータストリームを 1 本も開かなかった場合、PUBLISH_DONE の Stream Count を 0 にしなければならない。
  - test: `tests/app/moqtrun_test.c` — `test_moqtrun_relay_table_full_counts`
  - test: `tests/app/moqtrun_drain_test.c` — `test_moqtrun_done_track_ended`
  - evidence: ハブは `moqtrun_sub_done`/`moqtrun_done_emit` で正確な Stream Count を送ります(台帳 3-9/10-3)。データストリームを開かなかったときはそれが 0 になります。ストリーム 0 本のエンコーディングを、一般の正確な数の経路から切り出して確かめる draft-22 専用のテストはありません。

## SS9 制御メッセージで共有する Reason Phrase / Location / Track Namespace の構造

- [x] MQ22-104 実装は、Message Parameters、Location、Reason Phrase を、それらを埋め込むすべての制御メッセージで一貫してエンコード・デコードしなければならない。
  - test: `tests/app/moqctl_test.c` — `test_moqctl_params_forward_roundtrip`
  - test: `tests/app/moqctl_test.c` —
    `test_moqctl_location_roundtrip_and_order`
  - test: `tests/app/moqctl_test.c` — `test_moqctl_reason_boundary`
  - vuln: V-0800

## SS9.20.9 LOCATION_FILTER(draft-22: 型付きで、長さの前置はない)

- [x] MQ22-105 実装は、LOCATION_FILTER の Location Filter Type を、None (0x00)、Relative Start (0x01)、Absolute Start (0x02)、Absolute Start/Group End (0x03)、Absolute Range (0x04)、Next Object (0x05) のいずれかとしてデコードしなければならない。フィールドの並び([StartGroup], [StartObject], [EndGroupDelta], [EndObject])は型によって決まり、外側の Length フィールドはない。draft-19 の、長さを前置した 4 種類のエンコーディングとは異なる。
  - test: `tests/app/moqctl_test.c` — `test_moqctl_rangeloc22_none`
  - test: `tests/app/moqctl_test.c` —
    `test_moqctl_rangeloc22_relative_start_roundtrip`
  - test: `tests/app/moqctl_test.c` —
    `test_moqctl_rangeloc22_abs_start_roundtrip`
  - test: `tests/app/moqctl_test.c` —
    `test_moqctl_rangeloc22_abs_start_group_end_roundtrip`
  - test: `tests/app/moqctl_test.c` —
    `test_moqctl_rangeloc22_abs_range_roundtrip`
  - test: `tests/app/moqctl_test.c` —
    `test_moqctl_rangeloc22_next_object_roundtrip`
  - note: コードポイント 0x01-0x04 は draft-19 と draft-22 の両方にあり、意味が異なります(`draft19-vs-22-diff.md` の §6.2 を参照)。デコードは `MOQVER_CAP_LOCFILTER_TYPED` でバージョンごとに切り替え、自動判別はしません。`moqctl_rangeloc22_take/_put` は、draft-19 のデコーダーと同じ内部の `moqctl_rangeloc` モデルに写します(台帳 3-6、コミット `fc97a2e5`)。
- [~] MQ22-106 LOCATION_FILTER の StartGroup + EndGroupDelta が 2^64-1 を超える場合、実装はプロトコル違反でセッションを閉じなければならない。
  - evidence: コーデックは VIOLATION を返します(`test_moqctl_rangeloc22_egd_overflow_violation`)。リクエストのデコードに失敗するとハブは PROTOCOL_VIOLATION で閉じます(`test_moqtrun_fillfix_malformed_subscribe`、`test_moqtrun_setup_malformed_closes`)が、この条件を起こすハブのテストはありません。
- [~] MQ22-107 エンドポイントが定義済みの 6 つの値以外の Location Filter Type を受信した場合、実装はプロトコル違反でセッションを閉じなければならない。
  - evidence: コーデックは VIOLATION を返します(`test_moqctl_rangeloc22_unknown_type_violation`)。リクエストのデコードに失敗するとハブは PROTOCOL_VIOLATION で閉じます(`test_moqtrun_fillfix_malformed_subscribe`、`test_moqtrun_setup_malformed_closes`)が、この条件を起こすハブのテストはありません。
- [x] MQ22-108 パブリッシャーは、Forward State と Location Filter の組み合わせ(Pass = Forward AND Filters)を通過した Object だけを転送しなければならない。
  - test: `tests/app/moqtrun_sub_test.c` —
    `test_moqtrun_sub_reattach_keeps_state`
  - test: `tests/app/moqtrun_sub_test.c` — `test_moqtrun_sub_filter22_starts`
  - test: `tests/app/moqtrun_sub_test.c` — `test_moqtrun_sub_filter22_ends`
  - test: `tests/app/moqtrun_sub_test.c` — `test_moqtrun_sub_filter22_inverted`
  - test: `tests/app/moqtrun_sub_test.c` —
    `test_moqtrun_sub_filter22_end_gates`
- [~] MQ22-108a Location Filter の有効な範囲は、全体が Largest Object より前にあることによって無効になることはない(つねに有効)。draft-19 では、満たせないフィルターをパブリッシャーが拒否するべきである(SHOULD)点が異なる。
  - evidence: `moqctl_rangeloc22_take` には「すでに過去」を理由に拒否する経路がありません。`moqtrun_sub_filter22_*` のテストのフィルター評価は、現在の Largest Object 以降のフィルターの受け入れを動かしていて、作りからしてこの「つねに有効」の規則と一致します(構造上は有効だが古いフィルターに INVALID_RANGE を出すコードの経路はない)。
- [x] MQ22-108b Location Filter の終わりに達しても(Largest Object がフィルターの End を越えても)、購読を終了させてはならない。draft-19 の PUBLISH_DONE SUBSCRIPTION_ENDED(draft-22 で削除。MQ22-102 を参照)とは異なる。
  - test: `tests/app/moqtrun_drain_test.c` —
    `test_moqtrun_done_filter_end_keeps_sub`
- [~] MQ22-108c パブリッシャーは、SUBSCRIBE と REQUEST_UPDATE に加えて、PUBLISH(初期のフィルターを設定する)と PUBLISH_STATE_NOTIFY(現在有効なフィルターを報告する)でも LOCATION_FILTER を送信してもよい。draft-19 では、それを運べるのは SUBSCRIBE、PUBLISH_OK、REQUEST_UPDATE だけである点が異なる。
  - evidence: `test_moqtrun_upd_filter_d22` は、REQUEST_UPDATE の LOCATION_FILTER が購読のフィルターを置き換えることを確かめています。PUBLISH と PUBLISH_STATE_NOTIFY で LOCATION_FILTER を受け入れることはパラメーターの登録表の側(`test_moqctl_params_registry_scope`)で確かめていて、ハブのテストはありません。
  - note: MQ22-094a(PUBLISH の初期のパラメーター)と MQ22-182(PUBLISH_STATE_NOTIFY)を参照。

## SS13 Grease

- [x] MQ22-109 実装は、grease の値を予約している登録表(Setup Options、Properties、エラーコードやステータスコードの表)で、0 以上の整数 N に対する grease の値のパターン 0x7f*N + 0x9D を認識しなければならない。
  - test: `tests/app/moqctl_test.c` — `test_moqctl_grease_pattern`
- [x] MQ22-110 エンドポイントは、grease を入れた登録表(Setup Options、エラーコード)の未知の値を受信したというだけの理由で、セッションを閉じてはならない。
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_setup_unknown_options_ignored`
  - test: `tests/app/moqctl_test.c` —
    `test_moqctl_unknown_error_normalizes_to_internal`

## SS3.1.3 Track Alias

- [x] MQ22-111 パブリッシャーは、同じセッションで、同じ Track Alias を 2 つの異なる Track を指すために同時に使ってはならない。
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_chat_and_audio_get_different_aliases`
- [x] MQ22-112 購読者が、別の Established の購読にすでに結び付いた Track Alias を再利用する PUBLISH または SUBSCRIBE_OK を受信した場合、実装は DUPLICATE_TRACK_ALIAS でセッションを閉じなければならない。
  - test: `tests/app/moqtrun_sess_test.c` — `test_mtss_publish_dup_alias_closes`
  - test: `tests/app/moqtrun_upsub_test.c` — `test_moqtrun_upsub_dup_alias_closes`

## SS11.1.1 Object Status

- [x] MQ22-113 実装は、Object Status の値 0x0(Normal)、0x3(End of Group)、0x4(End of Track)を認識しなければならない。
  - test: `tests/app/moqdata_test.c` — `test_moqdata_obj_take_status_values`
- [x] MQ22-114 Object が登録されていない Status の値を持つ場合、実装はプロトコル違反でセッションを閉じなければならない。
  - test: `tests/app/moqtrun_sess_test.c` — `test_mtss_subgroup_object_violations`
- [x] MQ22-115 Object は、Object Status が Normal (0x0) でない限り、空のペイロードを持たなければならない。Object Status フィールドは、Payload Length が 0 のときにだけ存在しなければならない。
  - test: `tests/app/moqdata_test.c` — `test_moqdata_subhdr_take_status_eog`
  - test: `tests/app/moqdata_test.c` —
    `test_moqdata_obj_take_status_eog_stream`

## SS11.1.2 Object Properties

- [x] MQ22-116 エンドポイントが、Status が Normal でない Object で Object Properties を受信した場合、実装はプロトコル違反でセッションを閉じなければならない。
  - test: `tests/app/moqtrun_sess_test.c` — `test_mtss_subgroup_object_violations`
- [x] MQ22-117 Object Properties は、Properties Length(varint)と、それに続く Key-Value-Pair のリストとしてシリアライズしなければならない。
  - test: `tests/app/moqdata_test.c` — `test_moqdata_obj_take_properties`

## SS11.3.1 Subgroup ヘッダー

- [x] MQ22-118 SUBGROUP_HEADER で開いたストリーム上の Object はすべて、Delivery Mode = Subgroup(「Object Forwarding Preference」から名前が変わった)を持ち、ヘッダーが宣言する Track Alias、Group ID、Subgroup ID に属さなければならない。
  - test: `tests/app/moqdata_test.c` — `test_moqdata_subhdr_take_basic`
- [x] MQ22-119 SUBGROUP_HEADER の Type Flags フィールドは 0b0XX1XXXX の形(ビット 4 はつねに立つ)でなければならない。それ以外の形で受信した場合、実装はプロトコル違反でセッションを閉じなければならない。
  - test: `tests/app/moqtrun_sess_test.c` — `test_mtss_unknown_uni_closes`
  - note: 有効な値の集合は draft-19 とバイト単位で同一です(48 個)。draft-22 は、フィールドの名前を「Type Flags」に変え、予約ビットの規則を一般化しただけです。`draft19-vs-22-diff.md` の §10 を参照。
- [x] MQ22-120 実装は、SUBGROUP_ID_MODE フィールド(ビット 1-2)を次のようにデコードしなければならない: 0b00 は Subgroup ID がなく 0、0b01 は Subgroup ID がなく最初の Object の Object ID と等しい、0b10 は Subgroup ID がヘッダーにある。
  - test: `tests/app/moqdata_test.c` — `test_moqdata_subhdr_take_mode2`
  - test: `tests/app/moqdata_test.c` — `test_moqdata_subhdr_take_mode1_resolve`
- [x] MQ22-121 SUBGROUP_ID_MODE が 0b11 の場合、実装はプロトコル違反でセッションを閉じなければならない。
  - test: `tests/app/moqtrun_sess_test.c` — `test_mtss_subgroup_mode3_closes`
- [x] MQ22-122 実装は、SUBGROUP_HEADER の Type Flags フィールドの PROPERTIES ビット (0x01)、END_OF_GROUP ビット (0x08)、DEFAULT_PRIORITY ビット (0x20)、FIRST_OBJECT ビット (0x40) をデコードしなければならない。
  - test: `tests/app/moqdata_test.c` — `test_moqdata_type_bits_golden`
- [x] MQ22-123 DEFAULT_PRIORITY が立っている場合、ヘッダーの Publisher Priority フィールドは省かなければならず、Subgroup は購読の制御メッセージから優先度を引き継がなければならない。
  - test: `tests/app/moqdata_test.c` — `test_moqdata_subhdr_take_basic`
- [~] MQ22-124 END_OF_GROUP ビットが立ち、ストリームが FIN で終わる場合、実装は同じ Group ID でより大きい Object ID を持つ Object は存在しないと推定しなければならない。
  - evidence: このビットはデコードしています(MQ22-122)が、「END_OF_GROUP で FIN したら、より大きい Object ID は存在しない」という推定そのものを確かめる専用のテストはありません。これは、リレーが Object を丸ごと転送するやり方に暗に含まれています。
- [x] MQ22-125 Original Publisher は、新しい Subgroup を開くとき、FIRST_OBJECT ビットを立てて、ストリームの最初の Object がその Subgroup でこれまでに配信された最初の Object であることを示さなければならない。
  - test: `tests/app/moqdata_test.c` — `test_moqdata_type_bits_golden`
- [x] MQ22-249 (SS2.2, SS11.3.1) リレーは、最初の Object から転送する Subgroup では FIRST_OBJECT ビットを保ち、Subgroup の途中から開くストリームではそれを落とさなければならない。
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_late_subscriber_gets_late_opened_stream`
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_object_relay_preserves_bytes`
- [x] MQ22-126 実装は、SUBGROUP_HEADER を、そのワイヤーのフィールド(Type Flags、Track Alias、Group ID、省略可能な Subgroup ID、省略可能な Publisher Priority)とバイト単位で一致するようにエンコード・デコードしなければならない。
  - test: `tests/app/moqdata_test.c` — `test_moqdata_subhdr_put_golden`
  - test: `tests/app/moqdata_test.c` — `test_moqdata_subhdr_put_errors`
- [x] MQ22-127 SUBGROUP_HEADER が、宣言されたフィールドがすべてそろう前に途切れている場合、実装はデコードをデータ不足として報告しなければならない。
  - test: `tests/app/moqdata_test.c` — `test_moqdata_subhdr_take_truncated`
- [x] MQ22-128 実装は、モード 0b01(後で決まる)の Subgroup ID を、最初の Object の Object ID をデコードしたらそこから決めなければならない。
  - test: `tests/app/moqdata_test.c` — `test_moqdata_subhdr_take_mode1_resolve`

## SS11.3.1 Subgroup の Object のフィールド

- [x] MQ22-129 実装は、Subgroup の Object を Object ID Delta + 省略可能な Properties + Object Payload Length + 省略可能な Object Status + 省略可能な Object Payload としてエンコード・デコードしなければならない。
  - test: `tests/app/moqdata_test.c` — `test_moqdata_obj_take_basic_stream`
  - test: `tests/app/moqdata_test.c` — `test_moqdata_obj_put`
- [x] MQ22-130 Object ID は、Subgroup の最初の Object では Object ID Delta そのもの、それ以降の各 Object では直前の Object ID + Delta + 1 でなければならない。
  - test: `tests/app/moqdata_test.c` — `test_moqdata_obj_take_delta_chain`
  - relay: ハブが Subgroup の途中から遅れて開くストリームでは、最初の Object の Delta を絶対的な Object ID に書き換え、モード 0b01 の Subgroup ID をヘッダーに明示します(モード 0b10)。
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_late_subscriber_gets_late_opened_stream`
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_late_open_sgid_mode1_explicit`
- [x] MQ22-130a 計算した累積の Object ID が 2^64-1 を超える場合、実装はプロトコル違反でセッションを閉じなければならない。
  - test: `tests/app/moqtrun_sess_test.c` — `test_mtss_subgroup_object_violations`

- [x] MQ22-246 (SS11.3) Subgroup ストリームがシリアライズされた Object の途中で FIN により終わる場合、ハブは PROTOCOL_VIOLATION でセッションを閉じるべきである。
  - test: `tests/app/moqtrun_sess_test.c` — `test_mtss_subgroup_fin_mid_object`

## SS9.11 FETCH(draft-22: Track Namespace/Name + LOCATION_FILTER。Fetch Type はない)

- [x] MQ22-131 実装は、FETCH を Type (0x16) + Length + Request ID + Track Namespace + Track Name Length + Track Name + Number of Parameters + Parameters(要求する範囲は LOCATION_FILTER パラメーターで運ぶ。MQ22-105 を参照)としてエンコード・デコードしなければならない。draft-19 では、FETCH が明示的な Fetch Type フィールド(Standalone / Relative Joining / Absolute Joining)と、本体に直接置いた Start/End Location フィールドを運ぶ点が異なる。
  - test: `tests/app/moqfetch_test.c` —
    `test_moqfetch_req22_with_filter_roundtrip`
  - test: `tests/app/moqfetch_test.c` —
    `test_moqfetch_req22_no_filter_defaults`
  - test: `tests/app/moqfetch_test.c` —
    `test_moqfetch_req22_encode_with_larger_typed_param`
  - test: `tests/app/moqfetch_test.c` — `test_moqfetch_req22_bad_ns_rejects`
  - note: `moqfetch_req22_take/_encode` は、draft-19 のデコーダーと同じ、バージョンに依存しない内部モデル `moqfetch_req` へデコードします(台帳 3-7、コミット `53a66346`/`a8e0eef2`)。
- [x] MQ22-131a FETCH が LOCATION_FILTER を省いている場合、実装は draft-22 の「省略はフィルターなしを意味する」規則に従い、そのリクエストを Track 全体({0,0} から Largest Object まで)を対象とするものとして扱わなければならない。
  - test: `tests/app/moqfetch_test.c` —
    `test_moqfetch_req22_no_filter_defaults`
- [x] MQ22-132 draft-22 のセッションの FETCH のリクエストストリームが draft-19 の Joining の構造(Joining Request ID / Joining Start を伴う Fetch Type フィールド)を運ぶ場合、実装はプロトコル違反でセッションを閉じなければならない。Joining FETCH は draft-22 で完全に削除された(fill fetch ストリームに置き換わった。MQ22-135 以降を参照)からである。
  - test: `tests/app/moqtrun_fetch_test.c` —
    `test_moqtrun_fetch_d22_joining_violation`
  - note: `moqtrun_fetch_route` は `MOQVER_CAP_FILL_FETCH` で分岐します。台帳 4-5 と、そこで「D-2」として参照しているコミットを参照。
- [x] MQ22-133 FETCH にはキャッシュから応答しなければならない。その範囲は、LOCATION_FILTER パラメーターから、draft-19 の Standalone/Joining の形と共有する、バージョンに依存しない内部モデルへ正規化する。
  - test: `tests/app/moqtrun_fetch_test.c` — `test_moqtrun_fetch_d22_served`
- [x] MQ22-134 FETCH の LOCATION_FILTER の範囲が無効な場合(Start が Largest Object より後にある、MQ22-106/MQ22-107 の構造上の違反など)、実装はセッションを閉じずに、それを REQUEST_ERROR INVALID_RANGE で拒否しなければならない。
  - test: `tests/app/moqtrun_fetch_test.c` —
    `test_moqtrun_fetch_d22_invalid_range`

## SS9.12/11.4.1 FETCH_OK、End Location、End of Range の印(draft-22: 端を含む)

- [x] MQ22-135 実装は、FETCH_OK の End Location を、端を含むもの(実際に配送した最後の Object)としてエンコード・デコードしなければならない。draft-19 では End Location が端を含まない(「+1」で、Object 0 は Group 全体を意味する)点が異なる。
  - test: `tests/app/moqfetch_test.c` — `test_moqfetch_ok19_end_inclusive`
  - test: `tests/app/moqfetch_test.c` — `test_moqfetch_end19_whole_group`
  - note: これらのテストは、draft-19 と draft-22 の両方のコーデックの経路が読む、バージョンに依存しない End Location のモデル(`moqfetch_end19_incl`/`moqfetch_end19_wire`)を動かします。台帳 3-8 は、この変換がすでに実装済みで、共有のモデルに対してテスト済みであることを確かめています。共有の `moqfetch_end19_incl` のラウンドトリップのほかに、端を含むか含まないかの境界を確かめる draft-22 専用のテストはまだありません(そのため、draft-22 と名の付いたテストではなく、モデルのレベルのテストで `[x]` としている)。
- [x] MQ22-136 実装は、draft-22 の FETCH のデータストリームで、End of Timed-Out Range の印 (0x20C) を受け入れなければならない。draft-19 では 0x20C は認識できない値で、プロトコル違反でセッションを閉じる点が異なる。
  - test: `tests/app/moqfetch_test.c` — `test_moqfetch_eor_timed_out`
  - test: `tests/app/moqtrun_fetch_test.c` — `test_moqtrun_fetch_d22_served`
  - note: `moqfetch_is_eor` / `MOQVER_CAP_EOR_TIMED_OUT`。台帳 3-10、コミット `32172307`。

## SS11.4.1 Fetch ヘッダーと Fetch の Object のフィールド

- [x] MQ22-235 (SS11.4.1, SS11.4.1.1) 実装は、fetch ストリームを、FETCH_HEADER (0x05, Request ID) と、それに続く Object としてデコード・エンコードしなければならない。各 Object の Serialization Flags は、Group/Object ID の差分、Subgroup ID のエンコーディング、Publisher Priority、Properties を選び、ビット 0x40 は Datagram Object(Subgroup ID なし。下位 2 ビットは無視)を示す。
  - test: `tests/app/moqfetch_test.c` — `test_moqfetch_hdr`
  - test: `tests/app/moqfetch_test.c` — `test_moqfetch_stream_golden`
  - test: `tests/app/moqfetch_test.c` — `test_moqfetch_obj_subgroup_modes`
  - test: `tests/app/moqfetch_test.c` — `test_moqfetch_obj_group_order`
  - test: `tests/app/moqfetch_test.c` — `test_moqfetch_obj_datagram_lsbs`
  - test: `tests/app/moqfetch_test.c` — `test_moqfetch_obj_roundtrip`
- [x] MQ22-236 (SS11.4.1.1) 最初の Object が Group や Object ID の差分を欠くか直前の Object のフィールドを参照する場合、128 以上の Serialization Flags の値が定義済みの印でない場合、または計算した Group ID や Object ID が 0..2^64-1 の外に出る場合、実装はプロトコル違反を報告しなければならない。
  - test: `tests/app/moqfetch_test.c` — `test_moqfetch_obj_flags_reject`
  - test: `tests/app/moqfetch_test.c` — `test_moqfetch_obj_group_order`
  - test: `tests/app/moqfetch_test.c` — `test_moqfetch_obj_overflow`
  - test: `tests/app/moqfetch_test.c` — `test_moqfetch_obj_more_rejects`
- [x] MQ22-237 (SS11.4.1.2) 実装は、End of Range の印 0x8C(存在しない)、0x10C(不明)、0x20C(タイムアウト)を Group と Object ID だけを持つものとしてデコードして直前の Location を設定し、印の前に本物の Object がないときに、直前の Subgroup や Priority を参照する後続のフラグを拒否しなければならない。
  - test: `tests/app/moqfetch_test.c` — `test_moqfetch_stream_end_of_range`
  - test: `tests/app/moqfetch_test.c` — `test_moqfetch_eor_timed_out`
  - test: `tests/app/moqfetch_test.c` — `test_moqfetch_obj_after_eor_reject`

## SS11.5 パディング

- [x] MQ22-238 (SS11.5.1) 実装は、パディングのストリーム(型 0x132B3E28)のバイトを、中継も応答もせずにすべて捨てなければならない。
  - test: `tests/app/moqtrun_test.c` — `test_moqtrun_padding_stream_discarded`
  - test: `tests/app/moqdata_test.c` — `test_moqdata_classify_golden`
- [~] MQ22-239 (SS11.5.2) 実装は、パディングのデータグラム(型 0x132B3E29)を捨てなければならない。
  - evidence: ハブはこの型を認識しません。デコードできないものとして数え、不正なデータグラムと同じように落とします(`test_moqtrun_dg_malformed_counts_bad`)。結果として捨てています。

## SS7.6/11.4.1.2 リレーの FETCH の欠落の扱い(draft-22)

- [x] MQ22-137 Range Filter が FETCH や fill を絞る場合、応答の中の印のない欠落を、存在しないものではなく不明なものとして扱わなければならない。また、リレーは draft-19 のように確定するまで配送を止めるのではなく、一致する少なくとも 1 つのパブリッシャーへ上流の FETCH を出さなければならない。
  - test: `tests/app/moqtrun_upfetch_test.c` —
    `test_moqtrun_upfetch_range_filter`,
    `test_moqtrun_upfetch_range_filter_cached`
  - test: `tests/app/moqtrun_fill_test.c` —
    `test_moqtrun_fill_inherits_range_filter`
  - note: キャッシュは Object ID しか持たないので、Subgroup、優先度、Property を名指す集合はキャッシュ済みの Object を 1 つも通しません(印のない、つまり不明な欠落として残る)。Joining Fetch(draft-18/19)には何も適用しません。
- [x] MQ22-137a FETCH で Location Filter の終わりに達しても、SUBSCRIPTION_ENDED を出してはならない(MQ22-108b を参照。差分の目録では FETCH/リレーの節の規則でもあるので、重複した相互参照をここにも残している)。
  - test: `tests/app/moqtrun_drain_test.c` —
    `test_moqtrun_done_filter_end_keeps_sub`
- [x] MQ22-213 ハブが持つ Track の Standalone FETCH や fill が、キャッシュが保証できない Location から始まり、FILL_TIMEOUT が 0 でないとき、ハブは範囲の始まりからそのような最後の Location までの FETCH を 1 つ、同じ Group Order で、その Track のパブリッシャーへ、いなければそれを覆う名前空間を告知しているセッションへ送信しなければならない。ただし、ハブに GOAWAY を送ったセッションや WebTransport セッションのドレインを済ませたセッション、閉じようとしているセッション、新しい経路の待機ですでに試したセッション、要求者には決して送らない(SS3.2.3, SS7.6, SS9.2)。ハブ自身の Track は決して上流へ出さない。同じ GOAWAY の規則は上流の SUBSCRIBE にも当てはまる。ハブ自身の GOAWAY(ドレイン)ではそれを止めないので、ドレイン中のハブも購読を別の告知元へ移す。
  - test: `tests/app/moqtrun_upfetch_test.c` —
    `test_moqtrun_upfetch_gap_to_owner`, `test_moqtrun_upfetch_fill_gap`,
    `test_moqtrun_upfetch_cached_no_upstream`,
    `test_moqtrun_upfetch_owner_excluded`,
    `test_moqtrun_upfetch_tried_announcer_skipped`,
    `test_moqtrun_upfetch_two_not_shared`,
    `test_moqtrun_upfetch_upstream_draft`,
    `test_moqtrun_upfetch_cache_only`, `test_moqtrun_upfetch_hub_owned`,
    `test_moqtrun_upfetch_upsub_skips_goaway`,
    `test_moqtrun_upfetch_drain_failover`
- [x] MQ22-214 ハブは、上流の各項目を届いた瞬間に、すべてのフィールドを保ったまま下流のストリームへ再エンコードして中継しなければならない。中継するのは、その項目が要求された範囲の内側にあり、配送順(Descending の FETCH では Group は降順、Object は昇順)で最後に中継した項目より後にあり、上流の End を越えていない場合に限る。それ以外の場合や、トランスポートが書き込みを拒んだ場合は、上流の FETCH を取り消し、残りはカーソルの位置からキャッシュが応答し、キャッシュに Object がないところは Unknown とする(SS3.2.1, SS7.8)。16 KiB 未満の Object は、途切れている間は丸ごと保持して一度に書くので、その書き込みが拒まれたら上と同じくキャッシュに切り替える。それより大きい Object は、フィールドがそろった時点で先頭を送り、ペイロードは届くたびに送るので、大きすぎて中継できない Object はなく、拒まれたペイロードの書き込みは次の tick か次の配送で再試行する。素通しで送っている Object の途中で区間が終わった場合(上流で切れた、または拒まれたペイロードで予算を使い切った)は、下流のストリームを INTERNAL_ERROR でリセットする。保持できない途切れた FETCH_HEADER は、データストリームをまだ待っているそのピアへの上流の FETCH を終わらせる。キャッシュが空と分かっている範囲は、ヘッダーと FIN を一度だけ送る。
  - test: `tests/app/moqtrun_upfetch_test.c` —
    `test_moqtrun_upfetch_reencode`, `test_moqtrun_upfetch_descending_order`,
    `test_moqtrun_upfetch_descending_rejects`,
    `test_moqtrun_upfetch_out_of_place`, `test_moqtrun_upfetch_refused_write`,
    `test_moqtrun_upfetch_tick_leaves_leg`, `test_moqtrun_upfetch_short_end`,
    `test_moqtrun_upfetch_fin_then_ok`,
    `test_moqtrun_upfetch_evicted_during_leg`,
    `test_moqtrun_upfetch_marker_relay`, `test_moqtrun_upfetch_torn_header`,
    `test_moqtrun_upfetch_torn_object`, `test_moqtrun_upfetch_range_filter`,
    `test_moqtrun_upfetch_large_object`,
    `test_moqtrun_upfetch_leg_ends_mid_object`,
    `test_moqtrun_upfetch_torn_small_refused`,
    `test_moqtrun_upfetch_large_refused_retry`,
    `test_moqtrun_upfetch_cut_at_head`, `test_moqtrun_upfetch_wide_head`,
    `test_moqtrun_upfetch_torn_header_unheld`,
    `test_moqtrun_upfetch_empty_range_once`
- [x] MQ22-215 ハブが持たない Track の FETCH は、丸ごと、それを覆う告知元へ送らなければならない。その FETCH_OK は上流の FETCH_OK を待ち、その End Location、End Of Track、Track Properties を写さなければならない。告知元がなければ DOES_NOT_EXIST、FILL_TIMEOUT が 0 なら TIMEOUT、リクエストストリームがなければ EXCESSIVE_LOAD で拒否し、上流の REQUEST_ERROR は同じコード、Retry Interval、Redirect で要求者に届ける(SS7.6, SS9.4)。それ以外の形で応答なしに終わったもの(データストリームが止められた、兄弟の Malformed Track でリセットされた)は REQUEST_ERROR INTERNAL_ERROR を受け取り、要求者が取り消したものは何も受け取らない。End が Start より前にある FETCH_OK は、告知元のセッションを PROTOCOL_VIOLATION で閉じる。予約済みの名前空間や認可されていない名前は、これらの処理より前に拒否する(SS7.4)。
  - test: `tests/app/moqtrun_upfetch_test.c` —
    `test_moqtrun_upfetch_no_track_waits_ok`,
    `test_moqtrun_upfetch_no_track_refusals`,
    `test_moqtrun_upfetch_error_passthrough`,
    `test_moqtrun_upfetch_empty_answer`,
    `test_moqtrun_upfetch_refused_before_routing`,
    `test_moqtrun_upfetch_unanswered_stop`,
    `test_moqtrun_upfetch_malformed_unanswered`,
    `test_moqtrun_upfetch_no_track_bad_end`
- [x] MQ22-216 上流の FETCH は、min(FILL_TIMEOUT, `WIRED_MOQTRUN_UPFETCH_BUDGET_MS`) が経過したら取り消し、キャッシュにないものを、draft-22 に向けては End of Timed-Out Range として報告しなければならない(それより前のドラフトに向けては End of Unknown Range とし、中継した 0x20C も 0x10C として届ける)。FILL_TIMEOUT が 0 なら上流には何も問い合わせない(SS9.20.5, SS11.4.1)。
  - test: `tests/app/moqtrun_upfetch_test.c` —
    `test_moqtrun_upfetch_budget`, `test_moqtrun_upfetch_fill_timeout_zero`,
    `test_moqtrun_upfetch_marker_relay`
- [x] MQ22-250 (SS9.1.6) ハブは、上流の FETCH で、上流のピアが広告した MAX_FILTER_RANGES を超える数の Range Filter パラメーターを送信してはならない(ピアが 0 を広告したか何も広告しなかった場合は 1 つも送らない)。
  - test: `tests/app/moqtrun_upfetch_test.c` —
    `test_moqtrun_upfetch_range_filter_peer_limit`,
    `test_moqtrun_upfetch_range_filter`
  - note: 範囲が上限を超えると、フィルターを 1 つも送りません(一部だけ落とすと、OR で結んだ集合を狭めてしまうことがある)。ハブは、より広い応答を自分で絞り込みます。
- [x] MQ22-217 要求者が取り消した、データストリームを止めた、または切断したとき、ハブはスロットを解放する前に上流の FETCH を取り消し(リクエストストリームに RESET_STREAM と STOP_SENDING、データストリームに STOP_SENDING)、後からそのために届いたデータストリームを止めなければならない。上流のリセット、リクエストストリーム上の GOAWAY、切断は区間を終わらせ、ハブが持つ Track に対する上流の REQUEST_ERROR はキャッシュに引き継ぎ、1 つのリクエストストリーム上の 2 回目の GOAWAY はそのセッションを閉じる(SS3.2.4, SS9.2, SS9.12)。
  - test: `tests/app/moqtrun_upfetch_test.c` —
    `test_moqtrun_upfetch_requester_gone`, `test_moqtrun_upfetch_leg_ends`,
    `test_moqtrun_upfetch_two_goaways`, `test_moqtrun_upfetch_error_held`,
    `test_moqtrun_upfetch_bad_end`
- [x] MQ22-218 上流の FETCH_OK が示した End Of Track を越える上流の Object、その Track で見た Group の終わりを越える Object、キャッシュ済みの複製と食い違う Object は、中継もキャッシュもしてはならず、そのパブリッシャーからのその Track の fetch をすべて MALFORMED_TRACK でリセットしなければならない(そのパブリッシャーが Track の所有者なら、ハブが持つ Track も PUBLISH_DONE MALFORMED_TRACK で終わる。ほかの告知元が所有者の Track を終わらせることはできない)。素通しのペイロードは、届くたびにキャッシュ済みの複製と照合する。FETCH_OK に未知の Mandatory Track Property があれば fetch を取り消す(未応答なら UNSUPPORTED_EXTENSION、データの後ならリセット)。上流の不正なバイトは、上流のセッションだけを閉じる(SS3.7, SS11.4, SS12.1)。
  - test: `tests/app/moqtrun_upfetch_test.c` —
    `test_moqtrun_upfetch_malformed_past_end`,
    `test_moqtrun_upfetch_malformed_conflict`,
    `test_moqtrun_upfetch_malformed_group_end`,
    `test_moqtrun_upfetch_malformed_siblings`,
    `test_moqtrun_upfetch_repeat_of_relayed`,
    `test_moqtrun_upfetch_mandatory`, `test_moqtrun_upfetch_bad_reply_bytes`,
    `test_moqtrun_upfetch_delta_underflow`,
    `test_moqtrun_upfetch_malformed_not_owner`,
    `test_moqtrun_upfetch_torn_conflict`
- [x] MQ22-219 区間の途中で Track の所有者のセッションが閉じたら、それ以上そのセッションへは何も送信してはならない。fill は、開いていてもいなくてもすぐに INTERNAL_ERROR でリセットし、PUBLISH_DONE を引き止めないようにする。FETCH は、解放されたキャッシュをその End まで Unknown として読む(SS3.4.1)。
  - test: `tests/app/moqtrun_upfetch_test.c` —
    `test_moqtrun_upfetch_owner_gone_fill`,
    `test_moqtrun_upfetch_owner_gone_fetch`

## ハブのリレー: fill fetch ストリーム(FILL_PARAMETERS。draft-22 のみ、-20 で新設)

draft-22 では、購読者は、すでに購読している Track の範囲を限った埋め戻しを、購読を置き換えずに、FETCH_HEADER で枠付けした専用のデータストリームで要求できます。SUBSCRIBE(最初の fill)や REQUEST_UPDATE(後からの fill)の FILL_PARAMETERS (0x23) は、新しい fill fetch ストリームを開きます。このストリームは FETCH のデータストリームと同じ枠付けで、その SUBSCRIBE や REQUEST_UPDATE 自身の Request ID を参照します。1 つの購読につき、複数の fill ストリームを同時に開いてよいことになっています。この仕組みは、draft-18 と draft-19 にはまったくありません。

- [x] MQ22-138 購読に対する SUBSCRIBE または REQUEST_UPDATE が FILL_PARAMETERS を含む場合、実装は、そのメッセージ自身の Request ID を参照する、FETCH_HEADER で枠付けした新しいデータストリームを開き、fill の範囲(FILL_PARAMETERS 自身の LOCATION_FILTER があればそれ、なければ購読のフィルター)を、開いた時点で分かっている Largest Object まで(決してそれを越えずに)送らなければならない。
  - test: `tests/app/moqtrun_fill_test.c` — `test_moqtrun_fill_subscribe_opens`
  - test: `tests/app/moqtrun_fill_test.c` — `test_moqtrun_fill_update_opens`
  - test: `tests/app/moqtrun_fill_test.c` —
    `test_moqtrun_fill_open_end_is_largest`
  - test: `tests/app/moqtrun_fill_test.c` —
    `test_moqtrun_fill_end_clipped_to_largest`
  - test: `tests/app/moqtrun_fill_test.c` —
    `test_moqtrun_fill_filter_separate_from_subscription`
  - note: 台帳 4-6(裁定 9-2: fill fetch を実装する)。Q-01(FILL_PARAMETERS の値は、通常のメッセージの Parameters と同じ形で、Number-of-Parameters の数から始まる)と Q-02(fill 自身の LOCATION_FILTER の型 0x00 も省略も、どちらも「フィルターなし」を意味する)は、`tasks/moqt-multidraft-ledger.md` 9-4 の裁定に従って実装しています。
- [x] MQ22-139 fill の要求された範囲が空であるか、全体が現在の Largest Object より後から始まる場合、実装は fill fetch ストリームを一切開いてはならない。
  - test: `tests/app/moqtrun_fill_test.c` —
    `test_moqtrun_fill_empty_or_future_range`
- [x] MQ22-140 同じ購読について、複数の fill fetch ストリームを同時に開いてもよく、それぞれを独立に管理する。
  - test: `tests/app/moqtrun_fill_test.c` — `test_moqtrun_fill_two_at_once`
  - test: `tests/app/moqtrun_fill_test.c` —
    `test_moqtrun_fill_survives_done_and_slot_reuse`
- [x] MQ22-141 fill fetch ストリームは、その範囲を、購読の Group Order(GROUP_ORDER による昇順または降順。FILL_PARAMETERS の内側で上書きできる)で配送し、存在しない Group は印を付けずに飛ばさなければならない。
  - test: `tests/app/moqtrun_fill_test.c` — `test_moqtrun_fill_descending`
  - test: `tests/app/moqtrun_fill_test.c` —
    `test_moqtrun_fill_descending_skips_gap`
  - test: `tests/app/moqtrun_fill_test.c` —
    `test_moqtrun_fill_next_object_no_gap`
  - test: `tests/app/moqtrun_fill_test.c` — `test_moqtrun_fill_ascending_sends_first`
  - test: `tests/app/moqtrun_fill_test.c` — `test_moqtrun_fill_descending_sends_last`
- [x] MQ22-142 fill の元データがキャッシュから追い出されているか、FILL_TIMEOUT でタイムアウトした場合、実装はストリームを止めたままにしたり黙って落としたりせず、End of Timed-Out Range の印(0x20C。MQ22-136 を参照)で報告しなければならない。
  - test: `tests/app/moqtrun_fill_test.c` — `test_moqtrun_fill_miss_is_timed_out_now`
  - test: `tests/app/moqtrun_fill_test.c` — `test_moqtrun_fill_evicted_run_collapsed`
  - test: `tests/app/moqtrun_fill_test.c` — `test_moqtrun_fill_eviction_under_cursor`
- [x] MQ22-143 所有する購読を取り消すと、そのために開いたすべての fill fetch ストリームをリセットしなければならない。fill ストリーム自身の取り消し(要求者のリセット、STOP_SENDING、上流の失敗)は、決して購読そのものに影響してはならない。
  - test: `tests/app/moqtrun_fill_test.c` — `test_moqtrun_fill_cancel_resets_all`
  - test: `tests/app/moqtrun_fill_test.c` —
    `test_moqtrun_fill_stop_sending_leaves_sub`
  - test: `tests/app/moqtrun_fill_test.c` — `test_moqtrun_fill_upstream_gone_resets`
  - test: `tests/app/moqtrun_fill_test.c` — `test_moqtrun_fill_blocked_upstream_gone`
- [x] MQ22-144 配送タイムアウトを過ぎて止まった fill ストリームは、ほかの止まったデータストリームと同じように放棄しなければならず、購読自身のライブ配送を決して滞らせてはならない。
  - test: `tests/app/moqtrun_fill_test.c` —
    `test_moqtrun_fill_stall_delivery_timeout`
  - test: `tests/app/moqtrun_fill_test.c` —
    `test_moqtrun_fill_blocked_never_starves_live`
- [x] MQ22-145 PUBLISH_DONE の Stream Count は、その購読の開いているすべての fill fetch ストリームを含まなければならず、PUBLISH_DONE は、保留中の(まだ開いていない)fill のリクエストが片付くのを待ってから送信しなければならない。
  - test: `tests/app/moqtrun_fill_test.c` — `test_moqtrun_fill_counts_in_done`
  - test: `tests/app/moqtrun_fill_test.c` — `test_moqtrun_fill_done_waits_for_held`
- [x] MQ22-146 実装の固定の fill スロットの容量がすでに埋まっている場合、この実装で認めた容量の裁定(台帳 4-6、2026-10-04: 8+8 スロット。上限を上げることも明示的にエラーにすることも YAGNI とした)に従い、新しい fill のリクエストを、スロットが空くまで(エラーで応答せずに)保留しなければならない。
  - test: `tests/app/moqtrun_fill_test.c` — `test_moqtrun_fill_slot_full_held`
  - test: `tests/app/moqtrun_fill_test.c` —
    `test_moqtrun_fill_slot_full_cancel_drops`
  - test: `tests/app/moqtrun_fill_test.c` —
    `test_moqtrun_fill_slot_full_done_waits`
- [x] MQ22-147 FETCH_HEADER ストリームの Request ID は、FETCH だけでなく、SUBSCRIBE や REQUEST_UPDATE(fill)を指してもよい。draft-19 では、FETCH_HEADER は自身が応答する FETCH しか名指さない点が異なる。
  - test: `tests/app/moqtrun_fill_test.c` —
    `test_moqtrun_fill_inbound_fetch_known_rid`
  - test: `tests/app/moqtrun_fill_test.c` —
    `test_moqtrun_fill_inbound_fetch_unknown_rid`

## ハブのリレー: PUBLISH/SUBSCRIBE の振り分け(SS7 リレー、SS9.3/9.6/9.8 の適用)

- [x] MQ22-148 PUBLISH が成功したら、ハブは同じ制御ストリームで、それを閉じずに REQUEST_OK を応答しなければならない。
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_publish_replies_request_ok`
- [x] MQ22-149 ピアは、異なる Track を複数(実装のピアごとの Track の容量まで)PUBLISH してもよく、それぞれが独立に REQUEST_OK を受け取る。
  - test: `tests/app/moqtrun_test.c` — `test_moqtrun_peer_publishes_two_tracks`
- [x] MQ22-150 ピアが実装のピアごとの容量を超える数の異なる Track を PUBLISH しようとした場合、実装は既存の Track を黙って上書きせずに、REQUEST_ERROR で応答しなければならない。
  - test: `tests/app/moqtrun_test.c` — `test_moqtrun_sixth_publish_gets_error`
- [x] MQ22-151 すでにスロットを占めている同じ Track Name を再び PUBLISH したときは、新しいスロットを使わずにそのスロットを再利用しなければならない。
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_republish_same_name_reuses_slot`
- [x] MQ22-152 ピアが PUBLISH したいずれかの Track を名指す SUBSCRIBE は、割り当てた Track Alias とともに SUBSCRIBE_OK を受け取らなければならない。
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_subscribe_audio_track_replies_ok`
- [x] MQ22-153 同じ振り分けの呼び出しで届いた 2 つの SUBSCRIBE メッセージは、一方が他方を上書きすることなく、それぞれ自身の応答をキューに入れなければならない。
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_two_subscribe_oks_one_dispatch_no_overflow`

## ハブのリレー: 一致する購読者だけへの Object の転送(SS7.4, SS3.1.3)

- [x] MQ22-154 Object は、その Track Alias が示す Track の購読者だけに転送し、同じセッションのほかの Track の購読者には転送してはならない。
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_chat_object_relays_only_to_chat_subscriber`
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_audio_object_relays_only_to_audio_subscriber`
- [x] MQ22-155 Object の Track Alias が、パブリッシャーが宣言したどの Track とも一致しない場合、実装はそれをどの購読者にも転送してはならない。
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_unknown_alias_object_relays_nowhere`
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_unbound_stream_id_relays_nowhere`
- [x] MQ22-156 同じ Track への複数の購読に一致する Object は、一致する購読ごとに 1 回ずつ送信しなければならない。
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_chat_object_relays_to_all_three_subscribers`
- [x] MQ22-157 ある購読者への Object の転送が失敗した(下のトランスポートが送信を拒んだ)場合も、実装はそれを一致するほかのすべての購読者へ転送し、損失を黙って見過ごさずに数えなければならない。
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_chat_one_of_three_subscribers_refused`
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_send_uni_failure_counts_open_drop`
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_stream_send_rejection_drops_frame_not_fatal`
- [x] MQ22-158 Delivery Mode が Subgroup で送られた Object は、パブリッシャーのストリームの枠付けに合わせて、リレーの 1 回の送信につき、SUBGROUP_HEADER と Object がそろった 1 つの完全な単位として中継しなければならない。
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_multi_object_stream_relays_in_one_send_uni`
- [x] MQ22-159 長く続く Subgroup ストリームの後続のデータ(SUBGROUP_HEADER を繰り返さずに届く)は、新しいヘッダーと読み違えずに、すでに結び付いた同じリレーのストリームへ追記しなければならない。
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_data_stream_continues_across_calls_without_header`
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_audio_first_object_opens_then_appends`
- [x] MQ22-160 パブリッシャーの Subgroup ストリームが FIN したとき、実装は境界をまたいで追記せずに、対応するリレーのストリームを閉じ、新しいパブリッシャーのストリーム上の次の Subgroup のために新しいストリームを開かなければならない。
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_audio_publisher_fin_closes_and_reopens`
- [x] MQ22-161 実装は、各 Subgroup を、その配送の形に合ったトランスポートのプリミティブで一貫して中継しなければならない(1 回で終わる Subgroup は open+send+FIN を一度に、長く続く Subgroup は FIN なしで開いて後から追記する)。
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_chat_still_uses_send_uni_every_object`
- [x] MQ22-162 同じ Track の 2 人の購読者は、それぞれ独立したリレーのストリームを持たなければならない。これにより、一方への配送が他方のストリームの結び付きに影響しない。
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_audio_two_subscribers_independent_streams`

## ハブのリレー: 拒否が続くときの切り捨て(SS11.3.2 のリセットの規律の適用)

- [x] MQ22-163 購読者のリレーのストリームが、実装のしきい値を超えて busy(拒否)が続いた場合、実装は古い滞留を抱え続けずに、そのストリームをリセットし、次の配送で新しいストリームを開き直さなければならない。
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_busy_streak_sheds_after_threshold`
- [x] MQ22-164 busy が続く途中で配送が受け入れられたら、busy の連続回数のカウンターをリセットしなければならない。これにより、散発的な一時的拒否が積み重なって切り捨てに至ることはない。
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_busy_streak_success_resets`
- [x] MQ22-165 ストリームを切り捨てた後、その放棄したストリームに対して届いたパブリッシャーの単独の FIN は、そこへ転送してはならない。
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_shed_stream_skips_publisher_fin`
- [x] MQ22-166 busy の連続回数のカウンターは購読者ごとに管理しなければならない。これにより、詰まった 1 人の購読者の切り捨てが、ほかの購読者の健全なストリームに影響しない。
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_busy_shed_isolated_per_subscriber`
- [x] MQ22-167 リセットそのものが下のトランスポートに拒まれた場合、実装はそれを済んだものとして扱わずに、次の busy の回で切り捨てを再試行しなければならない。
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_shed_refused_retries_next_round`
- [x] MQ22-168 Track を再び PUBLISH したときは、そのリレーの状態を、以前の世代で積み上がった busy の連続回数のカウンターも含めて消去しなければならない。
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_republish_clears_busy_streak`
- [x] MQ22-202 `newest_group_only` が設定され(既定では無効な、明示的に選ぶハブのポリシー)、損失を許すリレーが、その購読でこれまでに開いたどれよりも新しい Group で購読者のストリームを開くとき、実装はその購読の直前の最新のストリームを(パブリッシャーがすでに終えたものでも)リセットしなければならない。これにより、古い Group の未送信の滞留が、Group の順序どおりのスケジューリングの後ろで新しい Group を引き止めることはない。
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_newer_group_resets_finished_older_stream`
- [x] MQ22-203 その後、古い Group のまだ開いているパブリッシャーのストリームの各回は、その購読者には一切届いてはならない: 追記も、開き直しも、FIN もしない。
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_newer_group_cuts_open_older_relay`
- [x] MQ22-204 同じ Group の別のストリームや、信頼性のある(リングで裏打ちされた)Track のストリームは、何もリセットしてはならない。
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_same_group_stream_keeps_sibling`,
    `test_moqtrun_newer_group_keeps_reliable_stream`
- [x] MQ22-220 既定(`newest_group_only` が 0)では、新しい Group のストリームは何もリセットしてはならず、古い Group の後続の回もそのまま転送しなければならない: 「A relay MUST NOT reorder or drop objects received on a multi-object stream」(7.4 節)。
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_newer_group_keeps_older_by_default`
- [x] MQ22-205 再 PUBLISH や付け直しでは、新しい世代で Group の番号が振り直されるので、購読の最新の Group を忘れなければならない。
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_republish_forgets_newest_group`,
    `test_moqtrun_reattach_forgets_newest_group`

## ハブのリレー: セッションの後始末(SS6.6 終了をリレーの状態に適用)

- [x] MQ22-169 セッションが閉じたとき、実装はそのピアのスロットを解放しなければならない。これにより、同じ下のセッションのポインターで後から再接続したものを、閉じたピアではなく新しいピアとして扱う。
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_close_frees_peer_for_reregistration`
- [x] MQ22-170 購読者のセッションが閉じたとき、実装はほかのすべてのピアの Track 上にあるその購読のエントリを無効にしなければならない。これにより、後の Object を閉じたセッションへ中継しない。
  - test: `tests/app/moqtrun_test.c` — `test_moqtrun_close_drops_subscriptions`
- [x] MQ22-171 実装が一度も登録していないセッション(またはすでに閉じたセッション)を閉じても、何もせず、ほかのピアに影響を与えてはならない。
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_close_unknown_session_noop`
- [x] MQ22-172 実装のピアテーブルの容量を超えて登録と切断を繰り返しても、スロットを漏らしてはならない。再接続のたびに、必ず SETUP を受け取らなければならない。
  - test: `tests/app/moqtrun_test.c` — `test_moqtrun_close_reregister_churn`

## ハブのリレー: 制御ストリームとリクエストストリーム

- [~] MQ22-173 実装は、すべての Message Parameter を draft-22 の登録表(値のエンコーディング、現れてよいメッセージ、許される値の範囲)に従ってデコードしなければならない。メッセージや範囲の外にあるパラメーターは、プロトコル違反でセッションを閉じなければならない。
  - evidence: 登録表によるデコード(値のエンコーディング、許されるメッセージ、値の範囲)はコーデックで確かめています(`test_moqctl_params_registry_scope`、`test_moqctl_params_uint8_value_ranges`、`test_moqctl_params_repeatable_filters`、`test_moqctl_golden_subscribe_params`)。ハブは対象外のパラメーターで閉じます(`test_moqtrun_upd_bad_and_control`)が、範囲外の値を送るハブのテストはありません。
- [x] MQ22-174 ストリームの複数回の配送に分かれて届いた制御メッセージは、組み立て直して 1 回だけ処理しなければならない。ハブの受信の上限(1024 バイト)より長いメッセージは、INTERNAL_ERROR でセッションを閉じなければならない。
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_ctl_split_subscribe_answered_once`
  - test: `tests/app/moqtrun_test.c` — `test_moqtrun_ctl_message_then_half`
  - test: `tests/app/moqtrun_test.c` — `test_moqtrun_ctl_max_length_accepted`
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_ctl_over_max_closes_session`
- [x] MQ22-175 制御ストリームがまったく未知の Message Type を運ぶ場合、ハブはプロトコル違反でセッションを閉じなければならない。
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_ctl_unknown_type_closes_session`
- [x] MQ22-176 専用の双方向ストリームで開いた各リクエストには、そのストリームで応答しなければならない。ストリームのリセットはリクエストを取り消す(購読の解除/配信の取り下げ)が、FIN だけでは取り消さない。1 つのセッションが同時に開いておけるリクエストは最大 32 個である(それを超えるものは EXCESSIVE_LOAD でリセットする)。
  - test: `tests/app/moqtrun_sub_test.c` —
    `test_moqtrun_req_subscribe_answered_on_its_stream`
  - test: `tests/app/moqtrun_sub_test.c` —
    `test_moqtrun_req_two_streams_answered_apart`
  - test: `tests/app/moqtrun_sub_test.c` — `test_moqtrun_req_reset_unsubscribes`
  - test: `tests/app/moqtrun_sub_test.c` — `test_moqtrun_req_fin_keeps_request`
  - test: `tests/app/moqtrun_sub_test.c` — `test_moqtrun_req_per_session_cap`
  - test: `tests/app/moqtrun_sub_test.c` — `test_moqtrun_req_pool_full_resets`
  - test: `tests/app/moqtrun_ns_test.c` —
    `test_moqtrun_ns_fin_half_closes_d19_d22`

## ハブのリレー: 購読

- [x] MQ22-177 SUBSCRIBE は、配信された Track と完全な Track Name(名前空間と名前)で照合しなければならない。したがって、異なる名前空間にある同じ名前は異なる Track である。
  - test: `tests/app/moqtrun_sub_test.c` — `test_moqtrun_sub_ns_must_match`
  - test: `tests/app/moqtrun_sub_test.c` —
    `test_moqtrun_sub_same_name_other_ns_coexist`
- [x] MQ22-178 ハブは、各購読の Request ID、SUBSCRIBER_PRIORITY、GROUP_ORDER、FORWARD、配送タイムアウト、フィルターの始点を記録し、パブリッシャーが再参加してもそれらを保ち、Track に Object が入ったら SUBSCRIBE_OK で LARGEST_OBJECT を報告しなければならない。
  - test: `tests/app/moqtrun_sub_test.c` — `test_moqtrun_sub_params_recorded`
  - test: `tests/app/moqtrun_sub_test.c` —
    `test_moqtrun_sub_reattach_keeps_state`
  - test: `tests/app/moqtrun_sub_test.c` — `test_moqtrun_sub_ok_largest`
  - test: `tests/app/moqtrun_sub_test.c` —
    `test_moqtrun_sub_largest_from_datagram`
  - test: `tests/app/moqtrun_sub_test.c` —
    `test_moqtrun_sub_params_include_properties_d22`
  - test: `tests/app/moqtrun_sub_test.c` —
    `test_moqtrun_pub_params_delivery_timeout_d22`
- [x] MQ22-179 Object は、共有のバッファープールから各購読者へ確実に中継しなければならない。遅い購読者がプールを引き止めるのはウォーターマークまでで、止まった購読者はタイムアウトの後に落とし、末尾を落としたストリームは続けない(続けると購読者との同期がずれる)。
  - test: `tests/app/moqtrel_test.c` — `test_moqtrel_append_hold_at_watermark`
  - test: `tests/app/moqtrel_test.c` — `test_moqtrel_reclaim_follows_slowest`
  - test: `tests/app/moqtrel_test.c` — `test_moqtrel_stalled_after_timeout`
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_poison_survives_reset_and_close`
- [x] MQ22-180 購読者の優先度は、その購読者のリレーのストリームの WebTransport のストリームの urgency に対応付けなければならない。優先度を変える REQUEST_UPDATE は、以後のストリームに適用され、その購読の開いている keep-open のストリームと fill ストリームのクラスを付け直す。io の stream_sched フックがあれば、ハブは各 Object ストリームの完全なクラス(urgency 4、Subscriber << 8 | Publisher Priority、Group の順序と fill を先・ライブを後にする順で並べた購読ごとのフロー)を設定し、送信のポンプはそれに従ってスケジューリングする。
  - test: `tests/app/moqtrun_drain_test.c` — `test_moqtrun_sched_relay_keys`
  - test: `tests/app/moqtrun_drain_test.c` — `test_moqtrun_sched_update_reclasses`
  - test: `tests/app/moqtrun_drain_test.c` — `test_moqtrun_sched_fill_shares_flow`
  - test: `tests/app/srvrun_test.c` — `test_srvrun_wt_sched_fill_before_live`
  - test: `tests/app/moqtrun_drain_test.c` — `test_moqtrun_prio_per_subscriber`
  - test: `tests/app/moqtrun_drain_test.c` — `test_moqtrun_prio_update_applies`
  - test: `tests/app/moqtrun_drain_test.c` — `test_moqtrun_prio_op_absent`
- [x] MQ22-181 SUBSCRIBE に対する、その購読のリクエストストリーム上の REQUEST_UPDATE は、そのパラメーターを全部置き換えるか何も変えないかのどちらかでなければならない: 拒否された更新は何も変えない。
  - test: `tests/app/moqtrun_upd_test.c` — `test_moqtrun_upd_forward_toggles`
  - test: `tests/app/moqtrun_upd_test.c` — `test_moqtrun_upd_params_replace`
  - test: `tests/app/moqtrun_upd_test.c` —
    `test_moqtrun_upd_failed_changes_nothing`
  - test: `tests/app/moqtrun_upd_test.c` — `test_moqtrun_upd_survives_rejoin`
- [x] MQ22-182 パブリッシャーは、自身の購読のストリームで PUBLISH_STATE_NOTIFY(0x22。draft-22 で新設)を送信して、現在の LARGEST_OBJECT、FORWARD、LOCATION_FILTER の状態を購読者へ報告してもよい。これは決してほかのストリームで送信してはならず、応答を受け取ってはならず、MAX_REQUEST_UPDATES に数えてはならない。
  - test: `tests/app/moqtrun_upd_test.c` —
    `test_moqtrun_notify_on_publish_stream_d22`
  - test: `tests/app/moqtrun_upd_test.c` —
    `test_moqtrun_notify_elsewhere_closes_d22`
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_ctl_publish_state_notify_d22_only`
  - note: `moqtrun_dispatch_pub_notify`。台帳 4-10。3 つの経路で向きを確かめています。
- [x] MQ22-182a PUBLISH_NAMESPACE は、Track Namespace の **Prefix** (それで始まる任意の名前空間)として照合しなければならない。draft-19 では、1 つの Track Namespace をそのまま名指す点が異なる。リレーは決して PUBLISH_NAMESPACE を下流へ転送してはならず、代わりに一致する SUBSCRIBE_NAMESPACE に NAMESPACE を使う。
  - test: `tests/app/moqtrun_upsub_test.c` — `test_moqtrun_upsub_prefix`
  - test: `tests/app/moqtrun_ns_test.c` — `test_moqtrun_ns_prefix_overlap`
  - test: `tests/app/moqtrun_upd_test.c` — `test_moqtrun_upd_ns_prefix_changes`
  - test: `tests/app/moqtrun_upd_test.c` —
    `test_moqtrun_upd_ns_prefix_overlap_refused`
  - note: 台帳 4-9 の調べでは、`moqtrun_disc_under`/`_starts`/`_overlap` は、draft-19 と draft-22 の両方について、すでにバイト単位のプレフィックス照合(完全一致ではない)を実装しています。draft-19 自身の NAMESPACE 送信義務の規則が、SUBSCRIBE_NAMESPACE にすでにプレフィックス照合を求めているからです。draft-22 の変更は、フィールド自身の名前(「Track Namespace Prefix」)と、同じアルゴリズムを PUBLISH_NAMESPACE の照合の規則にも当てはめることで、すでに正しく、コードの変更は必要ありませんでした。
- [x] MQ22-182b TRACK_STATUS には、Track の最大の Location を運ぶ REQUEST_OK(空なら Location なし)か、Track が未知であるか認可関数が拒否したときは REQUEST_ERROR で応答しなければならない。
  - test: `tests/app/moqtrun_upd_test.c` — `test_moqtrun_tstat_ok_largest`
  - test: `tests/app/moqtrun_upd_test.c` — `test_moqtrun_tstat_ok_empty`
  - test: `tests/app/moqtrun_upd_test.c` — `test_moqtrun_tstat_unknown_and_blob`
  - test: `tests/app/moqtrun_upd_test.c` — `test_moqtrun_tstat_authorized`
- [x] MQ22-183 アプリケーションが認可関数を設定している構成では、すべての SUBSCRIBE、TRACK_STATUS、PUBLISH、PUBLISH_NAMESPACE、SUBSCRIBE_NAMESPACE をそれに見せ(draft-22 は認可を配信する側にも広げている。MQ22-097a を参照)、拒否は REQUEST_ERROR UNAUTHORIZED としなければならない。Alias に基づく認可トークンは、セッションを閉じなければならない(ハブはトークンのキャッシュを持たない。8.9): REGISTER は AUTH_TOKEN_CACHE_OVERFLOW、DELETE と USE_ALIAS は UNKNOWN_AUTH_TOKEN_ALIAS で閉じる。
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_subscribe_requires_authorization`
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_subscribe_alias_token_rejected`
  - test: `tests/app/moqtrun_ns_test.c` — `test_moqtrun_ns_authorization`
  - test: `tests/app/moqtrun_upd_test.c` —
    `test_moqtrun_publish_requires_authorization`
  - vuln: V-0786, V-0792, V-0793, V-0839

## ハブのリレー: 配送タイムアウト

- [x] MQ22-184 OBJECT_DELIVERY_TIMEOUT(SUBSCRIBE または REQUEST_UPDATE から)が 0 でない場合、時間内に配送できなかった Object は放棄しなければならない: そのストリームを DELIVERY_TIMEOUT (0x2) でリセットするか、データグラムを落とす。
  - test: `tests/app/moqtrun_upd_test.c` — `test_moqtrun_timeout_live`
  - test: `tests/app/moqtrun_upd_test.c` — `test_moqtrun_timeout_datagram`
  - test: `tests/app/moqtrun_upd_test.c` — `test_moqtrun_timeout_by_update`
  - test: `tests/app/moqtrun_upd_test.c` — `test_moqtrun_timeout_torn_object`
  - test: `tests/app/moqtrun_upd_test.c` — `test_moqtrun_timeout_zero`

## ハブのリレー: キャッシュと FETCH

- [x] MQ22-185 キャッシュのアリーナが付いている(`wired_moqt_cache_attach`)場合、ハブは Group を丸ごとだけキャッシュし、予算を超えたら最も古い Group を追い出し、単独で予算を超える Group は落とさなければならない。
  - test: `tests/app/moqcache_test.c` — `test_moqcache_evicts_oldest_group`
  - test: `tests/app/moqcache_test.c` — `test_moqcache_group_over_budget_dropped`
  - test: `tests/app/moqtrun_fetch_test.c` — `test_moqtrun_fetch_cache_attach`
  - test: `tests/app/moqtrun_fetch_test.c` —
    `test_moqtrun_fetch_cache_default_off`
- [x] MQ22-207 1 つの Track のキャッシュ済みの Object を前向きにたどるとき、各検索は前回止まったところから再開し、アリーナの先頭から走査した場合と同じ項目を返さなければならない。追い出し(レコードを移動する)は再開位置を捨てる。
  - test: `tests/app/moqcache_test.c` — `test_moqcache_walk_resumes`,
    `test_moqcache_evict_drops_resume`
- [x] MQ22-186 FETCH は、要求者が取り消したとき、データストリームが止められたとき、パブリッシャーか要求者が去ったとき、配送が止まったときに、そのスロットを解放しなければならない。
  - test: `tests/app/moqtrun_fetch_test.c` —
    `test_moqtrun_fetch_cancelled_by_request_reset`
  - test: `tests/app/moqtrun_fetch_test.c` —
    `test_moqtrun_fetch_data_stream_stopped`
  - test: `tests/app/moqtrun_fetch_test.c` —
    `test_moqtrun_fetch_publisher_leaves`
  - test: `tests/app/moqtrun_fetch_test.c` — `test_moqtrun_fetch_stall_gives_up`

## ハブのリレー: 名前空間の発見

- [~] MQ22-187 PUBLISH_NAMESPACE はパブリッシャーごとに受け入れなければならず(複数のパブリッシャーが 1 つの名前空間を共有してよい)、SUBSCRIBE_NAMESPACE は、一致するすべての名前空間について NAMESPACE を受け取り、その後はパブリッシャーの出入りに応じて NAMESPACE / NAMESPACE_DONE を受け取らなければならない。
  - test: `tests/app/moqtrun_ns_test.c` — `test_moqtrun_ns_publish_accepted`
  - test: `tests/app/moqtrun_ns_test.c` — `test_moqtrun_ns_initial_set`
  - test: `tests/app/moqtrun_ns_test.c` — `test_moqtrun_ns_live_join_and_cancel`
  - test: `tests/app/moqtrun_ns_test.c` — `test_moqtrun_ns_publisher_leaves`
  - test: `tests/app/moqtrun_ns_test.c` — `test_moqtrun_ns_multiple_publishers`
  - test: `tests/app/moqtrun_ns_test.c` — `test_moqtrun_ns_prefix_overlap`
  - evidence: `[~]` としているのは、PREFIX_OVERLAP を厳しく解釈しているからです。1 つのセッションの中で、2 つのプレフィックスはどちらかが空であるか最初のフィールドが等しいときに重なるものとしていて、ドラフトが求めるより多くを拒否します。

## ハブのリレー: GOAWAY と PUBLISH_DONE

- [~] MQ22-188 `wired_moqt_goaway` は、セッションごとに GOAWAY を 1 回だけ送信しなければならない。その後に届いたリクエストは GOING_AWAY で拒否する。タイムアウトが切れたら、ハブは PUBLISH_DONE を送信し、まだ処理中のものに応答し、GOAWAY_TIMEOUT で閉じる。
  - test: `tests/app/moqtrun_drain_test.c` —
    `test_moqtrun_goaway_once_per_session`
  - test: `tests/app/moqtrun_drain_test.c` — `test_moqtrun_goaway_late_rejected`
  - test: `tests/app/moqtrun_drain_test.c` —
    `test_moqtrun_goaway_timeout_flush_then_close`
  - test: `tests/app/moqtrun_drain_test.c` — `test_moqtrun_goaway_retried_on_tick`
  - evidence: io テーブルに対する単体テストだけです。GOAWAY とドレインの手順を、サードパーティの MOQT のピアと動かしたことはまだありません。
- [x] MQ22-189 ピアからの 2 回目の GOAWAY や、クライアントからの New Session URI を含む GOAWAY を受信したら、プロトコル違反でセッションを閉じなければならない。
  - test: `tests/app/moqtrun_drain_test.c` — `test_moqtrun_peer_goaway_twice`
  - test: `tests/app/moqtrun_drain_test.c` — `test_moqtrun_peer_goaway_uri`
- [x] MQ22-190 PUBLISH_DONE の前に、ハブは購読のデータストリーム(開いている fill fetch ストリームも含む。MQ22-143 を参照)をリセットしなければならない。パブリッシャーのセッションが終わると、その購読者へ PUBLISH_DONE TRACK_ENDED を送る。
  - test: `tests/app/moqtrun_drain_test.c` —
    `test_moqtrun_done_resets_streams_first`
  - test: `tests/app/moqtrun_drain_test.c` — `test_moqtrun_done_track_ended`
- [~] MQ22-191 ピアからの WebTransport の WT_DRAIN_SESSION(`wired_moqt_on_session_draining`)は、そのセッションについてだけ MOQT の GOAWAY の手順を始めなければならない。
  - test: `tests/app/moqtrun_drain_test.c` — `test_moqtrun_drain_one_session`
  - evidence: 単体テストだけです。実際のピアとはまだ動かしていません。

## ハブのリレー: Object Datagram

- [x] MQ22-192 Object Datagram は、そのエイリアスが名指す Track のすべての購読者へバイト単位で同一のまま中継しなければならない。エイリアスがどの Established の購読も名指さないデータグラムは落とさなければならない(SS3.1.3.1)。
  - test: `tests/app/moqdg_test.c` — `test_moqdg_roundtrip_golden`
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_dg_relays_identical_bytes_to_subscriber`
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_dg_relays_to_all_three_subscribers`
  - test: `tests/app/moqtrun_test.c` — `test_moqtrun_dg_unknown_alias_counts_bad`
- [x] MQ22-233 (SS11.2.1) 実装は、OBJECT_DATAGRAM を、その Type Flags が選ぶフィールド(PROPERTIES 0x01、END_OF_GROUP 0x02、ZERO_OBJECT_ID 0x04、DEFAULT_PRIORITY 0x08、STATUS 0x20)とともにデコード・エンコードし、ビット 4、未規定のビット、END_OF_GROUP を伴う STATUS、Properties Length が 0 の PROPERTIES、Normal でないステータスでの Properties を違反に分類しなければならない。
  - test: `tests/app/moqdg_test.c` — `test_moqdg_type_valid_accepts`
  - test: `tests/app/moqdg_test.c` — `test_moqdg_type_valid_rejects`
  - test: `tests/app/moqdg_test.c` — `test_moqdg_take_props`
  - test: `tests/app/moqdg_test.c` — `test_moqdg_put_golden`
  - test: `tests/app/moqdg_test.c` — `test_moqdg_take_reject_golden`
- [x] MQ22-234 (SS11, SS11.2.1) データグラムが未知の型か無効な Type Flags を持つ場合、ハブは PROTOCOL_VIOLATION でセッションを閉じなければならない。
  - test: `tests/app/moqtrun_sess_test.c` — `test_mtss_datagram_invalid_closes`

## 複数ドラフト対応の回で完成したハブの機能(台帳 10 章)

- [x] MQ22-193 (SS9.18) ハブは、SUBSCRIBE_TRACKS に、そのリクエストストリームで REQUEST_OK をちょうど 1 つ応答しなければならず、同じセッションの確立済みの SUBSCRIBE_TRACKS と Track Namespace Prefix が重なるものを PREFIX_OVERLAP で拒否しなければならない。
  - test: `tests/app/moqtrun_subtracks_test.c` — `test_subtracks_ok_once`
  - test: `tests/app/moqtrun_subtracks_test.c` — `test_subtracks_prefix_overlap`
  - test: `tests/app/moqns_test.c` — `test_moqns_subscribe_tracks_param_scope`
  - note: draft-19 のセッションで動かしています。ハブの経路はバージョンに依存しません。
- [x] MQ22-194 (SS9.18) 確立済みの SUBSCRIBE_TRACKS のプレフィックスに一致し、購読者自身が配信したものではない Track のそれぞれについて、ハブは、その Track を名指し SUBSCRIBE_TRACKS の FORWARD の値を運ぶ PUBLISH を、新しい双方向ストリームで 1 つ開かなければならない。SUBSCRIBE_TRACKS を取り消すと新しい PUBLISH は止まるが、確立済みのものは残る。応答の前に消えた Track はその PUBLISH ストリームをリセットし、REQUEST_ERROR の応答はスロットを解放する。PUBLISH_OK(REQUEST_OK)の応答は、PUBLISH の Track Alias で購読者の購読を開き、PUBLISH のパラメーターから始める(FORWARD 0 は Object を引き止める)。そのストリーム上の購読者の REQUEST_UPDATE は、SUBSCRIBE のものと同じように適用し、そこで応答する(台帳 12-11、12-18)。SS9.8 が PUBLISH に認める SUBSCRIBE_TRACKS のパラメーターである FORWARD と GROUP_ORDER は、FORWARD 1 も含めて与えられたとおりに返す(SS3.6.2「explicitly communicated」、台帳 12-19)。SS9.8 が PUBLISH から除く SUBSCRIBE_TRACKS の Object の Range Filter も、その購読の始まりには適用する(SS3.6.1「Objects published in the resulting Subscriptions can be filtered by any Range Filter」)。Range Filter が不正、重複、または MAX_FILTER_RANGES を超えている SUBSCRIBE_TRACKS は INVALID_FILTER で拒否する(SS3.3.2、台帳 12-26)。更新に失敗したら PUBLISH_DONE UPDATE_FAILED で終わらせ、その後ハブは PUBLISH ストリームに FIN を送る(SS9.5.1、SS9.9、台帳 12-27)。2 回目の REQUEST_OK または REQUEST_ERROR は PROTOCOL_VIOLATION でセッションを閉じる(SS3.1、台帳 12-28)。
  - test: `tests/app/moqtrun_misc_test.c` — `test_moqtrun_misc_pub_ok_relays`
  - test: `tests/app/moqtrun_misc_test.c` —
    `test_moqtrun_misc_subtracks_rngf_gates`
  - test: `tests/app/moqtrun_misc_test.c` —
    `test_moqtrun_misc_subtracks_rngf_limit`
  - test: `tests/app/moqtrun_misc_test.c` —
    `test_moqtrun_misc_pub_update_failed_fins`
  - test: `tests/app/moqtrun_misc_test.c` —
    `test_moqtrun_misc_pub_second_ok_closes`
  - test: `tests/app/moqtrun_misc_test.c` —
    `test_moqtrun_misc_pub_error_after_ok_closes`
  - test: `tests/app/moqtrun_misc_test.c` —
    `test_moqtrun_misc_pub_forward0_then_update`
  - test: `tests/app/moqtrun_misc_test.c` —
    `test_moqtrun_misc_pub_update_before_ok`
  - test: `tests/app/moqtrun_misc_test.c` —
    `test_moqtrun_misc_d22_publish_params`
  - test: `tests/app/moqtrun_subtracks_test.c` —
    `test_subtracks_publish_match_excludes_self`
  - test: `tests/app/moqtrun_subtracks_test.c` —
    `test_subtracks_forward_zero_reflected`
  - test: `tests/app/moqtrun_subtracks_test.c` —
    `test_subtracks_cancel_keeps_established`
  - test: `tests/app/moqtrun_subtracks_test.c` —
    `test_subtracks_track_vanishes_resets_publish`
  - test: `tests/app/moqtrun_subtracks_test.c` —
    `test_subtracks_publish_error_frees_slot`
  - test: `tests/app/moqtrun_subtracks_test.c` —
    `test_subtracks_liveness_eventually_attempted`
  - note: 台帳 10-2(E-2): ハブが始める PUBLISH の経路です。TLA+ で検査した設計は `tasks/loopeng/moqt/MoqtHubPublish/`(git には含まない)にあります。draft-19 のセッションで動かしています。ハブの経路はバージョンに依存しません。
- [x] MQ22-195 (SS9.19) そのような PUBLISH のための双方向ストリームをハブが開けない場合、ハブは代わりに SUBSCRIBE_TRACKS のリクエストストリームで PUBLISH_SKIPPED(Track Namespace Suffix, Track Name)を送信しなければならず、同じ Track の同じ世代について後から PUBLISH を送信してはならない。
  - test: `tests/app/moqtrun_subtracks_test.c` —
    `test_subtracks_skip_then_no_publish`
  - test: `tests/app/moqns_test.c` — `test_moqns_pub_skipped_roundtrip`
  - test: `tests/app/moqns_test.c` — `test_moqns_pub_skipped_rejects`
  - note: draft-19 のセッションで動かしています。ハブの経路はバージョンに依存しません。
- [x] MQ22-196 (SS9.5, SS9.5.2) FETCH、PUBLISH_NAMESPACE、SUBSCRIBE_NAMESPACE に対する、そのリクエストストリーム上の REQUEST_UPDATE は処理しなければならない。受け入れた更新には確認応答を返す(新しい SUBSCRIBE_NAMESPACE のプレフィックスは、以後の告知から有効になる)。拒否した FETCH の更新は FETCH のデータストリームをリセットし、拒否した名前空間の更新(PREFIX_OVERLAP など)はリクエストストリームを閉じて古いプレフィックスをそのまま残す。
  - test: `tests/app/moqtrun_upd_test.c` — `test_moqtrun_upd_on_fetch_stream`
  - test: `tests/app/moqtrun_upd_test.c` — `test_moqtrun_upd_on_fetch_stream_refused`
  - test: `tests/app/moqtrun_upd_test.c` — `test_moqtrun_upd_ns_prefix_changes`
  - test: `tests/app/moqtrun_upd_test.c` —
    `test_moqtrun_upd_ns_prefix_overlap_refused`
  - note: 台帳 10-5。draft-19 のセッションで動かしています。ハブの経路はバージョンに依存しません。
- [x] MQ22-197 (SS9.11) GROUP_ORDER が Descending の FETCH には、新しい Group から順に応答しなければならず(Group の中の Object は昇順のまま)、本体のデコードに失敗した FETCH は PROTOCOL_VIOLATION でセッションを閉じなければならない。
  - test: `tests/app/moqtrun_fetch_test.c` —
    `test_moqtrun_fetch_descending_group_order`
  - test: `tests/app/moqtrun_fetch_test.c` — `test_moqtrun_fetch_malformed_closes`
  - test: `tests/app/moqtrun_fetch_test.c` —
    `test_moqtrun_fetch_descending_unknown_groups`,
    `test_moqtrun_fetch_descending_skips_missing_group`,
    `test_moqtrun_fetch_descending_start_object`
  - note: 台帳 10-6。draft-19 のセッションで動かしています。ハブの経路はバージョンに依存しません。欠落は 3.2.2 を文字どおりに読んで扱います(最初に期待するのは {End.Group, 0}、最後は {Start.Group, 2^64-1}、Group をまたぐ欠落は複数の論理的な欠落とする)。存在しない Group には印を付けず、キャッシュが保証できない Group にはそれぞれ専用の End of Unknown Range を付けます(known-limitations.md を参照)。
- [x] MQ22-198 (SS3.3.1) ライブの Track に後から加わった購読者は、その Location Filter の始点の Group から始めなければならない。ライブの先端より前の始点は現在の Group に切り詰め、未来の始点はその Group まで配送を止める。
  - test: `tests/app/moqtrun_sub_test.c` —
    `test_moqtrun_sub_live_attach_filter_start`
  - test: `tests/app/moqtrun_sub_test.c` —
    `test_moqtrun_sub_filter22_start_object_oneshot`,
    `test_moqtrun_sub_filter22_start_object_keepopen`,
    `test_moqtrun_sub_filter22_start_object_append`,
    `test_moqtrun_sub_filter22_ring_start_object`,
    `test_moqtrun_sub_filter22_ring_late_replay_start`,
    `test_moqtrun_sub_filter22_ring_late_replay_end`,
    `test_moqtrun_sub_filter22_ring_end_object_append`,
    `test_moqtrun_sub_filter22_ring_end_object_open`
  - note: 台帳 10-7。最初の Group の中にある始点の Object と End の Object は、損失を許すリレーの経路でも信頼性のある(リングの)リレーの経路でも、Object 単位で切り出します。切り出したストリームの最初の Object は、絶対的な ID で枠付けし直します。すべてのドラフトで動かしています。ハブの経路はバージョンに依存しません。
- [x] MQ22-199 (SS9.1.6, SS9.1.7) ハブの SETUP は、MAX_FILTER_RANGES と MAX_REQUEST_UPDATES(どちらも 4。`WIRED_MOQTRUN_MAX_FILTER_RANGES` / `WIRED_MOQTRUN_MAX_REQ_UPDATES`)を広告し、ピアのものをデコードしなければならない。オプションがなければドラフトの既定値 0 のままとする。
  - test: `tests/app/moqtrun_test.c` — `test_moqtrun_setup_advertises_limits`
  - test: `tests/app/moqctl_test.c` — `test_moqctl_setup_limit_options_roundtrip`
  - test: `tests/app/moqctl_test.c` — `test_moqctl_setup_limit_options_default_zero`
  - note: 台帳 10-11。
- [x] MQ22-200 (SS9.1.7, SS9.5) 応答していない REQUEST_UPDATE をすでに MAX_REQUEST_UPDATES 個抱えたリクエストストリームでは、もう 1 つ届いたら TOO_MANY_REQUEST_UPDATES でセッションを閉じなければならない。応答の回を送り出すと、まとめたすべての更新のクレジットが戻る。
  - test: `tests/app/moqtrun_upd_test.c` — `test_moqtrun_upd_credit_too_many`
  - test: `tests/app/moqtrun_upd_test.c` —
    `test_moqtrun_upd_credit_restored_by_flush`
  - test: `tests/app/moqtrun_vgate_test.c` — `test_moqtrun_vgate_update_credit`
  - note: 台帳 10-10。`MOQVER_CAP_MAX_REQUEST_UPDATES` で切り替えます。このビットは draft-19 と draft-22 にあり、draft-18 にはありません(12-5)。
- [x] MQ22-201 (SS3.3.2, SS8.6) Range Filter のパラメーターは、差分を解決してデコードし、検証しなければならない。デコードできない値、1 つのメッセージで繰り返された (Type, SetID)、広告した MAX_FILTER_RANGES を超える Range の総数(SUBSCRIBE、FETCH、REQUEST_UPDATE)は INVALID_FILTER とする。REQUEST_UPDATE は、触れたフィルターの型を丸ごと置き換え、長さ 0 の値はそれを取り除く。SetID どうしは OR で結び、OBJECTID_FILTER はデータグラムで転送する各 Object を制御する。
  - test: `tests/app/moqctl_test.c` — `test_moqctl_rangefilter_value_roundtrip`
  - test: `tests/app/moqctl_test.c` —
    `test_moqctl_rangefilter_open_end_prop_and_remove`
  - test: `tests/app/moqctl_test.c` —
    `test_moqctl_rangefilter_overflow_and_truncated`
  - test: `tests/app/moqtrun_sub_test.c` — `test_moqtrun_sub_rngf_dup_identity`
  - test: `tests/app/moqtrun_sub_test.c` — `test_moqtrun_sub_rngf_limit`
  - test: `tests/app/moqtrun_fetch_test.c` — `test_moqtrun_fetch_rngf_limit`
  - test: `tests/app/moqtrun_upd_test.c` — `test_moqtrun_upd_rngf_replace_remove`
  - test: `tests/app/moqtrun_sub_test.c` — `test_moqtrun_sub_rngf_sets_or`
  - test: `tests/app/moqtrun_sub_test.c` —
    `test_moqtrun_sub_objectid_filter_gates_datagram`
  - note: 台帳 10-9。配送を制御するのは OBJECTID_FILTER だけで、それも Object ごとの(データグラムの)関門でだけです。ほかのフィルターの型は検証して保存しますが、通過させます(対象外を参照)。draft-19 のセッションで動かしています。ハブの経路はバージョンに依存しません。

## 実験的な拡張(moqtail 互換の Track 切り替え)

ここに挙げる項目は **draft-22 の要件ではありません。** 以下のコードポイントは、draft-22 ではどれも未割り当てです。これらは、2 つの実装が相互接続できるように moqtail(`ee9753c`)の値を使う、明示的に有効にする拡張を記述しています。上のカバレッジの行と、[機能の索引](README.md)の合計からは除いています。概要: [MoQT の Track 切り替え](moqt-track-switching.md)。

どれも draft-22 のセッションに限られ、ハブが有効にしたとき(`wired_moqt_hub.switch_track`、`ssts_algs` / `ssts_alg_n`)にだけ動きます。ワイヤーの状況: コーデックは moqtail-rs の単体テストから写したバイトベクターで固定していて、ハブの振る舞いはプロセス内(ループバック)でしかテストしていません。**moqtail やほかのサードパーティの実装とは、まだ一度も動かしていません。** ワイヤー形式の規則(`.claude/rules/rfc-and-verification-layers.md`)により、ハブの項目は、テストが通っていても、そのような実行ができるまで `[~]` のままにします。

- [x] MQ22-X01 (0x24 SWITCH_FROM, codec) コーデックは、draft-22 に限り、SUBSCRIBE と REQUEST_UPDATE(購読)の SWITCH_FROM {Request ID, Mode 0 Hard / 1 Soft, Flags 0x80 Publish Done} をデコード・エンコードしなければならない。末尾の余分なバイト、未知の Mode、ほかの Flags のビットは違反とする。
  - test: `tests/app/moqctl_switch_test.c` —
    `test_mcsw_switch_from_golden_encode` (`24 03 07 00 80`)
  - test: `tests/app/moqctl_switch_test.c` —
    `test_mcsw_switch_from_golden_decode`
  - test: `tests/app/moqctl_switch_test.c` — `test_mcsw_switch_from_violations`
  - test: `tests/app/moqctl_switch_test.c` — `test_mcsw_switch_from_scope`
  - test: `tests/app/moqctl_switch_test.c` — `test_mcsw_moqtail_list`
  - test: `tests/app/moqctl_switch_test.c` —
    `test_mcsw_moqtail_switch_from_3byte`
  - note: ゴールデンベクターと moqtail のベクターは、moqtail-rs の単体テストのバイト列です(実際のピアではなく、サードパーティの静的な固定値)。
- [x] MQ22-X02 (0x41 SWITCHING_SET_ASSIGNMENT, codec) コーデックは、draft-22 に限り、SUBSCRIBE と REQUEST_UPDATE(購読)の {Set ID, Algorithm ID, Threshold kbps, Weight 1..10, Activate, 省略可能な Rank} をデコード・エンコードしなければならない。
  - test: `tests/app/moqctl_switch_test.c` — `test_mcsw_ssa_norank`
  - test: `tests/app/moqctl_switch_test.c` — `test_mcsw_ssa_violations`
  - test: `tests/app/moqctl_switch_test.c` — `test_mcsw_ssa_scope`
  - test: `tests/app/moqctl_switch_test.c` — `test_mcsw_moqtail_ssa`
  - test: `tests/app/moqctl_switch_test.c` — `test_mcsw_moqtail_ssa_trailing`
- [x] MQ22-X03 (0x09 SSTS_ALGORITHMS Setup Option, codec) コーデックは、このオプションを algorithm-id の varint を連結したものとしてデコード・エンコードし、既知の ID を先にして最大 `MOQCTL_SSTS_MAX_ALGS`(4)個まで保持しなければならない。不正なリストは、閉じずに無視する(意図的な逸脱。[既知の制限](known-limitations.md#moqt-の-track-切り替え実験的)を参照)。
  - test: `tests/app/moqctl_switch_test.c` — `test_mcsw_ssts_absent`,
    `test_mcsw_ssts_two`, `test_mcsw_ssts_cap_keeps_known`,
    `test_mcsw_ssts_malformed`
- [x] MQ22-X04 (コード 0x32、0x33、PUBLISH_DONE 0x3) コードポイントは moqtail のものと一致する。draft-22 では、`moqctl_request_error_for` は INVALID_SWITCH 0x32 と UNSUPPORTED_EXTENSION 0x33 をそのまま通す。PUBLISH_DONE の「switched」0x3 は、`moqctl_publish_done_for` が draft-22 でそれを TRACK_ENDED に写すので、直接書かなければならない。
  - test: `tests/app/moqctl_switch_test.c` — `test_mcsw_codes`
  - note: draft-18/19 では 0x24 そのものが PROTOCOL_VIOLATION になる(MQ22-X05)ので、0x32 が draft-18/19 のセッションに届くことはありません。
- [~] MQ22-X05 (オプトインの判定) `switch_track` が 0 か `ssts_alg_n` が 0 の場合、または draft-18/19 のセッションでは、0x24 か 0x41 を含む SUBSCRIBE は、拡張の導入前と同じく PROTOCOL_VIOLATION でセッションを閉じなければならない。
  - test: `tests/app/moqtrun_switch_test.c` — `test_moqtrun_switch_off_closes`
  - test: `tests/app/moqtrun_switch_test.c` —
    `test_moqtrun_switch_old_drafts_close`
  - test: `tests/app/moqtrun_ssts_test.c` — `test_moqtrun_ssts_off_violates`
  - test: `tests/app/moqtrun_ssts_test.c` —
    `test_moqtrun_ssts_nonmember_and_d19`
- [~] MQ22-X06 (SWITCH_FROM の境界と有効化の判定、TS-1/TS-2) G = max(両方の Track の Largest) + 1 とする。古い購読は G−1 で終わり、新しい購読は {G, 0} から始まる。2 回配送される Group も、飛ばされる Group もない。
  - test: `tests/app/moqtrun_switch_test.c` —
    `test_moqtrun_switch_boundary_plus_one`,
    `test_moqtrun_switch_boundary_b_ahead`,
    `test_moqtrun_switch_soft_cut_at_boundary`,
    `test_moqtrun_switch_no_group_twice`, `test_moqtrun_switch_soft_no_gap`,
    `test_moqtrun_switch_reattach_keeps_bounds`,
    `test_moqtrun_switch_filter_update_keeps_bounds`
  - note: TLA+ の `TrackSwitch.tla`(`tasks/loopeng/moqt/TrackSwitch/`。git には含まない)。
- [~] MQ22-X07 (Soft / Hard、TS-3/TS-4) Soft は、古い購読を G−1 まで送り切り、`WIRED_MOQTSW_SOFT_WAIT_MS` を過ぎたらあきらめる。Hard は、新しい Track の Group G(またはそれ以降)がハブに届いた時点、または新しい購読がなくなった時点で、古い購読の開いているストリームを CANCELLED でリセットする。
  - test: `tests/app/moqtrun_switch_test.c` —
    `test_moqtrun_switch_soft_drains_old`,
    `test_moqtrun_switch_soft_done_after_fin`,
    `test_moqtrun_switch_soft_deadline_giveup`,
    `test_moqtrun_switch_soft_g0_ends_now`,
    `test_moqtrun_switch_hard_resets_old`,
    `test_moqtrun_switch_hard_ends_on_b_boundary`,
    `test_moqtrun_switch_hard_no_silent_gap`,
    `test_moqtrun_switch_hard_b_gone_cuts_old`,
    `test_moqtrun_switch_hard_datagram_b`
- [~] MQ22-X08 (古い購読の終了、TS-5/TS-6) Publish Done があれば、古い購読は、最後のストリームの後に PUBLISH_DONE 0x3 をちょうど 1 つ受け取る。なければ、古い購読は一時停止され(ストリームはリセット、FORWARD 0、リクエストストリームは開いたまま、PUBLISH_DONE なし)、後の SWITCH_FROM でそこへ切り替え直せる。
  - test: `tests/app/moqtrun_switch_test.c` —
    `test_moqtrun_switch_no_flag_no_done`,
    `test_moqtrun_switch_done_once_track_ended`,
    `test_moqtrun_switch_hard_no_flag_suspends`,
    `test_moqtrun_switch_back`, `test_moqtrun_switch_no_leak`
- [~] MQ22-X09 (拒否、TS-9) FORWARD を伴う SWITCH_FROM、自分自身や存在しないか終わった購読、同じ Track、ハブが所有する Track を名指す SWITCH_FROM、PUBLISH の更新に載った SWITCH_FROM、FILL_PARAMETERS を伴う SWITCH_FROM は、REQUEST_ERROR 0x32 で拒否し、何も変えない。
  - test: `tests/app/moqtrun_switch_test.c` —
    `test_moqtrun_switch_rejects_ended_old`,
    `test_moqtrun_switch_hub_track_refused`,
    `test_moqtrun_switch_publish_update_refused`,
    `test_moqtrun_switch_fill_refused`,
    `test_moqtrun_switch_ssts_member_refused`
- [~] MQ22-X10 (SSTS negotiation and membership) ハブは 0x09 を draft-22 でだけ広告し、ネゴシエートしたアルゴリズムは 2 つのリストの共通部分とする。ネゴシエートしていないアルゴリズムを名指す割り当てや、すでに別のセットにある Track は、0x33 で拒否する。
  - test: `tests/app/moqtrun_ssts_test.c` — `test_moqtrun_ssts_setup_option`,
    `test_moqtrun_ssts_negotiation`,
    `test_moqtrun_ssts_refused_not_negotiated`,
    `test_moqtrun_ssts_track_in_other_set`,
    `test_moqtrun_ssts_cancel_removes_member`
- [~] MQ22-X11 (SSTS per-Group decision, SS-1..SS-4) 各 Group のメンバーは、その Group が最初に届いたときに一度だけ決め、その決定は変えない。ストリームでもデータグラムでも、ちょうど 1 つのメンバーの Group を丸ごと転送する。
  - test: `tests/app/moqtrun_ssts_test.c` —
    `test_moqtrun_ssts_one_member_per_group`,
    `test_moqtrun_ssts_forward_after_decision`,
    `test_moqtrun_ssts_whole_group`, `test_moqtrun_ssts_decision_final`,
    `test_moqtrun_ssts_switches_at_group_boundary`,
    `test_moqtrun_ssts_one_member_reliable`, `test_moqtrun_ssts_datagram`,
    `test_moqtrun_ssts_inactive_set_forwards_nothing`
  - note: TLA+ の `SstsDecision.tla`(git には含まない)。
- [x] MQ22-206 Group の途中でセットに加わったメンバー(SUBSCRIBE または REQUEST_UPDATE)には、Track の最大の Group をすぐに決める。その Group についてすでに記録した決定があればそれを使い、なければその場で決めて記録する。これにより、信頼性のあるリングがその Group を新しいメンバーへ再送する。
  - test: `tests/app/moqtrun_ssts_test.c` —
    `test_moqtrun_ssts_mid_group_join_decides`,
    `test_moqtrun_ssts_update_keeps_decision`
- [~] MQ22-X12 (SSTS algorithms 0 and 0xff01) 既定の重み付き分配と、背圧の段階のステートマシンは、moqtail 自身のテストが記述するとおりに振る舞う。
  - test: `tests/app/moqssts_test.c` — `test_moqssts`(moqtail のテストケースを移植)、例: `test_moqssts_rises_one_tier_per_five_clear_groups`、`test_moqssts_falls_one_tier_at_the_downshift_depth`、`test_moqssts_two_sets_of_the_same_rank_split_by_weight`
  - test: `tests/app/moqtrun_ssts_test.c` — `test_moqtrun_ssts_bp_upshift`,
    `test_moqtrun_ssts_bp_downshift`, `test_moqtrun_ssts_default_cap`
- [ ] MQ22-X13 (相互接続性) moqtail(またはこれらのコードポイントを実装したほかの実装)とのサードパーティの相互接続性。まだ動かしていない。
- 未実装: PUBLISH_OK / REQUEST_OK での SWITCHING_SET_ASSIGNMENT(moqtail は許している)と、講演で述べられた切り替えの促し、GOP の拡張、遅延の予算。後の 3 つは moqtail のコードにもない。

## 未実装

draft-22 のリレーの範囲内ですが、まだ実装していない項目です。これらのどれかを必要とするピアは NOT_SUPPORTED を受け取ります(注記のある場合は別の振る舞い)。予約済みの名前空間、SUBSCRIBE_TRACKS、PUBLISH_SKIPPED、FETCH の GROUP_ORDER、FETCH と名前空間リクエストへの REQUEST_UPDATE、MAX_REQUEST_UPDATES、Range Filter の検証は、台帳 10 章で実装するまでここに載せていました(MQ22-028、MQ22-193〜MQ22-201)。続いて SUBSCRIBE_TRACKS への REQUEST_UPDATE(型ごとの重なりを見るプレフィックス、FORWARD。失敗すると双方向ストリームを閉じる。9.5.1)を実装しました: `test_moqtrun_vgate_update_kinds`。FETCH のキャッシュから応答する部分での Range Filter も続けて実装した(MQ22-137)ので、今はここに載せている項目はありません。

## 対象外

このハブリレーのサブセットが実装しない機能と要件です。上のカバレッジの分母から除いています:

- (SS9.9) 従来の制御ストリームで作った購読への PUBLISH_DONE: 設計上の判断です。PUBLISH_DONE は Request ID を持たないので、複数の購読が共有するストリームでは、どれが終わったのかを名指せません。購読は保持し、パブリッシャーが再参加したら付け直します。

- (SS8.8) 名前空間と Track の名前を人が読める文字列として表示・解析すること: 運用者やログの関心事です。この SDK は名前を生のバイト列としてだけ比較します。
- (SS12.1) 受信側での Malformed Track の検出の目録の残り(Subgroup の最終 Object より後の Object ID、FIN したストリームをまたいで異なる最終 Object、購読の経路でペイロードが異なる重複した Object): デコード時の違反(未知の Object Status、Object ID のオーバーフロー)のほかに検出するのは、END_OF_GROUP / END_OF_TRACK より後の Object、Subgroup の中での Publisher Priority の不一致、ストリームからデータグラムへの Delivery Mode の変化だけです(MQ22-025)。
- (SS6.1, SS6.2) `moqt` URI スキーム、フラグメント識別子、MOQT URI の参照解決、SVCB/HTTPS RR によるホストの解決: サーバー専用のハブにとってはクライアント側の関心事です。ネイティブ QUIC のセッションそのもの(SS6.2.2: ALPN `moqt-22`、PATH/AUTHORITY の Setup Options、CONNECTION_CLOSE による終了)は実装しています(`wired_moqt_on_session_raw`、`tests/app/moqtrun_raw_test.c`)。実際のピアの固定したトレースができるまでは、プロセス内でしか確かめていません。
- (SS6.6.1, SS7.2, SS7.3) 上で扱った GOAWAY の仕組みを超えるセッションの移行と、リレーの穏やかな切り替え: これは単一のハブで、切り替え先の上流のリレーがありません。
- (SS3.3.x, SS8.6) 配送時に OBJECT_PROPERTY_FILTER に従って動くこと、ストリームで転送する Object に対して OBJECTID_FILTER に従って動くこと: これらはデコード、検証し、MAX_FILTER_RANGES に数え、更新します(MQ22-201)が、ストリームの関門は中継するストリームから個々の Object を切り出さないので、通過させます。OBJECTID_FILTER は、データグラムで転送する Object については制御します。SUBGROUP_FILTER と PRIORITY_FILTER はストリームを開くときにストリーム全体を制御し(`test_moqtrun_sub_rngf_gates_stream`)、TRACK_PROPERTY_FILTER は SUBSCRIBE_TRACKS に提示する Track を制御します(`test_moqtrun_misc_subtracks_track_prop_filter`)。fill fetch の範囲の絞り込みは MQ22-138 以降で扱っています。
- (SS5, SS5.1--5.2) 優先度: スケジューリングのアルゴリズムは WebTransport の送信のポンプで動きます(Subscriber、次に Publisher Priority、次に 1 つの購読の中での Group の順序と fill を先・ライブを後。MQ22-180)。残っているのは次の点です。すでにキューに入った一度きりのストリームは、REQUEST_UPDATE をまたいでもクラスを保ちます。データグラムはストリームのクラスを迂回します。FETCH 自身の SUBSCRIBER_PRIORITY は保持しません(128 として順位付けする)。購読をまたいで等しいクラスは、ポンプの各回をラウンドロビンで分け合います。制御ストリームとリクエストストリームの、Object に対する優先度(SS5.1.2)は、WebTransport 層のストリームの既定値に任せています。
- (SS7.3) 1 つの Track の複数のパブリッシャー: 複数のパブリッシャーが 1 つの名前空間を共有することはできます(MQ22-187)が、各 Track のパブリッシャーは依然として 1 つです。1 つの Track のパブリッシャーをまたいだ集約や重複の除去は実装していません。
- (SS9.20.5, SS9.20.6, SS9.20.16, SS9.20.19) FILL_TIMEOUT 自身の予算に従った動作(その存在だけが Timed-Out の印を制御する。MQ22-142 を参照)と EXPIRES: 登録表でデコードするだけで、ほかには使いません。NEW_GROUP_REQUEST は draft-18 と同じく上流へ中継します(MQ18-229。共有のコード)。(SS9.20.6) RENDEZVOUS_TIMEOUT は 12-1(ff1c0df)から動作に反映しています: パブリッシャーのいない Track への SUBSCRIBE は、パブリッシャーが現れるまで保留し、タイムアウト(上限 1.5 秒)になったら TIMEOUT で応答します。tests/app/moqtrun_rdv_test.c を参照。
- (SS9.1.3, SS9.1.4, SS8.9) MAX_AUTH_TOKEN_CACHE_SIZE と、Setup Option としての AUTHORIZATION TOKEN: 広告しません。ハブはトークンのキャッシュを持たないので、Alias に基づくトークンはセッションを閉じます(MQ22-183)。(MAX_FILTER_RANGES と MAX_REQUEST_UPDATES は広告します。MQ22-199。)
- (SS11.5) パディングのデータグラム: 送信しません。
- (SS10, SS10.1--10.x) Track/Object の Properties としての MOQT Properties(MAX_CACHE_DURATION、DEFAULT_PUBLISHER_GROUP_ORDER、DYNAMIC_GROUPS、Immutable Properties、Prior Group/Object ID Gap、番号が振り直された暫定のプロパティ: TIMESTAMP 0x10、VIDEO_FRAME_MARKING 0x09、AUDIO_CONFIG 0x0F、ENCRYPTED_LIST 0x0A、PADDING 0x32): Properties のワイヤー上の欄は汎用にデコードし、そのまま中継します。ハブは、DEFAULT_PUBLISHER_PRIORITY(Publisher Priority を省いたヘッダーのストリームの urgency)、SUBGROUP_DELIVERY_TIMEOUT、MAX_CACHE_DURATION を、Immutable Properties の中にあるものも含めて読み、範囲外の DEFAULT_PUBLISHER_GROUP_ORDER / DYNAMIC_GROUPS でセッションを閉じ、Mandatory Track Properties を拒否します(MQ22-222〜MQ22-224)。Group の順序と動的な Group のスケジューリングの意味論は適用しません。
- (SS15) セキュリティの考慮事項(購読の増幅、通信のセキュリティ、メディアのセキュリティ、リソースの枯渇、タイムアウト、リレーのセキュリティ、実装のフィンガープリンティング、mTLS/RFC 9525 の証明書検証の詳細、Reason Phrase / MOQT_IMPLEMENTATION のログの無害化)のうち、すでに扱った名前空間の認可の要件(MQ22-097a/MQ22-183)を超えるもの: 運用や配備の指針で、この台帳がテストするワイヤー上の振る舞いではありません。Object のエンドツーエンドの暗号化(Secure Objects / SFRAME)は外部の仕組みで、このリレーは実装も解釈もしません。
- (SS16) IANA の考慮事項: 登録表の管理で、実装の振る舞いではありません。
- 実際のリレーの振る舞いとしての REDIRECT(要求者を別の URI や宛先へ移すために送ること、上流からのものに反応すること): これは単一のハブで、リダイレクトの行き先や送り元になる上流のリレーや兄弟のインスタンスがありません。理由は上のセッションの移行の項目と同じです。draft-22 で変わった、名前空間や名前が空の Redirect の意味論(「元と同じ」ではなく文字どおりの宛先)と、緩められた Retry Interval 0 の文言もこれに含まれ、どちらもこのリレーは使いません。Redirect 構造のワイヤー形式は扱っています(MQ22-084〜MQ22-088)。
- バージョンごとの範囲(台帳 4-4): このハブは、セッションごとに draft-18、-19、-22 をネゴシエートします(`moqver.c`)。Range Filter、MAX_FILTER_RANGES、MAX_REQUEST_UPDATES は draft-19 以降にしかないので、draft-18 のセッションでは Range Filter のパラメーターをプロトコル違反として拒否し、2 つの Setup Option はピアが無視します。draft-19 と draft-22 のセッションでは上に書いたとおりに振る舞います(MQ22-199〜MQ22-201)。SUBSCRIBE_TRACKS は、draft-19 と draft-22 のセッションではすべての Subscription のパラメーターを受け入れますが、draft-18 のセッションでは AUTHORIZATION TOKEN と FORWARD だけです(`moqctl.c` の `MOQCTL_PARAM_RULES`)。それらのドラフト自身の一覧は [draft-18](draft-moq-transport-18.md) と [draft-19](draft-moq-transport.md) を参照してください。
- (SS9.2) クライアントが自身の GOAWAY で長さ 0 の New Session URI を使うこと: クライアントだけの規則です。0 でないものをサーバー側で拒否するのは MQ22-045 です。
- (SS7.1) 存在しないと記録済みの Object をキャッシュも転送もしないこと(SHOULD NOT): ハブは Group 単位のキャッシュの外に Object ごとの不在の記録を持ちません。実装していません。
- (SS7.5) 下流のフィルターを集約して上流へ伝えること(SHOULD): 上流の SUBSCRIBE はフィルターを運びません(MQ22-228)。実装していません。
- (SS9.9) ハブの上流の購読についての、購読者側の PUBLISH_DONE のタイマーと、遅れたストリームへの STOP_SENDING(SHOULD): 実装していません。
- リレーどうしの連携(draft-22 の §7 の「coordinated relay set」の概念): これは単一のハブで、リレーの連合ではありません。
- ホストの解決の詳細(DNS A/AAAA、SVCB/HTTPS RR、既定のポート 443)と、クエリー部分を範囲から除く規則: 下の WebTransport/HTTP 層に完全に任せていて、MOQT 層の振る舞いではありません。
