[ドキュメント](../README.md) › [機能](README.md) › draft-ietf-moq-transport-23

# draft-ietf-moq-transport-23: Media over QUIC Transport

仕様の本文(`tasks/specs/draft-ietf-moq-transport-23.txt`。git には含まない)から抽出した、この SDK の MOQT サブセットについての要件台帳です。対象のサブセットは、[draft-22 の台帳](draft-moq-transport-22.md)と同じ単一の中央ハブリレーです。ピアが WebTransport のサブプロトコルか ALPN で `moqt-23` をネゴシエートすると、セッションは draft-23 で動きます。

draft-22 と変わらない要件は、draft-22 の台帳の文言とテストの参照を同じ番号で流用しています(ID の数字は draft-22 の台帳と同じで、MQ23-251 以降が draft-23 で加わった項目です)。draft-23 で変わった要件は、draft-23 の振る舞いに書き直し、draft-23 のセッションで確かめるテストを挙げています。各要件には、それを確かめるテストを付けています。チェックがなくテスト行もない項目は、未解決のギャップです。

ハブはすべてのセッション、Track、キャッシュを 1 つのプロセスのメモリに持ちます。`examples/moqt_chat` と同じように、単一プロセスで動かしてください(`--workers`、`--cores`、AF_XDP の振り分けは使わない)。

凡例:

- `[x]`: 挙げたテストで確認済み
- `[~]`: 間接的に確認(専用のテストはなく、evidence 行で確かめ方を説明)
- `[ ]`: まだどのテストでも確認していない

**カバレッジ: テスト済み 265/299、間接 34、未テスト 0。**


## SS8.1 可変長整数

- [x] MQ23-001 実装は、MOQT の可変長整数を、先頭バイトの上位から続く 1 のビットの数でエンコード長(1〜9 バイト)を決め、残りのビットと後続のバイトにネットワークバイトオーダーで値が入っているものとしてデコードしなければならない。
  - test: `tests/app/moqvi_test.c` — `test_moqvi_decode_official_examples`
  - test: `tests/app/moqvi_test.c` — `test_moqvi_decode_zero_all_lengths`
  - test: `tests/app/moqvi_test.c` — `test_moqvi_decode_nine_byte_padded`
- [x] MQ23-002 実装は、64 ビット符号なし整数のすべて(0〜2^64-1)を MOQT の可変長整数エンコーディングでエンコードしなければならない。
  - test: `tests/app/moqvi_test.c` — `test_moqvi_encode_official_examples`
  - test: `tests/app/moqvi_test.c` — `test_moqvi_encode_boundaries`
- [x] MQ23-003 実装は、可変長整数を、値を表せる最小のバイト数でエンコードしなければならない。
  - test: `tests/app/moqvi_test.c` — `test_moqvi_roundtrip`
  - test: `tests/app/moqvi_test.c` — `test_moqvi_encode_official_examples`
- [x] MQ23-004 可変長整数が必要最小より多いバイト数でエンコードされている場合、実装はそれでも正しい値にデコードしなければならない(最小でないエンコーディングも有効)。
  - test: `tests/app/moqvi_test.c` — `test_moqvi_decode_zero_all_lengths`
  - test: `tests/app/moqvi_test.c` — `test_moqvi_decode_nine_byte_padded`
- [x] MQ23-005 可変長整数のエンコード長が利用できるバイト数を超える場合、実装は入力の終わりを越えて読まず、デコードをデータ不足として報告しなければならない。
  - test: `tests/app/moqvi_test.c` — `test_moqvi_decode_truncated`
- [x] MQ23-006 実装は、可変長整数を自身のエンコード長を越えてバイトを消費せずにデコードし、入力の後続のバイトに手を付けずに残さなければならない。
  - test: `tests/app/moqvi_test.c` — `test_moqvi_decode_ignores_trailing`
- [x] MQ23-007 出力先のバッファーが値のエンコード長を収めるには小さすぎる場合、実装はバッファーの終わりを越えて書かず、エンコードを失敗させなければならない。
  - test: `tests/app/moqvi_test.c` — `test_moqvi_put_too_small`

## SS8.2 Location 構造

- [x] MQ23-008 実装は、Location を連続する 2 つの可変長整数(Group, Object)としてエンコード・デコードしなければならない。
  - test: `tests/app/moqctl_test.c` —
    `test_moqctl_location_roundtrip_and_order`
- [x] MQ23-009 実装は、2 つの Location A と B を、A.Group < B.Group であるか、A.Group == B.Group かつ A.Object < B.Object であるときに限り A < B となるように比較しなければならない。
  - test: `tests/app/moqctl_test.c` —
    `test_moqctl_location_roundtrip_and_order`

## SS8.3 Key-Value-Pair 構造

- [x] MQ23-010 実装は、Key-Value-Pair の Type を、直前までの累積 Type に Delta Type を足した値(最初のペアでは 0 に足す)としてデコードしなければならない。
  - test: `tests/app/moqkvp_test.c` — `test_moqkvp_take_even_num`
  - test: `tests/app/moqkvp_test.c` — `test_moqkvp_take_delta_accumulates`
- [x] MQ23-011 Key-Value-Pair の累積 Type が 2^64-1 を超える場合、実装は DELTA_ENCODING_OVERFLOW (0x400) でセッションを閉じなければならない。
  - test: `tests/app/moqkvp_test.c` — `test_moqkvp_take_type_overflow`
  - test: `tests/app/moqtrun_cc_test.c` — `test_moqtrun_cc`
  - note: `test_moqtrun_cc` は、Setup Option の Delta Type が 2^64-1 を越える SETUP で、draft-23 では DELTA_ENCODING_OVERFLOW、それより前のドラフトでは PROTOCOL_VIOLATION になることを確かめます。
- [x] MQ23-012 実装は、Type が奇数の Key-Value-Pair の Value を Length バイトとして、Type が偶数のペアの Value を 1 つの可変長整数としてデコードしなければならない。
  - test: `tests/app/moqkvp_test.c` — `test_moqkvp_take_even_num`
  - test: `tests/app/moqkvp_test.c` — `test_moqkvp_take_odd_raw`
- [x] MQ23-013 Key-Value-Pair の Length フィールドは 2^16-1 バイトを超えてはならない。それより大きい長さを受信した場合、実装は FIELD_LENGTH_EXCEEDED (0x401) でセッションを閉じなければならない。
  - test: `tests/app/moqkvp_test.c` — `test_moqkvp_take_len_65535_accepted`
  - test: `tests/app/moqkvp_test.c` — `test_moqkvp_take_len_65536_violation`
  - test: `tests/app/moqtrun_cc_test.c` — `test_moqtrun_cc`
  - vuln: V-0799
- [x] MQ23-014 Key-Value-Pair の Value が、実装の理解する Type で定められたシリアライズの形に合わない場合、実装は MALFORMED_KEY_VALUE (0x6) でセッションを閉じなければならない。
  - test: `tests/app/moqtrun_ssts_test.c` — `test_moqtrun_ssts_setup_malformed_closes`
  - test: `tests/app/moqctl_test.c` — `test_moqctl_params_auth_token_malformed_kvfmt`
  - test: `tests/app/moqctl_test.c` — `test_moqctl_setup_d23_max_ctl_size_malformed`
  - note: draft-23 はコードの名前を KEY_VALUE_FORMATTING_ERROR から MALFORMED_KEY_VALUE に変えました。値は同じ 0x6 です。デコードできない Token 構造は、draft-23 では MALFORMED_AUTH_TOKEN になります(MQ23-262)。
- [x] MQ23-015 実装は、Key-Value-Pair の Delta Type や Type が偶数の Value に最小のエンコード長を、デコードの条件として課してはならない(最小でないエンコーディングも有効)。
  - test: `tests/app/moqkvp_test.c` — `test_moqkvp_take_nonminimal_delta`
  - test: `tests/app/moqkvp_test.c` — `test_moqkvp_take_nonminimal_even_value`
- [x] MQ23-016 Key-Value-Pair が自身の既知のバイト境界の内側で途切れている場合、実装は入力を消費せずにデータ不足として報告し、閉じるかどうかの判断を呼び出し側に任せなければならない。
  - test: `tests/app/moqkvp_test.c` — `test_moqkvp_take_truncated_insufficient`
- [x] MQ23-017 実装は、Key-Value-Pair を呼び出し側が与えたバイト境界を越えて読まずにデコードし、Type の順序を保ったままラウンドトリップできる Key-Value-Pair のリストをエンコードしなければならない。
  - test: `tests/app/moqkvp_test.c` — `test_moqkvp_roundtrip`
- [~] MQ23-251 (SS8.4) 自身が解釈しない Property については、リレーは同じ型が複数あっても許し、そのまま転送しなければならない。
  - evidence: ハブは解釈しない Property をバイト列のまま中継し、型ごとの数を数えません(`test_moqtrun_object_relay_preserves_bytes`、`test_moqtrun_sub_include_properties_1_forwards`)。同じ未知の型を 2 つ含むものを中継する専用のテストはありません。
- [x] MQ23-252 (SS8.4, SS12.1) 自身が解釈する Property を、定義が許す数を超えて、または定義された範囲(Track か Object か)の外で受信した場合、実装はその Track を不正なものとして扱わなければならない。
  - test: `tests/app/moqtrun_tprops_test.c` — `test_moqtrun_tprops_once_in_scope`
  - test: `tests/app/moqtrun_tprops_test.c` — `test_moqtrun_tprops_upfetch_twice_d23`
  - gap: 上流の FETCH への REQUEST_OK の Track Properties には、まだこの検査を当てていません([#237](https://github.com/hakkadaikon/wired/issues/237))。

## SS8.4 Track と Object のプロパティ

- [x] MQ23-240 (SS8.4, SS7.8, SS10.7-10.9) リレーは、自身が解釈しない Track と Object の Properties を、変更・追加・削除・統合を一切せずにそのまま転送しなければならない。Immutable Properties と、Prior Group/Object ID Gap のプロパティも含む。
  - test: `tests/app/moqtrun_sub_test.c` —
    `test_moqtrun_sub_include_properties_1_forwards`
  - test: `tests/app/moqtrun_upfetch_test.c` —
    `test_moqtrun_upfetch_reencode`
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_object_relay_preserves_bytes`
  - note: 1 つ目のテストは、パブリッシャーの Track Properties を SUBSCRIBE_OK へバイト単位でそのまま中継します。2 つ目のテストは、再エンコードしても Object の Properties が保たれることを確かめます。キャッシュがそれを保存していることは、キャッシュから応答する FETCH の経路(MQ23-214)を通じてしか示していません。

## SS8.5 Reason Phrase 構造

- [x] MQ23-018 実装は、Reason Phrase を、可変長整数の Length と、それに続く Length バイトの UTF-8 としてデコードしなければならない。
  - test: `tests/app/moqctl_test.c` — `test_moqctl_reason_boundary`
  - vuln: V-0800
- [~] MQ23-019 Reason Phrase の Length が 1024 バイトを超える場合、実装は FIELD_LENGTH_EXCEEDED (0x401) でセッションを閉じなければならない。
  - evidence: コーデックは長さの超過を FIELD_LENGTH_EXCEEDED の分類で返します(`test_moqctl_reason_boundary`)。その分類から draft-23 のコードへの変換は `test_moqtrun_cc` がほかの長さの超過で確かめています。Reason Phrase を運ぶメッセージそのもので閉じるところは確かめていません。

## SS8.7 Track Namespace 構造

- [x] MQ23-020 実装は、Track Namespace を、可変長整数のフィールド数と、それに続くその数の長さ付き Track Namespace Field としてデコードしなければならない。
  - test: `tests/app/moqctl_test.c` — `test_moqctl_ftn_decode_basic`
- [x] MQ23-021 Track Namespace Field の Length が 0 の場合、実装は INVALID_TRACK_NAMESPACE (0x302) でセッションを閉じなければならない。
  - test: `tests/app/moqctl_test.c` — `test_moqctl_ns_field_len_zero_rejected`
  - test: `tests/app/moqtrun_cc_test.c` — `test_moqtrun_cc`
- [x] MQ23-022 Track Namespace の Track Namespace Field が 32 個を超える場合、実装は INVALID_TRACK_NAMESPACE (0x302) でセッションを閉じなければならない。
  - test: `tests/app/moqctl_test.c` — `test_moqctl_ns_fields_32_accept_33_reject`
  - test: `tests/app/moqtrun_cc_test.c` — `test_moqtrun_cc`
- [~] MQ23-023 Track Namespace または Full Track Name が 4096 バイトを超える場合、実装は FIELD_LENGTH_EXCEEDED (0x401) でセッションを閉じなければならない。
  - evidence: コーデックは超過を FIELD_LENGTH_EXCEEDED の分類で返します(`test_moqctl_ftn_4096_accept_4097_reject`)。分類からコードへの変換は `test_moqtrun_cc` が確かめています。4097 バイトの名前を受けてセッションを閉じるところは確かめていません。
- [x] MQ23-024 実装は、Track Namespace Field と Track Name を、バイト列の完全一致で比較しなければならない。
  - test: `tests/app/moqctl_test.c` — `test_moqctl_ftn_eq_exact_bytes`
- [x] MQ23-253 (SS2.4.1) Track Name は 1 バイト以上でなければならない。SUBSCRIBE、PUBLISH、FETCH、TRACK_STATUS で長さ 0 の Track Name を受信した場合、実装は PROTOCOL_VIOLATION でセッションを閉じなければならない。
  - test: `tests/app/moqtrun_cc_test.c` — `test_moqtrun_cc`
  - note: 名前空間を対象とするリクエストへの REDIRECT の Error Detail だけは、空の Track Name を運びます(MQ23-264)。draft-22 の `.session` と空の Track Name の組み合わせへの DOES_NOT_EXIST は、draft-23 では先にこの規則でセッションを閉じます。

## SS12.1 不正な Track

- [~] MQ23-025 購読者が Malformed Track を検出した場合、実装はそのパブリッシャーからのその Track に対応する購読を取り消さなければならない。
  - evidence: デコード時の違反(未知の Object Status、累積 Object ID のオーバーフロー。MQ23-114/MQ23-130a を参照)に加えて、リレーは次を検出します。#4(その Group の最新の END_OF_GROUP Object より後の Object)、#5(END_OF_TRACK Object より後の Object)、#1(同じ Group と Subgroup ID の最新の Subgroup ヘッダーと Publisher Priority が異なる Subgroup ストリーム)、#7(キャッシュが Subgroup ストリームから得て保持している Object に対するデータグラム。Track は両方のモードを混ぜてよいので、同じ Object の場合だけを数える)。検出すると、すべての購読を PUBLISH_DONE MALFORMED_TRACK で終え、その Track の fetch ストリームを MALFORMED_TRACK でリセットし、パブリッシャーのリクエストを取り消し、きっかけになった Object はキャッシュしません。未対応のもの: 購読の経路での #6(ペイロードが異なる重複した Object。Object ごとにキャッシュを引く必要がある)と、#2/#3(FIN をまたぐ Subgroup の最終 Object)。
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

- [x] MQ23-028 リクエストが参照する Track Namespace の最初のフィールドが 1 つのピリオドである場合、実装はそれを DOES_NOT_EXIST で拒否しなければならない。
  - test: `tests/app/moqtrun_sub_test.c` — `test_moqtrun_reserved_ns_rejected`
  - test: `tests/app/moqtrun_ns_test.c` — `test_moqtrun_ns_reserved_rejected`
  - test: `tests/app/moqtrun_sub_test.c` — `test_moqtrun_other_dot_ns_served`
  - note: `moqtrun_ns_reserved`(台帳 10-1)は、最初のフィールドがちょうど `.` か `.session` である PUBLISH、SUBSCRIBE、PUBLISH_NAMESPACE、SUBSCRIBE_NAMESPACE を DOES_NOT_EXIST で拒否します。それ以外の `.` で始まるフィールドは、通常の名前空間と同じように扱います。この判定はバージョンに依存しません。

- [x] MQ23-221 (SS6.5) リクエストが名指す Track Namespace の最初のフィールドが `.session` である場合、ハブ(セッションレベルの Track を 1 つも定義しない)はそれを REQUEST_ERROR DOES_NOT_EXIST で拒否し、決してほかのセッションへ転送してはならない。
  - test: `tests/app/moqtrun_sub_test.c` — `test_moqtrun_reserved_ns_rejected`
  - test: `tests/app/moqtrun_ns_test.c` — `test_moqtrun_ns_reserved_rejected`

## SS3.1.3.1 未知の Track Alias

- [x] MQ23-226 (SS3.1.3.1) 実装は、接続のフロー制御のクレジットを、どのデータストリームよりも先に制御ストリームへ割り当てなければならない。
  - test: `tests/app/moqtrun_drain_test.c` — `test_moqtrun_prio_control_first`
    (ハブの制御ストリームは urgency 2 で、リクエストストリームの 3、Object ストリームの 4..7 より上)
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_wt_priority_conn_credit_to_urgent`(WT の送信パスは、接続の最後のクレジットをより緊急度の高いクラスに渡す)

## SS3.6 プレフィックスによる Track の購読

- [~] MQ23-225 (SS3.6, SS3.1) アプリケーションが名前空間の認可関数を設定している構成では、ハブはすべての SUBSCRIBE_TRACKS をそれに見せ、拒否されたら REQUEST_ERROR UNAUTHORIZED で応答しなければならない。これにより、ハブはそのコンテンツの認可を受けていない購読者へ PUBLISH を決して送らない。
  - evidence: SUBSCRIBE_TRACKS は、PUBLISH_NAMESPACE と SUBSCRIBE_NAMESPACE と同じ `moqtrun_disc_verdict` を通ります(`moqtrun_row.c`)。`test_moqtrun_ns_authorization` が確かめているのは、この 2 つの名前空間リクエストだけです。

## SS3.7 理解が必須の Track プロパティ

- [x] MQ23-222 (SS3.7) PUBLISH が Mandatory Track Property(型 0x4000-0x7FFF のうち grease の値 0x7f*N+0x9D を除くもの。このハブは一切理解しない)を含む場合、ハブは REQUEST_ERROR UNSUPPORTED_EXTENSION で応答し、その Track を転送してはならない。
  - test: `tests/app/moqtrun_sub_test.c` — `test_moqtrun_sub_publish_mandatory_refused`
  - test: `tests/app/moqtrun_tprops_test.c` — `test_moqtrun_tprops_grease`
- [x] MQ23-223 (SS3.7, SS9.4.2.2) 上流の SUBSCRIBE_OK が Mandatory Track Property を含む場合、ハブはその購読を取り消し、保留中の下流の SUBSCRIBE のそれぞれに REQUEST_ERROR UNSUPPORTED_EXTENSION で応答しなければならない。その REQUEST_ERROR には、理解しない Property ごとに UNSUPPORTED_PROPERTY の Error Detail を含めるべきである。
  - test: `tests/app/moqtrun_upsub_test.c` — `test_moqtrun_upsub_ok_mandatory_refused`
  - test: `tests/app/moqtrun_errdet_test.c` — `test_mted_upsub_ok_mandatory_d23`
- [x] MQ23-224 (SS3.7) Object が Mandatory Track Property を Object Property として含む場合、ハブはその Track を不正なもの(SS12.1)として扱わなければならない。
  - test: `tests/app/moqtrun_done_test.c` — `test_moqtrun_pubdone_malformed_mandatory_obj_prop`
  - test: `tests/app/moqtrun_upfetch_d23_test.c` — `test_moqtrun_upfetch_d23_obj_props`

## SS6.2 セッションの確立

- [x] MQ23-248 (SS6.2) サーバーは、`moqt-23` を(自身が話すそれ以前のドラフトとともに)WT-Available-Protocols と ALPN で提示し、ネゴシエートしたトークンが `moqt-23` のセッションを draft-23 の意味論で動かさなければならない。
  - test: `tests/app/moqver_test.c` — `test_moqver_find_each_token`
  - test: `tests/app/moqver_test.c` — `test_moqver_offer`
  - test: `tests/app/moqver_test.c` — `test_moqver_caps_d23`
  - test: `tests/app/moqtrun_raw_test.c` — `test_moqtrun_raw_ver_from_alpn`
- [~] MQ23-247 (SS6.2) サーバーは、MOQT を運ぶ接続で QUIC DATAGRAM 拡張をサポートし、ネゴシエートしなければならない。
  - evidence: `test_server_tp_datagram_frame_size`(`tests/tls/server_tp_test.c`)は、サーバーが max_datagram_frame_size を広告できることを示します。MOQT の運用でそれを有効にするのは設定の問題で、ここでは確かめていません(RFC 9221 の台帳を参照)。

## SS6.3 セッションの初期化

- [x] MQ23-029 サーバーは、単方向の制御ストリームを 1 本開き、最初のメッセージとして SETUP を送信しなければならない。
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_token_session_opens_uni_ctl`
  - test: `tests/app/moqtrun_test.c` — `test_moqtrun_client_uni_ctl_accepted`
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_refused_uni_ctl_open_retries`
  - note: WT のトークンが空のセッション(サブプロトコルを提示しないクライアント。たとえば WebTransport の `protocols` に対応していないブラウザー)は、以前のドラフトと同じ双方向の制御ストリーム 1 本を使い続けます(`test_moqtrun_empty_token_keeps_bidi_ctl`)。
- [x] MQ23-030 両方のエンドポイントが SETUP を送信し受信したら、セッションは Established にならなければならない。
  - test: `tests/app/moqtrun_test.c` — `test_moqtrun_client_uni_ctl_accepted`
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_token_requests_held_until_established`
- [x] MQ23-031 双方向のリクエストストリームは、First-type のメッセージ(TRACK_STATUS, SUBSCRIBE, PUBLISH, FETCH, PUBLISH_NAMESPACE, SUBSCRIBE_NAMESPACE, SUBSCRIBE_TRACKS)のいずれかで始まらなければならない。そうでない場合、実装は UNEXPECTED_MESSAGE (0x303) でセッションを閉じなければならない。
  - test: `tests/app/moqtrun_sub_test.c` — `test_moqtrun_req_bad_first_message_closes`
- [x] MQ23-032 Object を含む単方向ストリームや双方向のリクエストストリームが、両方の制御ストリームで SETUP が済む前に届く場合、ハブはそれをバッファーに入れ、SETUP が済んでから処理しなければならない。
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_token_requests_held_until_established`
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_token_object_stream_held_until_established`
- [x] MQ23-033 SETUP がまだ済んでおらず、リクエストストリームをバッファーに入れられない場合、ハブはそれをリセット(EXCESSIVE_LOAD)しなければならない。
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_token_unbufferable_request_reset`
- [~] MQ23-034 ピアは、自身の SETUP の後、ハブの SETUP を待たずにリクエストをパイプライン化してもよい。
  - evidence: ハブはセッションが開いたときに自身の SETUP を送信し、クライアントの SETUP が届くとすぐにそのクライアントのリクエストを処理します(`test_moqtrun_token_requests_held_until_established`)。パイプライン化そのものはセッションモデル(`test_moqsess_pipeline_before_peer_setup`)でしか固定しておらず、ハブはそのモデルを使っていません。
- [x] MQ23-035 セッションの存続中に制御ストリームがトランスポート層で閉じられた場合、実装は CLOSED_CONTROL_STREAM (0x306) でセッションを閉じなければならない。
  - test: `tests/app/moqtrun_test.c` — `test_moqtrun_ctl_fin_violates`
  - test: `tests/app/moqtrun_test.c` — `test_moqtrun_ctl_reset_violates`
- [x] MQ23-036 同じピアが 2 本目の制御ストリームを開いた場合、実装は UNEXPECTED_MESSAGE (0x303) でセッションを閉じなければならない(draft-23 の SS12.2 が名指さない箇所のコードの選択)。
  - test: `tests/app/moqtrun_test.c` — `test_moqtrun_second_ctl_stream_violates`
  - test: `tests/app/moqtrun_test.c` — `test_moqtrun_on_session_twice_is_idempotent`
- [x] MQ23-254 (SS9.1.8) 実装は、Setup Option MAX_CONTROL_MESSAGE_SIZE (0x09) を、ちょうど 1 つの vi64 を入れた奇数型の値としてデコードし、65535 未満の値、余るバイト、足りないバイトを MALFORMED_KEY_VALUE でセッションを閉じなければならない。ピアが送らなければ 65535 とする。
  - test: `tests/app/moqctl_test.c` — `test_moqctl_setup_d23_max_ctl_size_ok`
  - test: `tests/app/moqctl_test.c` — `test_moqctl_setup_d23_max_ctl_size_malformed`
  - test: `tests/app/moqtrun_test.c` — `test_moqtrun_setup_d23_max_ctl_size`
  - test: `tests/app/moqtrun_test.c` — `test_moqtrun_setup_d23_hub_omits_max_ctl_size`
  - note: ハブ自身の SETUP はこのオプションを送りません(上限は既定値の 65535)。実験的な SSTS_ALGORITHMS は、draft-23 では 0x09 から 0x3F01 に移しています(`test_moqctl_setup_d23_ssts_moved`)。
- [x] MQ23-255 (SS9) 実装は、ピアの MAX_CONTROL_MESSAGE_SIZE より長い Length の制御メッセージを送信してはならない。
  - test: `tests/app/moqtrun_test.c` — `test_moqtrun_envelope_length_spelling`
  - note: どのピアの上限も 65535 以上なので、ハブは本体が 65535 バイトを超えるメッセージを書きません。
- [~] MQ23-256 (SS9.1) 実装は、ピアの SETUP を受信する前に、拡張を提示するリクエスト(とそれに関わる Object)を送信するべきではない。
  - evidence: ハブが自分から始めるリクエスト(上流の SUBSCRIBE と FETCH、SUBSCRIBE_TRACKS への PUBLISH)は、SETUP を交わし終えたセッションにだけ送ります。専用のテストはありません。

## SS12.2/12.5 セッション終了とストリームリセットのエラーコード(使っている一部)

- [~] MQ23-037 実装は、セッション終了のエラーコード表のうち自身が使う項目を認識しなければならない。draft-23 で加わった INVALID_STREAM_HEADER (0x200)、MALFORMED_OBJECT (0x201)、INVALID_OBJECT_STATUS (0x202)、TRUNCATED_OBJECT (0x203)、MALFORMED_MESSAGE (0x300)、INVALID_FIELD (0x301)、INVALID_TRACK_NAMESPACE (0x302)、UNEXPECTED_MESSAGE (0x303)、ROLE_VIOLATION (0x304)、INVALID_PARAMETER (0x305)、CLOSED_CONTROL_STREAM (0x306)、DELTA_ENCODING_OVERFLOW (0x400)、FIELD_LENGTH_EXCEEDED (0x401) を含む。
  - test: `tests/app/moqtrun_cc_test.c` — `test_mtcc_cap_only_d23`
  - evidence: 原因ごとのコードは `moqtrun_ccode.c` の表で決め、`test_moqtrun_cc` が原因ごとの表でドラフトごとに確かめています。INVALID_FIELD を出す経路(draft-22 以降の FETCH が Joining の構造を持つとき)と CLOSED_CONTROL_STREAM(MQ23-035)は、その表の外で確かめています。表全体を列挙する専用のテストはありません。

## SS6.4.1 単方向ストリームの型

- [x] MQ23-038 実装は、単方向ストリームの先頭の可変長整数を、SETUP (0x2F00)、FETCH_HEADER (0x05)、SUBGROUP_HEADER (0b0XX1XXXX)、PADDING (0x132B3E28) のいずれかに分類しなければならない。
  - test: `tests/app/moqdata_test.c` — `test_moqdata_classify_golden`
- [x] MQ23-039 エンドポイントが未知の単方向ストリームの型を受信した場合、実装は INVALID_STREAM_HEADER (0x200) でセッションを閉じなければならない。
  - test: `tests/app/moqtrun_cc_test.c` — `test_moqtrun_cc`
  - test: `tests/app/moqtrun_sess_test.c` — `test_mtss_padding_stream_kept`
- [x] MQ23-040 実装は、単方向ストリームを、途切れた先頭の型フィールドを越えてバイトを消費せずに分類し、代わりに分類をデータ不足として報告しなければならない。
  - test: `tests/app/moqdata_test.c` — `test_moqdata_classify_truncated`

## SS6.6 終了

- [x] MQ23-041 サーバーは、WebTransport で運ぶ MOQT セッションを、CLOSE_WEBTRANSPORT_SESSION の仕組みで閉じなければならない。
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_ctl_unknown_type_closes_session`
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_ctl_pool_exhausted_closes`
  - test: `tests/app/moqtrun_sub_test.c` —
    `test_moqtrun_req_bad_first_message_closes`
  - evidence: ハブは、io テーブルの `close_session` 操作(本番では `wired_server_wt_close_session`)を通じて、ドラフトの終了コードで閉じます。WT_CLOSE_SESSION カプセルそのものは WebTransport の台帳で確かめています。

## SS6.6.1 セッションの移行 / SS9.2 GOAWAY(セッションのライフサイクル)

- [x] MQ23-042 GOAWAY を送信または受信したエンドポイントは、セッションを開いたまま、エンドポイントが終了しつつあることを示すエラーで新しいリクエストを拒否してもよい。
  - test: `tests/app/moqtrun_drain_test.c` —
    `test_moqtrun_goaway_late_rejected`
- [x] MQ23-043 制御ストリームで GOAWAY を受信したエンドポイントは、自分から新しいリクエストを始めてはならない。ただし、GOAWAY だけを理由にセッションを閉じることはしない。
  - test: `tests/app/moqtrun_upfetch_test.c` —
    `test_moqtrun_upfetch_upsub_skips_goaway`
- [x] MQ23-044 ピアが GOAWAY のタイムアウト内にセッションを閉じない場合、送信側は GOAWAY_TIMEOUT でセッションを閉じなければならない。
  - test: `tests/app/moqtrun_drain_test.c` —
    `test_moqtrun_goaway_timeout_flush_then_close`
- [x] MQ23-045 サーバーが New Session URI Length が 0 でない GOAWAY を受信した場合、実装は ROLE_VIOLATION (0x304) でセッションを閉じなければならない。
  - test: `tests/app/moqtrun_drain_test.c` — `test_moqtrun_peer_goaway_uri`
- [x] MQ23-046 制御ストリームで GOAWAY を 2 回以上受信した場合、実装は UNEXPECTED_MESSAGE (0x303) でセッションを閉じなければならない。
  - test: `tests/app/moqtrun_drain_test.c` — `test_moqtrun_peer_goaway_twice`
- [x] MQ23-047 リクエストの受信側が、そのリクエストのストリームで GOAWAY を受信した場合、実装は PROTOCOL_VIOLATION でセッションを閉じなければならない(リクエストストリームで GOAWAY を送ってよいのはリクエストの受信側だけである)。
  - test: `tests/app/moqtrun_sub_test.c` — `test_moqtrun_req_goaway_receiver`
  - test: `tests/app/moqtrun_sub_test.c` — `test_moqtrun_req_second_goaway_closes`
  - note: draft-22 までは、ハブはリクエストストリームの GOAWAY を受け入れて無視していました。draft-23 のセッションでは 1 回目で閉じます。

## SS7 リレー(SS7.x の転送の規律)

- [x] MQ23-048 リレーは、複数の Object を運ぶストリームで受信した Object を購読者へ転送するとき、その順序を入れ替えたり Object を落としたりしてはならない。
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_object_relay_to_subscriber`
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_object_relay_two_subscribers_two_objects`
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_relay_forwards_bytes_as_they_arrive`
- [x] MQ23-049 リレーは、Object を転送するとき、Object のヘッダーのフィールドやペイロードを変更してはならない。
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_object_relay_preserves_bytes`
- [x] MQ23-050 リレーは、下流の SUBSCRIBE への応答として SUBSCRIBE_OK を送信する前に、Established の上流の購読を持っていなければならない。
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_subscribe_matching_publish_replies_ok`
  - test: `tests/app/moqtrun_upsub_test.c` —
    `test_moqtrun_upsub_ok_after_upstream`
- [x] MQ23-051 どのパブリッシャーも PUBLISH していない Track への SUBSCRIBE をリレーが受信した場合、実装は、その Track の名前空間またはそのプレフィックスを PUBLISH_NAMESPACE した(購読者以外の)セッションへ、上流の SUBSCRIBE を送信しなければならない(SS7.6)。送信はその場で行うか、保留した SUBSCRIBE では PUBLISH_NAMESPACE が届いたときに行う。上流の購読が Established になったら SUBSCRIBE_OK を、上流がエラーを返したらそのコードで REQUEST_ERROR を応答する。そのようなパブリッシャーがいない(かつ RENDEZVOUS_TIMEOUT もない)場合は、REQUEST_ERROR DOES_NOT_EXIST を応答しなければならない。
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_subscribe_without_publish_replies_error`
  - test: `tests/app/moqtrun_upsub_test.c` —
    `test_moqtrun_upsub_ok_after_upstream`,
    `test_moqtrun_upsub_error_relayed`,
    `test_moqtrun_upsub_hold_then_announce`,
    `test_moqtrun_upsub_own_namespace`, `test_moqtrun_upsub_prefix`,
    `test_moqtrun_upsub_cross_draft`
  - test: `tests/app/moqtrun_errdet_test.c` — `test_mted_upsub_redirect_relayed`
  - note: 上流の SUBSCRIBE は Full Track Name ごとに 1 つで、最初に一致した告知元へ送ります。ただし `multi_publisher` が有効なら、一致するパブリッシャーのそれぞれ(後から告知したものも含む)へ 1 つずつ送ります(MQ23-229)。下流の誰も必要としなくなった上流の購読は取り消します(`test_moqtrun_upsub_last_cancel_cancels_upstream`)。上流がパブリッシャー側で終わったときは、下流の購読を終えずに、別の告知元を待ちます(MQ23-208〜MQ23-212)。
- [~] MQ23-052 複数の購読者が同じ Track を要求するとき、リレーはその Track についての認可済みの購読を集約し、上流からの 1 つの Object を一致する下流の購読者すべてへ転送してもよい。
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_chat_object_relays_to_all_three_subscribers`
  - test: `tests/app/moqtrun_upsub_test.c` —
    `test_moqtrun_upsub_two_share_one`
- [x] MQ23-208 ハブの上流の購読がパブリッシャー側で終わったとき(PUBLISH_DONE GOING_AWAY または INTERNAL_ERROR、ハブの SUBSCRIBE ストリームのリセット、パブリッシャーのセッションの切断。ハブ自身による切断(GOAWAY のドレインの期限切れ、プロトコル違反)も含む)、リレーは下流の各購読を、終わった時点から最大 `WIRED_MOQTRUN_RDV_MAX_MS` の間(延長はしない)保持し、その待機中にまだ試していない一致する告知元の 1 つへ SUBSCRIBE を送信しなければならない。待っている購読者自身のセッションは、その購読者については除外し、ほかにまだ試していない告知元が残っていないときに限ってほかの購読者のために問い合わせる(SS7.6, SS7.6.1)。その SUBSCRIBE が拒否されるかリセットされたら次へ進み、あるセッションがその Track を覆う新しい PUBLISH_NAMESPACE を送ると、そのセッションは再び候補になる。最初の SUBSCRIBE_OK で、待っているすべての購読を、すでに持っている Track Alias と状態(待機中に受けた REQUEST_UPDATE も含む)のまま付け直す。スイッチングセットのメンバーは付け直しのときにそのセットを離れるので、待機中にスイッチングセットを割り当てる REQUEST_UPDATE は拒否する(UNSUPPORTED_EXTENSION。その後、そのリクエストの唯一の PUBLISH_DONE は UPDATE_FAILED)。
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
  - note: `multi_publisher` が無効なら、上流は 1 つの Track につき一度に 1 つです(MQ23-229)。有効なら一致するパブリッシャーすべてを購読し、パブリッシャーが去った購読は、待たずに別のパブリッシャーの購読へまとめます。
- [x] MQ23-209 新しい経路を待っている購読には、2 回目の SUBSCRIBE_OK も REQUEST_ERROR も送ってはならない(SS3.1: 1 つのリクエストに応答は 1 つ)。一方、同じ Track への新しい SUBSCRIBE には、保留中の上流から引き続き応答しなければならない(購読者自身のセッションへの上流には決して乗せない。RENDEZVOUS_TIMEOUT があれば期限まで待ち続ける。ハブが閉じようとしているセッションへの上流や、そのセッション上の告知元も使わない)。待機中にすでに試した告知元しか残っていなければ、すぐに DOES_NOT_EXIST を応答する。
  - test: `tests/app/moqtrun_repath_test.c` —
    `test_moqtrun_repath_takeover`, `test_moqtrun_repath_refusal_hidden`,
    `test_moqtrun_repath_fresh_rides`, `test_moqtrun_repath_fresh_dne`,
    `test_moqtrun_repath_fresh_own_upstream`,
    `test_moqtrun_repath_fresh_own_upstream_rt`,
    `test_moqtrun_repath_fresh_closing_upstream`
- [x] MQ23-210 期限までに新しい経路が Established にならない場合、リレーは待っている各購読に、元の終了のステータス(GOING_AWAY または INTERNAL_ERROR。リセットやセッションの切断では INTERNAL_ERROR)の PUBLISH_DONE をちょうど 1 回送信しなければならない。SUBSCRIBE がまだ保留中でも送信し、その SUBSCRIBE は取り消す。待機中、リクエストストリームにはほかに何も送らない。その Stream Count は、付け直しの前後を通じて、ハブがその購読のために開いたすべてのストリームを数える。待つ余地がなければ PUBLISH_DONE はすぐに送る。SWITCH_FROM の古い側、新しい経路の SUBSCRIBE_OK で付け直せない待機者(その SUBSCRIBE_OK の時点)でも同じで、購読者自身の GOAWAY のドレインが尽きたときは GOING_AWAY で送る。
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
- [x] MQ23-211 上流の PUBLISH_DONE がそれ以外のステータスの場合と、Malformed Track(SS12.1)の場合は、下流の購読をそのステータスですぐに終えなければならない。ほかの告知元には問い合わせない。
  - test: `tests/app/moqtrun_repath_test.c` —
    `test_moqtrun_repath_final_status`, `test_moqtrun_repath_malformed`
- [x] MQ23-212 待機中に去った購読は、決して付け直してはならず、PUBLISH_DONE も受け取らない。誰も待たなくなった上流の SUBSCRIBE は取り消し、取り消したものへの応答は無視し、Established になった新しい上流は、そのパブリッシャーが名前空間を取り下げても残す。
  - test: `tests/app/moqtrun_repath_test.c` —
    `test_moqtrun_repath_leave`, `test_moqtrun_repath_all_leave`,
    `test_moqtrun_repath_stale_ok`, `test_moqtrun_repath_one_upstream`,
    `test_moqtrun_repath_withdraw_keeps`

- [x] MQ23-228 (SS7.7, SS7.2, SS5.1.3, SS9.19.3, SS9.19.4) リレーの上流の SUBSCRIBE は、パラメーターを 1 つも持ってはならない。つまり一時停止させず(PAUSED の既定値は 0)、Subscriber Priority、Group Order、配送タイムアウトを下流の購読から写さない。
  - test: `tests/app/moqtrun_upsub_test.c` —
    `test_moqtrun_upsub_ok_after_upstream`
- [x] MQ23-229 (SS7.8) リレーは、Track に一致する各パブリッシャー(Established の上流の購読と、その Track を覆う PUBLISH_NAMESPACE を送ったセッション)へ少なくとも 1 つの SUBSCRIBE を送信しなければならない。そのパブリッシャーからその Track をすでに購読している(応答待ちを含む)ときは送らない。
  - test: `tests/app/moqtrun_nsx_test.c` — `test_moqtrun_nsx_subscribe_every_announcer`
  - test: `tests/app/moqtrun_nsx_test.c` — `test_moqtrun_nsx_dup_pubns_no_resubscribe`
  - test: `tests/app/moqtrun_nsx_test.c` — `test_moqtrun_nsx_overlap_pubns_one_subscribe`
  - test: `tests/app/moqtrun_nsx_test.c` — `test_moqtrun_nsx_reannounce_no_resubscribe`
  - test: `tests/app/moqtrun_nsx_test.c` — `test_moqtrun_nsx_second_dsub_no_resubscribe`
  - test: `tests/app/moqtrun_nsx_test.c` — `test_moqtrun_nsx_no_subscribe_uncovered`
  - test: `tests/app/moqtrun_mpub_test.c` — `test_moqtrun_mpub_subscribes_every_announcer`
- [x] MQ23-227 (SS7.2, SS7.7) パブリッシャーの PUBLISH が購読を一時停止させ(PAUSED 1)、下流の購読者が一時停止していない場合、リレーは REQUEST_UPDATE PAUSED 0 でそれを再開させなければならない。
  - test: `tests/app/moqtrun_upsub_test.c` — `test_moqtrun_upsub_publish_resumed_d23`
  - test: `tests/app/moqtrun_upsub_test.c` — `test_moqtrun_upsub_publish_resumed`
- [x] MQ23-230 (SS9.19.6, SS7.7) SUBSCRIBE が、パブリッシャーのいない Track に対して 0 でない RENDEZVOUS_TIMEOUT を持つ場合、ハブはそれを(最大 `WIRED_MOQTRUN_RDV_MAX_MS` の間)保留し、パブリッシャーが現れたら SUBSCRIBE_OK で応答し(その購読者の SUBSCRIBE_TRACKS が受け取るはずの PUBLISH は、あわせて送らない)、期限が来たら REQUEST_ERROR TIMEOUT で応答しなければならない。パラメーターがないか 0 なら、すぐに DOES_NOT_EXIST で応答し、続けて FIN を送る。
  - test: `tests/app/moqtrun_rdv_test.c` — `test_moqtrun_rdv_s2_timeout`
  - test: `tests/app/moqtrun_rdv_test.c` — `test_moqtrun_rdv_s3_zero_is_dne`
  - test: `tests/app/moqtrun_rdv_test.c` — `test_moqtrun_rdv_s4_resolve`
  - test: `tests/app/moqtrun_rdv_test.c` — `test_moqtrun_rdv_s6_clamp`
  - test: `tests/app/moqtrun_rdv_test.c` —
    `test_moqtrun_rdv_s12_subtracks_skips_held`

## SS9 制御メッセージ: 共通の外枠

- [x] MQ23-053 実装は、すべての制御メッセージを Message Type(vi64)+ Message Length(vi64)+ Message Body としてエンコード・デコードしなければならない。Length は最小のバイト数で書き、最小でないエンコーディングも受け入れる。
  - test: `tests/app/moqtrun_test.c` — `test_moqtrun_envelope_length_spelling`
  - test: `tests/app/moqtrun_test.c` — `test_moqtrun_ctl_d23_nonminimal_length`
  - test: `tests/app/moqctl_test.c` — `test_moqctl_setup_roundtrip`
  - note: draft-22 までの Message Length は 16 ビットのビッグエンディアンでした。draft-23 では制御メッセージのヘッダーが最大 18 バイトになります。
- [x] MQ23-054 実装は、Message Type の表のうち自身が実装する項目を認識しなければならない: SETUP (0x2F00)、GOAWAY (0x10)、SUBSCRIBE (0x3)、SUBSCRIBE_OK (0x4)、PUBLISH (0x1D)、PUBLISH_DONE (0xB)、REQUEST_OK (0x7)、REQUEST_ERROR (0x5)、PUBLISH_STATE_NOTIFY (0x22)。0x18(draft-22 までの FETCH_OK)は予約済みで、未知の型として扱う。
  - test: `tests/app/moqctl_test.c` — `test_moqctl_peek_type_setup`
  - test: `tests/app/moqctl_test.c` — `test_moqctl_subscribe_roundtrip`
  - test: `tests/app/moqctl_test.c` — `test_moqctl_subscribe_ok_roundtrip`
  - test: `tests/app/moqctl_test.c` — `test_moqctl_publish_roundtrip`
  - test: `tests/app/moqctl_test.c` — `test_moqctl_publish_done_roundtrip`
  - test: `tests/app/moqctl_test.c` — `test_moqctl_request_ok_roundtrip`
  - test: `tests/app/moqctl_test.c` — `test_moqctl_request_error_roundtrip`
  - test: `tests/app/moqctl_test.c` — `test_moqctl_goaway_roundtrip`
  - test: `tests/app/moqfetch_d23_test.c` — `test_moqfetch23_type_retired`
- [x] MQ23-055 エンドポイントが未知の Message Type を受信した場合、実装は UNEXPECTED_MESSAGE (0x303) でセッションを閉じなければならない。
  - test: `tests/app/moqctl_test.c` — `test_moqctl_peek_type_unknown`
  - test: `tests/app/moqtrun_test.c` — `test_moqtrun_ctl_unknown_type_closes_session`
  - test: `tests/app/moqfetch_d23_test.c` — `test_moqfetch23_type_retired`
- [x] MQ23-056 実装は、外枠の先読みでは本体をデコードしない既知の Message Type(REQUEST_UPDATE、FETCH、TRACK_STATUS、PUBLISH_NAMESPACE、SUBSCRIBE_NAMESPACE、SUBSCRIBE_TRACKS など)を、まったく未知の型と区別しなければならない。これにより、呼び出し側はセッションを閉じる代わりに、それを振り分けるか NOT_SUPPORTED で応答できる。現在のハブは、SUBSCRIBE_TRACKS(MQ23-193)を含めてこれらすべてに応答する。
  - test: `tests/app/moqctl_test.c` —
    `test_moqctl_peek_type_known_unimplemented`
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_unknown_first_type_gets_not_supported`
- [x] MQ23-057 制御メッセージの宣言された Length が Message Body と一致しない場合、実装は MALFORMED_MESSAGE (0x300) でセッションを閉じなければならない。
  - test: `tests/app/moqctl_test.c` — `test_moqctl_peek_type_length_mismatch`
  - test: `tests/app/moqctl_test.c` — `test_moqctl_peek_type_truncated`
  - test: `tests/app/moqtrun_test.c` — `test_moqtrun_setup_malformed_closes`
  - test: `tests/app/moqtrun_cc_test.c` — `test_moqtrun_cc`
- [x] MQ23-058 実装は、自身の MAX_CONTROL_MESSAGE_SIZE(ハブは既定値の 65535 のまま広げない)までの制御メッセージを受け入れ、それより長い Length を受信した場合は FIELD_LENGTH_EXCEEDED (0x401) でセッションを閉じなければならない。
  - test: `tests/app/moqtrun_test.c` — `test_moqtrun_ctl_large_message_reassembled`
  - test: `tests/app/moqtrun_test.c` — `test_moqtrun_ctl_d23_over_limit_closes`
  - test: `tests/app/moqtrun_test.c` — `test_moqtrun_ctl_d23_over_limit_skipped_without_close`
  - test: `tests/app/moqctl_test.c` — `test_moqctl_peek_type_max_len_field`
- [x] MQ23-231 (SS9) 制御メッセージの本体を型に従って解析したとき、宣言された Message Length でちょうど終わらない(フィールドが途中で切れている、またはバイトが余る)場合、実装は MALFORMED_MESSAGE (0x300) でセッションを閉じなければならない。
  - test: `tests/app/moqtrun_cc_test.c` — `test_moqtrun_cc`
  - test: `tests/app/moqfetch_test.c` — `test_moqfetch_length_mismatch`
  - test: `tests/app/moqns_test.c` — `test_moqns_length_mismatch`

## SS6.4.2.1 Request ID

- [~] MQ23-059 サーバーは、1 から始めて、自身が始める新しいリクエストごとに 2 ずつ増やした奇数の Request ID を生成しなければならない。
  - test: `tests/app/moqtrun_upsub_test.c` —
    `test_moqtrun_upsub_ok_after_upstream`
  - evidence: テストは、上流の SUBSCRIBE の Request ID が奇数であることを確かめています。開始値 1 と +2 の刻み(`request_id_next`、moqtrun.h)は確かめていません。クライアントの偶数 ID の規則はクライアントだけのものです。
- [x] MQ23-060 エンドポイントが受信した Request ID の最下位ビットが送信者にとって正しくない場合、実装は INVALID_REQUEST_ID でセッションを閉じなければならない。
  - test: `tests/app/moqtrun_sess_test.c` — `test_mtss_rid_parity_closes`
- [x] MQ23-061 エンドポイントが重複した Request ID を検出した場合、実装は INVALID_REQUEST_ID でセッションを閉じなければならない(すべての重複を検出することは求められない)。
  - test: `tests/app/moqtrun_sess_test.c` — `test_mtss_rid_duplicate_closes`
  - test: `tests/app/moqtrun_sess_test.c` — `test_mtss_rid_out_of_order_ok`
  - test: `tests/app/moqtrun_sess_test.c` — `test_mtss_rid_window_slides`
  - note: draft-22 は重複の検出そのものを求めていました。ハブの範囲を限った窓による検出は、draft-23 でもそのまま適合します。

## SS9.19 メッセージのパラメーター

- [x] MQ23-062 実装は、Message Parameters を、Type Delta(varint。直前の Parameter Type からの累積)と、それに続く Value としてデコードしなければならない。Value のエンコーディング(uint8、varint、Location、長さ付きのバイト列、Track Namespace)は Type ごとに決まっている。
  - test: `tests/app/moqctl_test.c` — `test_moqctl_params_forward_roundtrip`
  - test: `tests/app/moqctl_test.c` —
    `test_moqctl_params_delivery_timeout_decode`
- [~] MQ23-063 パラメーターは Type の昇順にシリアライズしなければならない。累積の Parameter Type が 2^64-1 を超える場合、実装は DELTA_ENCODING_OVERFLOW (0x400) でセッションを閉じなければならない。
  - evidence: コーデックはオーバーフローを DELTA_ENCODING_OVERFLOW の分類で返します(`test_moqctl_params_type_overflow_violation`)。分類からコードへの変換は `test_moqtrun_cc`(Setup Option の Delta Type)が確かめています。Message Parameter そのもので閉じるところは確かめていません。
- [x] MQ23-064 エンドポイントが未知の Message Parameter の Type を受信した場合、実装は INVALID_PARAMETER (0x305) でセッションを閉じなければならない。
  - test: `tests/app/moqctl_test.c` — `test_moqctl_params_unknown_type_violation`
  - test: `tests/app/moqctl_d23_test.c` — `test_moqctl_d23_paused_take`
  - test: `tests/app/moqtrun_cc_test.c` — `test_moqtrun_cc`
  - note: draft-23 のセッションでは FORWARD (0x10) が未登録になり、未知のパラメーターとして扱います(`test_moqctl_d23_paused_take`)。
- [~] MQ23-065 送信者が 1 つのメッセージで同じ Parameter Type を繰り返した場合、実装は INVALID_PARAMETER (0x305) でセッションを閉じなければならない。
  - evidence: コーデックは INVALID_PARAMETER の分類で返します(`test_moqctl_params_duplicate_type_violation`)。分類からコードへの変換は `test_moqtrun_cc`(GROUP_ORDER の範囲外)が確かめています。重複そのもので閉じるところは確かめていません。
- [x] MQ23-066 Message Parameter が、それが現れてよいメッセージ以外に現れた場合、実装は INVALID_PARAMETER (0x305) でセッションを閉じなければならない。
  - test: `tests/app/moqtrun_upd_test.c` — `test_moqtrun_upd_bad_and_control`
  - test: `tests/app/moqctl_test.c` — `test_moqctl_params_scope_violation`
  - test: `tests/app/moqctl_d23_test.c` — `test_moqctl_d23_scope`
- [x] MQ23-067 SUBSCRIBE、PUBLISH_OK、FETCH の Message Parameters は、パブリッシャーが送信する Object のペイロードを変えさせてはならない。
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_object_relay_preserves_bytes`
  - evidence: moqtrun.c は、Object のペイロードを組み立てるときにパラメーターの値を一切参照しません。relay-preserves-bytes のテストはペイロードが端から端まで同一であることを示しますが、パラメーターを変えてこの保証だけを切り出してはいません。

## SS9.19.3/9.19.4 SUBGROUP_DELIVERY_TIMEOUT / OBJECT_DELIVERY_TIMEOUT

- [x] MQ23-068 実装は、Message Parameter の SUBGROUP_DELIVERY_TIMEOUT (0x06) と OBJECT_DELIVERY_TIMEOUT (0x02) を varint としてデコードし、値 0 をタイムアウトなしとして扱わなければならない。どちらも SUBSCRIBE、PUBLISH、SUBSCRIBE_TRACKS、購読への REQUEST_UPDATE に現れてよい。
  - test: `tests/app/moqctl_test.c` — `test_moqctl_params_delivery_timeout_decode`
  - test: `tests/app/moqctl_d23_test.c` — `test_moqctl_d23_scope`
- [x] MQ23-069 ハブは、自身の SUBSCRIBE_OK / REQUEST_OK / PUBLISH_DONE の応答に配送タイムアウトのパラメーターを入れて送信してはならない(損失のない単一ハブのサブセットは配送タイムアウトを設定しない)。
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_subscribe_ok_carries_no_timeout_param`
- [x] MQ23-070 0 でない SUBGROUP_DELIVERY_TIMEOUT または OBJECT_DELIVERY_TIMEOUT パラメーターを持つ SUBSCRIBE は、受け入れて適用しなければならない。
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_subscribe_nonzero_timeout_accepted`
  - test: `tests/app/moqtrun_upd_test.c` — `test_moqtrun_timeout_accepted`
  - test: `tests/app/moqtrun_sub_test.c` —
    `test_moqtrun_sub_subgroup_timeout_min`
- [x] MQ23-070a OBJECT_DELIVERY_TIMEOUT の時計は、Object のヘッダーの最後のバイトを受信した(または渡された)時点から始めなければならない(draft-19 では最初のペイロードのバイトから始まる点が異なる)。
  - test: `tests/app/moqtrun_upd_test.c` — `test_moqtrun_timeout_torn_header`
  - note: 保持している断片がヘッダーを丸ごと含むときはその断片の到着時刻、含まないときはヘッダーを完成させた配送の時刻から測ります。draft-22 も同じ規則です。draft-18/19 の「最初のペイロードのバイト」とは、配送の切れ目がちょうどヘッダーの終わりに来たときだけ異なります(この場合もヘッダーの完成時刻で測る)。

- [x] MQ23-245 (SS5.2) SUBGROUP_DELIVERY_TIMEOUT が 0 でない場合、ハブは上流の Subgroup ストリームが FIN したときにタイマーを始め、タイマーが切れた時点で下流のストリームが「all data committed」に達していなければ、そのストリームをリセットしなければならない。
  - test: `tests/app/moqtrun_sub_test.c` —
    `test_moqtrun_sub_subgroup_timeout_after_fin`
  - note: 中継したストリームの上流の FIN で起動します(最初の配送で丸ごと送った一度きりのストリームでは起動しない)。「committed」は、トランスポートのすべて確認応答済みの合図(`wired_moqt_io.stream_inflight`)です。

## SS9.19.18 PAUSED パラメーター

- [x] MQ23-071 実装は、PAUSED パラメーター(Type 0x11)を、値が 0(一時停止していない)または 1(一時停止)の uint8 としてエンコード・デコードし、省略時は 0 としなければならない。1 を超える値は INVALID_PARAMETER でセッションを閉じる。
  - test: `tests/app/moqctl_d23_test.c` — `test_moqctl_d23_paused_take`
  - test: `tests/app/moqctl_d23_test.c` — `test_moqctl_d23_paused_put`
  - note: draft-22 の FORWARD(0x10、1 が転送、既定値 1)を、ID を変えて意味を反転したものです。ハブは内部では 1 つの状態として持ち、ドラフトに合わせて書き分けます。
- [x] MQ23-072 PUBLISH で PAUSED=1 を送ったパブリッシャーは、購読者が REQUEST_UPDATE で一時停止を解くまで、Object を 1 つも送信してはならない。購読への Object の転送は、その一時停止の状態で制御する。
  - test: `tests/app/moqtrun_misc_test.c` — `test_moqtrun_misc_pub_forward0_then_update`
  - test: `tests/app/moqtrun_sub_test.c` — `test_moqtrun_sub_reattach_keeps_state`
  - test: `tests/app/moqtrun_upsub_test.c` — `test_moqtrun_upsub_publish_resumed_d23`

## SS9.19.12-9.19.17 Range Filter、FILL_PARAMETERS、LARGEST_OBJECT の規則

- [x] MQ23-241 (SS9.19.12) PRIORITY_FILTER をデコードした値が 255 を超える場合、ハブはそのリクエストを REQUEST_ERROR INVALID_FILTER で拒否しなければならない。
  - test: `tests/app/moqtrun_sub_test.c` — `test_moqtrun_sub_rngf_value_checks`
- [x] MQ23-242 (SS9.19.13, SS9.19.14) OBJECT_PROPERTY_FILTER または TRACK_PROPERTY_FILTER が奇数の Property Type を名指す場合、ハブはそのリクエストを REQUEST_ERROR INVALID_FILTER で拒否しなければならない。
  - test: `tests/app/moqtrun_sub_test.c` — `test_moqtrun_sub_rngf_value_checks`
- [x] MQ23-243 (SS9.19.15) FILL_PARAMETERS が自身の表にないパラメーターを含む場合、ハブは INVALID_PARAMETER (0x305) でセッションを閉じなければならない。
  - test: `tests/app/moqctl_d23_test.c` — `test_moqctl_d23_fill_count`
  - test: `tests/app/moqtrun_sess_test.c` — `test_mtss_fill_unlisted_param_closes`
- [x] MQ23-244 (SS9.19.17, SS7.5) リレーは、上流の SUBSCRIBE_OK、PUBLISH、REQUEST_UPDATE_OK、TRACK_STATUS_OK、PUBLISH_STATE_NOTIFY の LARGEST_OBJECT と、上流の購読で受信した最大の Location のうち最大のものを、LARGEST_OBJECT として報告しなければならない。
  - test: `tests/app/moqtrun_d23lg_test.c` — `test_moqtrun_d23lg_upstream_subok_value`
  - test: `tests/app/moqtrun_d23lg_test.c` — `test_moqtrun_d23lg_psn_raises_largest`
  - test: `tests/app/moqtrun_d23lg_test.c` — `test_moqtrun_d23lg_psn_value_in_answer`
  - test: `tests/app/moqtrun_d23lg_test.c` — `test_moqtrun_d23lg_ruok_largest_used`
  - test: `tests/app/moqtrun_d23lg_test.c` — `test_moqtrun_d23lg_answers_monotone`
  - test: `tests/app/moqtrun_d23lg_test.c` — `test_moqtrun_d23lg_late_object_keeps_largest`
  - test: `tests/app/moqtrun_sub_test.c` — `test_moqtrun_sub_ok_largest`
  - note: ハブは TRACK_STATUS を上流へ送らないので、TRACK_STATUS_OK からの値は入りません。

## SS9.1 SETUP

- [x] MQ23-073 実装は、SETUP の Setup Options を、メッセージのペイロード全体にわたる Key-Value-Pair のリストとしてエンコード・デコードしなければならない。
  - test: `tests/app/moqctl_test.c` — `test_moqctl_setup_roundtrip`
- [x] MQ23-074 エンドポイントは、認識できない Setup Option を、未知のものの重複も含めて無視しなければならない。
  - test: `tests/app/moqctl_test.c` —
    `test_moqctl_setup_unknown_option_ignored`
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_setup_unknown_options_ignored`
- [~] MQ23-075 送信者は、そのオプションが複数のインスタンスを明示的に許していない限り、1 つのメッセージで同じ Setup Option の Type を繰り返してはならない。
  - evidence: `moqctl_setup_encode` は、PATH/AUTHORITY/MOQT_IMPLEMENTATION をそれぞれ高々 1 回しか書かない作りになっています。エンコーダーに重複を入れて、デコード時に拒否されることを確かめるテストはありません(デコードは、繰り返された既知のオプションについて最後に見た値を保持するだけで、これは KVP 層自身の重複を許すモデルと一致する)。

## SS9.1.1/9.1.2 AUTHORITY / PATH / MOQT_IMPLEMENTATION

- [x] MQ23-076 実装は、Setup Option の PATH (0x01) と AUTHORITY (0x05) をバイト列の値としてデコードしなければならない。
  - test: `tests/app/moqctl_test.c` — `test_moqctl_setup_path_option_decode`
- [x] MQ23-077 WebTransport を使っている間に PATH または AUTHORITY オプションを受信した場合、実装はそれぞれ INVALID_PATH または INVALID_AUTHORITY でセッションを閉じなければならない。ネイティブ QUIC では、不正なものを MALFORMED_PATH または MALFORMED_AUTHORITY で閉じる。
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_setup_path_closes_invalid_path`
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_setup_authority_closes_invalid_authority`
  - test: `tests/app/moqtrun_raw_test.c` —
    `test_moqtrun_raw_same_setup_on_wt_closes`
  - test: `tests/app/moqtrun_raw_test.c` — `test_moqtrun_raw_malformed_closes`
- [x] MQ23-078 実装は、Setup Option の MOQT_IMPLEMENTATION (0x07) を UTF-8 のバイト列の値としてデコードしなければならない。
  - test: `tests/app/moqctl_test.c` — `test_moqctl_setup_roundtrip`

## SS9.1.4 AUTHORIZATION TOKEN Setup Option

- [x] MQ23-232 (SS9.1.4) クライアントの SETUP が、Alias Type が DELETE または USE_ALIAS の AUTHORIZATION TOKEN オプションを含む場合、サーバーは ROLE_VIOLATION (0x304) でセッションを閉じなければならない。
  - test: `tests/app/moqtrun_sess_test.c` — `test_mtss_setup_token_alias`
  - test: `tests/app/moqtrun_cc_test.c` — `test_moqtrun_cc`

## SS9.2 GOAWAY(ワイヤー形式)

- [x] MQ23-079 実装は、GOAWAY を Type (0x10) + Length + New Session URI Length + New Session URI + Timeout としてエンコード・デコードしなければならない(draft-19 から変更なし。draft-18 と違い、末尾の Request ID フィールドはない)。
  - test: `tests/app/moqctl_test.c` — `test_moqctl_goaway_roundtrip`
- [x] MQ23-080 New Session URI Length が 8192 バイトを超える場合、実装は FIELD_LENGTH_EXCEEDED (0x401) でセッションを閉じなければならない。
  - test: `tests/app/moqctl_test.c` — `test_moqctl_goaway_uri_boundary`
  - test: `tests/app/moqtrun_cc_test.c` — `test_moqtrun_cc`
- [x] MQ23-258 (SS9.2) ハブが送ったリクエストのストリームで GOAWAY を受信した場合、ハブはそのリクエストを新しいセッションまたは現在のセッションで送り直し、古いリクエストストリームを閉じるべきである。同じリクエストストリームでの 2 回目の GOAWAY は UNEXPECTED_MESSAGE でセッションを閉じる。
  - test: `tests/app/moqtrun_upsub_test.c` — `test_moqtrun_upsub_goaway`
  - test: `tests/app/moqtrun_subtracks_test.c` — `test_moqtrun_subtracks`
  - note: 制御ストリームで GOAWAY を送ったピアには送り直しません。ストリームを開けないときは、次の tick か次の配送で再試行します。SUBSCRIBE_TRACKS のために送った PUBLISH は、新しい Request ID で送り直し、古い購読を PUBLISH_DONE GOING_AWAY で終えます(応答前ならストリームをリセットします)。
  - gap: 上流の FETCH は送り直さず、その区間を終えます([#239](https://github.com/hakkadaikon/wired/issues/239))。

## SS9.3 REQUEST_OK

- [x] MQ23-082 実装は、REQUEST_OK を Type (0x7) + Length + Number of Parameters + Parameters + Track Properties(メッセージの残りのバイト)としてエンコード・デコードしなければならない。Track Properties を持つのは TRACK_STATUS_OK と FETCH への応答だけである。
  - test: `tests/app/moqctl_test.c` — `test_moqctl_request_ok_roundtrip`
  - test: `tests/app/moqfetch_d23_test.c` — `test_moqfetch23_ok_encode`
- [x] MQ23-083 Track Properties が空でなければならない REQUEST_OK の変種(PUBLISH_OK など)が、空でない Track Properties を含む場合、実装は INVALID_FIELD (0x301) でセッションを閉じなければならない。
  - test: `tests/app/moqtrun_sess_test.c` — `test_mtss_publish_ok_props_closes`
- [x] MQ23-083a OK が Track Properties を運ぶリクエストで INCLUDE_PROPERTIES=0 が送られる場合、実装は Track の実際のプロパティにかかわらず、空の Track Properties を末尾に出さなければならない。
  - test: `tests/app/moqtrun_sub_test.c` —
    `test_moqtrun_sub_include_properties_0_empty_tail`
  - test: `tests/app/moqctl_test.c` —
    `test_moqctl_params_include_properties_range`
  - evidence: INCLUDE_PROPERTIES=1(または省略。これが既定)のとき、SUBSCRIBE_OK はパブリッシャーの Track Properties(最大 `WIRED_MOQTRUN_TRACK_PROPS_MAX` バイト)を運びます。
  - test: `tests/app/moqtrun_sub_test.c` —
    `test_moqtrun_sub_include_properties_1_forwards`

## SS9.4 REQUEST_ERROR

- [x] MQ23-084 実装は、REQUEST_ERROR を Type (0x5) + Length + Error Code + Retry Interval + Error Reason + Error Details としてエンコード・デコードしなければならない。Error Details はメッセージの残りを占める Key-Value-Pair の並びである。
  - test: `tests/app/moqctl_errdet_test.c` — `test_mced_golden_take`
  - test: `tests/app/moqctl_errdet_test.c` — `test_mced_golden_put`
  - test: `tests/app/moqctl_errdet_test.c` — `test_mced_roundtrip_property`
  - test: `tests/app/moqctl_errdet_test.c` — `test_mced_d22_positional`
- [x] MQ23-085 Error Code が REDIRECT の REQUEST_ERROR は REDIRECT の Error Detail (0x01) を運ばなければならない。それがない REQUEST_ERROR REDIRECT を受信した場合、実装は MALFORMED_MESSAGE (0x300) でセッションを閉じなければならない。
  - test: `tests/app/moqtrun_errdet_test.c` — `test_mted_redirect_d23`
  - test: `tests/app/moqctl_errdet_test.c` — `test_mced_rejects`
- [x] MQ23-086 サーバーが Connect URI Length が 0 でない REDIRECT を受信した場合、実装は ROLE_VIOLATION (0x304) でセッションを閉じなければならない。
  - test: `tests/app/moqtrun_errdet_test.c` — `test_mted_redirect_d23`
- [x] MQ23-087 実装は、自身が使う REQUEST_ERROR のコードを認識しなければならない: INTERNAL_ERROR、NOT_SUPPORTED、GOING_AWAY、INVALID_FILTER、UNINTERESTED、DOES_NOT_EXIST、UNAUTHORIZED、REDIRECT、UNAVAILABLE (0xA)。PREFIX_OVERLAP (0x30) は draft-23 で削除された。
  - test: `tests/app/moqctl_test.c` — `test_moqctl_codes_d23`
  - test: `tests/app/moqctl_test.c` — `test_moqctl_unknown_error_normalizes_to_internal`
- [x] MQ23-088 エンドポイントが認識できない REQUEST_ERROR のコードを受信した場合、実装はセッションを閉じずに、それを INTERNAL_ERROR として扱わなければならない。
  - test: `tests/app/moqctl_test.c` —
    `test_moqctl_unknown_error_normalizes_to_internal`
- [x] MQ23-259 (SS9.4.2, SS13) 実装は、未知の Error Detail の型と、その Error Code のために定義されていない既知の型を無視しなければならない。未知の型の重複も許す。REDIRECT が 2 つあれば最初のものを使う。
  - test: `tests/app/moqctl_errdet_test.c` — `test_mced_ignored`
- [~] MQ23-260 (SS9.4.2) 送信者は、定義が許す場合を除き、同じ Error Detail の型を繰り返してはならない。
  - evidence: ハブが組み立てる Error Details は、UNSUPPORTED_PROPERTY(繰り返しが許される)と、上流から写した REDIRECT 1 つだけです(`test_mced_golden_put`、`test_mted_upsub_ok_mandatory_d23`)。繰り返しがないことを確かめる専用のテストはありません。
- [x] MQ23-261 (SS9.4.2.2) UNSUPPORTED_EXTENSION を下流へ伝えるリレーは、受信した UNSUPPORTED_PROPERTY の Error Details を含めるべきである。
  - test: `tests/app/moqtrun_errdet_test.c` — `test_mted_upsub_error_relays_details_d23`
- [x] MQ23-262 (SS8.9) AUTHORIZATION TOKEN の Token 構造をデコードできない場合(未知の Alias Type を含む)、実装は MALFORMED_AUTH_TOKEN (0x16) でセッションを閉じなければならない。
  - test: `tests/app/moqtrun_cc_test.c` — `test_moqtrun_cc`
- [x] MQ23-263 (SS7.4) 上流へリクエストを送るためのストリームの枠がないリレーは、そのリクエストをすぐに REQUEST_ERROR UNAVAILABLE (0xA) で失敗させるか、待って TIMEOUT で失敗させなければならない。ハブはすぐに UNAVAILABLE で失敗させる。
  - test: `tests/app/moqtrun_upsub_test.c` — `test_moqtrun_upsub_open_fails`
  - test: `tests/app/moqtrun_upfetch_test.c` — `test_moqtrun_upfetch_no_track_refusals`
- [x] MQ23-264 (SS9.4.2.1) 名前空間を対象とするリクエストへの REDIRECT の Error Detail は、空の Track Name を運ばなければならない。
  - test: `tests/app/moqctl_errdet_test.c` — `test_mced_redirect_empty_name`

## SS9.6 SUBSCRIBE / SS9.7 SUBSCRIBE_OK

- [x] MQ23-089 実装は、SUBSCRIBE を Type (0x3) + Length + Request ID + Track Namespace + Track Name + Number of Parameters + Parameters としてエンコード・デコードしなければならない。
  - test: `tests/app/moqctl_test.c` — `test_moqctl_subscribe_roundtrip`
- [x] MQ23-090 購読が成功したら、パブリッシャーは SUBSCRIBE_OK をちょうど 1 つ応答しなければならない。
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_subscribe_matching_publish_replies_ok`
  - test: `tests/app/moqtrun_sub_test.c` —
    `test_moqtrun_req_subscribe_answered_on_its_stream`
- [x] MQ23-091 実装は、SUBSCRIBE_OK を Type (0x4) + Length + Track Alias + Number of Parameters + Parameters + Track Properties としてエンコード・デコードしなければならない。許されるパラメーターは EXPIRES と LARGEST_OBJECT だけである(draft-19 より狭い)。
  - test: `tests/app/moqctl_test.c` — `test_moqctl_subscribe_ok_roundtrip`
- [x] MQ23-092 実装が同じ SUBSCRIBE または PUBLISH への 2 つ目の応答(SUBSCRIBE_OK、PUBLISH_OK、REQUEST_ERROR)を受信した場合、実装は UNEXPECTED_MESSAGE (0x303) でセッションを閉じるべきである。
  - test: `tests/app/moqtrun_misc_test.c` — `test_moqtrun_misc_pub_second_ok_closes`
  - test: `tests/app/moqtrun_misc_test.c` — `test_moqtrun_misc_pub_error_after_ok_closes`
- [~] MQ23-093 パブリッシャーが SUBSCRIBE を REQUEST_ERROR で拒否した場合、その購読には Object を 1 つも送信してはならない。
  - evidence: 拒否した SUBSCRIBE は購読を作らない(`test_moqtrun_subscribe_without_publish_replies_error`、`test_moqtrun_sub_ns_must_match`)ので、そこへ何も中継しようがありません。その後に Object を送るテストはありません。
- [x] MQ23-093a ピアは、同じ Track への同時の購読を、それぞれ固有の Request ID で複数持ってもよい(draft-18 とは異なる。`docs/features/draft-moq-transport-18.md` の MQ18-094a を参照)。
  - test: `tests/app/moqtrun_upd_test.c` —
    `test_moqtrun_sub_duplicate_reanswered_d19_d22`
  - note: `moqtrun_sub_held_reply` は `MOQVER_CAP_DUP_SUBSCRIPTION` で分岐し、このビットは d19/d22 にはありません。台帳 4-2 を参照。
- [x] MQ23-265 (SS9.19.17) Track の Object を公開または受信したことのある送信者は、SUBSCRIBE_OK、PUBLISH、REQUEST_UPDATE_OK、TRACK_STATUS_OK、PUBLISH_STATE_NOTIFY に LARGEST_OBJECT を含めなければならない(FETCH への応答を除く)。
  - test: `tests/app/moqtrun_d23lg_test.c` — `test_moqtrun_d23lg_include_iff_seen`
  - test: `tests/app/moqtrun_d23lg_test.c` — `test_moqtrun_d23lg_subtracks_publish_largest`
- [x] MQ23-266 (SS9.19.16) EXPIRES は、PUBLISH、SUBSCRIBE_OK、FETCH への応答、すべての REQUEST_OK(TRACK_STATUS_OK を含む)に現れてよい。
  - test: `tests/app/moqctl_d23_test.c` — `test_moqctl_d23_scope`

## SS9.8 PUBLISH

- [x] MQ23-094 実装は、PUBLISH を Type (0x1D) + Length + Request ID + Track Namespace + Track Name + Track Alias + Number of Parameters + Parameters + Track Properties としてエンコード・デコードしなければならない。
  - test: `tests/app/moqctl_test.c` — `test_moqctl_publish_roundtrip`
- [~] MQ23-094a PUBLISH は、パブリッシャーの初期の購読のパラメーター(OBJECT_DELIVERY_TIMEOUT、SUBGROUP_DELIVERY_TIMEOUT、EXPIRES、LARGEST_OBJECT、PAUSED、SUBSCRIBER_PRIORITY、LOCATION_FILTER、GROUP_ORDER)を運ばなければならない(draft-19 では、代わりに PUBLISH_OK が購読者のパラメーターを運ぶ点が異なる)。
  - evidence: `moqctl_publish` のワイヤーのデコーダーは、汎用の `params` フィールドをすでに運んでいます(19/22 でバイト単位で同一)。ギャップはハブの振る舞いだけにあります。`moqtrun_handle_publish` は受信した PUBLISH から LARGEST_OBJECT だけを読み、FORWARD/優先度/フィルター/タイムアウトは適用しません。これは draft-19 の台帳ですでに未解決の同じギャップと一致します(`draft-moq-transport.md` の「未実装」の節と、台帳 4-7 の裁定を参照。裁定は、このハブの常に転送し優先度を持たない振る舞いが、観測できる違反なしに draft-22 の MAY を満たすとしている)。
- [x] MQ23-095 PUBLISH から始まった購読が成功したら、購読者は PUBLISH_OK(EXPIRES だけを運ぶ REQUEST_OK)をちょうど 1 つ応答しなければならず、その後に REQUEST_UPDATE を続けて購読者が制御するパラメーターを設定してもよい(draft-19 では、それらのパラメーターが PUBLISH_OK そのものに載る点が異なる)。
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_publish_replies_request_ok`
  - test: `tests/app/moqtrun_misc_test.c` —
    `test_moqtrun_misc_pub_forward0_then_update`
  - test: `tests/app/moqtrun_vgate_test.c` — `test_moqtrun_vgate_update_kinds`
  - test: `tests/app/moqtrun_misc_test.c` — `test_moqtrun_misc_stray_update`
  - note: 送信者自身の PUBLISH ストリーム上の REQUEST_UPDATE は、どのドラフトでも受け入れます(18/19 の SS10.9 と 22 の SS9.5 は、どちらも PUBLISH を挙げている)。SS9.5 の 2 つの場合(制御ストリーム、TRACK_STATUS ストリーム)の外にあるものは、PROTOCOL_VIOLATION でセッションを閉じます(台帳 12-17、`MOQVER_CAP_UPDATE_STRAY_CLOSE`)。
- [~] MQ23-096 パブリッシャーは、PUBLISH から始まった購読で、PUBLISH_OK を受信する前に Object を送信し始めてもよい。
  - evidence: ハブは PUBLISH にすぐに応答し、その後に続く Object を中継します(`test_moqtrun_object_relay_to_subscriber`)。Object が REQUEST_OK より先に届く場合を固定するテストはありません。
- [~] MQ23-097 購読者が PUBLISH を REQUEST_ERROR UNINTERESTED で拒否した場合、購読は Object を 1 つも送信せずに終了しなければならない。
  - evidence: ハブが送った PUBLISH への REQUEST_ERROR はそのスロットを解放します(`test_subtracks_publish_error_frees_slot`)。その後に Object を送るテストはありません。
- [x] MQ23-097a 認可されていないピアが、配信を許されていない名前空間を PUBLISH しようとした場合、実装はそれを REQUEST_ERROR UNAUTHORIZED で拒否しなければならない。これは、リレーが購読する側だけでなく配信する側の名前空間も認可することを求める、draft-22 の SS15.3.3「Preventing Impersonation」の要件に対応する。
  - test: `tests/app/moqtrun_upd_test.c` —
    `test_moqtrun_publish_requires_authorization`
  - note: `moqtrun_publish_refused` は、`moqtrun_subscribe_refused` と対になるものです。`docs/security/vuln-ledger.md` に記した V-0839 のギャップを閉じます。台帳 4-14a と、コミット `041b9ef4` の一連のコミットを参照。
  - vuln: V-0793, V-0839

## SS9.9 PUBLISH_DONE

- [x] MQ23-098 実装は、PUBLISH_DONE を Type (0xB) + Length + Status Code + Stream Count + Error Reason としてエンコード・デコードしなければならない。Stream Count が「不明」であることを表す番兵の値は 2^64-1(9 バイトの varint)で、draft-19 の 2^62-1 とは異なる。
  - test: `tests/app/moqctl_test.c` — `test_moqctl_publish_done_roundtrip`
  - note: wired の PUBLISH_DONE の Stream Count は現在つねに正確な数です(台帳 3-9/10-3: `MOQTRUN_DONE_STREAMS_UNKNOWN` はコードベースから完全に削除した)。そのため、どちらのバージョンでもハブがこの番兵を出すことはありません。意味があるのはピアの PUBLISH_DONE をデコードするときだけで、このハブは今のところ、ログ出力以外には自身の fill や購読の管理にそれを使っていません。
- [x] MQ23-099 送信者は、その購読のために開いたすべてのデータストリーム(そのために開いた fill fetch ストリームも含む。draft-22 で新設。MQ23-186 を参照)を閉じるまで、PUBLISH_DONE を送信してはならない。
  - test: `tests/app/moqtrun_done_test.c` —
    `test_moqtrun_pubdone_waits_open_stream`
  - test: `tests/app/moqtrun_drain_test.c` —
    `test_moqtrun_done_resets_streams_first`
  - test: `tests/app/moqtrun_fill_test.c` — `test_moqtrun_fill_counts_in_done`
  - test: `tests/app/moqtrun_fill_test.c` —
    `test_moqtrun_fill_done_waits_for_held`
  - test: `tests/app/moqtrun_done_test.c` —
    `test_moqtrun_pubdone_count_after_supersede`
- [x] MQ23-100 購読は、PUBLISH_DONE を送り、購読の双方向ストリームを閉じることで終了しなければならない。その後、送信者は購読の状態を破棄してもよい。
  - test: `tests/app/moqtrun_done_test.c` — `test_moqtrun_pubdone_fin_after`
  - test: `tests/app/moqtrun_done_test.c` — `test_moqtrun_pubdone_one_sub`
- [~] MQ23-101 購読者が応答を送る前に PUBLISH_DONE が届いた場合、購読者は FIN を送る前に、後回しにした PUBLISH_OK をちょうど 1 つ送らなければならない。
  - evidence: ハブはすべての PUBLISH にすぐに応答するので、応答していない PUBLISH を抱えることはありません。この規則は購読のモデル(`test_moqsub_publish_done_before_response_defers_ok`)でしか固定していません。
- [x] MQ23-102 実装は、自身が使う PUBLISH_DONE のステータスコードを認識しなければならない: INTERNAL_ERROR、TRACK_ENDED、GOING_AWAY。Location Filter の終わりがもはや購読を終了させないので(MQ23-137a を参照)、draft-22 は SUBSCRIPTION_ENDED (0x3。未割り当て)を削除している。
  - test: `tests/app/moqctl_test.c` —
    `test_moqctl_unknown_error_normalizes_to_internal`
  - note: いずれにせよ未知の PUBLISH_DONE のコードは INTERNAL_ERROR に正規化するので、この削除はワイヤー上は安全です。
- [~] MQ23-103 パブリッシャーが購読のためにデータストリームを 1 本も開かなかった場合、PUBLISH_DONE の Stream Count を 0 にしなければならない。
  - test: `tests/app/moqtrun_test.c` — `test_moqtrun_relay_table_full_counts`
  - test: `tests/app/moqtrun_drain_test.c` — `test_moqtrun_done_track_ended`
  - evidence: ハブは `moqtrun_sub_done`/`moqtrun_done_emit` で正確な Stream Count を送ります(台帳 3-9/10-3)。データストリームを開かなかったときはそれが 0 になります。ストリーム 0 本のエンコーディングを、一般の正確な数の経路から切り出して確かめる draft-22 専用のテストはありません。
- [x] MQ23-267 (SS9.9, SS12.4) 実装は、PUBLISH_DONE のステータス EXPIRED_AUTH_TOKEN (0x7) を認識し、上流から受けたら下流へそのまま伝えなければならない。
  - test: `tests/app/moqtrun_done_test.c` — `test_moqtrun_pubdone_expired_auth_d23`
  - test: `tests/app/moqctl_test.c` — `test_moqctl_codes_d23`

## SS9 制御メッセージで共有する Reason Phrase / Location / Track Namespace の構造

- [x] MQ23-104 実装は、Message Parameters、Location、Reason Phrase を、それらを埋め込むすべての制御メッセージで一貫してエンコード・デコードしなければならない。
  - test: `tests/app/moqctl_test.c` — `test_moqctl_params_forward_roundtrip`
  - test: `tests/app/moqctl_test.c` —
    `test_moqctl_location_roundtrip_and_order`
  - test: `tests/app/moqctl_test.c` — `test_moqctl_reason_boundary`
  - vuln: V-0800

## SS9.19.9 LOCATION_FILTER(型付きで、長さの前置はない)

- [x] MQ23-105 実装は、LOCATION_FILTER の Location Filter Type を、None (0x00)、Relative Start (0x01)、Absolute Start (0x02)、Absolute Start/Group End (0x03)、Absolute Range (0x04)、Next Object (0x05) のいずれかとしてデコードしなければならない。フィールドの並び([StartGroup], [StartObject], [EndGroupDelta], [EndObject])は型によって決まり、外側の Length フィールドはない。draft-19 の、長さを前置した 4 種類のエンコーディングとは異なる。
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
- [~] MQ23-106 LOCATION_FILTER の StartGroup + EndGroupDelta が 2^64-1 を超える場合、実装は DELTA_ENCODING_OVERFLOW (0x400) でセッションを閉じなければならない。
  - evidence: コーデックはオーバーフローを DELTA_ENCODING_OVERFLOW の分類で返します(`test_moqctl_rangeloc22_egd_overflow_violation`)。分類からコードへの変換は `test_moqtrun_cc` が確かめています。
- [~] MQ23-107 エンドポイントが定義済みの 6 つの値以外の Location Filter Type を受信した場合、実装は INVALID_PARAMETER (0x305) でセッションを閉じなければならない。
  - evidence: コーデックは INVALID_PARAMETER の分類で返します(`test_moqctl_rangeloc22_unknown_type_violation`)。分類からコードへの変換は `test_moqtrun_cc` が確かめています。
- [x] MQ23-108 パブリッシャーは、一時停止の状態と Location Filter の組み合わせ(Pass = (NOT Paused) AND Location AND Range)を通過した Object だけを転送しなければならない。
  - test: `tests/app/moqtrun_sub_test.c` — `test_moqtrun_sub_reattach_keeps_state`
  - test: `tests/app/moqtrun_sub_test.c` — `test_moqtrun_sub_filter22_starts`
  - test: `tests/app/moqtrun_sub_test.c` — `test_moqtrun_sub_filter22_ends`
  - test: `tests/app/moqtrun_sub_test.c` — `test_moqtrun_sub_filter22_inverted`
  - test: `tests/app/moqtrun_sub_test.c` — `test_moqtrun_sub_filter22_end_gates`
- [~] MQ23-108a Location Filter の有効な範囲は、全体が Largest Object より前にあることによって無効になることはない(つねに有効)。draft-19 では、満たせないフィルターをパブリッシャーが拒否するべきである(SHOULD)点が異なる。
  - evidence: `moqctl_rangeloc22_take` には「すでに過去」を理由に拒否する経路がありません。`moqtrun_sub_filter22_*` のテストのフィルター評価は、現在の Largest Object 以降のフィルターの受け入れを動かしていて、作りからしてこの「つねに有効」の規則と一致します(構造上は有効だが古いフィルターに INVALID_RANGE を出すコードの経路はない)。
- [x] MQ23-108b Location Filter の終わりに達しても(Largest Object がフィルターの End を越えても)、購読を終了させてはならない。draft-19 の PUBLISH_DONE SUBSCRIPTION_ENDED(draft-22 で削除。MQ23-102 を参照)とは異なる。
  - test: `tests/app/moqtrun_drain_test.c` —
    `test_moqtrun_done_filter_end_keeps_sub`
- [~] MQ23-108c パブリッシャーは、SUBSCRIBE と REQUEST_UPDATE に加えて、PUBLISH(初期のフィルターを設定する)と PUBLISH_STATE_NOTIFY(現在有効なフィルターを報告する)でも LOCATION_FILTER を送信してもよい。draft-19 では、それを運べるのは SUBSCRIBE、PUBLISH_OK、REQUEST_UPDATE だけである点が異なる。
  - evidence: `test_moqtrun_upd_filter_d22` は、REQUEST_UPDATE の LOCATION_FILTER が購読のフィルターを置き換えることを確かめています。PUBLISH と PUBLISH_STATE_NOTIFY で LOCATION_FILTER を受け入れることはパラメーターの登録表の側(`test_moqctl_params_registry_scope`)で確かめていて、ハブのテストはありません。
  - note: MQ23-094a(PUBLISH の初期のパラメーター)と MQ23-182(PUBLISH_STATE_NOTIFY)を参照。

## SS13 Grease

- [x] MQ23-109 実装は、grease の値を予約している登録表(Setup Options、Properties、エラーコードやステータスコードの表)で、0 以上の整数 N に対する grease の値のパターン 0x7f*N + 0x9D を認識しなければならない。
  - test: `tests/app/moqctl_test.c` — `test_moqctl_grease_pattern`
- [x] MQ23-110 エンドポイントは、grease を入れた登録表(Setup Options、エラーコード)の未知の値を受信したというだけの理由で、セッションを閉じてはならない。
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_setup_unknown_options_ignored`
  - test: `tests/app/moqctl_test.c` —
    `test_moqctl_unknown_error_normalizes_to_internal`

## SS3.1.3 Track Alias

- [x] MQ23-111 パブリッシャーは、同じセッションで、同じ Track Alias を 2 つの異なる Track を指すために同時に使ってはならない。
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_chat_and_audio_get_different_aliases`
- [x] MQ23-112 購読者が、別の Established の購読にすでに結び付いた Track Alias を再利用する PUBLISH または SUBSCRIBE_OK を受信した場合、実装は DUPLICATE_TRACK_ALIAS でセッションを閉じなければならない。
  - test: `tests/app/moqtrun_sess_test.c` — `test_mtss_publish_dup_alias_closes`
  - test: `tests/app/moqtrun_upsub_test.c` — `test_moqtrun_upsub_dup_alias_closes`

## SS11.1.1 Object Status

- [x] MQ23-113 実装は、Object Status の値 0x0(Normal)、0x3(End of Group)、0x4(End of Track)を認識しなければならない。
  - test: `tests/app/moqdata_test.c` — `test_moqdata_obj_take_status_values`
- [x] MQ23-114 Object が登録されていない Status の値を持つ場合、実装は INVALID_OBJECT_STATUS (0x202) でセッションを閉じるべきである。
  - test: `tests/app/moqtrun_sess_test.c` — `test_mtss_subgroup_object_violations`
  - test: `tests/app/moqtrun_cc_test.c` — `test_moqtrun_cc`
- [x] MQ23-115 Object は、Object Status が Normal (0x0) でない限り、空のペイロードを持たなければならない。Object Status フィールドは、Payload Length が 0 のときにだけ存在しなければならない。
  - test: `tests/app/moqdata_test.c` — `test_moqdata_subhdr_take_status_eog`
  - test: `tests/app/moqdata_test.c` —
    `test_moqdata_obj_take_status_eog_stream`

## SS11.1.2 Object Properties

- [x] MQ23-116 エンドポイントが、Status が Normal でない Object で Object Properties を受信した場合、実装は INVALID_OBJECT_STATUS (0x202) でセッションを閉じなければならない。
  - test: `tests/app/moqtrun_cc_test.c` — `test_moqtrun_cc`
- [x] MQ23-117 Object Properties は、Properties Length(varint)と、それに続く Key-Value-Pair のリストとしてシリアライズしなければならない。
  - test: `tests/app/moqdata_test.c` — `test_moqdata_obj_take_properties`

## SS11.3.1 Subgroup ヘッダー

- [x] MQ23-118 SUBGROUP_HEADER で開いたストリーム上の Object はすべて、Delivery Mode = Subgroup(「Object Forwarding Preference」から名前が変わった)を持ち、ヘッダーが宣言する Track Alias、Group ID、Subgroup ID に属さなければならない。
  - test: `tests/app/moqdata_test.c` — `test_moqdata_subhdr_take_basic`
- [x] MQ23-119 SUBGROUP_HEADER の Type Flags フィールドは 0b0XX1XXXX の形(ビット 4 はつねに立つ)でなければならない。それ以外の形で受信した場合、実装は INVALID_STREAM_HEADER (0x200) でセッションを閉じなければならない。
  - test: `tests/app/moqtrun_cc_test.c` — `test_moqtrun_cc`
  - test: `tests/app/moqtrun_sess_test.c` — `test_mtss_unknown_uni_closes`
  - note: `test_moqtrun_cc` はビット 4 のない型 0x01 で確かめています。
- [x] MQ23-120 実装は、SUBGROUP_ID_MODE フィールド(ビット 1-2)を次のようにデコードしなければならない: 0b00 は Subgroup ID がなく 0、0b01 は Subgroup ID がなく最初の Object の Object ID と等しい、0b10 は Subgroup ID がヘッダーにある。
  - test: `tests/app/moqdata_test.c` — `test_moqdata_subhdr_take_mode2`
  - test: `tests/app/moqdata_test.c` — `test_moqdata_subhdr_take_mode1_resolve`
- [~] MQ23-121 SUBGROUP_ID_MODE が 0b11 の場合、実装は INVALID_STREAM_HEADER (0x200) でセッションを閉じなければならない。
  - evidence: `test_mtss_subgroup_mode3_closes` は既定のドラフトでセッションを閉じることを確かめます。ヘッダーの不正は MQ23-119 と同じ分類で INVALID_STREAM_HEADER に変換しますが、モード 0b11 を draft-23 のセッションで確かめるテストはありません。
- [x] MQ23-122 実装は、SUBGROUP_HEADER の Type Flags フィールドの PROPERTIES ビット (0x01)、END_OF_GROUP ビット (0x08)、DEFAULT_PRIORITY ビット (0x20)、FIRST_OBJECT ビット (0x40) をデコードしなければならない。
  - test: `tests/app/moqdata_test.c` — `test_moqdata_type_bits_golden`
- [x] MQ23-123 DEFAULT_PRIORITY が立っている場合、ヘッダーの Publisher Priority フィールドは省かなければならず、Subgroup は購読の制御メッセージから優先度を引き継がなければならない。
  - test: `tests/app/moqdata_test.c` — `test_moqdata_subhdr_take_basic`
- [~] MQ23-124 END_OF_GROUP ビットが立ち、ストリームが FIN で終わる場合、実装は同じ Group ID でより大きい Object ID を持つ Object は存在しないと推定しなければならない。
  - evidence: このビットはデコードしています(MQ23-122)が、「END_OF_GROUP で FIN したら、より大きい Object ID は存在しない」という推定そのものを確かめる専用のテストはありません。これは、リレーが Object を丸ごと転送するやり方に暗に含まれています。
- [x] MQ23-125 Original Publisher は、新しい Subgroup を開くとき、FIRST_OBJECT ビットを立てて、ストリームの最初の Object がその Subgroup でこれまでに配信された最初の Object であることを示さなければならない。
  - test: `tests/app/moqdata_test.c` — `test_moqdata_type_bits_golden`
- [x] MQ23-249 (SS2.2, SS11.3.1) リレーは、最初の Object から転送する Subgroup では FIRST_OBJECT ビットを保ち、Subgroup の途中から開くストリームではそれを落とさなければならない。
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_late_subscriber_gets_late_opened_stream`
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_object_relay_preserves_bytes`
- [x] MQ23-126 実装は、SUBGROUP_HEADER を、そのワイヤーのフィールド(Type Flags、Track Alias、Group ID、省略可能な Subgroup ID、省略可能な Publisher Priority)とバイト単位で一致するようにエンコード・デコードしなければならない。
  - test: `tests/app/moqdata_test.c` — `test_moqdata_subhdr_put_golden`
  - test: `tests/app/moqdata_test.c` — `test_moqdata_subhdr_put_errors`
- [x] MQ23-127 SUBGROUP_HEADER が、宣言されたフィールドがすべてそろう前に途切れている場合、実装はデコードをデータ不足として報告しなければならない。
  - test: `tests/app/moqdata_test.c` — `test_moqdata_subhdr_take_truncated`
- [x] MQ23-128 実装は、モード 0b01(後で決まる)の Subgroup ID を、最初の Object の Object ID をデコードしたらそこから決めなければならない。
  - test: `tests/app/moqdata_test.c` — `test_moqdata_subhdr_take_mode1_resolve`

## SS11.3.1 Subgroup の Object のフィールド

- [x] MQ23-129 実装は、Subgroup の Object を Object ID Delta + 省略可能な Properties + Object Payload Length + 省略可能な Object Status + 省略可能な Object Payload としてエンコード・デコードしなければならない。
  - test: `tests/app/moqdata_test.c` — `test_moqdata_obj_take_basic_stream`
  - test: `tests/app/moqdata_test.c` — `test_moqdata_obj_put`
- [x] MQ23-130 Object ID は、Subgroup の最初の Object では Object ID Delta そのもの、それ以降の各 Object では直前の Object ID + Delta + 1 でなければならない。結果が 2^64-1 を超える場合、実装は DELTA_ENCODING_OVERFLOW (0x400) でセッションを閉じなければならない。
  - test: `tests/app/moqdata_test.c` — `test_moqdata_obj_take_delta_chain`
  - test: `tests/app/moqtrun_cc_test.c` — `test_moqtrun_cc`
  - relay: ハブが Subgroup の途中から遅れて開くストリームでは、最初の Object の Delta を絶対的な Object ID に書き換え、モード 0b01 の Subgroup ID をヘッダーに明示します(モード 0b10)。
  - test: `tests/app/moqtrun_test.c` — `test_moqtrun_late_subscriber_gets_late_opened_stream`
  - test: `tests/app/moqtrun_test.c` — `test_moqtrun_late_open_sgid_mode1_explicit`
- [x] MQ23-130a 計算した累積の Object ID が 2^64-1 を超える場合、実装は DELTA_ENCODING_OVERFLOW (0x400) でセッションを閉じなければならない。
  - test: `tests/app/moqtrun_sess_test.c` — `test_mtss_subgroup_object_violations`
  - test: `tests/app/moqtrun_cc_test.c` — `test_moqtrun_cc`

- [x] MQ23-246 (SS11.3) Subgroup ストリームがシリアライズされた Object の途中で FIN により終わる場合、ハブは TRUNCATED_OBJECT (0x203) でセッションを閉じるべきである。
  - test: `tests/app/moqtrun_sess_test.c` — `test_mtss_subgroup_fin_mid_object`
  - test: `tests/app/moqtrun_cc_test.c` — `test_moqtrun_cc`

## SS9.11 FETCH(Track Namespace/Name + LOCATION_FILTER。Fetch Type はない)

- [x] MQ23-131 実装は、FETCH を Type (0x16) + Length + Request ID + Track Namespace + Track Name Length + Track Name + Number of Parameters + Parameters(要求する範囲は LOCATION_FILTER パラメーターで運ぶ。MQ23-105 を参照)としてエンコード・デコードしなければならない。draft-19 では、FETCH が明示的な Fetch Type フィールド(Standalone / Relative Joining / Absolute Joining)と、本体に直接置いた Start/End Location フィールドを運ぶ点が異なる。
  - test: `tests/app/moqfetch_test.c` —
    `test_moqfetch_req22_with_filter_roundtrip`
  - test: `tests/app/moqfetch_test.c` —
    `test_moqfetch_req22_no_filter_defaults`
  - test: `tests/app/moqfetch_test.c` —
    `test_moqfetch_req22_encode_with_larger_typed_param`
  - test: `tests/app/moqfetch_test.c` — `test_moqfetch_req22_bad_ns_rejects`
  - note: `moqfetch_req22_take/_encode` は、draft-19 のデコーダーと同じ、バージョンに依存しない内部モデル `moqfetch_req` へデコードします(台帳 3-7、コミット `53a66346`/`a8e0eef2`)。
- [x] MQ23-131a FETCH が LOCATION_FILTER を省いている場合、実装は draft-22 の「省略はフィルターなしを意味する」規則に従い、そのリクエストを Track 全体({0,0} から Largest Object まで)を対象とするものとして扱わなければならない。
  - test: `tests/app/moqfetch_test.c` —
    `test_moqfetch_req22_no_filter_defaults`
- [~] MQ23-132 draft-22 以降のセッションの FETCH のリクエストストリームが draft-19 の Joining の構造(Joining Request ID / Joining Start を伴う Fetch Type フィールド)を運ぶ場合、実装はセッションを閉じなければならない。draft-23 のコードは INVALID_FIELD (0x301) である。
  - evidence: `test_moqtrun_fetch_d22_joining_violation` は draft-22 のセッションで閉じることを確かめます。draft-23 では同じ経路(`moqtrun_live.c`)が INVALID_FIELD の分類で閉じますが、そのコードを確かめるテストはありません。
- [x] MQ23-133 FETCH にはキャッシュから応答しなければならない。その範囲は、LOCATION_FILTER パラメーターから、draft-19 の Standalone/Joining の形と共有する、バージョンに依存しない内部モデルへ正規化する。
  - test: `tests/app/moqtrun_fetch_test.c` — `test_moqtrun_fetch_d22_served`
- [x] MQ23-134 FETCH の LOCATION_FILTER の範囲が無効な場合(Start が Largest Object より後にある、MQ23-106/MQ23-107 の構造上の違反など)、実装はセッションを閉じずに、それを REQUEST_ERROR INVALID_RANGE で拒否しなければならない。
  - test: `tests/app/moqtrun_fetch_test.c` —
    `test_moqtrun_fetch_d22_invalid_range`

## SS9.3/11.4.2 FETCH への REQUEST_OK と End of Range の印

- [x] MQ23-135 FETCH には REQUEST_OK で応答しなければならない。Largest Object が要求した範囲の中にあれば、応答はそこで終わり、REQUEST_OK は LARGEST_OBJECT を含まなければならない。範囲の中になければ、応答は要求した End Location で終わる。
  - test: `tests/app/moqfetch_d23_test.c` — `test_moqfetch23_ok_encode`
  - test: `tests/app/moqfetch_d23_test.c` — `test_moqfetch23_ok_take`
  - test: `tests/app/moqtrun_fetch_d23_test.c` — `test_moqtrun_fetch_d23_ok`
  - note: draft-22 の FETCH_OK (0x18) が運んでいた End Of Track と End Location は、draft-23 ではなくなりました。End of Track はデータストリームの印 (0x81) で伝えます(MQ23-268)。
- [x] MQ23-136 実装は、FETCH のデータストリームで、End of Timed-Out Range の印 (0x20C) を受け入れなければならない。draft-19 では 0x20C は認識できない値で、プロトコル違反でセッションを閉じる点が異なる。
  - test: `tests/app/moqfetch_test.c` — `test_moqfetch_eor_timed_out`
  - test: `tests/app/moqtrun_fetch_test.c` — `test_moqtrun_fetch_d22_served`
  - note: `moqfetch_is_eor` / `MOQVER_CAP_EOR_TIMED_OUT`。台帳 3-10、コミット `32172307`。
- [x] MQ23-268 (SS3.2.2, SS11.4.2.2) 実装は、Serialization Flags の 0x80(End of Group)と 0x81(End of Track)を、ほかのフィールドを持たない印としてデコード・エンコードしなければならない。印の後の直前の Object ID は 2^64-1 になり、直前の Object がない印は MALFORMED_OBJECT で閉じる。
  - test: `tests/app/moqfetch_d23_test.c` — `test_moqfetch23_end_of_group`
- [x] MQ23-269 (SS3.2.2) パブリッシャーは、Track を終えると分かっている Object の後に End of Track を、応答の最後の Object がその Group を終えると分かっていれば End of Group を、続けなければならない。
  - test: `tests/app/moqtrun_fetch_d23_test.c` — `test_moqtrun_fetch_d23_end_marks`
  - test: `tests/app/moqtrun_upfetch_d23_test.c` — `test_moqtrun_upfetch_d23_markers`
  - test: `tests/app/moqtrun_upfetch_d23_test.c` — `test_moqtrun_upfetch_d23_eot`
- [x] MQ23-270 (SS3.2) LOCATION_FILTER が相対的なもの(Type 0x01)である FETCH は、REQUEST_ERROR INVALID_RANGE で拒否しなければならない。
  - test: `tests/app/moqtrun_fetch_d23_test.c` — `test_moqtrun_fetch_d23_relative`
- [x] MQ23-271 (SS3.2) FETCH への REQUEST_OK は、Largest Object が要求した範囲の中にあるかが分かるまで送ってはならない。
  - test: `tests/app/moqtrun_upfetch_d23_test.c` — `test_moqtrun_upfetch_d23_relay`
  - test: `tests/app/moqtrun_fetch_d23_test.c` — `test_moqtrun_fetch_d23_ok`

## SS11.4.1 Fetch ヘッダーと Fetch の Object のフィールド

- [x] MQ23-235 (SS11.4.1, SS11.4.1.1) 実装は、fetch ストリームを、FETCH_HEADER (0x05, Request ID) と、それに続く Object としてデコード・エンコードしなければならない。Group ID Delta がないとき、Object ID Delta があれば Object ID は直前 + Delta + 2、なければ直前 + 1 である。
  - test: `tests/app/moqfetch_d23_test.c` — `test_moqfetch23_object_delta`
  - test: `tests/app/moqfetch_d23_test.c` — `test_moqfetch23_put`
  - test: `tests/app/moqfetch_d23_test.c` — `test_moqfetch23_object_flag`
  - test: `tests/app/moqtrun_fetch_d23_test.c` — `test_moqtrun_fetch_d23_stream`
  - test: `tests/app/moqfetch_test.c` — `test_moqfetch_hdr`
  - test: `tests/app/moqfetch_test.c` — `test_moqfetch_obj_subgroup_modes`
  - test: `tests/app/moqfetch_test.c` — `test_moqfetch_obj_group_order`
- [x] MQ23-236 (SS11.4.1, SS11.4.1.1) 最初の Object が直前の Object のフィールドを参照する場合と、127 を超える Serialization Flags の値が定義済みの印 (0x8C、0x10C、0x20C、0x40C、0x80、0x81) でない場合、実装は MALFORMED_OBJECT (0x201) で、計算した Group ID が 0 未満か 2^64-1 超、または Object ID が 2^64-1 超の場合は DELTA_ENCODING_OVERFLOW (0x400) で、セッションを閉じなければならない。
  - test: `tests/app/moqfetch_test.c` — `test_moqfetch_obj_flags_reject`
  - test: `tests/app/moqfetch_test.c` — `test_moqfetch_obj_overflow`
  - test: `tests/app/moqfetch_d23_test.c` — `test_moqfetch23_object_overflow`
  - test: `tests/app/moqfetch_test.c` — `test_moqfetch_obj_more_rejects`
- [x] MQ23-237 (SS11.4.2) 実装は、End of Range の印 0x8C(存在しない)、0x10C(不明)、0x20C(タイムアウト)、0x40C(Gone)を、Group ID Delta と Object ID Delta を持つものとしてデコードしなければならない。最初の印は絶対値で、以降は直前の Object か印から差分で求める(Group の差分が 0 なら Object は直前 + 差分 + 1)。結果が 0 未満か 2^64-1 超なら DELTA_ENCODING_OVERFLOW で閉じる。
  - test: `tests/app/moqfetch_d23_test.c` — `test_moqfetch23_eor_delta`
  - test: `tests/app/moqfetch_d23_test.c` — `test_moqfetch23_eor_overflow`
  - test: `tests/app/moqfetch_d23_test.c` — `test_moqfetch23_gone`
  - test: `tests/app/moqfetch_test.c` — `test_moqfetch_eor_timed_out`
  - test: `tests/app/moqfetch_test.c` — `test_moqfetch_obj_after_eor_reject`

## SS11.5 パディング

- [x] MQ23-238 (SS11.5.1) 実装は、パディングのストリーム(型 0x132B3E28)のバイトを、中継も応答もせずにすべて捨てなければならない。
  - test: `tests/app/moqtrun_test.c` — `test_moqtrun_padding_stream_discarded`
  - test: `tests/app/moqdata_test.c` — `test_moqdata_classify_golden`
- [~] MQ23-239 (SS11.5.2) 実装は、パディングのデータグラム(型 0x132B3E29)を捨てなければならない。
  - evidence: ハブはこの型を認識しません。デコードできないものとして数え、不正なデータグラムと同じように落とします(`test_moqtrun_dg_malformed_counts_bad`)。結果として捨てています。

## SS7.7/11.4.2 リレーの FETCH の欠落の扱い

- [x] MQ23-137 Range Filter が FETCH や fill を絞る場合、応答の中の印のない欠落を、存在しないものではなく不明なものとして扱わなければならない。また、リレーは draft-19 のように確定するまで配送を止めるのではなく、一致する少なくとも 1 つのパブリッシャーへ上流の FETCH を出さなければならない。
  - test: `tests/app/moqtrun_upfetch_test.c` —
    `test_moqtrun_upfetch_range_filter`,
    `test_moqtrun_upfetch_range_filter_cached`
  - test: `tests/app/moqtrun_fill_test.c` —
    `test_moqtrun_fill_inherits_range_filter`
  - note: キャッシュは Object ID しか持たないので、Subgroup、優先度、Property を名指す集合はキャッシュ済みの Object を 1 つも通しません(印のない、つまり不明な欠落として残る)。Joining Fetch(draft-18/19)には何も適用しません。
- [x] MQ23-137a FETCH で Location Filter の終わりに達しても、SUBSCRIPTION_ENDED を出してはならない(MQ23-108b を参照。差分の目録では FETCH/リレーの節の規則でもあるので、重複した相互参照をここにも残している)。
  - test: `tests/app/moqtrun_drain_test.c` —
    `test_moqtrun_done_filter_end_keeps_sub`
- [x] MQ23-213 ハブが持つ Track の Standalone FETCH や fill が、キャッシュが保証できない Location から始まり、FILL_TIMEOUT が 0 でないとき、ハブは範囲の始まりからそのような最後の Location までの FETCH を 1 つ、同じ Group Order で、その Track のパブリッシャーへ、いなければそれを覆う名前空間を告知しているセッションへ送信しなければならない。ただし、ハブに GOAWAY を送ったセッションや WebTransport セッションのドレインを済ませたセッション、閉じようとしているセッション、新しい経路の待機ですでに試したセッション、要求者には決して送らない(SS3.2.3, SS7.6, SS9.2)。ハブ自身の Track は決して上流へ出さない。同じ GOAWAY の規則は上流の SUBSCRIBE にも当てはまる。ハブ自身の GOAWAY(ドレイン)ではそれを止めないので、ドレイン中のハブも購読を別の告知元へ移す。
  - test: `tests/app/moqtrun_upfetch_test.c` —
    `test_moqtrun_upfetch_gap_to_owner`, `test_moqtrun_upfetch_fill_gap`,
    `test_moqtrun_upfetch_middle_gap`,
    `test_moqtrun_upfetch_cached_no_upstream`,
    `test_moqtrun_upfetch_owner_excluded`,
    `test_moqtrun_upfetch_tried_announcer_skipped`,
    `test_moqtrun_upfetch_two_not_shared`,
    `test_moqtrun_upfetch_upstream_draft`,
    `test_moqtrun_upfetch_cache_only`, `test_moqtrun_upfetch_hub_owned`,
    `test_moqtrun_upfetch_upsub_skips_goaway`,
    `test_moqtrun_upfetch_drain_failover`
- [x] MQ23-214 ハブは、上流の各項目を届いた瞬間に、すべてのフィールドを保ったまま下流のストリームへ再エンコードして中継しなければならない。中継するのは、その項目が要求された範囲の内側にあり、配送順(Descending の FETCH では Group は降順、Object は昇順)で最後に中継した項目より後にあり、上流の End を越えていない場合に限る。それ以外の場合や、トランスポートが書き込みを拒んだ場合は、上流の FETCH を取り消し、残りはカーソルの位置からキャッシュが応答し、キャッシュに Object がないところは Unknown とする(SS3.2.1, SS7.8)。16 KiB 未満の Object は、途切れている間は丸ごと保持して一度に書くので、その書き込みが拒まれたら上と同じくキャッシュに切り替える。それより大きい Object は、フィールドがそろった時点で先頭を送り、ペイロードは届くたびに送るので、大きすぎて中継できない Object はなく、拒まれたペイロードの書き込みは次の tick か次の配送で再試行する。素通しで送っている Object の途中で区間が終わった場合(上流で切れた、または拒まれたペイロードで予算を使い切った)は、下流のストリームを INTERNAL_ERROR でリセットする。保持できない途切れた FETCH_HEADER は、データストリームをまだ待っているそのピアへの上流の FETCH を終わらせる。キャッシュが空と分かっている範囲は、ヘッダーと FIN を一度だけ送る。
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
- [x] MQ23-215 ハブが持たない Track の FETCH は、丸ごと、それを覆う告知元へ送らなければならない。その REQUEST_OK は上流の REQUEST_OK を待ち、その LARGEST_OBJECT と Track Properties を写さなければならない。告知元がなければ DOES_NOT_EXIST、告知元へのリクエストストリームを開けなければ UNAVAILABLE で応答する。
  - test: `tests/app/moqtrun_upfetch_d23_test.c` — `test_moqtrun_upfetch_d23_relay`
  - test: `tests/app/moqtrun_upfetch_test.c` — `test_moqtrun_upfetch_no_track_refusals`
  - test: `tests/app/moqtrun_upfetch_test.c` — `test_moqtrun_upfetch_no_track_waits_ok`
  - test: `tests/app/moqtrun_upfetch_test.c` — `test_moqtrun_upfetch_error_passthrough`
  - test: `tests/app/moqtrun_upfetch_test.c` — `test_moqtrun_upfetch_refused_before_routing`
- [x] MQ23-216 上流の FETCH は、min(FILL_TIMEOUT, `WIRED_MOQTRUN_UPFETCH_BUDGET_MS`) が経過したら取り消し、キャッシュにないものを、draft-22 以降に向けては End of Timed-Out Range として報告しなければならない(それより前のドラフトに向けては End of Unknown Range とし、中継した 0x20C も 0x10C として届ける)。FILL_TIMEOUT が 0 なら上流には何も問い合わせない(SS9.20.5, SS11.4.1)。
  - test: `tests/app/moqtrun_upfetch_test.c` —
    `test_moqtrun_upfetch_budget`, `test_moqtrun_upfetch_fill_timeout_zero`,
    `test_moqtrun_upfetch_marker_relay`
- [x] MQ23-250 (SS9.1.6) ハブは、上流の FETCH で、上流のピアが広告した MAX_FILTER_RANGES を超える数の Range Filter パラメーターを送信してはならない(ピアが 0 を広告したか何も広告しなかった場合は 1 つも送らない)。
  - test: `tests/app/moqtrun_upfetch_test.c` —
    `test_moqtrun_upfetch_range_filter_peer_limit`,
    `test_moqtrun_upfetch_range_filter`
  - note: 範囲が上限を超えると、フィルターを 1 つも送りません(一部だけ落とすと、OR で結んだ集合を狭めてしまうことがある)。ハブは、より広い応答を自分で絞り込みます。
- [x] MQ23-217 要求者が取り消した、データストリームを止めた、または切断したとき、ハブはスロットを解放する前に上流の FETCH を取り消し(リクエストストリームに RESET_STREAM と STOP_SENDING、データストリームに STOP_SENDING)、後からそのために届いたデータストリームを止めなければならない。上流のリセット、リクエストストリーム上の GOAWAY、切断は区間を終わらせ、ハブが持つ Track に対する上流の REQUEST_ERROR はキャッシュに引き継ぎ、1 つのリクエストストリーム上の 2 回目の GOAWAY はそのセッションを閉じる(SS3.2.4, SS9.2, SS9.12)。
  - test: `tests/app/moqtrun_upfetch_test.c` —
    `test_moqtrun_upfetch_requester_gone`, `test_moqtrun_upfetch_leg_ends`,
    `test_moqtrun_upfetch_two_goaways`, `test_moqtrun_upfetch_error_held`,
    `test_moqtrun_upfetch_bad_end`
- [x] MQ23-218 上流の fetch ストリームが示した End of Track (0x81) を越える上流の Object、その Track で見た Group の終わりを越える Object、キャッシュ済みの複製と食い違う Object は、中継もキャッシュもしてはならず、そのパブリッシャーからの Track を不正なものとして扱わなければならない。
  - test: `tests/app/moqtrun_upfetch_d23_test.c` — `test_moqtrun_upfetch_d23_eot`
  - test: `tests/app/moqtrun_upfetch_test.c` — `test_moqtrun_upfetch_malformed_past_end`
  - test: `tests/app/moqtrun_upfetch_test.c` — `test_moqtrun_upfetch_malformed_conflict`
  - test: `tests/app/moqtrun_upfetch_test.c` — `test_moqtrun_upfetch_malformed_group_end`
  - test: `tests/app/moqtrun_upfetch_test.c` — `test_moqtrun_upfetch_mandatory`
- [x] MQ23-219 区間の途中で Track の所有者のセッションが閉じたら、それ以上そのセッションへは何も送信してはならない。fill は、開いていてもいなくてもすぐに INTERNAL_ERROR でリセットし、PUBLISH_DONE を引き止めないようにする。FETCH は、解放されたキャッシュをその End まで Unknown として読む(SS3.4.1)。
  - test: `tests/app/moqtrun_upfetch_test.c` —
    `test_moqtrun_upfetch_owner_gone_fill`,
    `test_moqtrun_upfetch_owner_gone_fetch`
- [x] MQ23-272 (SS2.1.2, SS3.2.2) 実装は、Object が一度も存在せず今後も存在しないと分かっているときにだけ、それを存在しないものとして示さなければならない。推測しただけの欠落は Unknown として示す。
  - test: `tests/app/moqcache_test.c` — `test_moqcache`
  - test: `tests/app/moqtrun_upfetch_test.c` — `test_moqtrun_upfetch`
  - test: `tests/app/moqtrun_fetch_d23_test.c` — `test_moqtrun_fetch_d23_hole`
  - test: `tests/app/moqtrun_fetch_d23_test.c` — `test_moqtrun_fetch_d23_late_unknown`
  - test: `tests/app/moqtrun_fill_test.c` — `test_moqtrun_fill_subscribe_opens_d23`
- [x] MQ23-273 (SS3.2.3) リレーは、上流から受けたのでなければ Object を Gone として示してはならない。上流の Gone の範囲は、受けたとおりに下流へ伝える。
  - test: `tests/app/moqtrun_upfetch_d23_test.c` — `test_moqtrun_upfetch_d23_markers`
- [x] MQ23-274 (SS3.2.2, SS12.5) Unknown の Object について fetch ストリームをリセットしてはならない。上流の FETCH が応答の途中で失敗したら、残りの範囲を End of Unknown Range で示して FIN で終える。
  - test: `tests/app/moqtrun_upfetch_d23_test.c` — `test_moqtrun_upfetch_d23_leg_fails`
  - test: `tests/app/moqtrun_upfetch_test.c` — `test_moqtrun_upfetch_no_track_desc_fails`
  - note: FETCH_OK を送る前に上流が失敗した FETCH には、REQUEST_ERROR で応答します(SS3.2)。素通しで送っている Object の途中で終わったときだけ、ストリームをリセットします(MQ23-214)。
- [x] MQ23-275 (SS10.3, SS2.1.2) キャッシュした Does Not Exist の状態は MAX_CACHE_DURATION の後に失効し、その Object は Unknown に戻らなければならない。
  - test: `tests/app/moqtrun_fetch_d23_test.c` — `test_moqtrun_fetch_d23_dne_expires`
- [x] MQ23-290 (SS7.1, SS10.3, SS3.2.3) リレーが上流の FETCH の応答で受けた Gone の範囲をキャッシュする場合、その Track の MAX_CACHE_DURATION が過ぎるまで、その範囲への後の FETCH や fill には上流に問い合わせず Gone として答え、過ぎた後は Unknown に戻さなければならない。Unknown と Timed-Out の範囲はキャッシュしない。
  - test: `tests/app/moqtrun_upfetch_d23_test.c` — `test_moqtrun_upfetch_d23_gone_cached`
  - test: `tests/app/moqtrun_upfetch_d23_test.c` — `test_moqtrun_upfetch_d23_gone_expires`
  - test: `tests/app/moqtrun_upfetch_d23_test.c` — `test_moqtrun_upfetch_d23_gone_only`
  - test: `tests/app/moqtrun_upfetch_d23_test.c` — `test_moqtrun_upfetch_d23_gone_partial`
  - test: `tests/app/moqcache_test.c` — `test_moqcache_gone_partial`
  - test: `tests/app/moqcache_test.c` — `test_moqcache_gone_whole_group`
  - test: `tests/app/moqcache_test.c` — `test_moqcache_gone_expires`
  - test: `tests/app/moqcache_test.c` — `test_moqcache_gone_full`
  - note: 固定長の表(16 件)に置き、満杯なら最も古い範囲を捨てます。捨てた範囲は Unknown に戻るだけで、誤った答えにはなりません。MAX_CACHE_DURATION がない Track の範囲は失効しません(SS10.3)。Range Filter を付けた FETCH と Descending の FETCH の応答の Gone は、範囲の始まりが曖昧になるのでキャッシュしません。draft-22 の要求者には Unknown として答えます。

## ハブのリレー: fill fetch ストリーム(FILL_PARAMETERS。draft-20 で新設)

購読者は、すでに購読している Track の範囲を限った埋め戻しを、購読を置き換えずに、FETCH_HEADER で枠付けした専用のデータストリームで要求できます。SUBSCRIBE、SUBSCRIBE_TRACKS、PUBLISH(最初の fill)や REQUEST_UPDATE(後からの fill)の FILL_PARAMETERS (0x23) は、新しい fill fetch ストリームを開きます。このストリームは FETCH のデータストリームと同じ枠付けで、その SUBSCRIBE や REQUEST_UPDATE 自身の Request ID を参照します。1 つの購読につき、複数の fill ストリームを同時に開いてよいことになっています。この仕組みは、draft-18 と draft-19 にはまったくありません。

- [x] MQ23-138 SUBSCRIBE、SUBSCRIBE_TRACKS、PUBLISH、購読への REQUEST_UPDATE が FILL_PARAMETERS を含む場合、実装は、その購読の Request ID を参照する、FETCH_HEADER で枠付けした新しいデータストリームを開き、fill の範囲を配送しなければならない。FILL_PARAMETERS の値は、Number of Parameters とその数の Parameters で、長さの前置はない。
  - test: `tests/app/moqctl_d23_test.c` — `test_moqctl_d23_fill_count`
  - test: `tests/app/moqtrun_fill_test.c` — `test_moqtrun_fill_subscribe_opens_d23`
  - test: `tests/app/moqtrun_fill_test.c` — `test_moqtrun_fill_subscribe_opens`
  - test: `tests/app/moqtrun_fill_test.c` — `test_moqtrun_fill_update_opens`
  - test: `tests/app/moqtrun_fill_test.c` — `test_moqtrun_fill_open_end_is_largest`
  - test: `tests/app/moqtrun_fill_test.c` — `test_moqtrun_fill_end_clipped_to_largest`
  - test: `tests/app/moqtrun_fill_test.c` — `test_moqtrun_fill_filter_separate_from_subscription`
  - test: `tests/app/moqtrun_nsx_test.c` — `test_moqtrun_nsx_tracks_fill_opens`
- [x] MQ23-139 fill の要求された範囲が空であるか、全体が現在の Largest Object より後から始まる場合、実装は fill fetch ストリームを一切開いてはならない。
  - test: `tests/app/moqtrun_fill_test.c` —
    `test_moqtrun_fill_empty_or_future_range`
- [x] MQ23-140 同じ購読について、複数の fill fetch ストリームを同時に開いてもよく、それぞれを独立に管理する。
  - test: `tests/app/moqtrun_fill_test.c` — `test_moqtrun_fill_two_at_once`
  - test: `tests/app/moqtrun_fill_test.c` —
    `test_moqtrun_fill_survives_done_and_slot_reuse`
- [x] MQ23-141 fill fetch ストリームは、その範囲を、購読の Group Order(GROUP_ORDER による昇順または降順。FILL_PARAMETERS の内側で上書きできる)で配送し、存在しない Group は印を付けずに飛ばさなければならない。
  - test: `tests/app/moqtrun_fill_test.c` — `test_moqtrun_fill_descending`
  - test: `tests/app/moqtrun_fill_test.c` —
    `test_moqtrun_fill_descending_missing_group`
  - test: `tests/app/moqtrun_fill_test.c` —
    `test_moqtrun_fill_next_object_no_gap`
  - test: `tests/app/moqtrun_fill_test.c` — `test_moqtrun_fill_ascending_sends_first`
  - test: `tests/app/moqtrun_fill_test.c` — `test_moqtrun_fill_descending_sends_last`
- [x] MQ23-142 fill の元データがキャッシュにないか、FILL_TIMEOUT でタイムアウトした場合、実装はストリームを止めたままにしたり黙って落としたりせず、印で報告しなければならない。推測しただけの欠落は End of Unknown Range (0x10C)、FILL_TIMEOUT の予算を使い切った(0 を含む)欠落は End of Timed-Out Range(0x20C。MQ23-136 を参照)とする(SS3.2.3, SS9.19.5)。
  - test: `tests/app/moqtrun_fill_test.c` — `test_moqtrun_fill_miss_is_timed_out_now`
  - test: `tests/app/moqtrun_fill_test.c` — `test_moqtrun_fill_evicted_run_collapsed`
  - test: `tests/app/moqtrun_fill_test.c` — `test_moqtrun_fill_eviction_under_cursor`
- [x] MQ23-143 所有する購読を取り消すと、そのために開いたすべての fill fetch ストリームをリセットしなければならない。fill ストリーム自身の取り消し(要求者のリセット、STOP_SENDING、上流の失敗)は、決して購読そのものに影響してはならない。
  - test: `tests/app/moqtrun_fill_test.c` — `test_moqtrun_fill_cancel_resets_all`
  - test: `tests/app/moqtrun_fill_test.c` —
    `test_moqtrun_fill_stop_sending_leaves_sub`
  - test: `tests/app/moqtrun_fill_test.c` — `test_moqtrun_fill_upstream_gone_resets`
  - test: `tests/app/moqtrun_fill_test.c` — `test_moqtrun_fill_blocked_upstream_gone`
- [x] MQ23-144 配送タイムアウトを過ぎて止まった fill ストリームは、ほかの止まったデータストリームと同じように放棄しなければならず、購読自身のライブ配送を決して滞らせてはならない。
  - test: `tests/app/moqtrun_fill_test.c` —
    `test_moqtrun_fill_stall_delivery_timeout`
  - test: `tests/app/moqtrun_fill_test.c` —
    `test_moqtrun_fill_blocked_never_starves_live`
- [x] MQ23-145 PUBLISH_DONE の Stream Count は、その購読の開いているすべての fill fetch ストリームを含まなければならず、PUBLISH_DONE は、保留中の(まだ開いていない)fill のリクエストが片付くのを待ってから送信しなければならない。
  - test: `tests/app/moqtrun_fill_test.c` — `test_moqtrun_fill_counts_in_done`
  - test: `tests/app/moqtrun_fill_test.c` — `test_moqtrun_fill_done_waits_for_held`
- [x] MQ23-146 実装の固定の fill スロットの容量がすでに埋まっている場合、この実装で認めた容量の裁定(台帳 4-6、2026-10-04: 8+8 スロット。上限を上げることも明示的にエラーにすることも YAGNI とした)に従い、新しい fill のリクエストを、スロットが空くまで(エラーで応答せずに)保留しなければならない。
  - test: `tests/app/moqtrun_fill_test.c` — `test_moqtrun_fill_slot_full_held`
  - test: `tests/app/moqtrun_fill_test.c` —
    `test_moqtrun_fill_slot_full_cancel_drops`
  - test: `tests/app/moqtrun_fill_test.c` —
    `test_moqtrun_fill_slot_full_done_waits`
- [x] MQ23-147 FETCH_HEADER ストリームの Request ID は、FETCH だけでなく、SUBSCRIBE や REQUEST_UPDATE(fill)を指してもよい。draft-19 では、FETCH_HEADER は自身が応答する FETCH しか名指さない点が異なる。
  - test: `tests/app/moqtrun_fill_test.c` —
    `test_moqtrun_fill_inbound_fetch_known_rid`
  - test: `tests/app/moqtrun_fill_test.c` —
    `test_moqtrun_fill_inbound_fetch_unknown_rid`

## ハブのリレー: PUBLISH/SUBSCRIBE の振り分け(SS7 リレー、SS9.3/9.6/9.8 の適用)

- [x] MQ23-148 PUBLISH が成功したら、ハブは同じ制御ストリームで、それを閉じずに REQUEST_OK を応答しなければならない。
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_publish_replies_request_ok`
- [x] MQ23-149 ピアは、異なる Track を複数(実装のピアごとの Track の容量まで)PUBLISH してもよく、それぞれが独立に REQUEST_OK を受け取る。
  - test: `tests/app/moqtrun_test.c` — `test_moqtrun_peer_publishes_two_tracks`
- [x] MQ23-150 ピアが実装のピアごとの容量を超える数の異なる Track を PUBLISH しようとした場合、実装は既存の Track を黙って上書きせずに、REQUEST_ERROR で応答しなければならない。
  - test: `tests/app/moqtrun_test.c` — `test_moqtrun_sixth_publish_gets_error`
- [x] MQ23-151 すでにスロットを占めている同じ Track Name を再び PUBLISH したときは、新しいスロットを使わずにそのスロットを再利用しなければならない。
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_republish_same_name_reuses_slot`
- [x] MQ23-152 ピアが PUBLISH したいずれかの Track を名指す SUBSCRIBE は、割り当てた Track Alias とともに SUBSCRIBE_OK を受け取らなければならない。
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_subscribe_audio_track_replies_ok`
- [x] MQ23-153 同じ振り分けの呼び出しで届いた 2 つの SUBSCRIBE メッセージは、一方が他方を上書きすることなく、それぞれ自身の応答をキューに入れなければならない。
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_two_subscribe_oks_one_dispatch_no_overflow`

## ハブのリレー: 一致する購読者だけへの Object の転送(SS7.5, SS3.1.3)

- [x] MQ23-154 Object は、その Track Alias が示す Track の購読者だけに転送し、同じセッションのほかの Track の購読者には転送してはならない。
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_chat_object_relays_only_to_chat_subscriber`
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_audio_object_relays_only_to_audio_subscriber`
- [x] MQ23-155 Object の Track Alias が、パブリッシャーが宣言したどの Track とも一致しない場合、実装はそれをどの購読者にも転送してはならない。
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_unknown_alias_object_relays_nowhere`
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_unbound_stream_id_relays_nowhere`
- [x] MQ23-156 同じ Track への複数の購読に一致する Object は、一致する購読ごとに 1 回ずつ送信しなければならない。
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_chat_object_relays_to_all_three_subscribers`
- [x] MQ23-157 ある購読者への Object の転送が失敗した(下のトランスポートが送信を拒んだ)場合も、実装はそれを一致するほかのすべての購読者へ転送し、損失を黙って見過ごさずに数えなければならない。
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_chat_one_of_three_subscribers_refused`
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_send_uni_failure_counts_open_drop`
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_stream_send_rejection_drops_frame_not_fatal`
- [x] MQ23-158 Delivery Mode が Subgroup で送られた Object は、パブリッシャーのストリームの枠付けに合わせて、リレーの 1 回の送信につき、SUBGROUP_HEADER と Object がそろった 1 つの完全な単位として中継しなければならない。
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_multi_object_stream_relays_in_one_send_uni`
- [x] MQ23-159 長く続く Subgroup ストリームの後続のデータ(SUBGROUP_HEADER を繰り返さずに届く)は、新しいヘッダーと読み違えずに、すでに結び付いた同じリレーのストリームへ追記しなければならない。
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_data_stream_continues_across_calls_without_header`
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_audio_first_object_opens_then_appends`
- [x] MQ23-160 パブリッシャーの Subgroup ストリームが FIN したとき、実装は境界をまたいで追記せずに、対応するリレーのストリームを閉じ、新しいパブリッシャーのストリーム上の次の Subgroup のために新しいストリームを開かなければならない。
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_audio_publisher_fin_closes_and_reopens`
- [x] MQ23-161 実装は、各 Subgroup を、その配送の形に合ったトランスポートのプリミティブで一貫して中継しなければならない(1 回で終わる Subgroup は open+send+FIN を一度に、長く続く Subgroup は FIN なしで開いて後から追記する)。
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_chat_still_uses_send_uni_every_object`
- [x] MQ23-162 同じ Track の 2 人の購読者は、それぞれ独立したリレーのストリームを持たなければならない。これにより、一方への配送が他方のストリームの結び付きに影響しない。
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_audio_two_subscribers_independent_streams`

## ハブのリレー: 拒否が続くときの切り捨て(SS11.3.2 のリセットの規律の適用)

- [x] MQ23-163 購読者のリレーのストリームが、実装のしきい値を超えて busy(拒否)が続いた場合、実装は古い滞留を抱え続けずに、そのストリームをリセットし、次の配送で新しいストリームを開き直さなければならない。
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_busy_streak_sheds_after_threshold`
- [x] MQ23-164 busy が続く途中で配送が受け入れられたら、busy の連続回数のカウンターをリセットしなければならない。これにより、散発的な一時的拒否が積み重なって切り捨てに至ることはない。
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_busy_streak_success_resets`
- [x] MQ23-165 ストリームを切り捨てた後、その放棄したストリームに対して届いたパブリッシャーの単独の FIN は、そこへ転送してはならない。
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_shed_stream_skips_publisher_fin`
- [x] MQ23-166 busy の連続回数のカウンターは購読者ごとに管理しなければならない。これにより、詰まった 1 人の購読者の切り捨てが、ほかの購読者の健全なストリームに影響しない。
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_busy_shed_isolated_per_subscriber`
- [x] MQ23-167 リセットそのものが下のトランスポートに拒まれた場合、実装はそれを済んだものとして扱わずに、次の busy の回で切り捨てを再試行しなければならない。
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_shed_refused_retries_next_round`
- [x] MQ23-168 Track を再び PUBLISH したときは、そのリレーの状態を、以前の世代で積み上がった busy の連続回数のカウンターも含めて消去しなければならない。
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_republish_clears_busy_streak`
- [x] MQ23-202 `newest_group_only` が設定され(既定では無効な、明示的に選ぶハブのポリシー)、損失を許すリレーが、その購読でこれまでに開いたどれよりも新しい Group で購読者のストリームを開くとき、実装はその購読の直前の最新のストリームを(パブリッシャーがすでに終えたものでも)リセットしなければならない。これにより、古い Group の未送信の滞留が、Group の順序どおりのスケジューリングの後ろで新しい Group を引き止めることはない。
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_newer_group_resets_finished_older_stream`
- [x] MQ23-203 その後、古い Group のまだ開いているパブリッシャーのストリームの各回は、その購読者には一切届いてはならない: 追記も、開き直しも、FIN もしない。
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_newer_group_cuts_open_older_relay`
- [x] MQ23-204 同じ Group の別のストリームや、信頼性のある(リングで裏打ちされた)Track のストリームは、何もリセットしてはならない。
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_same_group_stream_keeps_sibling`,
    `test_moqtrun_newer_group_keeps_reliable_stream`
- [x] MQ23-220 既定(`newest_group_only` が 0)では、新しい Group のストリームは何もリセットしてはならず、古い Group の後続の回もそのまま転送しなければならない: 「A relay MUST NOT reorder or drop objects received on a multi-object stream」(7.4 節)。
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_newer_group_keeps_older_by_default`
- [x] MQ23-205 再 PUBLISH や付け直しでは、新しい世代で Group の番号が振り直されるので、購読の最新の Group を忘れなければならない。
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_republish_forgets_newest_group`,
    `test_moqtrun_reattach_forgets_newest_group`

## ハブのリレー: セッションの後始末(SS6.6 終了をリレーの状態に適用)

- [x] MQ23-169 セッションが閉じたとき、実装はそのピアのスロットを解放しなければならない。これにより、同じ下のセッションのポインターで後から再接続したものを、閉じたピアではなく新しいピアとして扱う。
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_close_frees_peer_for_reregistration`
- [x] MQ23-170 購読者のセッションが閉じたとき、実装はほかのすべてのピアの Track 上にあるその購読のエントリを無効にしなければならない。これにより、後の Object を閉じたセッションへ中継しない。
  - test: `tests/app/moqtrun_test.c` — `test_moqtrun_close_drops_subscriptions`
- [x] MQ23-171 実装が一度も登録していないセッション(またはすでに閉じたセッション)を閉じても、何もせず、ほかのピアに影響を与えてはならない。
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_close_unknown_session_noop`
- [x] MQ23-172 実装のピアテーブルの容量を超えて登録と切断を繰り返しても、スロットを漏らしてはならない。再接続のたびに、必ず SETUP を受け取らなければならない。
  - test: `tests/app/moqtrun_test.c` — `test_moqtrun_close_reregister_churn`

## ハブのリレー: 制御ストリームとリクエストストリーム

- [~] MQ23-173 実装は、すべての Message Parameter を draft-23 の登録表(値のエンコーディング、現れてよいメッセージ、許される値の範囲)に従ってデコードしなければならない。メッセージや範囲の外にあるパラメーターは、INVALID_PARAMETER (0x305) でセッションを閉じなければならない。
  - evidence: 登録表によるデコード(値のエンコーディング、許されるメッセージ、値の範囲)はコーデックで確かめています(`test_moqctl_params_registry_scope`、`test_moqctl_params_uint8_value_ranges`、`test_moqctl_params_repeatable_filters`、`test_moqctl_golden_subscribe_params`)。ハブは対象外のパラメーターで閉じます(`test_moqtrun_upd_bad_and_control`)が、範囲外の値を送るハブのテストはありません。
- [x] MQ23-174 ストリームの複数回の配送に分かれて届いた制御メッセージは、組み立て直して 1 回だけ処理しなければならない。1 KiB を超えるメッセージ(65535 バイトまで)は共有の再組み立てバッファで受け取り、そのバッファが尽きたときは INTERNAL_ERROR でセッションを閉じなければならない。
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_ctl_split_subscribe_answered_once`
  - test: `tests/app/moqtrun_test.c` — `test_moqtrun_ctl_message_then_half`
  - test: `tests/app/moqtrun_test.c` — `test_moqtrun_ctl_max_length_accepted`
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_ctl_pool_exhausted_closes`
- [x] MQ23-175 制御ストリームがまったく未知の Message Type を運ぶ場合、ハブは UNEXPECTED_MESSAGE (0x303) でセッションを閉じなければならない。
  - test: `tests/app/moqtrun_test.c` — `test_moqtrun_ctl_unknown_type_closes_session`
- [x] MQ23-176 専用の双方向ストリームで開いた各リクエストには、そのストリームで応答しなければならない。ストリームのリセットはリクエストを取り消す(購読の解除/配信の取り下げ)が、FIN だけでは取り消さない。1 つのセッションが同時に開いておけるリクエストは最大 32 個である(それを超えるものは EXCESSIVE_LOAD でリセットする)。
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
- [x] MQ23-276 (SS9.5) 1 つのストリームの REQUEST_UPDATE は受信した順に処理し、REQUEST_UPDATE_OK は受信した順に返さなければならない。
  - test: `tests/app/moqtrun_d23uo_test.c` — `test_moqtrun_d23uo_immediate_in_order`
  - test: `tests/app/moqtrun_d23uo_test.c` — `test_moqtrun_d23uo_pipelined_in_order`
  - test: `tests/app/moqtrun_d23uo_test.c` — `test_moqtrun_d23uo_refused_reply_keeps_order`
  - test: `tests/app/moqtrun_d23uo_test.c` — `test_moqtrun_d23uo_every_update_resolved`
- [x] MQ23-277 (SS9.5, SS9.19.15, SS9.19.20) FILL_PARAMETERS または TRACK_NAMESPACE_PREFIX を含む REQUEST_UPDATE を、ほかの更新とまとめてはならない。
  - test: `tests/app/moqtrun_d23uo_test.c` — `test_moqtrun_d23uo_fill_not_coalesced`
  - test: `tests/app/moqtrun_d23uo_test.c` — `test_moqtrun_d23uo_prefix_not_coalesced`
  - test: `tests/app/moqtrun_d23uo_test.c` — `test_moqtrun_d23uo_fill_breaks_run`
  - test: `tests/app/moqtrun_d23uo_test.c` — `test_moqtrun_d23uo_prefix_breaks_run`
  - note: ハブがまとめる更新(MQ23-291)は、この 2 つを含む更新の手前で区切ります。
- [x] MQ23-278 (SS9.5.1) REQUEST_UPDATE が失敗した場合、ハブはそのリクエストを終えなければならない。購読なら PUBLISH_DONE UPDATE_FAILED を送り、送信者自身の PUBLISH なら Track を取り下げ、後から届いた更新には応答しない。
  - test: `tests/app/moqtrun_d23uo_test.c` — `test_moqtrun_d23uo_failed_update_publish_done`
  - test: `tests/app/moqtrun_d23uo_test.c` — `test_moqtrun_d23uo_error_covers_queued`
  - test: `tests/app/moqtrun_d23uo_test.c` — `test_moqtrun_d23uo_after_end_no_reply`
  - test: `tests/app/moqtrun_d23uo_test.c` — `test_moqtrun_d23uo_pipelined_failure_drops_second`
  - test: `tests/app/moqtrun_d23uo_test.c` — `test_moqtrun_d23uo_invalid_switch_ends`
  - test: `tests/app/moqtrun_d23uo_test.c` — `test_moqtrun_d23uo_publish_update_refused_ends`
  - test: `tests/app/moqtrun_d23uo_test.c` — `test_moqtrun_d23uo_publish_update_refused_after_done`
  - test: `tests/app/moqtrun_d23uo_test.c` — `test_moqtrun_d23uo_failed_prefix_keeps_old`
- [x] MQ23-279 (SS9.19.15) 開ける fill の数を超える FILL_PARAMETERS の REQUEST_UPDATE は、EXCESSIVE_LOAD で拒否してよい。ハブはそう拒否し、MQ23-278 によりその購読を終える。
  - test: `tests/app/moqtrun_d23uo_test.c` — `test_moqtrun_d23uo_fill_excessive_load_ends`
- [x] MQ23-280 (SS9.5) 更新を受け付けないリクエストストリーム(ハブが開いた上流の SUBSCRIBE と FETCH のストリームを含む。そのリクエストが終わった後も同じ)で REQUEST_UPDATE を受信した場合、ハブは UNEXPECTED_MESSAGE (0x303) でセッションを閉じなければならない。
  - test: `tests/app/moqtrun_d23uo_test.c` — `test_moqtrun_d23uo_wrong_direction_unexpected`
  - test: `tests/app/moqtrun_d23uo_test.c` — `test_moqtrun_d23uo_upfetch_update_unexpected`
  - test: `tests/app/moqtrun_d23uo_test.c` — `test_moqtrun_d23uo_upfetch_ended_update`
  - test: `tests/app/moqtrun_d23uo_test.c` — `test_moqtrun_d23uo_upsub_ended_update`
  - test: `tests/app/moqtrun_misc_test.c` — `test_moqtrun_misc_stray_update`
  - note: 終わったリクエストのストリーム ID は、そのスロットが次のリクエストに使われるまでしか覚えていません。その後にそのストリームで届くバイトは捨て、データストリームとしては読みません。このとき REQUEST_UPDATE でもセッションを閉じません。
- [x] MQ23-291 (SS9.5, SS9.1.7) 1 つのストリームで続けて届いた REQUEST_UPDATE をまとめる場合、ハブはそれらを累積した結果(後の更新の値が前の値を上書きする)として 1 回だけ適用し、成功した更新それぞれに REQUEST_OK を受信順に返さなければならない。失敗したときは REQUEST_ERROR を 1 つだけ返してそのリクエストを終え、まとめた更新もそれぞれ MAX_REQUEST_UPDATES に数えなければならない。
  - test: `tests/app/moqtrun_d23uo_test.c` — `test_moqtrun_d23uo_coalesced_applied_once`
  - test: `tests/app/moqtrun_d23uo_test.c` — `test_moqtrun_d23uo_coalesced_failure_one_error`
  - test: `tests/app/moqtrun_d23uo_test.c` — `test_moqtrun_d23uo_coalesced_run_credit`
  - note: まとめるのは draft-23 のセッションで、1 回の受信でストリームの組み立てバッファーにそろった REQUEST_UPDATE だけです。受信をまたいではまとめません。失敗時の REQUEST_ERROR で戻る枠は 1 つで、残りは終わったリクエストで捨てた更新と同じく応答のないまま数え続けます。

## ハブのリレー: 購読

- [x] MQ23-177 SUBSCRIBE は、配信された Track と完全な Track Name(名前空間と名前)で照合しなければならない。したがって、異なる名前空間にある同じ名前は異なる Track である。
  - test: `tests/app/moqtrun_sub_test.c` — `test_moqtrun_sub_ns_must_match`
  - test: `tests/app/moqtrun_sub_test.c` —
    `test_moqtrun_sub_same_name_other_ns_coexist`
- [x] MQ23-178 ハブは、各購読の Request ID、SUBSCRIBER_PRIORITY、GROUP_ORDER、一時停止の状態(PAUSED)、配送タイムアウト、フィルターの始点を記録し、パブリッシャーが再参加してもそれらを保ち、Track に Object が入ったら SUBSCRIBE_OK で LARGEST_OBJECT を報告しなければならない。
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
- [x] MQ23-179 Object は、共有のバッファープールから各購読者へ確実に中継しなければならない。遅い購読者がプールを引き止めるのはウォーターマークまでで、止まった購読者はタイムアウトの後に落とし、末尾を落としたストリームは続けない(続けると購読者との同期がずれる)。
  - test: `tests/app/moqtrel_test.c` — `test_moqtrel_append_hold_at_watermark`
  - test: `tests/app/moqtrel_test.c` — `test_moqtrel_reclaim_follows_slowest`
  - test: `tests/app/moqtrel_test.c` — `test_moqtrel_stalled_after_timeout`
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_poison_survives_reset_and_close`
- [x] MQ23-180 購読者の優先度は、その購読者のリレーのストリームの WebTransport のストリームの urgency に対応付けなければならない。優先度を変える REQUEST_UPDATE は、以後のストリームに適用され、その購読の開いている keep-open のストリームと fill ストリームのクラスを付け直す。io の stream_sched フックがあれば、ハブは各 Object ストリームの完全なクラス(urgency 4、Subscriber << 8 | Publisher Priority、Group の順序と fill を先・ライブを後にする順で並べた購読ごとのフロー)を設定し、送信のポンプはそれに従ってスケジューリングする。
  - test: `tests/app/moqtrun_drain_test.c` — `test_moqtrun_sched_relay_keys`
  - test: `tests/app/moqtrun_drain_test.c` — `test_moqtrun_sched_update_reclasses`
  - test: `tests/app/moqtrun_drain_test.c` — `test_moqtrun_sched_fill_shares_flow`
  - test: `tests/app/srvrun_test.c` — `test_srvrun_wt_sched_fill_before_live`
  - test: `tests/app/moqtrun_drain_test.c` — `test_moqtrun_prio_per_subscriber`
  - test: `tests/app/moqtrun_drain_test.c` — `test_moqtrun_prio_update_applies`
  - test: `tests/app/moqtrun_drain_test.c` — `test_moqtrun_prio_op_absent`
- [x] MQ23-181 SUBSCRIBE に対する、その購読のリクエストストリーム上の REQUEST_UPDATE は、そのパラメーターを全部置き換えるか何も変えないかのどちらかでなければならない: 拒否された更新は何も変えない。
  - test: `tests/app/moqtrun_upd_test.c` — `test_moqtrun_upd_forward_toggles`
  - test: `tests/app/moqtrun_upd_test.c` — `test_moqtrun_upd_params_replace`
  - test: `tests/app/moqtrun_upd_test.c` —
    `test_moqtrun_upd_failed_changes_nothing`
  - test: `tests/app/moqtrun_upd_test.c` — `test_moqtrun_upd_survives_rejoin`
- [x] MQ23-182 パブリッシャーは、自身の購読のストリームで PUBLISH_STATE_NOTIFY (0x22) を送信して、現在の LARGEST_OBJECT(分かっていれば必ず含める)、PAUSED、LOCATION_FILTER の状態を購読者へ報告してもよい。ほかの種類のリクエストのストリームで受信したら UNEXPECTED_MESSAGE で、パブリッシャーが受信したら ROLE_VIOLATION でセッションを閉じなければならない。
  - test: `tests/app/moqtrun_upd_test.c` — `test_moqtrun_notify_on_publish_stream_d22`
  - test: `tests/app/moqtrun_upd_test.c` — `test_moqtrun_notify_elsewhere_closes_d22`
  - test: `tests/app/moqtrun_test.c` — `test_moqtrun_ctl_publish_state_notify_d22_only`
  - test: `tests/app/moqtrun_cc_test.c` — `test_moqtrun_cc`
- [x] MQ23-182a PUBLISH_NAMESPACE は、Track Namespace の **Prefix** (それで始まる任意の名前空間)として照合しなければならない。draft-19 では、1 つの Track Namespace をそのまま名指す点が異なる。リレーは決して PUBLISH_NAMESPACE を下流へ転送してはならず、代わりに一致する SUBSCRIBE_NAMESPACE に NAMESPACE を使う。
  - test: `tests/app/moqtrun_upsub_test.c` — `test_moqtrun_upsub_prefix`
  - test: `tests/app/moqtrun_ns_test.c` — `test_moqtrun_ns_prefix_overlap`
  - test: `tests/app/moqtrun_upd_test.c` — `test_moqtrun_upd_ns_prefix_changes`
  - test: `tests/app/moqtrun_upd_test.c` —
    `test_moqtrun_upd_ns_prefix_overlap_refused`
  - note: `moqtrun_disc_under`/`_starts`/`_overlap` は、draft-19 と draft-22 の両方について、バイト単位のプレフィックス照合(完全一致ではない)を実装しています。draft-19 自身の NAMESPACE 送信義務の規則が、SUBSCRIBE_NAMESPACE にプレフィックス照合を求めているからです。draft-22 のフィールド名(「Track Namespace Prefix」)と PUBLISH_NAMESPACE の照合の規則も、同じアルゴリズムで満たします。
- [x] MQ23-182b TRACK_STATUS には、Track の最大の Location を運ぶ REQUEST_OK(空なら Location なし)か、Track が未知であるか認可関数が拒否したときは REQUEST_ERROR で応答しなければならない。
  - test: `tests/app/moqtrun_upd_test.c` — `test_moqtrun_tstat_ok_largest`
  - test: `tests/app/moqtrun_upd_test.c` — `test_moqtrun_tstat_ok_empty`
  - test: `tests/app/moqtrun_upd_test.c` — `test_moqtrun_tstat_unknown_and_blob`
  - test: `tests/app/moqtrun_upd_test.c` — `test_moqtrun_tstat_authorized`
- [x] MQ23-183 アプリケーションが認可関数を設定している構成では、すべての SUBSCRIBE、TRACK_STATUS、PUBLISH、PUBLISH_NAMESPACE、SUBSCRIBE_NAMESPACE をそれに見せ(draft-22 は認可を配信する側にも広げている。MQ23-097a を参照)、拒否は REQUEST_ERROR UNAUTHORIZED としなければならない。Alias に基づく認可トークンは、セッションを閉じなければならない(ハブはトークンのキャッシュを持たない。8.9): REGISTER は AUTH_TOKEN_CACHE_OVERFLOW、DELETE と USE_ALIAS は UNKNOWN_AUTH_TOKEN_ALIAS で閉じる。
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_subscribe_requires_authorization`
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_subscribe_alias_token_rejected`
  - test: `tests/app/moqtrun_ns_test.c` — `test_moqtrun_ns_authorization`
  - test: `tests/app/moqtrun_upd_test.c` —
    `test_moqtrun_publish_requires_authorization`
  - vuln: V-0786, V-0792, V-0793, V-0839
- [x] MQ23-286 (SS7.5) リレーは、一時停止しておらず、フィルターがないか下流のリクエスト以上に広いフィルターを持つ上流の購読からだけ LARGEST_OBJECT を求めなければならない。そのような購読がなければ、上流の購読を張るか、広げるか、一時停止を解いて、その結果の値を使う。
  - test: `tests/app/moqtrun_d23lg_test.c` — `test_moqtrun_d23lg_paused_pub_waits_resume`
  - test: `tests/app/moqtrun_d23lg_test.c` — `test_moqtrun_d23lg_paused_sub_resumes_upstream`
  - test: `tests/app/moqtrun_d23lg_test.c` — `test_moqtrun_d23lg_tstat_paused_fresh`
  - test: `tests/app/moqtrun_d23lg_test.c` — `test_moqtrun_d23lg_upstream_sub_not_paused`
  - test: `tests/app/moqtrun_d23lg_test.c` — `test_moqtrun_d23lg_no_ts_before_established`
  - test: `tests/app/moqtrun_d23lg_test.c` — `test_moqtrun_d23lg_publish_wakes_waiter`
  - test: `tests/app/moqtrun_d23lg_test.c` — `test_moqtrun_d23lg_live_answers_at_once`
  - test: `tests/app/moqtrun_d23lg_test.c` — `test_moqtrun_d23lg_never_above_upstream`
  - test: `tests/app/moqtrun_d23lg_test.c` — `test_moqtrun_d23lg_wait_edges`
  - test: `tests/app/moqtrun_d23lg_test.c` — `test_moqtrun_d23lg_update_waits_resume`
  - note: 一時停止中の PUBLISH への購読の REQUEST_UPDATE も、一時停止を解いた結果を待ってから REQUEST_OK で答えます。待っている更新の後ろに次の更新が届いたら、待っている方を TIMEOUT で終えます。
- [x] MQ23-287 (SS7.5) 上流の答えを待っている下流のリクエストは、上流が失敗したら(REQUEST_ERROR、PUBLISH_DONE、上流のセッションの喪失)REQUEST_ERROR で終えなければならない。待ちは固定数のスロットを使い、埋まっていれば新しいリクエストを EXCESSIVE_LOAD で拒否する。
  - test: `tests/app/moqtrun_d23lg_test.c` — `test_moqtrun_d23lg_upstream_refused_fails_waiters`
  - test: `tests/app/moqtrun_d23lg_test.c` — `test_moqtrun_d23lg_upstream_close_fails_waiters`
  - test: `tests/app/moqtrun_d23lg_test.c` — `test_moqtrun_d23lg_resume_refused_fails_waiters`
  - test: `tests/app/moqtrun_d23lg_test.c` — `test_moqtrun_d23lg_gone_track_refused`
  - test: `tests/app/moqtrun_d23lg_test.c` — `test_moqtrun_d23lg_wait_slots_bounded`
  - test: `tests/app/moqtrun_d23lg_test.c` — `test_moqtrun_d23lg_one_answer_per_request`
  - test: `tests/app/moqtrun_d23lg_test.c` — `test_moqtrun_d23lg_no_preauthorized_answer`
  - test: `tests/app/moqtrun_upsub_test.c` — `test_moqtrun_upsub_silent_upstream_times_out`
  - note: PUBLISH_DONE で終わった上流の待ちは、Status Code に対応する REQUEST_ERROR で終えます(TRACK_ENDED は DOES_NOT_EXIST)。対応がなければ INTERNAL_ERROR です。1 つのパブリッシャーの待ちはスロットの半分までで、超えた分は EXCESSIVE_LOAD で拒否します。
  - note: RENDEZVOUS_TIMEOUT のない待ちは、`WIRED_MOQTRUN_UP_WAIT_MS`(5 秒)で REQUEST_ERROR TIMEOUT にします(SS12.3)。応答しない上流がスロットを持ち続ける時間は、この値で上限が決まります。
- [x] MQ23-288 (SS10.4, SS10.5, SS10.6) DEFAULT_PUBLISHER_PRIORITY が 255 を、DEFAULT_PUBLISHER_GROUP_ORDER や DYNAMIC_GROUPS が定義の範囲を超える場合、実装は MALFORMED_KEY_VALUE (0x6) でセッションを閉じなければならない。
  - test: `tests/app/moqtrun_tprops_test.c` — `test_moqtrun_tprops_prio`
  - test: `tests/app/moqtrun_upsub_test.c` — `test_moqtrun_upsub_ok_bad_prop_closes`
  - test: `tests/app/moqtrun_upfetch_d23_test.c` — `test_moqtrun_upfetch_d23_props_close`
- [~] MQ23-289 (SS9.19.19) 購読者は、Track の Properties を受信していて、それが DYNAMIC_GROUPS=1 を含まないときに限り、REQUEST_UPDATE で NEW_GROUP_REQUEST を送ってはならない。
  - evidence: ハブは上流へ INCLUDE_PROPERTIES 0 を送らないので、Established の Track はつねに Properties を持ちます。そのため転送の関門(`moqtrun_ngr.c` の `moqtrun_ngr_wanted`)は draft-22 と同じ「DYNAMIC_GROUPS=1 を見たとき」で済み、`test_moqtrun_upsub_ngr_update` がそれを確かめています。draft-23 のセッションで確かめる専用のテストはありません。

## ハブのリレー: 配送タイムアウト

- [x] MQ23-184 OBJECT_DELIVERY_TIMEOUT(SUBSCRIBE または REQUEST_UPDATE から)が 0 でない場合、時間内に配送できなかった Object は放棄しなければならない: そのストリームを DELIVERY_TIMEOUT (0x2) でリセットするか、データグラムを落とす。
  - test: `tests/app/moqtrun_upd_test.c` — `test_moqtrun_timeout_live`
  - test: `tests/app/moqtrun_upd_test.c` — `test_moqtrun_timeout_datagram`
  - test: `tests/app/moqtrun_upd_test.c` — `test_moqtrun_timeout_by_update`
  - test: `tests/app/moqtrun_upd_test.c` — `test_moqtrun_timeout_torn_object`
  - test: `tests/app/moqtrun_upd_test.c` — `test_moqtrun_timeout_zero`

## ハブのリレー: キャッシュと FETCH

- [x] MQ23-185 キャッシュのアリーナが付いている(`wired_moqt_cache_attach`)場合、ハブは Group を丸ごとだけキャッシュし、予算を超えたら最も古い Group を追い出し、単独で予算を超える Group は落とさなければならない。
  - test: `tests/app/moqcache_test.c` — `test_moqcache_evicts_oldest_group`
  - test: `tests/app/moqcache_test.c` — `test_moqcache_group_over_budget_dropped`
  - test: `tests/app/moqtrun_fetch_test.c` — `test_moqtrun_fetch_cache_attach`
  - test: `tests/app/moqtrun_fetch_test.c` —
    `test_moqtrun_fetch_cache_default_off`
- [x] MQ23-207 1 つの Track のキャッシュ済みの Object を前向きにたどるとき、各検索は前回止まったところから再開し、アリーナの先頭から走査した場合と同じ項目を返さなければならない。追い出し(レコードを移動する)は再開位置を捨てる。
  - test: `tests/app/moqcache_test.c` — `test_moqcache_walk_resumes`,
    `test_moqcache_evict_drops_resume`
- [x] MQ23-186 FETCH は、要求者が取り消したとき、データストリームが止められたとき、パブリッシャーか要求者が去ったとき、配送が止まったときに、そのスロットを解放しなければならない。
  - test: `tests/app/moqtrun_fetch_test.c` —
    `test_moqtrun_fetch_cancelled_by_request_reset`
  - test: `tests/app/moqtrun_fetch_test.c` —
    `test_moqtrun_fetch_data_stream_stopped`
  - test: `tests/app/moqtrun_fetch_test.c` —
    `test_moqtrun_fetch_publisher_leaves`
  - test: `tests/app/moqtrun_fetch_test.c` — `test_moqtrun_fetch_stall_gives_up`

## ハブのリレー: 名前空間の発見

- [x] MQ23-187 PUBLISH_NAMESPACE はパブリッシャーごとに受け入れなければならない(複数のパブリッシャーが 1 つの名前空間を共有してよい)。1 つのセッションが同じプレフィックスを 2 回以上 PUBLISH_NAMESPACE した場合、それぞれに REQUEST_OK を返し、すべてが取り下げられるまで公開したままにしなければならない。
  - test: `tests/app/moqtrun_ns_test.c` — `test_moqtrun_ns_publish_accepted`
  - test: `tests/app/moqtrun_ns_test.c` — `test_moqtrun_ns_multiple_publishers`
  - test: `tests/app/moqtrun_nsx_test.c` — `test_moqtrun_nsx_refcount_one_withdraw_still_known`
  - test: `tests/app/moqtrun_nsx_test.c` — `test_moqtrun_nsx_refcount_done_on_last`
  - test: `tests/app/moqtrun_nsx_test.c` — `test_moqtrun_nsx_two_publishers_same_ns`
- [x] MQ23-281 (SS3.6, SS9.19.21) Track が N 個の SUBSCRIBE_TRACKS に一致する場合、ハブはそれぞれのために 1 つずつ PUBLISH を送り、その PUBLISH に SUBSCRIBE_TRACKS_ID (0x36) として元の SUBSCRIBE_TRACKS の Request ID を入れなければならない。
  - test: `tests/app/moqtrun_nsx_test.c` — `test_moqtrun_nsx_overlap_tracks_each_publish`
  - test: `tests/app/moqtrun_nsx_test.c` — `test_moqtrun_nsx_track_after_two_requests`
  - test: `tests/app/moqtrun_nsx_test.c` — `test_moqtrun_nsx_track_outside_prefix`
  - test: `tests/app/moqtrun_nsx_test.c` — `test_moqtrun_nsx_tracks_cancel_stops`
- [x] MQ23-282 (SS9.19.21) SUBSCRIBE_TRACKS_ID を含むクライアントの PUBLISH を受信した場合、ハブは INVALID_PARAMETER でセッションを閉じなければならない(ハブは SUBSCRIBE_TRACKS を送らない)。
  - test: `tests/app/moqtrun_nsx_test.c` — `test_moqtrun_nsx_client_publish_tagged`
- [x] MQ23-283 (SS3.4.1) SUBSCRIBE_TRACKS が FILL_PARAMETERS を含む場合、ハブはそれを各 PUBLISH に写し、一時停止していなければ PUBLISH を送るときに fill を開かなければならない。その PUBLISH が拒否されるか購読に結び付かなければ、fill のストリームをリセットする。
  - test: `tests/app/moqtrun_nsx_test.c` — `test_moqtrun_nsx_tracks_fill_opens`
  - test: `tests/app/moqtrun_nsx_test.c` — `test_moqtrun_nsx_tracks_fill_paused`
  - test: `tests/app/moqtrun_nsx_test.c` — `test_moqtrun_nsx_tracks_fill_too_long`
  - test: `tests/app/moqtrun_nsx_test.c` — `test_moqtrun_nsx_tracks_fill_rejected_resets`
  - test: `tests/app/moqtrun_nsx_test.c` — `test_moqtrun_nsx_tracks_fill_cancel_resets`
  - test: `tests/app/moqtrun_nsx_test.c` — `test_moqtrun_nsx_tracks_fill_unattached_resets`
- [x] MQ23-284 (SS7.8, SS12.3) 1 つの下流の SUBSCRIBE を複数の告知元へ送った場合、ハブはどれかが OK を返したら SUBSCRIBE_OK で応答し、すべてが失敗したときだけ最後の失敗のコード(セッションが失われたなら INTERNAL_ERROR)で REQUEST_ERROR を返さなければならない。失敗した上流の SUBSCRIBE は忘れ、次の下流の SUBSCRIBE か、その告知元の新しい PUBLISH_NAMESPACE で送り直す。
  - test: `tests/app/moqtrun_nsx_test.c` — `test_moqtrun_nsx_fan_one_fails`
  - test: `tests/app/moqtrun_nsx_test.c` — `test_moqtrun_nsx_fan_all_fail`
  - test: `tests/app/moqtrun_nsx_test.c` — `test_moqtrun_nsx_fan_all_fail_last_code`
  - test: `tests/app/moqtrun_nsx_test.c` — `test_moqtrun_nsx_fan_fail_then_loss`
  - test: `tests/app/moqtrun_nsx_test.c` — `test_moqtrun_nsx_fan_loss_then_fail`
  - test: `tests/app/moqtrun_nsx_test.c` — `test_moqtrun_nsx_refused_then_resent`
  - test: `tests/app/moqtrun_nsx_test.c` — `test_moqtrun_nsx_redsub_while_pending`
  - test: `tests/app/moqtrun_nsx_test.c` — `test_moqtrun_nsx_reannounce_while_sub`
  - test: `tests/app/moqtrun_nsx_test.c` — `test_moqtrun_nsx_other_pubns_keeps_refusal`
- [~] MQ23-285 (SS9.15) NAMESPACE は Track Namespace Suffix の後に Number of Parameters と Parameters を持つ。ハブは Number of Parameters を 0 として送らなければならない。
  - evidence: `moqtrun_ns_test.c` の補助関数 `mtns_ns_body` は、draft-23 のセッションへの NAMESPACE の最後のバイトが 0 であることを確かめてから、残りを Suffix として読みます。専用のテスト関数はありません。

## ハブのリレー: GOAWAY と PUBLISH_DONE

- [~] MQ23-188 `wired_moqt_goaway` は、セッションごとに GOAWAY を 1 回だけ送信しなければならない。その後に届いたリクエストは GOING_AWAY で拒否する。タイムアウトが切れたら、ハブは PUBLISH_DONE を送信し、まだ処理中のものに応答し、GOAWAY_TIMEOUT で閉じる。
  - test: `tests/app/moqtrun_drain_test.c` —
    `test_moqtrun_goaway_once_per_session`
  - test: `tests/app/moqtrun_drain_test.c` — `test_moqtrun_goaway_late_rejected`
  - test: `tests/app/moqtrun_drain_test.c` —
    `test_moqtrun_goaway_timeout_flush_then_close`
  - test: `tests/app/moqtrun_drain_test.c` — `test_moqtrun_goaway_retried_on_tick`
  - evidence: io テーブルに対する単体テストだけです。GOAWAY とドレインの手順を、サードパーティの MOQT のピアと動かしたことはまだありません。
- [x] MQ23-189 ピアからの 2 回目の GOAWAY は UNEXPECTED_MESSAGE で、クライアントからの New Session URI を含む GOAWAY は ROLE_VIOLATION で、セッションを閉じなければならない。
  - test: `tests/app/moqtrun_drain_test.c` — `test_moqtrun_peer_goaway_twice`
  - test: `tests/app/moqtrun_drain_test.c` — `test_moqtrun_peer_goaway_uri`
- [x] MQ23-190 PUBLISH_DONE の前に、ハブは購読のデータストリーム(開いている fill fetch ストリームも含む。MQ23-143 を参照)をリセットしなければならない。パブリッシャーのセッションが終わると、その購読者へ PUBLISH_DONE TRACK_ENDED を送る。
  - test: `tests/app/moqtrun_drain_test.c` —
    `test_moqtrun_done_resets_streams_first`
  - test: `tests/app/moqtrun_drain_test.c` — `test_moqtrun_done_track_ended`
- [~] MQ23-191 ピアからの WebTransport の WT_DRAIN_SESSION(`wired_moqt_on_session_draining`)は、そのセッションについてだけ MOQT の GOAWAY の手順を始めなければならない。
  - test: `tests/app/moqtrun_drain_test.c` — `test_moqtrun_drain_one_session`
  - evidence: 単体テストだけです。実際のピアとはまだ動かしていません。

## ハブのリレー: Object Datagram

- [x] MQ23-192 Object Datagram は、そのエイリアスが名指す Track のすべての購読者へバイト単位で同一のまま中継しなければならない。エイリアスがどの Established の購読も名指さないデータグラムは落とさなければならない(SS3.1.3.1)。
  - test: `tests/app/moqdg_test.c` — `test_moqdg_roundtrip_golden`
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_dg_relays_identical_bytes_to_subscriber`
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_dg_relays_to_all_three_subscribers`
  - test: `tests/app/moqtrun_test.c` — `test_moqtrun_dg_unknown_alias_counts_bad`
- [x] MQ23-233 (SS11.2.1) 実装は、OBJECT_DATAGRAM を、その Type Flags が選ぶフィールド(PROPERTIES 0x01、END_OF_GROUP 0x02、ZERO_OBJECT_ID 0x04、DEFAULT_PRIORITY 0x08、STATUS 0x20)とともにデコード・エンコードしなければならない。PROPERTIES が立ち Properties Length が 0 なら MALFORMED_OBJECT で、STATUS と PROPERTIES が立ち Status が Normal でなければ INVALID_OBJECT_STATUS で、セッションを閉じる。
  - test: `tests/app/moqdg_test.c` — `test_moqdg_type_valid_accepts`
  - test: `tests/app/moqdg_test.c` — `test_moqdg_type_valid_rejects`
  - test: `tests/app/moqdg_test.c` — `test_moqdg_take_props`
  - test: `tests/app/moqdg_test.c` — `test_moqdg_put_golden`
  - test: `tests/app/moqdg_test.c` — `test_moqdg_take_reject_golden`
  - test: `tests/app/moqtrun_cc_test.c` — `test_moqtrun_cc`
- [x] MQ23-234 (SS11, SS11.2.1) データグラムが未知の型か無効な Type Flags を持つ場合、ハブは INVALID_STREAM_HEADER (0x200) でセッションを閉じなければならない。
  - test: `tests/app/moqtrun_cc_test.c` — `test_moqtrun_cc`
  - test: `tests/app/moqtrun_test.c` — `test_moqtrun_dg_malformed_counts_bad`

## 複数ドラフト対応の回で完成したハブの機能(台帳 10 章)

- [x] MQ23-193 (SS9.17) ハブは、SUBSCRIBE_TRACKS に、そのリクエストストリームで REQUEST_OK をちょうど 1 つ応答しなければならない。同じセッションの SUBSCRIBE_TRACKS や SUBSCRIBE_NAMESPACE とプレフィックスが重なっても拒否しない。SUBSCRIBE_TRACKS が運んでよいパラメーターは §9.17 の一覧に限る。
  - test: `tests/app/moqtrun_subtracks_test.c` — `test_subtracks_ok_once`
  - test: `tests/app/moqtrun_nsx_test.c` — `test_moqtrun_nsx_overlap_tracks_each_publish`
  - test: `tests/app/moqtrun_nsx_test.c` — `test_moqtrun_nsx_overlap_ns_both`
  - test: `tests/app/moqctl_d23_test.c` — `test_moqctl_d23_scope`
- [x] MQ23-194 (SS9.17) 確立済みの SUBSCRIBE_TRACKS のプレフィックスに一致し、購読者自身が配信したものではない Track のそれぞれについて、ハブは、その Track を名指し SUBSCRIBE_TRACKS の PAUSED の値と SUBSCRIBE_TRACKS_ID を運ぶ PUBLISH を、新しい双方向ストリームで 1 つ開かなければならない。SUBSCRIBE_TRACKS を取り消すと新しい PUBLISH は止まるが、確立済みのものは残る。応答の前に消えた Track はその PUBLISH ストリームをリセットし、REQUEST_ERROR の応答はスロットを解放する。PUBLISH_OK(REQUEST_OK)の応答は、PUBLISH の Track Alias で購読者の購読を開き、PUBLISH のパラメーターから始める(PAUSED 1 は Object を引き止める)。そのストリーム上の購読者の REQUEST_UPDATE は、SUBSCRIBE のものと同じように適用し、そこで応答する(台帳 12-11、12-18)。SS9.8 が PUBLISH に認める SUBSCRIBE_TRACKS のパラメーターである PAUSED と GROUP_ORDER は、PAUSED 0 も含めて与えられたとおりに返す(SS3.6.2「explicitly communicated」、台帳 12-19)。SS9.8 が PUBLISH から除く SUBSCRIBE_TRACKS の Object の Range Filter も、その購読の始まりには適用する(SS3.6.1「Objects published in the resulting Subscriptions can be filtered by any Range Filter」)。Range Filter が不正、重複、または MAX_FILTER_RANGES を超えている SUBSCRIBE_TRACKS は INVALID_FILTER で拒否する(SS3.3.2、台帳 12-26)。更新に失敗したら PUBLISH_DONE UPDATE_FAILED で終わらせ、その後ハブは PUBLISH ストリームに FIN を送る(SS9.5.1、SS9.9、台帳 12-27)。2 回目の REQUEST_OK または REQUEST_ERROR は UNEXPECTED_MESSAGE でセッションを閉じる(SS3.1、台帳 12-28)。
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
  - note: 台帳 10-2(E-2): ハブが始める PUBLISH の経路です。draft-19 のセッションで動かしています。ハブの経路はバージョンに依存しません。
- [x] MQ23-195 (SS9.18) そのような PUBLISH のための双方向ストリームをハブが開けない場合、ハブは代わりに SUBSCRIBE_TRACKS のリクエストストリームで PUBLISH_SKIPPED(Track Namespace Suffix, Track Name)を送信しなければならず、同じ Track の同じ世代について後から PUBLISH を送信してはならない。
  - test: `tests/app/moqtrun_subtracks_test.c` —
    `test_subtracks_skip_then_no_publish`
  - test: `tests/app/moqns_test.c` — `test_moqns_pub_skipped_roundtrip`
  - test: `tests/app/moqns_test.c` — `test_moqns_pub_skipped_rejects`
  - note: draft-19 のセッションで動かしています。ハブの経路はバージョンに依存しません。
- [x] MQ23-196 (SS9.5, SS9.5.2) FETCH、PUBLISH_NAMESPACE、SUBSCRIBE_NAMESPACE、SUBSCRIBE_TRACKS に対する、そのリクエストストリーム上の REQUEST_UPDATE は処理しなければならない。SUBSCRIBE_NAMESPACE のプレフィックスの更新への REQUEST_OK は、もう一致しない名前空間の NAMESPACE_DONE を兼ね、新しく一致する名前空間には NAMESPACE を送る。SUBSCRIBE_TRACKS のプレフィックスの更新は既存の購読に影響せず、その SUBSCRIBE_TRACKS のためにすでに PUBLISH した Track を再び PUBLISH してはならない。
  - test: `tests/app/moqtrun_upd_test.c` — `test_moqtrun_upd_on_fetch_stream`
  - test: `tests/app/moqtrun_upd_test.c` — `test_moqtrun_upd_on_fetch_stream_refused`
  - test: `tests/app/moqtrun_nsx_test.c` — `test_moqtrun_nsx_ns_narrow_implied_done`
  - test: `tests/app/moqtrun_nsx_test.c` — `test_moqtrun_nsx_ns_widen_new_only`
  - test: `tests/app/moqtrun_nsx_test.c` — `test_moqtrun_nsx_ns_narrow_rewiden`
  - test: `tests/app/moqtrun_nsx_test.c` — `test_moqtrun_nsx_tracks_update_no_republish`
  - test: `tests/app/moqtrun_nsx_test.c` — `test_moqtrun_nsx_tracks_widen_publishes_new`
  - test: `tests/app/moqtrun_nsx_test.c` — `test_moqtrun_nsx_tracks_narrow_rewiden`
  - test: `tests/app/moqtrun_nsx_test.c` — `test_moqtrun_nsx_prefix_fieldwise`
- [x] MQ23-197 (SS9.11) GROUP_ORDER が Descending の FETCH には、新しい Group から順に応答しなければならず(Group の中の Object は昇順のまま)、本体のデコードに失敗した FETCH は、その原因のコード(MQ23-231 ほか)でセッションを閉じなければならない。
  - test: `tests/app/moqtrun_fetch_test.c` —
    `test_moqtrun_fetch_descending_group_order`
  - test: `tests/app/moqtrun_fetch_test.c` — `test_moqtrun_fetch_malformed_closes`
  - test: `tests/app/moqtrun_fetch_test.c` —
    `test_moqtrun_fetch_descending_unknown_groups`,
    `test_moqtrun_fetch_descending_missing_group_unknown`,
    `test_moqtrun_fetch_descending_start_object`
  - note: 台帳 10-6。draft-19 のセッションで動かしています。ハブの経路はバージョンに依存しません。欠落は 3.2.2 を文字どおりに読んで扱います(最初に期待するのは {End.Group, 0}、最後は {Start.Group, 2^64-1}、Group をまたぐ欠落は複数の論理的な欠落とする)。受信していない Group は存在しないとは見なさず(SS2.1.2)、キャッシュが保証できない Group にはそれぞれ専用の End of Unknown Range を付けます([既知の制限](../security/limitations/moqt-drafts.md)を参照)。
- [x] MQ23-198 (SS3.3.1) ライブの Track に後から加わった購読者は、その Location Filter の始点の Group から始めなければならない。ライブの先端より前の始点は現在の Group に切り詰め、未来の始点はその Group まで配送を止める。
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
- [x] MQ23-199 (SS9.1.6, SS9.1.7) ハブの SETUP は、MAX_FILTER_RANGES と MAX_REQUEST_UPDATES(どちらも 4。`WIRED_MOQTRUN_MAX_FILTER_RANGES` / `WIRED_MOQTRUN_MAX_REQ_UPDATES`)を広告し、ピアのものをデコードしなければならない。オプションがなければドラフトの既定値 0 のままとする。
  - test: `tests/app/moqtrun_test.c` — `test_moqtrun_setup_advertises_limits`
  - test: `tests/app/moqctl_test.c` — `test_moqctl_setup_limit_options_roundtrip`
  - test: `tests/app/moqctl_test.c` — `test_moqctl_setup_limit_options_default_zero`
  - note: 台帳 10-11。
- [x] MQ23-200 (SS9.1.7, SS9.5) 応答していない REQUEST_UPDATE をすでに MAX_REQUEST_UPDATES 個抱えたリクエストストリームでは、もう 1 つ届いたら TOO_MANY_REQUEST_UPDATES でセッションを閉じなければならない。REQUEST_OK と REQUEST_ERROR は、それが応答した更新の分だけ枠を戻す。リクエストが終わった後に捨てた更新は応答しないので、枠を占めたままになる。
  - test: `tests/app/moqtrun_upd_test.c` — `test_moqtrun_upd_credit_too_many`
  - test: `tests/app/moqtrun_upd_test.c` — `test_moqtrun_upd_credit_restored_by_flush`
  - test: `tests/app/moqtrun_d23uo_test.c` — `test_moqtrun_d23uo_over_credit_closes`
  - test: `tests/app/moqtrun_d23uo_test.c` — `test_moqtrun_d23uo_over_credit_after_end`
  - test: `tests/app/moqtrun_d23uo_test.c` — `test_moqtrun_d23uo_flush_keeps_dropped_outstanding`
  - test: `tests/app/moqtrun_d23uo_test.c` — `test_moqtrun_d23uo_error_credits_only_answered`
  - test: `tests/app/moqtrun_d23uo_test.c` — `test_moqtrun_d23uo_honest_peer_never_closed`
  - gap: 応答をキューに入れられなかったときにも枠を戻してしまう問題が残っています([#223](https://github.com/hakkadaikon/wired/issues/223))。
- [x] MQ23-201 (SS3.3.2, SS8.6) Range Filter のパラメーターは、差分を解決してデコードし、検証しなければならない。デコードできない値、1 つのメッセージで繰り返された (Type, SetID)、広告した MAX_FILTER_RANGES を超える Range の総数(SUBSCRIBE、FETCH、REQUEST_UPDATE)は INVALID_FILTER とする。REQUEST_UPDATE は、触れたフィルターの型を丸ごと置き換え、長さ 0 の値はそれを取り除く。SetID どうしは OR で結び、OBJECTID_FILTER はデータグラムで転送する各 Object を制御する。
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

moqtail 互換の Track 切り替えの拡張は、draft-23 の要件ではありません。項目とテストは [draft-22 の台帳](draft-moq-transport-22.md)の同名の節にあります。draft-23 のセッションで変わる点は 1 つで、SSTS_ALGORITHMS の Setup Option を 0x09(draft-23 の MAX_CONTROL_MESSAGE_SIZE)から 0x3F01 に移しています。

- [x] MQ23-X10 (SSTS_ALGORITHMS) ハブは、draft-23 のセッションでは SSTS_ALGORITHMS を Setup Option 0x3F01 で送受信しなければならない。
  - test: `tests/app/moqctl_test.c` — `test_moqctl_setup_d23_ssts_moved`

## 未実装

draft-23 のリレーの範囲内ですが、まだ実装していない項目と、実装に残っている既知の制限です。各行の issue で追っています。

- (SS9.1.7) 応答をキューに入れられなかった REQUEST_UPDATE の枠を戻してしまう: [#223](https://github.com/hakkadaikon/wired/issues/223)。
- (SS9.2) 上流の FETCH のストリームで GOAWAY を受けたときの FETCH の送り直し: [#239](https://github.com/hakkadaikon/wired/issues/239)。

## 対象外

このハブリレーのサブセットが実装しない機能と要件です。上のカバレッジの分母から除いています。draft-22 と共通の項目は [draft-22 の台帳の対象外](draft-moq-transport-22.md#対象外)を参照してください。draft-23 で加わったものは次のとおりです。

- (SS3.6) SUBSCRIBE_TRACKS の購読者が SUBSCRIBE_TRACKS_OK か REQUEST_ERROR 以外を受けたときの UNEXPECTED_MESSAGE: ハブは SUBSCRIBE_TRACKS を送りません。
- (SS3.7, SS9.12) 上流の TRACK_STATUS_OK の Mandatory Track Property への TRACK_STATUS_ERROR UNSUPPORTED_EXTENSION: ハブは TRACK_STATUS を上流へ送らず、自分で応答します。
- (SS4.1) PUBLISH_NAMESPACE への 2 つ目の応答と、(SS4.2) NAMESPACE より前の NAMESPACE_DONE: 受信するのは PUBLISH_NAMESPACE と SUBSCRIBE_NAMESPACE の送信者で、ハブはどちらも送りません。
- (SS7.6) CONFLICTING_FILTERS による名前空間の購読の拒否(MAY): 使いません。
- (SS9.4.2.1) 名前空間を対象とするリクエストへの空でない Track Name の REDIRECT を受けたときの INVALID_FIELD: ハブは名前空間を対象とするリクエストを送りません。
- (SS9.9) 認可のトークンが失効したときに PUBLISH_DONE EXPIRED_AUTH_TOKEN を送ること: ハブはトークンの失効を判定しません。上流から受けたものは伝えます(MQ23-267)。
- (SS9.12) TRACK_STATUS を上流へ転送するか、購読を始めて答えること(MAY): ハブは TRACK_STATUS に自分のキャッシュから応答します。
- (SS15.6) タイムアウトを置く箇所とその設定の指針: 説明の節で、要件はありません。
