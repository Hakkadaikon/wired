[ドキュメント](../README.md) › [機能](README.md) › draft-ietf-moq-transport-18

# draft-ietf-moq-transport-18: Media over QUIC Transport

仕様の本文(`tasks/specs/draft-ietf-moq-transport-18.txt`。git には含まない)から抽出した、この SDK の MOQT サブセットについての EARS 形式の要件台帳です。対象は WebTransport 上の中央ハブリレー 1 つで、SETUP、GOAWAY、PUBLISH、SUBSCRIBE(Location Filter、FORWARD、優先度、2 種類の配信タイムアウトを含む)、SUBSCRIBE・FETCH・名前空間リクエストに対する REQUEST_UPDATE、TRACK_STATUS、FETCH(単独と joining。Group 単位のキャッシュから返す)、PUBLISH_NAMESPACE / SUBSCRIBE_NAMESPACE、SUBSCRIBE_TRACKS(ハブが始める PUBLISH または PUBLISH_BLOCKED)、PUBLISH_DONE、そして Subgroup ストリームと Object Datagram での Object 配信を実装します。ピアが WebTransport のサブプロトコル `moqt-18` をネゴシエートしたとき、セッションは draft-18 で話します。データプレーンは draft-19 とバイト単位で同じです。このファイルには draft-18 に存在する要件だけを載せます(draft-19 に無いもの、draft-19 と書き方が違うものもあります。各項目の注記を参照してください)。draft-19 と一字一句同じ要件は、そちらの台帳の文言とテスト参照をそのまま使います。このファイルがあるのは、draft-18 だけを読む人が別のドラフトの台帳と突き合わせずに済むようにするためです。各要件には、それを確かめるテストを付けています。チェックがなくテスト行もない項目は、未解決のギャップです。

ハブはすべてのセッション、Track、キャッシュを 1 つのプロセスのメモリに持ちます。`examples/moqt_chat` と同じように、単一プロセス(`--workers`、`--cores`、AF_XDP の分散なし)で動かしてください。

凡例:

- `[x]`: 挙げたテストで確認済み
- `[~]`: 間接的に確認(専用のテストはなく、evidence 行で確かめ方を説明)
- `[ ]`: まだどのテストでも確認していない

**カバレッジ: テスト済み 219/248、間接 27、未テスト 2。**

## SS1.4.1 可変長整数

- [x] MQ18-001 実装は、MOQT の可変長整数を、先頭バイトの先頭から続く 1 のビットの数でエンコード長(1〜9 バイト)を決め、残りのビットと後続のバイトにネットワークバイトオーダーで値が入っているものとしてデコードしなければならない。
  - test: `tests/app/moqvi_test.c` — `test_moqvi_decode_official_examples`
  - test: `tests/app/moqvi_test.c` — `test_moqvi_decode_zero_all_lengths`
  - test: `tests/app/moqvi_test.c` — `test_moqvi_decode_nine_byte_padded`
- [x] MQ18-002 実装は、64 ビット符号なし整数のすべての値(0 から 2^64-1)を MOQT の可変長整数エンコーディングでエンコードしなければならない。
  - test: `tests/app/moqvi_test.c` — `test_moqvi_encode_official_examples`
  - test: `tests/app/moqvi_test.c` — `test_moqvi_encode_boundaries`
- [x] MQ18-003 実装は、可変長整数を、値を表せる最小のバイト数でエンコードしなければならない。
  - test: `tests/app/moqvi_test.c` — `test_moqvi_roundtrip`
  - test: `tests/app/moqvi_test.c` — `test_moqvi_encode_official_examples`
- [x] MQ18-004 可変長整数が必要最小限より多いバイト数でエンコードされている場合でも、実装は正しい値にデコードしなければならない(最小でないエンコーディングも有効)。
  - test: `tests/app/moqvi_test.c` — `test_moqvi_decode_zero_all_lengths`
  - test: `tests/app/moqvi_test.c` — `test_moqvi_decode_nine_byte_padded`
- [x] MQ18-005 可変長整数のエンコード長が利用できるバイト数を超える場合、実装は入力の終わりを越えて読まず、デコードをデータ不足として報告しなければならない。
  - test: `tests/app/moqvi_test.c` — `test_moqvi_decode_truncated`
- [x] MQ18-006 実装は、可変長整数を自身のエンコード長を越えてバイトを消費せずにデコードし、入力の後続のバイトに手を付けずに残さなければならない。
  - test: `tests/app/moqvi_test.c` — `test_moqvi_decode_ignores_trailing`
- [x] MQ18-007 出力先バッファーが値のエンコード長を収めるには小さすぎる場合、実装はバッファーを越えて書かず、エンコードを失敗させなければならない。
  - test: `tests/app/moqvi_test.c` — `test_moqvi_put_too_small`

## SS1.4.2 Location 構造

- [x] MQ18-008 実装は、Location を連続する 2 つの可変長整数(Group, Object)としてエンコード・デコードしなければならない。
  - test: `tests/app/moqctl_test.c` —
    `test_moqctl_location_roundtrip_and_order`
- [x] MQ18-009 実装は、2 つの Location A と B を、A.Group < B.Group であるか、A.Group == B.Group かつ A.Object < B.Object であるときに限り A < B となるように比較しなければならない。
  - test: `tests/app/moqctl_test.c` —
    `test_moqctl_location_roundtrip_and_order`

## SS1.4.3 Key-Value-Pair 構造

- [x] MQ18-010 実装は、Key-Value-Pair の Type を、直前までの累積 Type に Delta Type を足した値(最初のペアでは 0 に足す)としてデコードしなければならない。
  - test: `tests/app/moqkvp_test.c` — `test_moqkvp_take_even_num`
  - test: `tests/app/moqkvp_test.c` — `test_moqkvp_take_delta_accumulates`
- [x] MQ18-011 Key-Value-Pair の累積 Type が 2^64-1 を超えることになる場合、実装はプロトコル違反を報告しなければならない。
  - test: `tests/app/moqkvp_test.c` — `test_moqkvp_take_type_overflow`
- [x] MQ18-012 実装は、Type が奇数の Key-Value-Pair の Value を Length バイトのデータとして、Type が偶数のペアの Value を 1 つの可変長整数としてデコードしなければならない。
  - test: `tests/app/moqkvp_test.c` — `test_moqkvp_take_even_num`
  - test: `tests/app/moqkvp_test.c` — `test_moqkvp_take_odd_raw`
- [x] MQ18-013 Key-Value-Pair の Length フィールドは 2^16-1 バイトを超えてはならない。それより大きい長さを受信したら、実装はプロトコル違反を報告しなければならない。
  - test: `tests/app/moqkvp_test.c` — `test_moqkvp_take_len_65535_accepted`
  - test: `tests/app/moqkvp_test.c` — `test_moqkvp_take_len_65536_violation`
  - vuln: V-0799
- [x] MQ18-014 (§1.4.3) Key-Value-Pair の Value が、実装の理解する Type に定められたシリアライズ形式に合わない場合、実装はプロトコル違反とは区別して、KEY_VALUE_FORMATTING_ERROR でセッションを閉じなければならない。
  - test: `tests/app/moqctl_test.c` —
    `test_moqctl_params_auth_token_malformed_kvfmt`
- [x] MQ18-015 実装は、Key-Value-Pair の Delta Type や偶数 Type の Value が最小のエンコード長であることを、デコードの条件にしてはならない(最小でないエンコーディングも有効)。
  - test: `tests/app/moqkvp_test.c` — `test_moqkvp_take_nonminimal_delta`
  - test: `tests/app/moqkvp_test.c` — `test_moqkvp_take_nonminimal_even_value`
- [x] MQ18-016 (§1.4.3) Key-Value-Pair が自身の既知のバイト範囲の中で途切れている場合、実装はその範囲を越えて読まず、データ不足として報告しなければならない。
  - test: `tests/app/moqkvp_test.c` — `test_moqkvp_take_truncated_insufficient`
- [x] MQ18-017 実装は、Key-Value-Pair を呼び出し側が渡したバイト範囲を越えて読まずにデコードし、Type の順序を保ったまま、ラウンドトリップできる Key-Value-Pair のリストをエンコードしなければならない。
  - test: `tests/app/moqkvp_test.c` — `test_moqkvp_roundtrip`

## SS1.4.4 Reason Phrase 構造

- [x] MQ18-018 実装は、Reason Phrase を、可変長整数の Length と、それに続くその長さの UTF-8 のバイト列としてデコードしなければならない。
  - test: `tests/app/moqctl_test.c` — `test_moqctl_reason_boundary`
  - vuln: V-0800
- [~] MQ18-019 (§1.4.4) Reason Phrase の Length が 1024 バイトを超える場合、実装はプロトコル違反でセッションを閉じなければならない。
  - evidence: コーデックは違反を報告し(`test_moqctl_reason_boundary`)、ハブはデコードに失敗したリクエストや SETUP に対して PROTOCOL_VIOLATION で閉じる(`test_moqtrun_fillfix_malformed_subscribe`、`test_moqtrun_setup_malformed_closes`)。ただし、この条件を送るハブのテストはない。
## SS2.4.1 Track の命名

- [x] MQ18-020 実装は、Track Namespace を、可変長整数のフィールド数と、それに続くその数の長さ付き Track Namespace Field としてデコードしなければならない。
  - test: `tests/app/moqctl_test.c` — `test_moqctl_ftn_decode_basic`
- [~] MQ18-021 (§2.4.1) Track Namespace Field の Length が 0 の場合、実装はプロトコル違反でセッションを閉じなければならない。
  - evidence: コーデックは違反を報告し(`test_moqctl_ns_field_len_zero_rejected`)、ハブはデコードに失敗したリクエストや SETUP に対して PROTOCOL_VIOLATION で閉じる(`test_moqtrun_fillfix_malformed_subscribe`、`test_moqtrun_setup_malformed_closes`)。ただし、この条件を送るハブのテストはない。
- [~] MQ18-022 (§2.4.1) Track Namespace の Track Namespace Field が 32 個を超える場合、実装はプロトコル違反でセッションを閉じなければならない。
  - evidence: コーデックは違反を報告し(`test_moqctl_ns_fields_32_accept_33_reject`)、ハブはデコードに失敗したリクエストや SETUP に対して PROTOCOL_VIOLATION で閉じる(`test_moqtrun_fillfix_malformed_subscribe`、`test_moqtrun_setup_malformed_closes`)。ただし、この条件を送るハブのテストはない。
- [~] MQ18-023 (§2.4.1) Full Track Name(Track Namespace と Track Name)が 4096 バイトを超える場合、実装はプロトコル違反でセッションを閉じなければならない。
  - evidence: コーデックは違反を報告し(`test_moqctl_ftn_4096_accept_4097_reject`)、ハブはデコードに失敗したリクエストや SETUP に対して PROTOCOL_VIOLATION で閉じる(`test_moqtrun_fillfix_malformed_subscribe`、`test_moqtrun_setup_malformed_closes`)。ただし、この条件を送るハブのテストはない。
- [x] MQ18-024 実装は、Track Namespace Field と Track Name をバイト列の完全一致で比較しなければならない。
  - test: `tests/app/moqctl_test.c` — `test_moqctl_ftn_eq_exact_bytes`

## SS2.4.2 不正な形式の Track

- [x] MQ18-025 (§2.4.2) ハブが Malformed Track(MQ18-207 に挙げた条件のもの)を検出した場合、ハブはそのパブリッシャーからのその Track に対する購読や FETCH を取り消さなければならない。
  - test: `tests/app/moqtrun_done_test.c` —
    `test_moqtrun_pubdone_malformed_after_end_of_track`
  - test: `tests/app/moqtrun_upfetch_test.c` —
    `test_moqtrun_upfetch_malformed_past_end`
  - note: 受信側の一般的な条件の一覧(同じ Subgroup ID の中での Publisher Priority の変化、Subgroup の最後の Object より後の Object、食い違う最後の Object、Forwarding Preference の変化)は確かめていない。「対象外」を参照。
- [x] MQ18-207 (§2.4.2, §9.1) ハブがリレーとして Malformed Track を検出した場合(Track の END_OF_TRACK や Group の END_OF_GROUP より後の Object、上流の FETCH で FETCH_OK の End Of Track より後の Object やキャッシュ済みの Object とペイロードが食い違う Object)、ハブはただちに下流の購読を PUBLISH_DONE MALFORMED_TRACK で終え、その Track の FETCH ストリームを MALFORMED_TRACK でリセットしなければならず、きっかけになった Object をキャッシュしてはならない。
  - test: `tests/app/moqtrun_done_test.c` —
    `test_moqtrun_pubdone_malformed_after_end_of_track`
  - test: `tests/app/moqtrun_done_test.c` —
    `test_moqtrun_pubdone_malformed_after_end_of_group`
  - test: `tests/app/moqtrun_done_test.c` —
    `test_moqtrun_pubdone_malformed_resets_fetch`
  - test: `tests/app/moqtrun_upfetch_test.c` —
    `test_moqtrun_upfetch_malformed_past_end`
  - test: `tests/app/moqtrun_upfetch_test.c` —
    `test_moqtrun_upfetch_malformed_conflict`
  - note: PUBLISH_DONE のシナリオはすべてのドラフトで動き、上流 FETCH のシナリオは draft-22 のセッションで動く(この確認はバージョンに依存しない)。

## SS2.5 Property / SS2.5.1 Mandatory Track Property

- [~] MQ18-026 (§2.5) リレーは、型がアプリケーション固有の範囲 0x38-0x3F と 0x3800-0x3FFF に入る Property を、解釈せずにそのまま転送しなければならない。
  - evidence: これらの範囲の Property 型をハブは読まない(`moqtrun_tprop` は未知の型を読み飛ばす)。Track Property は受け取ったまま転送し(MQ18-208)、Object Property はリレーする Object のバイト列に含まれて運ばれる(`test_moqtrun_object_relay_preserves_bytes`)。これらの範囲の Property を送るテストはない。
  - note: draft-18 の §15.8 は 1 バイトのアプリケーション範囲を 0x78-0x7F としており、§2.5 の 0x38-0x3F と食い違う。draft-19 は 0x78-0x7F に決めた(`draft18-vs-19-diff.md` の SS11 を参照)。
- [x] MQ18-027 (§2.5.1) PUBLISH または上流の SUBSCRIBE_OK が、ハブの理解しない Mandatory Track Property(型 0x4000-0x7FFF)を含む場合、ハブはその Track を処理も転送もしてはならない。PUBLISH なら REQUEST_ERROR UNSUPPORTED_EXTENSION で拒否し、上流の SUBSCRIBE_OK なら上流の購読を取り消して、待っている下流の購読者に REQUEST_ERROR UNSUPPORTED_EXTENSION を送らなければならない。
  - test: `tests/app/moqtrun_sub_test.c` — `test_moqtrun_sub_publish_mandatory_refused`
  - test: `tests/app/moqtrun_upsub_test.c` — `test_moqtrun_upsub_ok_mandatory_refused`
- [~] MQ18-208 (§2.5, §9.6) Track をリレーするとき、ハブはパブリッシャーの Track Property を未知のものも含めて変えずに SUBSCRIBE_OK で転送し、その Track の後の PUBLISH が来たら、保持している組を(マージせずに)置き換えなければならない。
  - evidence: `test_moqtrun_sub_include_properties_1_forwards` は、PUBLISH の Property が後の SUBSCRIBE_OK に入っていることを確かめる(パラメーターなしの購読者はすべてのドラフトで動く)。置き換えは作りによるもので(`moqtrun_track_keep_props`)、テストはない。
  - test: `tests/app/moqtrun_sub_test.c` — `test_moqtrun_sub_props_long_forwarded`
  - note: `WIRED_MOQTRUN_TRACK_PROPS_MAX`(96 バイト)より長いブロックは、空のまま転送せず、その Track を INTERNAL_ERROR で拒否する。
- [x] MQ18-220 (§9.6, §10.14) ハブは、リレーする Track について自分が送る、ハブが始める PUBLISH、TRACK_STATUS の REQUEST_OK、FETCH_OK のすべてに、その Track の Track Property を含めなければならない。
  - test: `tests/app/moqtrun_subtracks_test.c` — `test_subtracks_publish_carries_props`
  - test: `tests/app/moqtrun_upd_test.c` — `test_moqtrun_tstat_ok_props`
  - test: `tests/app/moqtrun_fetch_test.c` — `test_moqtrun_fetch_ok_props`
- [x] MQ18-209 (§2.5.1) 上流の FETCH_OK がハブの理解しない Mandatory Track Property を含む場合、ハブはその上流の FETCH を取り消し、下流の FETCH にまだ応答していなければ REQUEST_ERROR UNSUPPORTED_EXTENSION で応答し、すでにデータを送っていればその FETCH ストリームをリセットしなければならない。
  - test: `tests/app/moqtrun_upfetch_test.c` — `test_moqtrun_upfetch_mandatory`
  - note: draft-22 のセッションで動かす。この確認はバージョンに依存しない。
- [x] MQ18-239 (§12.5, §12.6) 1-2 の範囲外の Track Property DEFAULT_PUBLISHER_GROUP_ORDER、または 1 を超える DYNAMIC_GROUPS を受信した場合、実装は PROTOCOL_VIOLATION でセッションを閉じなければならない。
  - test: `tests/app/moqtrun_sub_test.c` — `test_moqtrun_sub_props_bad_values_close`
  - test: `tests/app/moqtrun_upsub_test.c` — `test_moqtrun_upsub_ok_bad_prop_closes`
- [x] MQ18-224 (§12.7) ハブが Property の値(DEFAULT_PUBLISHER_PRIORITY、SUBGROUP_DELIVERY_TIMEOUT など)を読むとき、ハブは変更可能な Property と Immutable Properties の中身の両方を探さなければならない。
  - test: `tests/app/moqtrun_sub_test.c` — `test_moqtrun_sub_props_immutable`

## SS3.2.1 予約済みの名前空間 / SS3.2.2 セッションレベルの Track

- [x] MQ18-028 リクエストが、最初のフィールドがピリオド 1 文字の Track Namespace を参照している場合、実装はそれを DOES_NOT_EXIST で拒否しなければならない。
  - test: `tests/app/moqtrun_sub_test.c` — `test_moqtrun_reserved_ns_rejected`
  - test: `tests/app/moqtrun_ns_test.c` — `test_moqtrun_ns_reserved_rejected`
  - test: `tests/app/moqtrun_sub_test.c` — `test_moqtrun_other_dot_ns_served`
  - note: `moqtrun_ns_reserved`(台帳 10-1)は、最初のフィールドがちょうど `.` か `.session` のものを、PUBLISH、SUBSCRIBE、PUBLISH_NAMESPACE、SUBSCRIBE_NAMESPACE で DOES_NOT_EXIST により拒否する。`.` で始まるほかのフィールドは通常の名前空間と同じように扱う。この確認はバージョンに依存しない。

## SS3.3 セッションの初期化

- [x] MQ18-029 サーバーは、単方向の制御ストリームを 1 本開き、最初のメッセージとして SETUP を送らなければならない。
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_token_session_opens_uni_ctl`
  - test: `tests/app/moqtrun_test.c` — `test_moqtrun_client_uni_ctl_accepted`
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_refused_uni_ctl_open_retries`
  - note: WT のトークンが空のセッション(ブラウザーのクライアントはサブプロトコルをネゴシエートできない)は、以前のドラフトの双方向の制御ストリーム 1 本のままにする(`test_moqtrun_empty_token_keeps_bidi_ctl`)。単方向の制御ストリームの組は draft-17 で導入されたもので、draft-18 はそれを変えずに引き継いでいる。
- [x] MQ18-030 両方のエンドポイントが SETUP を送受信し終えたら、セッションは Established にならなければならない。
  - test: `tests/app/moqsess_test.c` — `test_moqsess_establish`
  - test: `tests/app/moqsess_test.c` —
    `test_moqsess_established_accepts_request`
  - test: `tests/app/moqtrun_test.c` — `test_moqtrun_client_uni_ctl_accepted`
- [x] MQ18-031 (§3.3) 双方向のリクエストストリームは、最初に置ける型のメッセージ(TRACK_STATUS、SUBSCRIBE、PUBLISH、FETCH、PUBLISH_NAMESPACE、SUBSCRIBE_NAMESPACE、SUBSCRIBE_TRACKS)のどれかで始まらなければならない。そうでなければ、実装はプロトコル違反でセッションを閉じなければならない。
  - test: `tests/app/moqtrun_sub_test.c` —
    `test_moqtrun_req_bad_first_message_closes`
- [x] MQ18-032 Object を含む単方向ストリームや双方向のリクエストストリームが、両方の制御ストリームで SETUP が完了する前に届いた場合、実装はそれをアプリケーションに渡さず、バッファーに保持しなければならない。
  - test: `tests/app/moqsess_test.c` —
    `test_moqsess_buffer_before_setup_then_deliver`
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_token_requests_held_until_established`
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_token_object_stream_held_until_established`
- [x] MQ18-033 (§3.3) SETUP がまだ完了していない場合、実装は双方向のリクエストストリームをバッファーに保持する代わりにリセットしてもよい。
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_token_unbufferable_request_reset`
- [~] MQ18-034 (§10.3) エンドポイントは、自分の SETUP を送ったあと、ピアの SETUP を待たずに後続の制御メッセージをパイプラインで送ってもよい。
  - evidence: セッションの状態機械は片側だけ開いた状態を受け入れ(`test_moqsess_pipeline_before_peer_setup`)、SETUP の完了前に届いたリクエストは保持してから応答する(`test_moqtrun_token_requests_held_until_established`)。ピアの SETUP より先にパイプラインで制御メッセージを送るテストはない。
- [x] MQ18-035 セッションの存続中に制御ストリームがトランスポート層で閉じられた場合、実装はプロトコル違反でセッションを閉じなければならない。
  - test: `tests/app/moqsess_test.c` —
    `test_moqsess_ctrl_stream_transport_close`
  - test: `tests/app/moqtrun_test.c` — `test_moqtrun_ctl_fin_violates`
  - test: `tests/app/moqtrun_test.c` — `test_moqtrun_ctl_reset_violates`
- [x] MQ18-036 (§3.3) 同じピアが 2 本目の制御ストリームを開いた場合、実装はプロトコル違反でセッションを閉じなければならない。
  - test: `tests/app/moqsess_test.c` — `test_moqsess_second_control_stream`
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_second_ctl_stream_violates`
- [x] MQ18-210 (§3.3.2, §10.14) ハブがリクエストを REQUEST_ERROR で拒否するとき、ハブは応答のあとにリクエストストリームの自分の側を FIN で閉じなければならない。
  - test: `tests/app/moqtrun_sub_test.c` —
    `test_moqtrun_req_refusal_fins_and_frees`

## SS6.1 リクエストストリームの終了(draft-18: FIN は取り消し)

- [x] MQ18-037a (§6.1) SUBSCRIBE_NAMESPACE のリクエストストリームの一方向が FIN で閉じられた場合、実装はそれをそのリクエストの取り消しとして扱わなければならない。draft-19 以降では、FIN は取り消しではない正常な片側クローズであり、この点が異なる。
  - test: `tests/app/moqtrun_ns_test.c` — `test_moqtrun_ns_fin_cancels_d18`
  - note: これは draft-18 固有のワイヤー上の動作(`MOQVER_CAP_FIN_CANCEL_NS`)。`draft18-vs-19-diff.md` の SS2 "Request-stream FIN semantics" を参照。
- [~] MQ18-211 (§6.1) SUBSCRIBE_TRACKS のリクエストストリームの一方向が FIN で閉じられた場合、実装はそれをそのリクエストの取り消しとして扱わなければならない。
  - evidence: `moqtrun_req_fin_kind` は、SUBSCRIBE_NAMESPACE と並べて SUBSCRIBE_TRACKS を同じ `MOQVER_CAP_FIN_CANCEL_NS` の判定の下に挙げている。その SUBSCRIBE_NAMESPACE の側は `test_moqtrun_ns_fin_cancels_d18` が確かめる。draft-18 の SUBSCRIBE_TRACKS の FIN のテストはない。

## SS3.3.3 ストリームリセットのエラーコード / SS3.5 終了(使っている部分)

- [~] MQ18-037 (§3.5) 実装は、検出した状況に対して、draft-18 の表にあるセッション終了のエラーコード(NO_ERROR、INTERNAL_ERROR、PROTOCOL_VIOLATION、INVALID_REQUEST_ID、KEY_VALUE_FORMATTING_ERROR、INVALID_PATH、MALFORMED_PATH、GOAWAY_TIMEOUT、AUTH_TOKEN_CACHE_OVERFLOW、UNKNOWN_AUTH_TOKEN_ALIAS、INVALID_AUTHORITY、MALFORMED_AUTHORITY)を使わなければならない。
  - evidence: これらのコードはコーデックでラウンドトリップさせるのではなく、使う場所で `#define` している(moqctl.h/moqsess.h/moqraw.h/moqtrun_types.h)。表を列挙するテストはないが、各コードはそれぞれの違反の箇所で確かめている(このファイルの望ましくない動作の項目)。DUPLICATE_TRACK_ALIAS は MQ18-113 で送る。draft-18 はセッションのコード 0x1B(TOO_MANY_REQUEST_UPDATES。draft-19 のみ)を定義していない。「対象外」を参照。

## SS3.4 単方向ストリームの型

- [x] MQ18-038 実装は、単方向ストリームの先頭の可変長整数を、SETUP(0x2F00)、FETCH_HEADER(0x05)、SUBGROUP_HEADER(0b0XX1XXXX)、PADDING(0x132B3E28)のどれかに分類しなければならない。
  - test: `tests/app/moqdata_test.c` — `test_moqdata_classify_golden`
- [x] MQ18-039 (§3.4) エンドポイントが未知の単方向ストリーム型を受信した場合、実装はプロトコル違反でセッションを閉じなければならない。
  - test: `tests/app/moqtrun_sess_test.c` — `test_mtss_unknown_uni_closes`
  - test: `tests/app/moqtrun_sess_test.c` — `test_mtss_padding_stream_kept`
- [x] MQ18-040 実装は、途中で切れた先頭の型フィールドを越えてバイトを消費せずに単方向ストリームを分類し、その場合は分類をデータ不足として報告しなければならない。
  - test: `tests/app/moqdata_test.c` — `test_moqdata_classify_truncated`

## SS3.5 終了

- [x] MQ18-041 サーバーは、WebTransport で運ぶ MOQT セッションを CLOSE_WEBTRANSPORT_SESSION の仕組みで閉じなければならない。
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_ctl_unknown_type_closes_session`
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_ctl_pool_exhausted_closes`
  - test: `tests/app/moqtrun_sub_test.c` —
    `test_moqtrun_req_bad_first_message_closes`
  - evidence: ハブは io テーブルの `close_session` 操作(本番では `wired_server_wt_close_session`)を通し、ドラフトの終了コードで閉じる。WT_CLOSE_SESSION カプセルそのものは WebTransport の台帳で確かめている。

## SS3.6 セッションの移行 / SS10.4 GOAWAY(セッションのライフサイクル、draft-18 のレイアウト)

- [x] MQ18-042 (§10.4) GOAWAY を送信または受信したエンドポイントは、セッションを開いたまま、エンドポイントが終了しつつあることを示すエラーで新しいリクエストを拒否してもよい。
  - test: `tests/app/moqtrun_drain_test.c` — `test_moqtrun_goaway_late_rejected`
- [x] MQ18-043 (§10.4) 制御ストリームで GOAWAY を受信したエンドポイントは、自分から新しいリクエストを始めてはならない。ただし、GOAWAY だけを理由にセッションを閉じることはしない。
  - test: `tests/app/moqtrun_upfetch_test.c` —
    `test_moqtrun_upfetch_upsub_skips_goaway`
- [x] MQ18-044 (§3.6, §10.4) ピアが GOAWAY のタイムアウト内にセッションを閉じない場合、送信側は GOAWAY_TIMEOUT でセッションを閉じなければならない。
  - test: `tests/app/moqtrun_drain_test.c` —
    `test_moqtrun_goaway_timeout_flush_then_close`
- [x] MQ18-045 (§10.4) サーバーが New Session URI Length が 0 でない GOAWAY を受信した場合、実装はプロトコル違反でセッションを閉じなければならない。
  - test: `tests/app/moqtrun_drain_test.c` — `test_moqtrun_peer_goaway_uri`
- [x] MQ18-046 (§10.4) 同じ制御ストリームで GOAWAY を 2 回以上受信した場合、実装はプロトコル違反でセッションを閉じなければならない。
  - test: `tests/app/moqtrun_drain_test.c` — `test_moqtrun_peer_goaway_twice`
- [x] MQ18-047 (§10.4) GOAWAY を制御ストリームではなくリクエストストリームで受信した場合、実装はセッションを閉じずにそれを受け入れなければならない。ただし、同じリクエストストリームでの 2 回目の GOAWAY は、やはりプロトコル違反として扱わなければならない。
  - test: `tests/app/moqtrun_sub_test.c` —
    `test_moqtrun_req_second_goaway_closes`
- [x] MQ18-048a 実装は、末尾に Request ID(vi64)を持つ制御ストリームの GOAWAY をエンコード・デコードしなければならない。この Request ID は、送信側がまだ処理していない(または処理していない可能性がある)ピアの Request ID の最小値である。draft-19 以降では GOAWAY に Request ID フィールドがまったくなく、この点が異なる。
  - test: `tests/app/moqctl_test.c` — `test_moqctl_goaway18_request_id`
  - test: `tests/app/moqctl_test.c` — `test_moqctl_goaway18_vs_19_shape`
  - test: `tests/app/moqtrun_drain_test.c` —
    `test_moqtrun_goaway_request_id_d18`
  - test: `tests/app/moqtrun_drain_test.c` — `test_moqtrun_peer_goaway_d18`
  - test: `tests/app/moqtrun_drain_test.c` —
    `test_moqtrun_peer_goaway_d18_parity`
  - note: `MOQVER_CAP_GOAWAY_REQID`。`draft18-vs-19-diff.md` の SS4 を参照。
- [x] MQ18-048b サーバーが、自分の送った制御ストリームの GOAWAY に載せた値以上の Request ID を持つ draft-18 のリクエスト(またはその GOAWAY のあとに届いたリクエスト)を受信した場合、実装はそれを REQUEST_ERROR GOING_AWAY で拒否しなければならない。
  - test: `tests/app/moqtrun_sub_test.c` —
    `test_moqtrun_req_goaway_watermark_d18`
  - note: 既存のバージョンに依存しない `moqtrun_is_late` の判定で対応した(ハブは GOAWAY を 1 回しか送らないので、GOAWAY の送信後のリクエストをすべて拒否することは、その値以上の Request ID のリクエストをすべて拒否することと同じになる)。台帳 4-1 を参照。

## SS9 リレー(SS9.4/9.6/9.7 の転送の決まり)

- [x] MQ18-049 リレーは、複数の Object を運ぶストリームで受信した Object を購読者へ転送するとき、順序を入れ替えたり落としたりしてはならない。
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_object_relay_to_subscriber`
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_object_relay_two_subscribers_two_objects`
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_relay_forwards_bytes_as_they_arrive`
  - note: draft-18 の本文は、アプリケーション固有の理由による入れ替えや破棄の例外を認めているが、draft-19 はそれを削除した。実装はその例外を使わない(常に厳格)ので、この項目はどちらのドラフトでも成り立つ。
- [x] MQ18-050 リレーは、Object を転送するとき、Object のヘッダーフィールドやペイロードを変更してはならない。
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_object_relay_preserves_bytes`
- [x] MQ18-051 リレーは、下流の SUBSCRIBE に SUBSCRIBE_OK で応答する前に、Established の上流の購読を持っていなければならない。
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_subscribe_matching_publish_replies_ok`
  - test: `tests/app/moqtrun_upsub_test.c` —
    `test_moqtrun_upsub_ok_after_upstream`
- [x] MQ18-052 どのパブリッシャーも PUBLISH していない Track への SUBSCRIBE をリレーが受信した場合、実装は、その Track の名前空間またはその接頭辞を PUBLISH_NAMESPACE した(購読者以外の)セッションへ、上流の SUBSCRIBE を送らなければならない(SS9.5)。送るのはその時点か、保留した SUBSCRIBE なら PUBLISH_NAMESPACE が届いたときである。そして、その上流の購読が Established になったら SUBSCRIBE_OK で、拒否されたら上流のコードで REQUEST_ERROR で応答しなければならない。そのようなパブリッシャーがいない(かつ RENDEZVOUS_TIMEOUT もない)場合は、REQUEST_ERROR DOES_NOT_EXIST で応答しなければならない。
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_subscribe_without_publish_replies_error`
  - test: `tests/app/moqtrun_upsub_test.c` —
    `test_moqtrun_upsub_ok_after_upstream`,
    `test_moqtrun_upsub_error_relayed`,
    `test_moqtrun_upsub_hold_then_announce`,
    `test_moqtrun_upsub_own_namespace`, `test_moqtrun_upsub_prefix`,
    `test_moqtrun_upsub_cross_draft`
  - note: 上流の SUBSCRIBE はパラメーターを持たないので、FORWARD は 1 になり、下流の SUBSCRIBER_PRIORITY、GROUP_ORDER、配信タイムアウトは転送しない(§7.3, §9.2, §10.2.3/10.2.4)。下流の誰も必要としなくなった上流の購読は取り消す(`test_moqtrun_upsub_last_cancel_cancels_upstream`)。
  - note: 上流の SUBSCRIBE は Full Track Name ごとに 1 つで、最初に一致した告知元へ送る。ただし `multi_publisher` が有効なら、一致するパブリッシャーそれぞれに 1 つずつ送る(§9.5, MQ18-223)。
- [x] MQ18-228 (§10.2.6) パブリッシャーのいない Track への SUBSCRIBE が 0 でない RENDEZVOUS_TIMEOUT を持つ場合、ハブはそれを保留し、パブリッシャーが現れたら SUBSCRIBE_OK で、(上限を設けた)期限に達したら REQUEST_ERROR TIMEOUT で応答しなければならない。パラメーターがないか 0 なら、ただちに REQUEST_ERROR DOES_NOT_EXIST で応答しなければならない。
  - test: `tests/app/moqtrun_rdv_test.c` — `test_moqtrun_rdv_s2_timeout`
  - test: `tests/app/moqtrun_rdv_test.c` — `test_moqtrun_rdv_s3_zero_is_dne`
  - test: `tests/app/moqtrun_rdv_test.c` — `test_moqtrun_rdv_s4_resolve`
- [x] MQ18-229 (§10.2.13) 下流の SUBSCRIBE や REQUEST_UPDATE が NEW_GROUP_REQUEST を持つ場合、ハブはそれを上流の SUBSCRIBE に含めるか、Established の購読なら上流へ REQUEST_UPDATE で送らなければならない(値が 0 か Largest Group より大きく、Track が動的な Group に対応し、未処理の要求がないとき)。
  - evidence: `moqtrun_ngr_upstream` は待っている側の値を上流の SUBSCRIBE にコピーする(`test_moqtrun_upsub_ngr_in_subscribe`)。`moqtrun_ngr_relay` は 3 つの条件の下で、ハブ自身の上流の SUBSCRIBE ストリームに REQUEST_UPDATE を送り、Largest Group が進むまで未処理として扱う(`test_moqtrun_upsub_ngr_update`)。
  - test: `tests/app/moqtrun_upsub_test.c` —
    `test_moqtrun_upsub_ngr_on_publish` (PUBLISH で始まった Track。REQUEST_UPDATE は PUBLISH ストリームで運ばれ、その REQUEST_OK / REQUEST_ERROR の応答もそこで解析する)
  - note: 従来の双方向制御ストリーム 1 本で届いた PUBLISH には送らない。
- [x] MQ18-053 (§9.4, §9.5) 複数の購読者が同じ Track を要求したとき、リレーはその Track への認可済みの購読を集約してもよい。その場合、Established の上流の購読がある Track への SUBSCRIBE には SUBSCRIBE_OK で応答し、上流の 1 つの Object を一致する下流の購読者全員へ転送する。
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_chat_object_relays_to_all_three_subscribers`
  - test: `tests/app/moqtrun_upsub_test.c` —
    `test_moqtrun_upsub_two_share_one`
- [x] MQ18-223 (§9.3) リレーは、同じ Track について複数のパブリッシャーから届く Object を扱い、一致する Established の購読へ転送しなければならず、重複を取り除くべきである。
  - test: `tests/app/moqtrun_mpub_test.c` —
    `test_moqtrun_mpub_subscribes_every_announcer`,
    `test_moqtrun_mpub_dedup_streams`, `test_moqtrun_mpub_dedup_datagrams`,
    `test_moqtrun_mpub_publisher_leaves`,
    `test_moqtrun_mpub_subscriber_cancel`, `test_moqtrun_mpub_one_refuses`,
    `test_moqtrun_mpub_late_announcer`, `test_moqtrun_mpub_two_publish`
  - note: `wired_moqt_hub.multi_publisher` の下での動作(examples/moqt_interop が設定する。既定の 0 では、moqt_chat の求めるとおり名前ごとにパブリッシャーは 1 つで、最新のセッションがそれを持つ)。重複の除去は、ハブ全体で 64 エントリの窓を使い、Subgroup ストリームは (Group, Subgroup)、データグラムは (Group, Object) で判定する。最初のパブリッシャーが途中で残した Subgroup を、ほかのパブリッシャーの落とした複製で補うことはしない。モデル: tasks/loopeng/MoqtMultiPub (#149)。

## SS10 制御メッセージ: 共通の外枠

- [x] MQ18-054 実装は、すべての制御メッセージを Message Type(varint)+ Message Length(16 ビット)+ Message Body としてエンコード・デコードしなければならない。
  - test: `tests/app/moqctl_test.c` — `test_moqctl_peek_type_setup`
  - test: `tests/app/moqctl_test.c` — `test_moqctl_setup_roundtrip`
- [x] MQ18-055 実装は、Message Type の表のうち自分が実装しているもの、すなわち SETUP(0x2F00)、GOAWAY(0x10)、SUBSCRIBE(0x3)、SUBSCRIBE_OK(0x4)、PUBLISH(0x1D)、PUBLISH_DONE(0xB)、REQUEST_OK(0x7)、REQUEST_ERROR(0x5)を認識しなければならない。
  - test: `tests/app/moqctl_test.c` — `test_moqctl_peek_type_setup`
  - test: `tests/app/moqctl_test.c` — `test_moqctl_setup_roundtrip`
  - test: `tests/app/moqctl_test.c` — `test_moqctl_subscribe_roundtrip`
  - test: `tests/app/moqctl_test.c` — `test_moqctl_subscribe_ok_roundtrip`
  - test: `tests/app/moqctl_test.c` — `test_moqctl_publish_roundtrip`
  - test: `tests/app/moqctl_test.c` — `test_moqctl_publish_done_roundtrip`
  - test: `tests/app/moqctl_test.c` — `test_moqctl_request_ok_roundtrip`
  - test: `tests/app/moqctl_test.c` — `test_moqctl_request_error_roundtrip`
  - test: `tests/app/moqctl_test.c` — `test_moqctl_goaway_roundtrip`
  - test: `tests/app/moqfetch_test.c` — `test_moqfetch_standalone_golden`
  - test: `tests/app/moqfetch_test.c` — `test_moqfetch_ok_golden`
  - test: `tests/app/moqns_test.c` — `test_moqns_publish_golden`
  - test: `tests/app/moqns_test.c` — `test_moqns_subscribe_golden`
  - test: `tests/app/moqtstat_test.c` — `test_moqtstat_golden`
  - test: `tests/app/moqtstat_test.c` — `test_moqtstat_update_golden`
  - note: FETCH(0x16)、FETCH_OK(0x18)、TRACK_STATUS(0xD)、REQUEST_UPDATE(0x2)、PUBLISH_NAMESPACE(0x6)、SUBSCRIBE_NAMESPACE(0x50)、NAMESPACE(0x8)、NAMESPACE_DONE(0xE)は、それぞれ専用のコーデック(fetch/、ns/、tstat/)でエンコード・デコードし、各コーデックは draft-19 としてデコードするゴールデンベクターで固定している。これらのメッセージの draft-18 と draft-19 のレイアウトはバイト単位で同じである。
- [x] MQ18-055a draft-18 のセッションが PUBLISH_OK を送る場合、実装はそれを REQUEST_OK(0x7)としてエンコードしなければならない。draft-18 のセッションがメッセージ型 0x1E を受信した場合、実装はそれを REQUEST_OK(0x7)の別名として受け入れなければならない。draft-19 以降では 0x1E は RESERVED で、未知の型としてセッションを閉じるので、この点が異なる。
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_ctl_publish_ok_alias_d18_only`
  - test: `tests/app/moqver_test.c` — `test_moqver_caps_d18`
  - note: `MOQVER_CAP_PUBLISH_OK_ALIAS`。判断 Q18-01(相互接続性を優先した選択: draft-18 のピアからの 0x1E は受け入れるが、送るのは常に 0x7)。`draft18-vs-19-diff.md` の SS3 を参照。
- [x] MQ18-056 エンドポイントが未知の Message Type を受信した場合、実装は呼び出し側がセッションを閉じられるように、それを区別して報告しなければならない。
  - test: `tests/app/moqctl_test.c` — `test_moqctl_peek_type_unknown`
- [x] MQ18-057 実装は、外枠の先読みでは自らデコードしない既知の Message Type(REQUEST_UPDATE、FETCH、TRACK_STATUS、PUBLISH_NAMESPACE、SUBSCRIBE_NAMESPACE、SUBSCRIBE_TRACKS など)を、まったく未知の型と区別し、呼び出し側がセッションを閉じる代わりにそれを振り分けるか NOT_SUPPORTED で応答できるようにしなければならない。現在、ハブは SUBSCRIBE_TRACKS を含むこれらすべてに応答する(MQ18-201)。
  - test: `tests/app/moqctl_test.c` —
    `test_moqctl_peek_type_known_unimplemented`
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_unknown_first_type_gets_not_supported`
- [x] MQ18-058 制御メッセージで宣言された Length が実際に利用できる Message Body の長さと一致しない場合、実装はそのメッセージを完全なものとして扱ってはならない(本文を越えて誤って読まず、データ不足として報告する)。
  - test: `tests/app/moqctl_test.c` — `test_moqctl_peek_type_length_mismatch`
  - test: `tests/app/moqctl_test.c` — `test_moqctl_peek_type_truncated`
- [x] MQ18-059 (§10) 実装は、制御メッセージの Length を 16 ビットのフィールドとして読まなければならない。したがってメッセージ本文は 2^16-1 バイトを超えない。Length が 65535 のときは失敗させず、本文全体を待つ。
  - test: `tests/app/moqctl_test.c` — `test_moqctl_peek_type_max_len_field`
  - note: ハブ自身の受信の上限はこれより小さい(1024 バイト、MQ18-180)。

## SS10.1 Request ID

- [~] MQ18-060 (§10.1) サーバーは、1 から始め、新しいリクエストごとに 2 ずつ増やして、奇数の Request ID を生成しなければならない。
  - evidence: ハブの上流の SUBSCRIBE と FETCH は、互いに異なる奇数の Request ID を持つ(`test_moqtrun_upsub_ok_after_upstream`、`test_moqtrun_upfetch_two_not_shared`)。1 から始めることと 2 ずつ増やすこと(`request_id_next`)はテストで固定していない。偶数側はクライアントの動作である。
- [x] MQ18-061 (§10.1) エンドポイントが、最下位ビットが送信側に対して正しくない Request ID を受信した場合、実装は INVALID_REQUEST_ID でセッションを閉じなければならない。
  - test: `tests/app/moqtrun_sess_test.c` — `test_mtss_rid_parity_closes`
- [x] MQ18-062 (§10.1) エンドポイントが重複した Request ID を受信した場合、実装は INVALID_REQUEST_ID でセッションを閉じなければならない。
  - test: `tests/app/moqtrun_sess_test.c` — `test_mtss_rid_duplicate_closes`
  - test: `tests/app/moqtrun_sess_test.c` — `test_mtss_rid_out_of_order_ok`
  - test: `tests/app/moqtrun_sess_test.c` — `test_mtss_rid_window_slides`

## SS10.2 Message Parameter

- [x] MQ18-063 実装は、Message Parameter を、Type Delta(varint。直前の Parameter Type からの累積)と、それに続く Value としてデコードしなければならない。Value のエンコーディング(uint8、varint、Location、長さ付きバイト列)は Type ごとに決まっている。
  - test: `tests/app/moqctl_test.c` — `test_moqctl_params_forward_roundtrip`
  - test: `tests/app/moqctl_test.c` —
    `test_moqctl_params_delivery_timeout_decode`
- [~] MQ18-064 (§10.2) パラメーターは Type の昇順でシリアライズしなければならない。累積の Parameter Type が 2^64-1 を超えることになる場合、実装はプロトコル違反でセッションを閉じなければならない。
  - evidence: コーデックは違反を報告し(`test_moqctl_params_type_overflow_violation`)、ハブはデコードに失敗したリクエストや SETUP に対して PROTOCOL_VIOLATION で閉じる(`test_moqtrun_fillfix_malformed_subscribe`、`test_moqtrun_setup_malformed_closes`)。ただし、この条件を送るハブのテストはない。
- [x] MQ18-065 エンドポイントが未知の Message Parameter Type を受信した場合、実装はプロトコル違反でセッションを閉じなければならない。
  - test: `tests/app/moqctl_test.c` —
    `test_moqctl_params_unknown_type_violation`
  - note: draft-18 は Range Filter のパラメーター型 0x25-0x29(draft-19 で新設)を登録していない。draft-18 のセッションがこれらのどれかを受信すると、この同じ規則によりプロトコル違反で閉じる。「対象外」を参照。
  - test: `tests/app/moqtrun_fillfix_test.c` —
    `test_moqtrun_fillfix_malformed_subscribe`
- [~] MQ18-066 (§10.2) 送信側が 1 つのメッセージで同じ Parameter Type を繰り返した場合、実装はプロトコル違反でセッションを閉じなければならない。
  - evidence: コーデックは違反を報告し(`test_moqctl_params_duplicate_type_violation`)、ハブはデコードに失敗したリクエストや SETUP に対して PROTOCOL_VIOLATION で閉じる(`test_moqtrun_fillfix_malformed_subscribe`、`test_moqtrun_setup_malformed_closes`)。ただし、この条件を送るハブのテストはない。
- [x] MQ18-067 Message Parameter が、現れたメッセージとは別のメッセージ型に対して定義されたものである場合、実装はプロトコル違反でセッションを閉じなければならない。
  - test: `tests/app/moqctl_test.c` — `test_moqctl_params_scope_violation`
  - test: `tests/app/moqctl_test.c` — `test_moqctl_params_registry_scope_per_draft`
  - note: EXPIRES(0x08)と GROUP_ORDER(0x22)について、draft-18 で許されるメッセージの組は draft-19 と異なる。MQ18-073a/MQ18-073b を参照。
  - test: `tests/app/moqtrun_upd_test.c` — `test_moqtrun_upd_bad_and_control`
- [~] MQ18-068 (§10.2) SUBSCRIBE、PUBLISH_OK、FETCH の Message Parameter によって、パブリッシャーが送る Object のペイロードを変えてはならない。
  - evidence: ハブが Object を組み立てたりリレーしたりするとき、パラメーターの値は参照しない(moqtrun.c)。`test_moqtrun_object_relay_preserves_bytes` はペイロードが端から端まで同じであることを示すが、パラメーターなしの SUBSCRIBE で確かめている。

## SS10.2.3/10.2.4 SUBGROUP_DELIVERY_TIMEOUT / OBJECT_DELIVERY_TIMEOUT

- [x] MQ18-069 実装は、Message Parameter の SUBGROUP_DELIVERY_TIMEOUT(0x06)と OBJECT_DELIVERY_TIMEOUT(0x02)を varint としてデコードしなければならない。値 0 はタイムアウトを設定しないことを意味する。
  - test: `tests/app/moqctl_test.c` —
    `test_moqctl_params_delivery_timeout_decode`
- [x] MQ18-070 (§10.2.1, §10.2.3, §10.2.4) ハブは、配信タイムアウトのパラメーターを、それらのパラメーターが許されるメッセージに入らない SUBSCRIBE_OK で送ってはならない。
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_subscribe_ok_carries_no_timeout_param`
- [x] MQ18-071 0 でない SUBGROUP_DELIVERY_TIMEOUT または OBJECT_DELIVERY_TIMEOUT パラメーターを持つ SUBSCRIBE は、受け入れて適用しなければならない。購読者の値とパブリッシャーの Track Property の値がどちらも 0 でなければ、その min() を使う。
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_subscribe_nonzero_timeout_accepted`
  - test: `tests/app/moqtrun_upd_test.c` — `test_moqtrun_timeout_accepted`
  - test: `tests/app/moqtrun_sub_test.c` —
    `test_moqtrun_sub_subgroup_timeout_min`
  - note: 台帳 10-4。draft-19 の台帳の MOQT-070 も同じ。

## SS10.2.12 FORWARD パラメーター

- [x] MQ18-072 実装は、FORWARD パラメーター(Type 0x10)を、値が 0(転送しない)か 1(転送する)の uint8 としてエンコード・デコードし、省略時は 1 としなければならない。
  - test: `tests/app/moqctl_test.c` — `test_moqctl_params_forward_roundtrip`
  - test: `tests/app/moqctl_test.c` — `test_moqctl_params_uint8_value_ranges`
  - test: `tests/app/moqtrun_sub_test.c` — `test_moqtrun_sub_params_absent`
- [x] MQ18-073 (§5.1, §10.10) PUBLISH で FORWARD=0 を送ったパブリッシャーは、購読者が Forward State を 1 にするまで、Object を 1 つも送信してはならない。購読への Object の転送は、その購読の Forward State で制御する。
  - test: `tests/app/moqtrun_misc_test.c` —
    `test_moqtrun_misc_pub_forward0_then_update`

## SS10.2.8/10.2.10 GROUP_ORDER / EXPIRES が許されるメッセージの組(draft-18)

- [x] MQ18-073a 実装は、draft-18 のセッションでは PUBLISH_OK の GROUP_ORDER(0x22)を受け入れなければならない。draft-19 以降では PUBLISH_OK に GROUP_ORDER は許されず、代わりに SUBSCRIBE_TRACKS に許されるので、この点が異なる。
  - test: `tests/app/moqctl_test.c` —
    `test_moqctl_params_registry_scope_per_draft`
  - test: `tests/app/moqtrun_sub_test.c` —
    `test_moqtrun_pub_params_group_order_d19`
  - note: 判断 Q18-02(許されるメッセージの組の表の見かけ上の矛盾より、§10.19.1 のリクエスト型ごとの規則に従う)は draft-19 以降に当てはまる。draft-18 の §10.19 には §10.19.1 がなく FORWARD だけを返し、§10.2.8 は SUBSCRIBE、PUBLISH_OK、FETCH だけを挙げている。そのため、GROUP_ORDER を持つ draft-18 の PUBLISH はプロトコル違反になる(台帳 12-7)。
- [x] MQ18-073b 実装は、draft-18 のセッションでは、SUBSCRIBE_NAMESPACE_OK、SUBSCRIBE_TRACKS_OK、PUBLISH_NAMESPACE_OK の EXPIRES(0x08)をプロトコル違反として拒否しなければならない。draft-19 以降ではこれら 3 つの REQUEST_OK の変種で EXPIRES が許されるので、この点が異なる。
  - test: `tests/app/moqctl_test.c` — `test_moqctl_params_registry_scope_per_draft`
  - note: draft-18 で EXPIRES が許されるメッセージの範囲はより狭い(SUBSCRIBE_OK、PUBLISH、PUBLISH_OK、REQUEST_UPDATE_OK のみ)。`draft18-vs-19-diff.md` の §5 を参照。

## SS10.3 SETUP

- [x] MQ18-074 実装は、SETUP の Setup Option を、メッセージのペイロード全体にわたる Key-Value-Pair のリストとしてエンコード・デコードしなければならない。
  - test: `tests/app/moqctl_test.c` — `test_moqctl_setup_roundtrip`
- [x] MQ18-075 エンドポイントは、認識できない Setup Option を無視しなければならない。
  - test: `tests/app/moqctl_test.c` —
    `test_moqctl_setup_unknown_option_ignored`
  - note: draft-18 は draft-19 で新設された MAX_FILTER_RANGES(0x06)と MAX_REQUEST_UPDATES(0x08)を登録していない。draft-18 のセッションがどちらかを受信した場合は、この同じ「未知のものは無視する」規則が当てはまる。「対象外」を参照。ハブ自身の SETUP は、draft-18 のピアにはどちらのオプションも付けない(`moqtrun_setup_limits`、台帳 4-4): `test_moqtrun_xver_setup_d18_omits_d19_options`。未知のオプションの重複も捨てる(`test_moqraw_unknown`)。
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_setup_unknown_options_ignored`
- [~] MQ18-076 (§10.3) 送信側は、オプションが複数のインスタンスを明示的に認めていない限り、1 つのメッセージで同じ Setup Option Type を繰り返してはならない。
  - evidence: `moqctl_setup_encode` は作りとして PATH/AUTHORITY/MOQT_IMPLEMENTATION をそれぞれ最大 1 回しか書かない(`test_moqctl_setup_roundtrip` はそれぞれ 1 つずつをラウンドトリップさせる)。重複を送るテストはない。

## SS10.3.1.1 AUTHORITY / SS10.3.1.2 PATH / SS10.3.1.5 MOQT_IMPLEMENTATION

- [x] MQ18-077 実装は、Setup Option の PATH(0x01)と AUTHORITY(0x05)をバイト列の値としてデコードしなければならない。
  - test: `tests/app/moqctl_test.c` — `test_moqctl_setup_path_option_decode`
  - test: `tests/app/moqtrun_raw_test.c` —
    `test_moqtrun_raw_path_authority_established`
- [x] MQ18-078 (§10.3.1.1, §10.3.1.2) WebTransport を使っている間に PATH または AUTHORITY オプションを受信した場合、実装はそれぞれ INVALID_PATH または INVALID_AUTHORITY でセッションを閉じなければならない。
  - test: `tests/app/moqraw_test.c` — `test_moqraw_wt`
  - test: `tests/app/moqtrun_raw_test.c` —
    `test_moqtrun_raw_same_setup_on_wt_closes`
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_setup_path_closes_invalid_path`
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_setup_authority_closes_invalid_authority`
- [x] MQ18-231 (§10.3.1.1, §10.3.1.2) ネイティブ QUIC のセッションで、PATH または AUTHORITY オプションが URI の規則に合わない場合、サーバーは MALFORMED_PATH または MALFORMED_AUTHORITY でセッションを閉じなければならない。アプリケーションのポリシーがそのパスまたはオーソリティに対応していない場合は、INVALID_PATH または INVALID_AUTHORITY で閉じなければならない。
  - test: `tests/app/moqraw_test.c` — `test_moqraw_path`
  - test: `tests/app/moqraw_test.c` — `test_moqraw_authority`
  - test: `tests/app/moqraw_test.c` — `test_moqraw_hook`
- [x] MQ18-079 (§10.3.1.5) 実装は、Setup Option の MOQT_IMPLEMENTATION(0x07)を UTF-8 のバイト列の値としてデコードしなければならない。
  - test: `tests/app/moqctl_test.c` — `test_moqctl_setup_roundtrip`
- [x] MQ18-232 (§10.3.1.5, §13.8) サーバーは、送らないように設定されていない限り、実装名とメジャーバージョンだけに限った MOQT_IMPLEMENTATION Setup Option を送るべきである。
  - test: `tests/app/moqtrun_test.c` — `test_moqtrun_setup_sends_implementation`
- [x] MQ18-226 (§10.2.2, §10.3.1.4) クライアントの SETUP が、Alias Type が DELETE または USE_ALIAS の AUTHORIZATION TOKEN Setup Option を持つ場合、サーバーは PROTOCOL_VIOLATION でセッションを閉じなければならない。MAX_AUTH_TOKEN_CACHE_SIZE を超える REGISTER は、セッションの失敗ではなく USE_VALUE として扱わなければならない。
  - test: `tests/app/moqtrun_sess_test.c` — `test_mtss_setup_token_alias`

## SS10.4 GOAWAY(ワイヤー形式、draft-18 の形)

- [x] MQ18-080 実装は、GOAWAY の共通の先頭部分を Type(0x10)+ Length + New Session URI Length + New Session URI + Timeout としてエンコード・デコードし、末尾の Request ID フィールドは制御ストリームでだけ持たせなければならない(MQ18-048a を参照)。
  - test: `tests/app/moqctl_test.c` — `test_moqctl_goaway_roundtrip`
  - test: `tests/app/moqctl_test.c` — `test_moqctl_goaway18_request_id`
  - test: `tests/app/moqctl_test.c` — `test_moqctl_goaway18_vs_19_shape`
- [~] MQ18-081 (§10.4) New Session URI Length が 8192 バイトを超える場合、実装はプロトコル違反でセッションを閉じなければならない。
  - evidence: コーデックは違反を報告し(`test_moqctl_goaway_uri_boundary`)、ハブはデコードに失敗したリクエストや SETUP に対して PROTOCOL_VIOLATION で閉じる(`test_moqtrun_fillfix_malformed_subscribe`、`test_moqtrun_setup_malformed_closes`)。ただし、この条件を送るハブのテストはない。
## SS10.5 REQUEST_OK

- [x] MQ18-083 実装は、REQUEST_OK を Type(0x7)+ Length + Number of Parameters + Parameters + Track Properties(メッセージの残りのバイト)としてエンコード・デコードしなければならない。
  - test: `tests/app/moqctl_test.c` — `test_moqctl_request_ok_roundtrip`
- [x] MQ18-084 (§10.5) PUBLISH_OK、REQUEST_UPDATE_OK、SUBSCRIBE_NAMESPACE_OK、PUBLISH_NAMESPACE_OK が空でない Track Properties を持つ場合、実装はプロトコル違反でセッションを閉じなければならない。
  - test: `tests/app/moqtrun_sess_test.c` — `test_mtss_publish_ok_props_closes`
  - evidence: これらのうちハブが受信しうるのは PUBLISH_OK だけである。ハブは REQUEST_UPDATE、SUBSCRIBE_NAMESPACE、PUBLISH_NAMESPACE を送らない。

## SS10.6 REQUEST_ERROR

- [x] MQ18-085 実装は、REQUEST_ERROR を Type(0x5)+ Length + Error Code + Retry Interval + Error Reason + 省略可能な Redirect としてエンコード・デコードしなければならない。
  - test: `tests/app/moqctl_test.c` — `test_moqctl_request_error_roundtrip`
  - test: `tests/app/moqctl_test.c` —
    `test_moqctl_request_error_redirect_roundtrip`
- [x] MQ18-086 Redirect 構造は、Error Code が REDIRECT のときだけ存在しなければならない。
  - test: `tests/app/moqctl_test.c` —
    `test_moqctl_request_error_redirect_roundtrip`
  - test: `tests/app/moqctl_test.c` — `test_moqctl_request_error_roundtrip`
- [x] MQ18-087 (§10.6.1) サーバーが、Connect URI Length が 0 でない Redirect、または名前空間を対象とするリクエストに対して Track Name が空でない Redirect を受信した場合、実装はプロトコル違反でセッションを閉じなければならない。
  - test: `tests/app/moqtrun_sess_test.c` — `test_mtss_publish_error_redirect_closes`
  - test: `tests/app/moqtrun_upsub_test.c` — `test_moqtrun_upsub_redirect_uri_closes`
  - test: `tests/app/moqtrun_upfetch_test.c` — `test_moqtrun_upfetch_error_redirect_uri_closes`
  - evidence: ハブは名前空間を対象とするリクエストを送らないので、Track Name の規則を当てはめる REQUEST_ERROR がない。
- [x] MQ18-088 (§10.6.2, §15.10.2) 実装は、draft-18 の REQUEST_ERROR のコード(INTERNAL_ERROR、UNAUTHORIZED、TIMEOUT、NOT_SUPPORTED、GOING_AWAY、EXCESSIVE_LOAD、UNSUPPORTED_EXTENSION、DUPLICATE_SUBSCRIPTION、REDIRECT、DOES_NOT_EXIST、INVALID_RANGE、UNINTERESTED、PREFIX_OVERLAP、INVALID_JOINING_REQUEST_ID)を使い、別のドラフトが違う形で定義するコードは draft-18 の呼び方で表さなければならない(たとえば INVALID_FILTER は INVALID_RANGE とする)。
  - test: `tests/app/moqctl_test.c` — `test_moqctl_request_error_for_draft`
  - test: `tests/app/moqctl_test.c` —
    `test_moqctl_unknown_error_normalizes_to_internal`
- [x] MQ18-089 エンドポイントが認識できない REQUEST_ERROR のコードを受信した場合、実装はセッションを閉じず、それを INTERNAL_ERROR として扱わなければならない。
  - test: `tests/app/moqctl_test.c` —
    `test_moqctl_unknown_error_normalizes_to_internal`
  - note: draft-18 は REQUEST_ERROR のコード 0x35(CONFLICTING_FILTERS)と 0x36(draft-19 での INVALID_FILTER のコード。draft-18 は Range Filter のレジストリに従って INVALID_FILTER を別の数値で使っているが、そのレジストリは draft-18 にはない。「対象外」を参照)を定義していない。どちらもこの同じ規則により未知のコードとして許容する。

## SS10.7 SUBSCRIBE / SS10.8 SUBSCRIBE_OK

- [x] MQ18-090 実装は、SUBSCRIBE を Type(0x3)+ Length + Request ID + Track Namespace + Track Name + Number of Parameters + Parameters としてエンコード・デコードしなければならない。
  - test: `tests/app/moqctl_test.c` — `test_moqctl_subscribe_roundtrip`
- [x] MQ18-091 (§5.1, §10.7) 購読が成功したとき、パブリッシャーはちょうど 1 つの SUBSCRIBE_OK で応答しなければならない。
  - test: `tests/app/moqctl_test.c` — `test_moqctl_subscribe_ok_roundtrip`
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_ctl_split_subscribe_answered_once`
- [x] MQ18-092 実装は、SUBSCRIBE_OK を Type(0x4)+ Length + Track Alias + Number of Parameters + Parameters + Track Properties としてエンコード・デコードしなければならない。
  - test: `tests/app/moqctl_test.c` — `test_moqctl_subscribe_ok_roundtrip`
- [x] MQ18-093 (§5.1) ハブが自分の送ったリクエストに対して 2 つ以上の応答(PUBLISH_OK または REQUEST_ERROR)を受信した場合、実装はプロトコル違反でセッションを閉じなければならない。
  - test: `tests/app/moqtrun_misc_test.c` —
    `test_moqtrun_misc_pub_second_ok_closes`
  - test: `tests/app/moqtrun_misc_test.c` —
    `test_moqtrun_misc_pub_error_after_ok_closes`
  - note: ハブが始める PUBLISH について示している。上流のパブリッシャーからの 2 つ目の SUBSCRIBE_OK はテストしていない。
- [x] MQ18-094 (§5.1.1) パブリッシャーが SUBSCRIBE を REQUEST_ERROR で拒否した場合、その購読について Object を送ってはならない。
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_subscribe_requires_authorization`
  - vuln: V-0786, V-0792, V-0793
- [x] MQ18-094a ピアが同じ役割から同じ Track への 2 つ目の同時の購読を送った場合、draft-18 のセッションはそれを REQUEST_ERROR DUPLICATE_SUBSCRIPTION で拒否しなければならない。draft-19 以降では同じ Track への複数の同時の購読が許されるので、この点が異なる。
  - test: `tests/app/moqtrun_upd_test.c` —
    `test_moqtrun_sub_duplicate_refused_d18`
  - note: `moqtrun_sub_held_reply` は、ネゴシエートしたバージョンの `MOQVER_CAP_DUP_SUBSCRIPTION` ビットで分岐する。台帳 4-2 と `draft18-vs-19-diff.md` の §9.3 を参照。

## SS10.10 PUBLISH

- [x] MQ18-095 実装は、PUBLISH を Type(0x1D)+ Length + Request ID + Track Namespace + Track Name + Track Alias + Number of Parameters + Parameters + Track Properties としてエンコード・デコードしなければならない。
  - test: `tests/app/moqctl_test.c` — `test_moqctl_publish_roundtrip`
- [x] MQ18-096 (§5.1) PUBLISH で始まった購読が成功したとき、購読者はちょうど 1 つの PUBLISH_OK(REQUEST_OK)で応答しなければならない。
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_publish_replies_request_ok`
- [~] MQ18-097 (§5.1) パブリッシャーは、PUBLISH で始まった購読について、PUBLISH_OK を受信する前に Object の送信を始めてもよい。
  - evidence: 購読者としてのハブは、自分の応答が処理される前に届いた Object を受け入れる(上流: `test_moqtrun_upsub_stream_before_ok`)。PUBLISH の送信側としてのハブは PUBLISH_OK を待つ(`test_moqtrun_misc_pub_ok_relays`)。
- [x] MQ18-098 (§5.1.1, §10.10) 購読者が PUBLISH を REQUEST_ERROR UNINTERESTED で拒否した場合、その購読は Object を 1 つも送らずに終わらなければならない。
  - test: `tests/app/moqtrun_subtracks_test.c` —
    `test_subtracks_publish_error_frees_slot`

## SS10.11 PUBLISH_DONE

- [x] MQ18-099 実装は、PUBLISH_DONE を Type(0xB)+ Length + Status Code + Stream Count + Error Reason としてエンコード・デコードしなければならない。
  - test: `tests/app/moqctl_test.c` — `test_moqctl_publish_done_roundtrip`
- [x] MQ18-100 (§5.1.1, §10.11) 送信側は、その購読のために開いたデータストリームをすべて閉じるまで、PUBLISH_DONE を送ってはならない。
  - test: `tests/app/moqtrun_drain_test.c` —
    `test_moqtrun_done_resets_streams_first`
- [x] MQ18-101 (§10.11) PUBLISH_DONE と購読の双方向ストリームのクローズによって、購読は終わらなければならない。そのあと、送信側は購読の状態を破棄してもよい。
  - test: `tests/app/moqtrun_drain_test.c` — `test_moqtrun_done_track_ended`
  - test: `tests/app/moqtrun_upsub_test.c` —
    `test_moqtrun_upsub_publish_done_relayed`
- [~] MQ18-102 (§10.11) 購読者が応答を送る前に PUBLISH_DONE が届いた場合、購読者は FIN を送る前に、後回しにした PUBLISH_OK をちょうど 1 つ送らなければならない。
  - evidence: これを示すのは配線していない `moqsub` モデルだけである(`test_moqsub_publish_done_before_response_defers_ok`)。ハブは PUBLISH に同期して応答するので、この競合は起きない。
- [x] MQ18-103 (§10.11) 実装は、自分が知らせる終わり方について、draft-18 の PUBLISH_DONE のステータスコード(INTERNAL_ERROR、TRACK_ENDED、SUBSCRIPTION_ENDED、GOING_AWAY、UPDATE_FAILED、MALFORMED_TRACK)を使わなければならない。
  - test: `tests/app/moqtrun_drain_test.c` — `test_moqtrun_done_track_ended`
  - test: `tests/app/moqtrun_done_test.c` —
    `test_moqtrun_pubdone_malformed_after_end_of_track`
  - test: `tests/app/moqctl_test.c` —
    `test_moqctl_unknown_error_normalizes_to_internal`
- [x] MQ18-104 (§10.11) パブリッシャーは、PUBLISH_DONE の Stream Count を、その購読のために開いたデータストリームの正確な数(1 本も開いていなければ 0)にするか、数えられない場合は 2^62-1 にしなければならない。
  - test: `tests/app/moqtrun_drain_test.c` — `test_moqtrun_done_track_ended`

## SS10 制御メッセージで共有する Reason Phrase / Location / Track Namespace の構造

- [x] MQ18-105 実装は、Message Parameter、Location、Reason Phrase を、それらを含むすべての制御メッセージで一貫してエンコード・デコードしなければならない。
  - test: `tests/app/moqctl_test.c` — `test_moqctl_params_forward_roundtrip`
  - test: `tests/app/moqctl_test.c` —
    `test_moqctl_location_roundtrip_and_order`
  - test: `tests/app/moqctl_test.c` — `test_moqctl_reason_boundary`
  - vuln: V-0800

## SS5.1.2 / SS10.2.9 Subscription Filter

- [x] MQ18-106 (§5.1.2) 実装は、Subscription Filter の Filter Type を、Next Group Start(0x1)、Largest Object(0x2)、AbsoluteStart(0x3)、AbsoluteRange(0x4)のどれかとしてデコードし、フィールドの並び(Start Location、End Group Delta)を型に応じて決めなければならない。
  - test: `tests/app/moqctl_test.c` —
    `test_moqctl_locfilter_next_group_and_largest`
  - test: `tests/app/moqctl_test.c` —
    `test_moqctl_locfilter_abs_start_and_range_roundtrip`
  - note: draft-18 では "Subscription Filter" と呼ぶ(draft-19 で "Location Filter" に改名)。構造はバイト単位で同じ。
- [~] MQ18-107 (§5.1.2) AbsoluteRange フィルターの End Group(Start.Group + End Group Delta)が 2^64-1 を超えることになる場合、実装はプロトコル違反でセッションを閉じなければならない。
  - evidence: コーデックは違反を報告し(`test_moqctl_locfilter_end_group_overflow_violation`)、ハブはデコードに失敗したリクエストや SETUP に対して PROTOCOL_VIOLATION で閉じる(`test_moqtrun_fillfix_malformed_subscribe`、`test_moqtrun_setup_malformed_closes`)。ただし、この条件を送るハブのテストはない。
- [~] MQ18-108 (§5.1.2) エンドポイントが定義済みの 4 つ以外の Subscription Filter Type を受信した場合、実装はプロトコル違反でセッションを閉じなければならない。
  - evidence: コーデックは違反を報告し(`test_moqctl_locfilter_unknown_type_violation`)、ハブはデコードに失敗したリクエストや SETUP に対して PROTOCOL_VIOLATION で閉じる(`test_moqtrun_fillfix_malformed_subscribe`、`test_moqtrun_setup_malformed_closes`)。ただし、この条件を送るハブのテストはない。
- [x] MQ18-109 パブリッシャーは、Forward State と Location Filter の組み合わせ(Pass = Forward AND Filters)を通過した Object だけを転送しなければならない。
  - test: `tests/app/moqtrun_upd_test.c` —
    `test_moqtrun_upd_forward_toggles`
  - test: `tests/app/moqtrun_upd_test.c` —
    `test_moqtrun_filter_groups_delivered`
  - test: `tests/app/moqtrun_sub_test.c` —
    `test_moqtrun_sub_filter_from_largest`
  - test: `tests/app/moqtrun_fetch_test.c` —
    `test_moqtrun_fetch_no_replay_before_start`
  - note: フィルターは、信頼性のあるリレーで遅れて来た購読者に Object を再送するときに評価する。開始 Group のうち開始 Object より前の Object は、どのリレー経路でも切り捨てる。

- [x] MQ18-217 (§5.1.2) ハブが Subscription Filter を満たせない場合、またはフィルターの End Group 全体がすでに公開済みの場合、ハブは REQUEST_ERROR INVALID_RANGE で応答するべきである。
  - evidence: `moqtrun_filter_past` は、End Group が Track の Largest Group より前にある AbsoluteRange を拒否する。`test_moqtrun_sub_range_past_invalid`(Largest Group で終わるものは受け入れる)。
  - test: `tests/app/moqtrun_sub_test.c` — `test_moqtrun_sub_range_past_invalid`

## SS14 Grease

- [x] MQ18-110 実装は、grease の値を予約しているレジストリ(Setup Option、Property、エラー・ステータスのコード表)で、非負整数 N に対する grease の値のパターン 0x7f*N + 0x9D を認識しなければならない。
  - test: `tests/app/moqctl_test.c` — `test_moqctl_grease_pattern`
- [x] MQ18-111 エンドポイントは、grease されたレジストリ(Setup Option、エラーコード)で未知の値を受信したことだけを理由に、セッションを閉じてはならない。
  - test: `tests/app/moqctl_test.c` —
    `test_moqctl_setup_unknown_option_ignored`
  - test: `tests/app/moqctl_test.c` —
    `test_moqctl_unknown_error_normalizes_to_internal`
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_setup_unknown_options_ignored`
## SS11.1 Track Alias

- [x] MQ18-112 パブリッシャーは、同じセッションの中で、同じ Track Alias を同時に 2 つの異なる Track を指すために使ってはならない。
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_chat_and_audio_get_different_aliases`
- [x] MQ18-113 (§11.1) 購読者が、別の Established の購読にすでに結び付いている Track Alias を使い回す PUBLISH または SUBSCRIBE_OK を受信した場合、実装は DUPLICATE_TRACK_ALIAS でセッションを閉じなければならない。
  - test: `tests/app/moqtrun_sess_test.c` — `test_mtss_publish_dup_alias_closes`
  - test: `tests/app/moqtrun_upsub_test.c` — `test_moqtrun_upsub_dup_alias_closes`

## SS11.2.1.1 Object Status

- [x] MQ18-114 実装は、Object Status の値 0x0(Normal)、0x3(End of Group)、0x4(End of Track)を認識しなければならない。
  - test: `tests/app/moqdata_test.c` — `test_moqdata_obj_take_status_values`
- [x] MQ18-115 (§11.2.1.1) Object が登録されていない Status の値を持つ場合、実装はプロトコル違反でセッションを閉じるべきである。
  - test: `tests/app/moqtrun_sess_test.c` — `test_mtss_subgroup_object_violations`
- [x] MQ18-116 Object は、Object Status が Normal(0x0)でない限り空のペイロードを持たなければならない。Object Status フィールドは Payload Length が 0 のときだけ存在しなければならない。
  - test: `tests/app/moqdata_test.c` — `test_moqdata_subhdr_take_status_eog`
  - test: `tests/app/moqdata_test.c` —
    `test_moqdata_obj_take_status_eog_stream`

## SS11.2.1.2 Object Property

- [x] MQ18-117 (§11.2.1.2) エンドポイントが、Status が Normal でない Object で Object Property を受信した場合、実装はプロトコル違反でセッションを閉じなければならない。
  - test: `tests/app/moqtrun_sess_test.c` — `test_mtss_subgroup_object_violations`
- [x] MQ18-118 Object Property は、Properties Length(varint)と、それに続く Key-Value-Pair のリストとしてシリアライズしなければならない。
  - test: `tests/app/moqdata_test.c` — `test_moqdata_obj_take_properties`
- [x] MQ18-118a (§12.1, §12.2, §15.8) Object Datagram が OBJECT_DELIVERY_TIMEOUT または SUBGROUP_DELIVERY_TIMEOUT の Object Property を持つ場合、実装はプロトコル違反でセッションを閉じなければならない(draft-18 はどちらも Track スコープの Property としてだけ登録している)。
  - test: `tests/app/moqtrun_ctlfix_test.c` — `test_mtcf_d18_dg_timeout_prop`
  - note: 判断 Q18-05。`MOQVER_CAP_DG_TIMEOUT_PROP_CLOSE`(draft-18 のみ)で切り替える。クローズを定める文は draft-18 にない。この判断は、Track だけのスコープであることから、Object Property としては無効になると読んでいる。

## SS11.4.2 Subgroup ヘッダー

- [x] MQ18-119 SUBGROUP_HEADER で開いたストリーム上のすべての Object は、Object Forwarding Preference = Subgroup でなければならず、ヘッダーが宣言する Track Alias、Group ID、Subgroup ID に属さなければならない。
  - test: `tests/app/moqdata_test.c` — `test_moqdata_subhdr_take_basic`
- [x] MQ18-120 (§11.4.2) SUBGROUP_HEADER の Type フィールドは 0b0XX1XXXX の形(ビット 4 が常に 1)でなければならない。ほかの形で受信した場合、実装はプロトコル違反でセッションを閉じなければならない。
  - test: `tests/app/moqtrun_sess_test.c` — `test_mtss_unknown_uni_closes`
- [x] MQ18-121 実装は、SUBGROUP_ID_MODE フィールド(ビット 1-2)を次のようにデコードしなければならない。0b00 は Subgroup ID がなく 0、0b01 は Subgroup ID がなく最初の Object の Object ID に等しい、0b10 は Subgroup ID がヘッダーにある。
  - test: `tests/app/moqdata_test.c` — `test_moqdata_subhdr_take_mode2`
  - test: `tests/app/moqdata_test.c` — `test_moqdata_subhdr_take_mode1_resolve`
- [x] MQ18-122 (§11.4.2) SUBGROUP_ID_MODE が 0b11 の場合、実装はプロトコル違反でセッションを閉じなければならない。
  - test: `tests/app/moqtrun_sess_test.c` — `test_mtss_subgroup_mode3_closes`
- [x] MQ18-123 実装は、SUBGROUP_HEADER の Type フィールドの PROPERTIES ビット(0x01)、END_OF_GROUP ビット(0x08)、DEFAULT_PRIORITY ビット(0x20)、FIRST_OBJECT ビット(0x40)をデコードしなければならない。
  - test: `tests/app/moqdata_test.c` — `test_moqdata_type_bits_golden`
- [x] MQ18-124 DEFAULT_PRIORITY が立っている場合、Publisher Priority フィールドはヘッダーから省かなければならず、Subgroup は購読の制御メッセージから優先度を引き継がなければならない。
  - test: `tests/app/moqdata_test.c` — `test_moqdata_subhdr_take_basic`
  - test: `tests/app/moqtrun_drain_test.c` — `test_moqtrun_prio_track_default`
- [~] MQ18-125 (§11.4.2) END_OF_GROUP ビットが立っていてストリームが FIN で終わった場合、実装は、同じ Group ID でより大きい Object ID を持つ Object は存在しないと推定しなければならない。
  - evidence: このビットはデコードされ(MQ18-123)、ヘッダーのバイト列に含めてリレーされる。推定を確かめるテストはない。
- [x] MQ18-126 (§2.2, §11.4.2) ハブが自分の Track(`wired_moqt_publish_blob` / `_live`)の Original Publisher として新しい Subgroup を開くとき、ハブは FIRST_OBJECT ビットを立てなければならない。
  - test: `tests/app/moqdata_test.c` — `test_moqdata_msg_build_golden`
  - test: `tests/app/moqdata_test.c` — `test_moqdata_type_bits_golden`
- [x] MQ18-127 実装は、SUBGROUP_HEADER を、ワイヤー上のフィールド(Type、Track Alias、Group ID、省略可能な Subgroup ID、省略可能な Publisher Priority)とバイト単位で一致するようにエンコード・デコードしなければならない。
  - test: `tests/app/moqdata_test.c` — `test_moqdata_subhdr_put_golden`
  - test: `tests/app/moqdata_test.c` — `test_moqdata_subhdr_put_errors`
- [x] MQ18-128 SUBGROUP_HEADER が宣言したフィールドがすべてそろう前に途切れている場合、実装はデコードをデータ不足として報告しなければならない。
  - test: `tests/app/moqdata_test.c` — `test_moqdata_subhdr_take_truncated`
- [x] MQ18-129 実装は、モード 0b01(後で決まる)の Subgroup ID を、最初の Object の Object ID をデコードした時点でそこから決めなければならない。
  - test: `tests/app/moqdata_test.c` — `test_moqdata_subhdr_take_mode1_resolve`

## SS11.4.2 Subgroup の Object のフィールド

- [x] MQ18-130 実装は、Subgroup の Object を Object ID Delta + 省略可能な Properties + Object Payload Length + 省略可能な Object Status + 省略可能な Object Payload としてエンコード・デコードしなければならない。
  - test: `tests/app/moqdata_test.c` — `test_moqdata_obj_take_basic_stream`
  - test: `tests/app/moqdata_test.c` — `test_moqdata_obj_put`
- [x] MQ18-130a 実装は、REQUEST_ERROR のコード DUPLICATE_SUBSCRIPTION(0x19)を認識しなければならない。これは、draft-18 のセッションで同じ役割から同じ Track への 2 つ目の同時の購読を拒否するときに使う(MQ18-094a)。draft-19 以降ではこのコードは削除されている(未割り当て)。
  - test: `tests/app/moqctl_test.c` — `test_moqctl_params_registry_scope_per_draft`
  - test: `tests/app/moqtrun_upd_test.c` —
    `test_moqtrun_sub_duplicate_refused_d18`
  - note: wired 自身の `MOQCTL_CLOSE_*` の 0x19(INVALID_AUTHORITY。別のレジストリにあるセッション終了のコード)とは関係がない。`draft18-vs-19-diff.md` の §7 の注記を参照。
- [x] MQ18-131 Object ID は、Subgroup の最初の Object では Object ID Delta そのもの、後続の各 Object では直前の Object ID に Delta と 1 を足した値でなければならない。
  - test: `tests/app/moqdata_test.c` — `test_moqdata_obj_take_delta_chain`
- [x] MQ18-132 (§11.4.2) 計算した累積の Object ID が 2^64-1 を超えることになる場合、実装はプロトコル違反でセッションを閉じなければならない。
  - test: `tests/app/moqtrun_sess_test.c` — `test_mtss_subgroup_object_violations`
- [x] MQ18-133 Subgroup の Object ストリームが、シリアライズされた Object の途中で FIN により終わった場合、実装はその途中までの Object を完全なものとして扱ってはならない。
  - test: `tests/app/moqdata_test.c` — `test_moqdata_obj_take_truncated`
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_decode_loop_stops_at_truncation`
  - gap: §11.4 は、その場合にセッションを PROTOCOL_VIOLATION で閉じるべき(SHOULD)としている。ハブは代わりに途切れた末尾を捨てる(`test_moqtrun_fresh_oneshot_no_object_discarded`)。
- [x] MQ18-134 Subgroup の Object ストリームで Object ごとのデコードがプロトコル違反を報告した場合、実装はその時点で、そのストリームの後続の Object のデコードをやめなければならない。
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_decode_loop_stops_at_violation`
- [x] MQ18-135 実装は、1 つのストリームバッファーから複数の Object を順にデコードし、その結果が各 Object を個別にデコードした結果と一致しなければならない。
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_decode_loop_single_object_matches_one_shot`
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_decode_loop_multiple_objects`

## SS11.4.3 Subgroup ストリームのクローズ

- [x] MQ18-136 送信側が Subgroup のすべての Object を送り終えた場合、送信側は FIN でストリームを閉じなければならない。
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_chat_split_data_then_bare_fin_relays_and_closes`
- [~] MQ18-137 (§11.4.3) ストリームの FIN を観測した実装は、購読の開始からのその Subgroup の Object をすべて受信したことが保証される。
  - evidence: ハブは、FIN より前の Object を送ったあとでだけ FIN を転送する(`test_moqtrun_torn_object_cut_through` が再組み立てを示す)。保証そのものを確かめるテストはない。
- [x] MQ18-138 リレーは、既存の Subgroup ストリームで、その Subgroup の次の Object でない Object を転送してはならない(2 回の受け渡しに分かれた Object は、送った部分の終わりからそのまま続ける)。
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_fresh_delivery_tail_cut_through`
  - test: `tests/app/moqtrun_test.c` — `test_moqtrun_frag_overflow_counted`
- [x] MQ18-139 新しい Object のバイトを伴わないパブリッシャーのストリームの FIN は、拒否される空のデータ送信ではなく、データなしの FIN で対応するリレーのストリームを閉じなければならない。
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_chat_split_data_then_bare_fin_relays_and_closes`
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_audio_split_data_then_bare_fin_closes`
- [ ] MQ18-235 (§11.4.3) 購読者がリレーの Subgroup ストリームで STOP_SENDING を送ったとき、ハブはそのストリームをリセットするべきであり、その Subgroup の後続の Object のために新しいストリームを開くべきではない。
  - gap: リレーのストリームで STOP_SENDING を送るテストはない。
- [x] MQ18-140 同じ Track で重なり合う 2 本のパブリッシャーのストリームは、それぞれ独立したストリームでリレーしなければならず、それぞれ自分のパブリッシャーの FIN によってだけ閉じなければならない。
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_interleaved_chat_messages_close_independently`
- [x] MQ18-141 (§2.2, §11.4.2) Subgroup ストリームが始まったあとに加わった購読者も、リレーのストリームを受け取らなければならない。そのストリームは元のストリームの SUBGROUP_HEADER で、FIRST_OBJECT を落として開く(ストリームはもう Subgroup の最初の Object から始まらないため)。最初の Object から始まるストリームは、受け取ったままのビットを保つ。
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_late_subscriber_gets_late_opened_stream`
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_object_relay_preserves_bytes`

## SS11.5.1 パディングストリーム

- [x] MQ18-142 実装は、パディングストリーム(Type 0x132B3E28)で受信したデータをすべて捨てなければならない。
  - test: `tests/app/moqtrun_test.c` — `test_moqtrun_padding_stream_discarded`

## SS11.4.4 Fetch ヘッダーと Fetch の Object のフィールド

- [x] MQ18-236 (§11.4.4, §11.4.4.1, §11.4.4.2) 実装は、FETCH_HEADER(0x5、Request ID)とその Fetch Object のフィールドをエンコード・デコードしなければならない。対象は、Subgroup のモードを含む Serialization Flags、Object ID / Group ID Delta、Priority と Properties のフラグ、Datagram フラグ(0x40。下位 2 ビットは無視)、Group の順序を考慮した Group ID の差分、End of Non-Existent / Unknown Range の印である。
  - test: `tests/app/moqfetch_test.c` — `test_moqfetch_hdr`
  - test: `tests/app/moqfetch_test.c` — `test_moqfetch_stream_golden`
  - test: `tests/app/moqfetch_test.c` — `test_moqfetch_obj_group_order`
  - test: `tests/app/moqfetch_test.c` — `test_moqfetch_obj_datagram_lsbs`
  - test: `tests/app/moqfetch_test.c` — `test_moqfetch_stream_end_of_range`
- [x] MQ18-237 (§11.4.4, §11.4.4.1, §11.4.4.2) Fetch Object が End of Range の印以外で 128 以上の Serialization Flags の値を使う場合、最初の Object が Group または Object ID Delta を持たないか直前のフィールドを参照する場合、End of Range のあとに直前の Object がないのに直前の Subgroup や Priority を参照する場合、または計算した Group ID や Object ID が 0..2^64-1 の範囲を外れる場合、実装はプロトコル違反を報告しなければならない。
  - test: `tests/app/moqfetch_test.c` — `test_moqfetch_obj_flags_reject`
  - test: `tests/app/moqfetch_test.c` — `test_moqfetch_obj_overflow`
  - test: `tests/app/moqfetch_test.c` — `test_moqfetch_obj_after_eor_reject`

## SS11.4.2 制御ストリームのフロー制御

- [x] MQ18-143 (§11.4.2) エンドポイントは、接続のフロー制御の枠を、データストリームに割り当てる前に制御ストリームへ割り当てなければならない。そうすることで、受信側が、届くためにフロー制御の枠を必要とする制御メッセージを待ってデッドロックすることを防ぐ。
  - test: `tests/app/moqtrun_drain_test.c` — `test_moqtrun_prio_control_first`
    (ハブの制御ストリームは urgency 2 で、リクエストストリームの 3、Object ストリームの 4..7 より上)
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_wt_priority_conn_credit_to_urgent` (WT の送信パスは、接続の最後のクレジットをより緊急度の高いクラスに与える)

## SS11.4.2 Subgroup の Object のフィールド(エンコーダーのバイト単位の一致)

- [x] MQ18-144 実装は、Subgroup の Object の Object ID Delta、Payload Length、そして明示的な Object Status(ペイロードが空のとき)またはペイロードのバイト列を、ワイヤー形式とバイト単位で一致するようにエンコードしなければならない。
  - test: `tests/app/moqdata_test.c` — `test_moqdata_obj_put`
- [x] MQ18-145 1 メッセージのビルダーは、Object を 1 つ運ぶ 1 つの SUBGROUP_HEADER をワイヤー形式とバイト単位で一致するように組み立てなければならず、出力先バッファーが小さすぎるときは途中まで書かずに失敗しなければならない。
  - test: `tests/app/moqdata_test.c` — `test_moqdata_msg_build_golden`
  - test: `tests/app/moqdata_test.c` — `test_moqdata_msg_build_bounds`
  - test: `tests/app/moqdata_test.c` —
    `test_moqdata_put_path_status_eog_golden`

## SS5.1 購読(状態機械、追加の確認)

- [x] MQ18-146 (§5.1) 購読が Established である間、どちらの側(SUBSCRIBE または PUBLISH)が始めたかにかかわらず、その購読への Object の転送を許さなければならない。
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_object_relay_to_subscriber`
  - test: `tests/app/moqtrun_misc_test.c` — `test_moqtrun_misc_pub_ok_relays`
- [x] MQ18-147 (§5.1) Established の購読で受信した REQUEST_UPDATE は、購読を Established のままにしなければならない。
  - test: `tests/app/moqtrun_upd_test.c` — `test_moqtrun_upd_forward_toggles`
- [x] MQ18-148 (§3.3.2) リクエストを送った直後、応答を受け取る前に自分の方向を FIN で閉じたリクエスト元について、そのリクエストを失敗として扱ってはならない。
  - test: `tests/app/moqtrun_sub_test.c` — `test_moqtrun_req_fin_keeps_request`
- [x] MQ18-149 (§5.1, §3.3.2) 購読者は、リクエストストリームを取り消すことで Established の購読を終わらせられなければならない。
  - test: `tests/app/moqtrun_sub_test.c` —
    `test_moqtrun_req_reset_unsubscribes`
- [~] MQ18-150 (§3.3.2) リクエスト元の自分の方向がすでに FIN で閉じている場合、購読の取り消しは受信方向に STOP_SENDING だけを送らなければならない。
  - evidence: これを示すのは配線していない `moqsub` モデルだけである(`test_moqsub_cancel_after_fin`)。ハブは、上流の SUBSCRIBE を取り消すとき RESET_STREAM と STOP_SENDING を送る(`test_moqtrun_upsub_last_cancel_cancels_upstream`)。
- [x] MQ18-151 (§3.3.2) 応答側が一度も応答を送らずに自分の方向を FIN で閉じた場合、リクエスト元はそのリクエストを失敗として扱わなければならない。
  - evidence: `moqtrun_up_rx` / `moqtrun_upf_rx` は FIN を受け取り、応答のない上流の SUBSCRIBE / FETCH を REQUEST_ERROR と同じように失敗させる。`test_moqtrun_upsub_fin_unanswered_fails` と `test_moqtrun_upfetch_fin_unanswered` は応答の前に FIN を送り、下流のリクエスト元が拒否され、ハブの側が FIN で閉じられ、スロットが解放されることを確かめる。
  - test: `tests/app/moqtrun_upsub_test.c` — `test_moqtrun_upsub_fin_unanswered_fails`
- [x] MQ18-212 (§5.1) パブリッシャーは、SUBSCRIBE_OK、PUBLISH、または Forward State を 0 から 1 に変える REQUEST_UPDATE への REQUEST_OK で伝えた Largest Location を、その購読の Joining Location として保存しなければならない。
  - test: `tests/app/moqtrun_upd_test.c` — `test_moqtrun_upd_forward_toggles`
  - test: `tests/app/moqtrun_fetch_test.c` —
    `test_moqtrun_fetch_rejoin_reresolves_start`
- [x] MQ18-213 (§5.1) ハブが、そのピアへの購読が Pending(パブリッシャー側)状態にある(ハブが始めた PUBLISH にまだ応答がない)Track への SUBSCRIBE を受信した場合、ハブはそれを REQUEST_ERROR DUPLICATE_SUBSCRIPTION で拒否しなければならない。
  - evidence: `moqtrun_fresh_refusal`(`moqtrun_pub_crossing`)。`test_subtracks_subscribe_crosses_publish` は、ハブの SUBSCRIBE_TRACKS による PUBLISH に応答がない間に購読し、draft-18 では DUPLICATE_SUBSCRIPTION、後のドラフトでは購読になることを確かめる。
  - test: `tests/app/moqtrun_subtracks_test.c` — `test_subtracks_subscribe_crosses_publish`
- [x] MQ18-214 (§5.1) ハブが、そのピアへの自分の上流の SUBSCRIBE がまだ Pending(購読者側)である Track への PUBLISH を受信した場合、ハブは PUBLISH_OK を送る前に自分の購読を終わらせなければならない。
  - evidence: `moqtrun_up_crossed` は、PUBLISH_OK をキューに入れる前に `moqtrun_publish_checked` の中で Pending の上流の SUBSCRIBE を取り消す。`test_moqtrun_upsub_publish_crosses` は、リセットが PUBLISH_OK より先に来ること、待っている側が PUBLISH に乗ることを確かめる。
  - test: `tests/app/moqtrun_upsub_test.c` — `test_moqtrun_upsub_publish_crosses`
- [x] MQ18-215 (§5.1.1) 購読者が購読を取り消したとき、ハブはその購読の開いているデータストリームをすべてリセットしなければならない。
  - evidence: `moqtrun_req_cancel` は購読を破棄する前に、その購読のリレーのストリームをリセットする(`moqtrun_cancel_peer_subs`)。`test_moqtrun_req_reset_resets_data_streams` は、購読者への開いている Subgroup ストリームがリセットされることを確かめる。
  - test: `tests/app/moqtrun_sub_test.c` — `test_moqtrun_req_reset_resets_data_streams`
- [x] MQ18-216 (§5.1) パブリッシャーは、未完成の Object でも、使えるようになった分から送り始めるべきである。
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_relay_forwards_bytes_as_they_arrive`
  - test: `tests/app/moqtrun_cut_test.c` —
    `test_moqtrun_cut_lossy_refusal_mid_object_resets`,
    `test_moqtrun_cut_reliable_resumes_at_byte`
  - note: Object のヘッダーがそろったら、そのバイト列は、それを受け取る開いているすべての Subgroup ストリームへ送り出す。Object の途中で拒否された損失を許すストリームはリセットする(残りを捨てて区切りを保つことはできないため)。リングバッファーを持つストリームは、そのバイトの位置から再試行する。モデル: `tasks/loopeng/MoqtCutThrough.tla`。
- [ ] MQ18-218 (§5.1) ピアが自分で公開している Track を SUBSCRIBE した場合、ハブはそれをほかの購読と同じように扱い、公開された Object を送り返さなければならない。
  - gap: テストはない。購読していた名前を改めて PUBLISH したパブリッシャーは、意図的に自分の Track には結び付けない(`test_moqtrun_publisher_is_not_reattached_to_own_track`)。

## SS10 制御メッセージ: セッションの状態機械の望ましくない動作(追加の確認)

- [x] MQ18-152 (§10) 制御ストリームが未知のメッセージ型、または Length と Body の不一致を含む場合、実装はプロトコル違反でセッションを閉じなければならない。
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_ctl_unknown_type_closes_session`
  - test: `tests/app/moqctl_test.c` — `test_moqctl_peek_type_length_mismatch`
- [x] MQ18-153 (§3.5) セッションが閉じたあとは、以降のイベントは何もしないものでなければならない(クローズの理由は保持される)。
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_ctl_unknown_type_closes_session`
  - test: `tests/app/moqsess_test.c` — `test_moqsess_closed_is_sticky`
## ハブのリレー: PUBLISH/SUBSCRIBE の振り分け(SS9 リレー、SS10.5/10.7/10.10 の適用)

- [x] MQ18-154 PUBLISH が成功したとき、ハブは同じ制御ストリームで、それを閉じずに REQUEST_OK で応答しなければならない。
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_publish_replies_request_ok`
- [x] MQ18-155 ピアは、2 つ以上の異なる Track を(実装のピアごとの Track 数の上限まで)PUBLISH してもよく、それぞれが独立して REQUEST_OK を受け取る。
  - test: `tests/app/moqtrun_test.c` — `test_moqtrun_peer_publishes_two_tracks`
- [x] MQ18-156 ピアが実装のピアごとの上限を超える数の異なる Track を PUBLISH しようとした場合、実装は既存の Track を何も知らせずに上書きすることはせず、REQUEST_ERROR で応答しなければならない。
  - test: `tests/app/moqtrun_test.c` — `test_moqtrun_sixth_publish_gets_error`
- [x] MQ18-157 すでにスロットを占めている同じ Track Name を再び PUBLISH したときは、新しいスロットを使わず、そのスロットを再利用しなければならない。
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_republish_same_name_reuses_slot`
- [x] MQ18-158 ピアが PUBLISH した Track のどれかを指定する SUBSCRIBE は、割り当てた Track Alias を持つ SUBSCRIBE_OK を受け取らなければならない。
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_subscribe_audio_track_replies_ok`
- [x] MQ18-159 同じ振り分けの呼び出しで届いた 2 つの SUBSCRIBE メッセージには、一方が他方を上書きすることなく、それぞれの応答をキューに入れなければならない。
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_two_subscribe_oks_one_dispatch_no_overflow`

## ハブのリレー: 一致する購読者だけへの Object の転送(SS9.4, SS11.1)

- [x] MQ18-160 Object は、その Track Alias が示す Track の購読者にだけ転送しなければならず、同じセッションのほかの Track の購読者に転送してはならない。
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_chat_object_relays_only_to_chat_subscriber`
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_audio_object_relays_only_to_audio_subscriber`
- [x] MQ18-161 Object の Track Alias がパブリッシャーの宣言したどの Track にも一致しない場合、実装はそれをどの購読者にも転送してはならない。
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_unknown_alias_object_relays_nowhere`
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_unbound_stream_id_relays_nowhere`
- [x] MQ18-162 同じ Track への複数の購読に一致する Object は、一致する購読ごとに 1 回ずつ送らなければならない。
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_chat_object_relays_to_all_three_subscribers`
- [x] MQ18-163 ある購読者への Object の転送が失敗した(下位のトランスポートが送信を拒否した)場合でも、実装はほかの一致する購読者全員へそれを転送しなければならず、その損失を見過ごさずに数えなければならない。
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_chat_one_of_three_subscribers_refused`
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_send_uni_failure_counts_open_drop`
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_stream_send_rejection_drops_frame_not_fatal`
- [x] MQ18-164 Forwarding Preference が Subgroup で送られた Object は、パブリッシャーのストリームの区切りに合わせ、リレーの送信 1 回ごとに SUBGROUP_HEADER と Object をひとまとまりにしてリレーしなければならない。
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_multi_object_stream_relays_in_one_send_uni`
- [x] MQ18-165 長く続く Subgroup ストリームの後続のデータ(SUBGROUP_HEADER を繰り返さずに届く)は、新しいヘッダーと読み違えず、すでに結び付いた同じリレーのストリームに追記しなければならない。
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_data_stream_continues_across_calls_without_header`
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_audio_first_object_opens_then_appends`
- [x] MQ18-166 パブリッシャーの Subgroup ストリームが FIN で終わったとき、実装は境界をまたいで追記せず、対応するリレーのストリームを閉じ、新しいパブリッシャーのストリームで来る次の Subgroup のために新しいストリームを開かなければならない。
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_audio_publisher_fin_closes_and_reopens`
- [x] MQ18-167 実装は、各 Subgroup を、その配信の形に合ったトランスポートの基本操作で一貫してリレーしなければならない(1 回で終わる Subgroup には open+send+FIN を 1 度に、長く続く Subgroup には FIN なしの open とその後の追記を使う)。
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_chat_still_uses_send_uni_every_object`
- [x] MQ18-168 同じ Track の 2 人の購読者は、それぞれ独立したリレーのストリームを受け取らなければならず、一方への配信が他方のストリームの結び付きに影響してはならない。
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_audio_two_subscribers_independent_streams`

## ハブのリレー: 拒否が続いたときの切り捨て(SS11.4.3 のリセットの決まりの適用)

- [x] MQ18-169 購読者のリレーのストリームが、実装のしきい値を超えて混雑し(拒否され)続けた場合、実装は古い滞留分を持ち続けず、そのストリームをリセットし、次の配信で新しいストリームを開き直さなければならない。
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_busy_streak_sheds_after_threshold`
- [x] MQ18-170 混雑が続く途中で配信が受け入れられたら、混雑の連続回数のカウンターをリセットしなければならない。そうすることで、ときどき起きる一時的な拒否が積み重なって切り捨てに至ることはない。
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_busy_streak_success_resets`
- [x] MQ18-171 ストリームを切り捨てたあと、その放棄したストリームに対してパブリッシャーから届くデータなしの FIN を、そこへ転送してはならない。
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_shed_stream_skips_publisher_fin`
- [x] MQ18-172 混雑の連続回数のカウンターは購読者ごとに持たなければならない。そうすることで、送れずにいる 1 人の購読者の切り捨てが、ほかの購読者の正常なストリームに影響しない。
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_busy_shed_isolated_per_subscriber`
- [x] MQ18-173 リセットそのものが下位のトランスポートに拒否された場合、実装はそれを完了したものとして扱わず、次の混雑の回で切り捨てを再試行しなければならない。
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_shed_refused_retries_next_round`
- [x] MQ18-174 Track の再 PUBLISH は、前の回で積み重なった混雑の連続回数のカウンターを含め、その Track のリレーの状態を消去しなければならない。
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_republish_clears_busy_streak`

## ハブのリレー: セッションの後片付け(SS3.5 終了のリレー状態への適用)

- [x] MQ18-175 セッションが閉じたとき、実装はそのピアのスロットを解放しなければならない。そうすることで、下位の同じセッションポインターで後から再接続したものを、終わったピアではなく新しいピアとして扱う。
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_close_frees_peer_for_reregistration`
- [x] MQ18-176 購読者のセッションが閉じたとき、実装は、ほかのすべてのピアの Track にあるその購読者の購読エントリを無効にしなければならない。そうすることで、後の Object を終わったセッションへリレーしない。
  - test: `tests/app/moqtrun_test.c` — `test_moqtrun_close_drops_subscriptions`
- [x] MQ18-177 実装が一度も登録していないセッション(またはすでに閉じたセッション)を閉じる操作は、何もせず、ほかのピアに影響を与えないものでなければならない。
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_close_unknown_session_noop`
- [x] MQ18-178 実装のピアテーブルの容量を超えて登録とクローズを繰り返しても、スロットを漏らしてはならず、どの再接続も SETUP を受け取らなければならない。
  - test: `tests/app/moqtrun_test.c` — `test_moqtrun_close_reregister_churn`

## ハブのリレー: 制御ストリームとリクエストストリーム

- [x] MQ18-179 実装は、すべての Message Parameter を draft-18 のレジストリ(値のエンコーディング、現れてよいメッセージ、許される値の範囲)に従ってデコードしなければならない。メッセージや範囲の外のパラメーターは、プロトコル違反でセッションを閉じなければならない。
  - test: `tests/app/moqctl_test.c` — `test_moqctl_params_registry_scope`
  - test: `tests/app/moqctl_test.c` — `test_moqctl_params_registry_scope_per_draft`
  - test: `tests/app/moqctl_test.c` — `test_moqctl_params_uint8_value_ranges`
  - test: `tests/app/moqctl_test.c` — `test_moqctl_params_repeatable_filters`
  - test: `tests/app/moqctl_test.c` — `test_moqctl_golden_subscribe_params`
- [x] MQ18-180 ストリームの複数回の受け渡しに分かれた制御メッセージは、再び組み立てて 1 回だけ処理しなければならない。1 KiB を超えるメッセージ(65535 バイトまで)は共有の再組み立てバッファで受け取り、そのバッファが尽きたときは INTERNAL_ERROR でセッションを閉じなければならない。
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_ctl_split_subscribe_answered_once`
  - test: `tests/app/moqtrun_test.c` — `test_moqtrun_ctl_message_then_half`
  - test: `tests/app/moqtrun_test.c` — `test_moqtrun_ctl_max_length_accepted`
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_ctl_pool_exhausted_closes`
- [x] MQ18-181 制御ストリームがまったく未知の Message Type を含む場合、ハブはプロトコル違反でセッションを閉じなければならない。
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_ctl_unknown_type_closes_session`
- [x] MQ18-182 それぞれ専用の双方向ストリームで開いたリクエストには、そのストリームで応答しなければならない。ストリームのリセットはリクエストを取り消し(購読の解除、公開の解除)、FIN だけでは取り消さない(ほとんどのリクエスト型の場合。draft-18 の SUBSCRIBE_NAMESPACE/SUBSCRIBE_TRACKS の例外は MQ18-037a を参照)。1 つのセッションが開いておけるリクエストは最大 32 個である(それより多いものは EXCESSIVE_LOAD でリセットする)。
  - test: `tests/app/moqtrun_sub_test.c` —
    `test_moqtrun_req_subscribe_answered_on_its_stream`
  - test: `tests/app/moqtrun_sub_test.c` —
    `test_moqtrun_req_two_streams_answered_apart`
  - test: `tests/app/moqtrun_sub_test.c` — `test_moqtrun_req_reset_unsubscribes`
  - test: `tests/app/moqtrun_sub_test.c` — `test_moqtrun_req_fin_keeps_request`
  - test: `tests/app/moqtrun_sub_test.c` — `test_moqtrun_req_per_session_cap`
  - test: `tests/app/moqtrun_sub_test.c` — `test_moqtrun_req_pool_full_resets`

## ハブのリレー: 購読

- [x] MQ18-183 SUBSCRIBE は、公開された Track に完全な Track Name(名前空間と名前)で一致しなければならない。したがって、名前が同じでも名前空間が違えば別の Track である。
  - test: `tests/app/moqtrun_sub_test.c` — `test_moqtrun_sub_ns_must_match`
  - test: `tests/app/moqtrun_sub_test.c` —
    `test_moqtrun_sub_same_name_other_ns_coexist`
- [x] MQ18-184 ハブは、各購読の Request ID、SUBSCRIBER_PRIORITY、GROUP_ORDER、FORWARD、配信タイムアウト、フィルターの開始位置を記録し、パブリッシャーが加わり直してもそれを保ち、Track に Object ができたら SUBSCRIBE_OK で LARGEST_OBJECT を報告しなければならない。
  - test: `tests/app/moqtrun_sub_test.c` — `test_moqtrun_sub_params_recorded`
  - test: `tests/app/moqtrun_sub_test.c` —
    `test_moqtrun_sub_reattach_keeps_state`
  - test: `tests/app/moqtrun_sub_test.c` — `test_moqtrun_sub_ok_largest`
  - test: `tests/app/moqtrun_sub_test.c` —
    `test_moqtrun_sub_largest_from_datagram`
- [x] MQ18-185 Object は、共有のバッファープールから各購読者へ信頼性をもってリレーしなければならない。遅い購読者がプールを引き止めるのは上限(watermark)までで、止まった購読者はタイムアウト後に切り離し、末尾を落としたストリームは続けない(続けると購読者との同期が崩れる)。
  - test: `tests/app/moqtrel_test.c` — `test_moqtrel_append_hold_at_watermark`
  - test: `tests/app/moqtrel_test.c` — `test_moqtrel_reclaim_follows_slowest`
  - test: `tests/app/moqtrel_test.c` — `test_moqtrel_stalled_after_timeout`
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_poison_survives_reset_and_close`
  - test: `tests/app/moqtrun_test.c` —
    `test_moqt_reliable_relay_sheds_stalled_sub`
- [x] MQ18-186 購読者の優先度は、その購読者のリレーのストリームの WebTransport のストリームの urgency に対応付けなければならない。優先度を変える REQUEST_UPDATE は後のストリームに適用され、その購読の開いたままのストリームと埋め戻しのストリームのクラスを付け直す。io の stream_sched フックがあれば、ハブは各 Object ストリームのクラス全体(urgency 4、Subscriber << 8 | Publisher Priority、Group の順序と「ライブより埋め戻しが先」で順位を付けた購読ごとのフロー)を設定し、送信ポンプはそれに従ってスケジュールする。
  - test: `tests/app/moqtrun_drain_test.c` — `test_moqtrun_sched_relay_keys`
  - test: `tests/app/moqtrun_drain_test.c` — `test_moqtrun_sched_update_reclasses`
  - test: `tests/app/moqtrun_drain_test.c` — `test_moqtrun_sched_fill_shares_flow`
  - test: `tests/app/srvrun_test.c` — `test_srvrun_wt_sched_fill_before_live`
  - test: `tests/app/moqtrun_drain_test.c` — `test_moqtrun_prio_per_subscriber`
  - test: `tests/app/moqtrun_drain_test.c` — `test_moqtrun_prio_update_applies`
  - test: `tests/app/moqtrun_drain_test.c` — `test_moqtrun_prio_op_absent`
- [x] MQ18-187 (§10.9) その購読のリクエストストリームで受け取った SUBSCRIBE への REQUEST_UPDATE は、パラメーターをすべてまとめて置き換えるか、まったく置き換えないかのどちらかでなければならない。含まれないパラメーターは値を保ち、拒否された更新は何も変えない。
  - test: `tests/app/moqtrun_upd_test.c` — `test_moqtrun_upd_forward_toggles`
  - test: `tests/app/moqtrun_upd_test.c` — `test_moqtrun_upd_params_replace`
  - test: `tests/app/moqtrun_upd_test.c` —
    `test_moqtrun_upd_failed_changes_nothing`
  - test: `tests/app/moqtrun_upd_test.c` — `test_moqtrun_upd_survives_rejoin`
- [~] MQ18-230 (§10.9.1) 購読への REQUEST_UPDATE が失敗したとき、ハブは購読も PUBLISH_DONE UPDATE_FAILED で終わらせ、そのリクエストストリームを FIN で閉じなければならない。
  - evidence: `moqtrun_update_sub_apply` は REQUEST_ERROR を送ってから PUBLISH_DONE UPDATE_FAILED を送る。テストが確かめるのは REQUEST_ERROR と FIN だけである(`test_moqtrun_upd_failed_changes_nothing`。ハブが始める PUBLISH については `test_moqtrun_misc_pub_update_failed_fins` で、これは draft-19/22 でだけ動く)。
- [x] MQ18-188 TRACK_STATUS には、Track の最大の位置(空なら位置なし)を持つ REQUEST_OK で応答するか、Track が未知か認可の処理が拒否した場合は REQUEST_ERROR で応答しなければならない。
  - test: `tests/app/moqtrun_upd_test.c` — `test_moqtrun_tstat_ok_largest`
  - test: `tests/app/moqtrun_upd_test.c` — `test_moqtrun_tstat_ok_empty`
  - test: `tests/app/moqtrun_upd_test.c` — `test_moqtrun_tstat_unknown_and_blob`
  - test: `tests/app/moqtrun_upd_test.c` — `test_moqtrun_tstat_authorized`
- [x] MQ18-189 (§9.4, §9.5, §10.2.2, §13) アプリケーションが認可の処理を組み込む構成では、すべての PUBLISH、SUBSCRIBE、TRACK_STATUS、PUBLISH_NAMESPACE、SUBSCRIBE_NAMESPACE をその処理に渡さなければならず、拒否は REQUEST_ERROR UNAUTHORIZED でなければならない。Alias を使う認可トークンは、セッションを閉じなければならない(ハブはトークンのキャッシュを持たない。10.2.2)。REGISTER は AUTH_TOKEN_CACHE_OVERFLOW で、DELETE と USE_ALIAS は UNKNOWN_AUTH_TOKEN_ALIAS で閉じる。
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_subscribe_requires_authorization`
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_subscribe_alias_token_rejected`
  - test: `tests/app/moqtrun_upd_test.c` —
    `test_moqtrun_publish_requires_authorization`
  - test: `tests/app/moqtrun_upd_test.c` — `test_moqtrun_tstat_authorized`
  - test: `tests/app/moqtrun_ns_test.c` — `test_moqtrun_ns_authorization`
  - note: SUBSCRIBE_TRACKS も同じ名前空間の確認(`moqtrun_disc_verdict`)を通るが、専用のテストはない。
  - vuln: V-0786, V-0792, V-0793, V-0839

## ハブのリレー: 配信タイムアウト

- [x] MQ18-190 (§8) 0 でない OBJECT_DELIVERY_TIMEOUT(SUBSCRIBE または REQUEST_UPDATE で指定)があるとき、時間内に配信されなかった Object は放棄しなければならない。そのストリームは DELIVERY_TIMEOUT(0x2)でリセットし、その Subgroup の残りのために新しいストリームは開かない。データグラムは届いたときにリレーするので、タイムアウトより長く残ることはない。
  - test: `tests/app/moqtrun_upd_test.c` — `test_moqtrun_timeout_live`
  - test: `tests/app/moqtrun_upd_test.c` — `test_moqtrun_timeout_datagram`
  - test: `tests/app/moqtrun_upd_test.c` — `test_moqtrun_timeout_by_update`
  - test: `tests/app/moqtrun_upd_test.c` — `test_moqtrun_timeout_torn_object`
  - test: `tests/app/moqtrun_upd_test.c` — `test_moqtrun_timeout_zero`
  - note: draft-18 は OBJECT_DELIVERY_TIMEOUT/SUBGROUP_DELIVERY_TIMEOUT を Track Property としてだけ定めている(draft-19 で加わった、Subgroup の最初の Object の Object Property としての扱いはない)。実装はどちらも Object Property として読まないので、タイムアウトの値を 1 か所から取る実装はこの違いの影響を受けない。`draft18-vs-19-diff.md` の §11 を参照。

- [x] MQ18-221 (§8) 0 でない SUBGROUP_DELIVERY_TIMEOUT があるとき、ハブは Subgroup の FIN が上流から届いた時点でタイマーを始め、タイマーが切れたときにリレーのストリームが「すべてのデータを確定」に達していなければ、そのストリームをリセットしなければならない。
  - test: `tests/app/moqtrun_sub_test.c` —
    `test_moqtrun_sub_subgroup_timeout_after_fin`
  - note: リレーするストリームの上流の FIN で開始する(最初の受け渡しで全体を送る 1 回きりのストリームでは開始しない)。「確定」は、トランスポートのすべて確認応答済みの合図(`wired_moqt_io.stream_inflight`)である。

## ハブのリレー: キャッシュと FETCH

- [x] MQ18-191 キャッシュ領域を取り付けた(`wired_moqt_cache_attach`)構成では、ハブは Group 単位でだけキャッシュし、予算を超えたら最も古い Group を追い出し、単独で予算を超える Group は捨てなければならない。
  - test: `tests/app/moqcache_test.c` — `test_moqcache_evicts_oldest_group`
  - test: `tests/app/moqcache_test.c` — `test_moqcache_group_over_budget_dropped`
  - test: `tests/app/moqtrun_fetch_test.c` — `test_moqtrun_fetch_cache_attach`
  - test: `tests/app/moqtrun_fetch_test.c` —
    `test_moqtrun_fetch_cache_default_off`
- [x] MQ18-192 単独の FETCH はキャッシュから返さなければならない。追い出された範囲や一度もキャッシュされなかった範囲は、何も知らせずに飛ばすのではなく、End of Unknown Range の印として報告しなければならない。
  - test: `tests/app/moqtrun_fetch_test.c` — `test_moqtrun_fetch_serves_cached`
  - test: `tests/app/moqtrun_fetch_test.c` —
    `test_moqtrun_fetch_evicted_group_unknown`
  - test: `tests/app/moqtrun_fetch_test.c` —
    `test_moqtrun_fetch_no_cache_unknown`
  - test: `tests/app/moqfetch_test.c` — `test_moqfetch_stream_end_of_range`
- [x] MQ18-193 (§10.12.2) joining FETCH(相対または絶対)は、FETCH と SUBSCRIBE の間に隙間が残らないように、加わる先の購読の Joining Location に対して解決しなければならない。購読の Forward State が 0 の場合、何も公開されていない場合、開始位置が Joining Location より後にある場合は INVALID_RANGE で、Request ID がそのセッションのどの購読も指していない場合は INVALID_JOINING_REQUEST_ID で拒否しなければならない。
  - test: `tests/app/moqtrun_fetch_test.c` —
    `test_moqtrun_fetch_relative_join_no_gap`
  - test: `tests/app/moqtrun_fetch_test.c` — `test_moqtrun_fetch_absolute_join`
  - test: `tests/app/moqtrun_fetch_test.c` —
    `test_moqtrun_fetch_join_invalid_range`
  - test: `tests/app/moqtrun_fetch_test.c` —
    `test_moqtrun_fetch_join_forward_off`
  - test: `tests/app/moqtrun_fetch_test.c` —
    `test_moqtrun_fetch_join_unknown_request`
  - note: draft-18 の FETCH の本文(Fetch Type + Standalone/Joining)は draft-19 とバイト単位で同じ。draft-22 は Joining FETCH をすべて削除した(`docs/features/draft-moq-transport-22.md` の 4-6 を参照)。
  - gap: まだ Pending(購読者側)の購読に対する Joining FETCH を確かめるテストはない。§10.12.2 は、それを購読が確立するまでバッファーに保持するとしている。
- [x] MQ18-233 (§10.12.3, §10.13) 単独の FETCH は、何も公開されていない場合、Start が Largest Object より後にある場合、End が Start より前にある場合は INVALID_RANGE で、誰もその Track を公開していない場合は DOES_NOT_EXIST で拒否しなければならない。Largest Object より後の End は、FETCH_OK で {Largest.Group, Largest.Object + 1} に切り詰めなければならない。
  - test: `tests/app/moqtrun_fetch_test.c` —
    `test_moqtrun_fetch_nothing_published`
  - test: `tests/app/moqtrun_fetch_test.c` —
    `test_moqtrun_fetch_range_against_largest`
  - test: `tests/app/moqtrun_fetch_test.c` —
    `test_moqtrun_fetch_end_before_start`
  - test: `tests/app/moqtrun_fetch_test.c` — `test_moqtrun_fetch_unknown_track`
- [x] MQ18-219 (§5.2, §9.4, §9.5, §10.12.3, §10.13) FETCH が、ハブが持っておらず、存在しないとも分かっていない Object を必要とするとき、ハブは Track のパブリッシャーかそれを含む名前空間の告知元へ上流の FETCH を 1 つ送り、上流の Object をその場でリレーし、End Location が分かるまで FETCH_OK を送らずにおかなければならない。FETCH_OK の End が Start より前にある上流のセッションは PROTOCOL_VIOLATION で閉じ、取り消すときは上流のリクエストストリームに RESET_STREAM と STOP_SENDING を送らなければならない。
  - test: `tests/app/moqtrun_upfetch_test.c` —
    `test_moqtrun_upfetch_gap_to_owner`
  - test: `tests/app/moqtrun_upfetch_test.c` —
    `test_moqtrun_upfetch_no_track_waits_ok`
  - test: `tests/app/moqtrun_upfetch_test.c` — `test_moqtrun_upfetch_bad_end`
  - test: `tests/app/moqtrun_upfetch_test.c` —
    `test_moqtrun_upfetch_requester_gone`
  - test: `tests/app/moqtrun_upfetch_test.c` —
    `test_moqtrun_upfetch_upstream_draft`
  - note: これらのテストでリクエスト元は draft-22 で動く。上流の FETCH は、draft-18 を含め、上流のセッション自身のドラフトの形で書く(`test_moqtrun_upfetch_upstream_draft`)。
- [x] MQ18-227 (§10.2.5) ハブは、上流の FETCH を待つ時間を FETCH の FILL_TIMEOUT(ないときは実装の既定値)で区切り、その後もまだ足りない部分を未知の範囲として報告しなければならない。FILL_TIMEOUT が 0 なら、上流には何も求めてはならない。
  - test: `tests/app/moqtrun_upfetch_test.c` — `test_moqtrun_upfetch_budget`
  - test: `tests/app/moqtrun_upfetch_test.c` —
    `test_moqtrun_upfetch_fill_timeout_zero`
  - note: draft-18 には End of Timed-Out Range の印がない。そのようなドラフトに対しては、隙間は End of Unknown Range になる(予算のテストの draft-19 の部分)。
- [x] MQ18-222 (§9.1) ハブが Object を存在しないものとして記録している場合、その Object が後から届いても、キャッシュも転送もするべきではない。
  - test: `tests/app/moqtrun_fetch_test.c` —
    `test_moqtrun_fetch_late_nonexistent_not_cached`
  - test: `tests/app/moqtrun_cut_test.c` —
    `test_moqtrun_stream_skips_gone_object`
  - note: 記録とはキャッシュのことである(閉じた Group の中で、存在しないとして返す Location)。Subgroup ストリームではそのような Object を切り取り、次の Object の Object ID Delta をつなぎ直す。そのような Object から始まるストリームはリレーせず、1 回きりのストリームは最初のそのような Object の位置で切る。
- [x] MQ18-238 (§12.3) Track が MAX_CACHE_DURATION を持つ場合、ハブは、Object の最初のバイトを受信してからそのミリ秒数を過ぎたあとに、その Object の転送を始めてはならない。
  - test: `tests/app/moqtrun_fetch_test.c` — `test_moqtrun_fetch_max_cache_duration`
  - note: 「受信した時刻」は Object が届く前の最後の `wired_moqt_tick` の時刻で、最初のバイトより後になることはないので、Object は早めに期限切れになるだけである。期限切れの Object を 1 つでも含むキャッシュ済みの Group は、全体が未知になる(キャッシュは Group の一部だけを持つことはない)。draft-18/19 の FETCH の本文で動かす。
- [x] MQ18-194 FETCH は、リクエスト元が取り消したとき、データストリームが止められたとき、パブリッシャーかリクエスト元が去ったとき、配信が止まったときに、そのスロットを解放しなければならない。
  - test: `tests/app/moqtrun_fetch_test.c` —
    `test_moqtrun_fetch_cancelled_by_request_reset`
  - test: `tests/app/moqtrun_fetch_test.c` —
    `test_moqtrun_fetch_data_stream_stopped`
  - test: `tests/app/moqtrun_fetch_test.c` —
    `test_moqtrun_fetch_publisher_leaves`
  - test: `tests/app/moqtrun_fetch_test.c` — `test_moqtrun_fetch_stall_gives_up`
  - test: `tests/app/moqtrun_fetch_test.c` —
    `test_moqtrun_fetch_requester_leaves`

## ハブのリレー: 名前空間の発見

- [x] MQ18-195 PUBLISH_NAMESPACE はパブリッシャーごとに受け入れなければならず(複数のパブリッシャーが 1 つの名前空間を共有してよい)、SUBSCRIBE_NAMESPACE には一致するすべての名前空間について NAMESPACE を送り、その後はパブリッシャーの出入りに応じて NAMESPACE / NAMESPACE_DONE を送らなければならない。
  - test: `tests/app/moqtrun_ns_test.c` — `test_moqtrun_ns_publish_accepted`
  - test: `tests/app/moqtrun_ns_test.c` — `test_moqtrun_ns_initial_set`
  - test: `tests/app/moqtrun_ns_test.c` — `test_moqtrun_ns_live_join_and_cancel`
  - test: `tests/app/moqtrun_ns_test.c` — `test_moqtrun_ns_publisher_leaves`
  - test: `tests/app/moqtrun_ns_test.c` — `test_moqtrun_ns_multiple_publishers`
  - test: `tests/app/moqtrun_ns_test.c` — `test_moqtrun_ns_prefix_overlap`
  - note: 1 つのセッションの中では、2 つの接頭辞は、どちらかが空であるか最初のフィールドが等しいときに重なる。§10.18 の "shares a common prefix" を文字どおりに読んだもので、(chat, room1) と (chat, room2) は重なる。

## ハブのリレー: GOAWAY と PUBLISH_DONE

- [~] MQ18-196 `wired_moqt_goaway` は、セッションごとに 1 回 GOAWAY を送らなければならない。そのあとに届いたリクエストは GOING_AWAY で拒否する。タイムアウトが切れたら、ハブは PUBLISH_DONE を送り、まだ処理中のものに応答し、GOAWAY_TIMEOUT で閉じる。
  - test: `tests/app/moqtrun_drain_test.c` —
    `test_moqtrun_goaway_once_per_session`
  - test: `tests/app/moqtrun_drain_test.c` — `test_moqtrun_goaway_late_rejected`
  - test: `tests/app/moqtrun_drain_test.c` —
    `test_moqtrun_goaway_timeout_flush_then_close`
  - test: `tests/app/moqtrun_drain_test.c` — `test_moqtrun_goaway_retried_on_tick`
  - evidence: io テーブルに対する単体テストだけで確かめている。GOAWAY と drain の手順を第三者の MOQT 実装に対して動かしたことはまだない。
- [x] MQ18-197 ピアからの 2 回目の GOAWAY、またはクライアントからの New Session URI を持つ GOAWAY は、プロトコル違反でセッションを閉じなければならない。
  - test: `tests/app/moqtrun_drain_test.c` — `test_moqtrun_peer_goaway_twice`
  - test: `tests/app/moqtrun_drain_test.c` — `test_moqtrun_peer_goaway_uri`
- [x] MQ18-198 ハブは、PUBLISH_DONE の前に購読のデータストリームをリセットしなければならない。パブリッシャーのセッションが終わると、その購読者に PUBLISH_DONE TRACK_ENDED を送る。
  - test: `tests/app/moqtrun_drain_test.c` —
    `test_moqtrun_done_resets_streams_first`
  - test: `tests/app/moqtrun_drain_test.c` — `test_moqtrun_done_track_ended`
- [~] MQ18-199 ピアからの WebTransport の WT_DRAIN_SESSION(`wired_moqt_on_session_draining`)は、そのセッションについてだけ MOQT の GOAWAY の手順を始めなければならない。
  - test: `tests/app/moqtrun_drain_test.c` — `test_moqtrun_drain_one_session`
  - evidence: 単体テストだけで確かめている。実際のピアでの実行はまだない。

## ハブのリレー: Object Datagram

- [x] MQ18-200 (§11.3) Object Datagram は、その alias が示す Track のすべての購読者へバイト単位で同じままリレーしなければならない。alias が未知のデータグラムは捨ててもよい(数える)。
  - test: `tests/app/moqdg_test.c` — `test_moqdg_roundtrip_golden`
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_dg_relays_identical_bytes_to_subscriber`
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_dg_relays_to_all_three_subscribers`
  - test: `tests/app/moqtrun_test.c` — `test_moqtrun_dg_unknown_alias_counts_bad`
- [x] MQ18-234 (§11, §11.3.1) データグラムの Type が未知または無効(0b00X0XXXX の外、または END_OF_GROUP 付きの STATUS)である場合、PROPERTIES ビットが立っているのに Properties Length が 0 である場合、または Object Status が Normal でないのに Properties がある場合、サーバーは PROTOCOL_VIOLATION でセッションを閉じなければならない。
  - test: `tests/app/moqtrun_sess_test.c` — `test_mtss_datagram_invalid_closes`
- [~] MQ18-240 (§11.5.2) サーバーは、パディングのデータグラム(型 0x132B3E29)で受信したデータをすべて捨てなければならない。
  - evidence: データグラムのコーデックにはパディングの型がないので、ハブはほかの不正な形式のデータグラムと同じく、デコードできないものとして捨てる(`test_moqtrun_dg_malformed_counts_bad`)。パディングの型を送るテストはない。

## 複数ドラフト対応の回で仕上げたハブの機能(台帳 10 章)

- [x] MQ18-201 (SS10.19) ハブは、SUBSCRIBE_TRACKS に、そのリクエストストリームでちょうど 1 つの REQUEST_OK で応答しなければならない。Track Namespace Prefix が同じセッションの確立済みの SUBSCRIBE_TRACKS と重なるものは、PREFIX_OVERLAP で拒否しなければならない。
  - test: `tests/app/moqtrun_subtracks_test.c` — `test_subtracks_ok_once`
  - test: `tests/app/moqtrun_subtracks_test.c` — `test_subtracks_prefix_overlap`
  - test: `tests/app/moqtrun_ctlfix_test.c` —
    `test_mtcf_d18_subtracks_range_filter`
  - note: draft-18 が SUBSCRIBE_TRACKS で認めるのは AUTHORIZATION TOKEN と FORWARD だけである(パラメーターの表を参照)。subtracks のシナリオは draft-18 を含むすべてのドラフトで動く。
- [x] MQ18-202 (SS10.19) 確立済みの SUBSCRIBE_TRACKS の接頭辞に一致し、購読者自身が公開したものではないすべての Track について、ハブは新しい双方向ストリームでその Track を指定する PUBLISH を 1 つ開き、SUBSCRIBE_TRACKS の FORWARD の値を載せなければならない。SUBSCRIBE_TRACKS を取り消すと新しい PUBLISH は止まるが、確立済みのものは残る。応答の前に消えた Track はその PUBLISH ストリームをリセットし、REQUEST_ERROR の応答はスロットを解放する。PUBLISH_OK(REQUEST_OK)の応答は、PUBLISH の Track Alias で購読者の購読を開き、PUBLISH のパラメーターから始める(FORWARD 0 なら Object を送らずにおく)。そのストリームでの購読者の REQUEST_UPDATE は SUBSCRIBE の場合と同じように適用し、そこで応答する(台帳 12-11、12-18。失敗した更新は MQ18-230)。2 つ目の REQUEST_OK(PUBLISH_OK)または REQUEST_ERROR は、PROTOCOL_VIOLATION でセッションを閉じる(SS5.1 の "SHOULD close the session with a protocol error"、台帳 12-28)。
  - test: `tests/app/moqtrun_misc_test.c` — `test_moqtrun_misc_pub_ok_relays`
  - test: `tests/app/moqtrun_misc_test.c` —
    `test_moqtrun_misc_pub_second_ok_closes`
  - test: `tests/app/moqtrun_misc_test.c` —
    `test_moqtrun_misc_pub_error_after_ok_closes`
  - test: `tests/app/moqtrun_misc_test.c` —
    `test_moqtrun_misc_pub_forward0_then_update`
  - test: `tests/app/moqtrun_misc_test.c` —
    `test_moqtrun_misc_pub_update_before_ok`
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
  - note: 台帳 10-2(E-2): ハブが始める PUBLISH の経路。TLA+ で検査した設計は `tasks/loopeng/moqt/MoqtHubPublish/`(git には含まない)にある。シナリオは draft-18 を含むすべてのドラフトで動く。
- [x] MQ18-225 (§9.5) ハブが、ある Track のパブリッシャーを待つ下流の SUBSCRIBE を保留していて、その購読者が一致する SUBSCRIBE_TRACKS も持っている場合、届いた PUBLISH は保留中の SUBSCRIBE を完了させなければならず、その購読者へハブが始める PUBLISH として重ねて転送してはならない。
  - test: `tests/app/moqtrun_rdv_test.c` —
    `test_moqtrun_rdv_s12_subtracks_skips_held`
- [x] MQ18-203 (SS10.20) ハブがそのような PUBLISH のための双方向ストリームを開けない場合、ハブは代わりに SUBSCRIBE_TRACKS のリクエストストリームで PUBLISH_SKIPPED(draft-18 では PUBLISH_BLOCKED)(Track Namespace Suffix, Track Name)を送らなければならず、同じ Track の同じ回について後から PUBLISH を送ってはならない。
  - test: `tests/app/moqtrun_subtracks_test.c` —
    `test_subtracks_skip_then_no_publish`
  - test: `tests/app/moqns_test.c` — `test_moqns_pub_skipped_roundtrip`
  - test: `tests/app/moqns_test.c` — `test_moqns_pub_skipped_rejects`
  - note: subtracks のシナリオは draft-18 を含むすべてのドラフトで動く。
- [~] MQ18-204 (SS10.9, SS10.9.1, SS10.9.2) FETCH、PUBLISH_NAMESPACE、SUBSCRIBE_NAMESPACE のリクエストストリームで受け取ったそれらへの REQUEST_UPDATE は、処理しなければならない。受け入れた更新には確認の応答を返す(SUBSCRIBE_NAMESPACE の新しい接頭辞は後の告知から有効になる)。拒否した FETCH の更新は FETCH のデータストリームをリセットし、拒否した名前空間の更新(PREFIX_OVERLAP など)はリクエストストリームを閉じて古い接頭辞をそのまま残す。
  - evidence: 受け入れた FETCH の更新(`test_moqtrun_upd_on_fetch_stream`)、SUBSCRIBE_NAMESPACE の接頭辞の変更(`test_moqtrun_upd_ns_prefix_changes`)、ストリームを FIN で閉じる PREFIX_OVERLAP の拒否(`test_moqtrun_upd_ns_prefix_overlap_refused`)は確かめている。PUBLISH_NAMESPACE の更新、拒否した更新での FETCH のデータストリームのリセット(`test_moqtrun_upd_on_fetch_stream_refused` は代わりにセッションのクローズを確かめる)、古い接頭辞が残ることは確かめていない。
- [x] MQ18-204a (SS10.9) 送信側自身の PUBLISH への REQUEST_UPDATE("The sender of a request (SUBSCRIBE, PUBLISH, FETCH, ...) can later send a REQUEST_UPDATE")には REQUEST_OK で応答し、Track を保たなければならない。draft-18 の SS10.9 には "other than in the two cases above" のクローズの規則がないので、制御ストリームでの REQUEST_UPDATE は REQUEST_ERROR NOT_SUPPORTED のままにする。
  - test: `tests/app/moqtrun_vgate_test.c` — `test_moqtrun_vgate_update_kinds`
  - test: `tests/app/moqtrun_misc_test.c` — `test_moqtrun_misc_stray_update`
  - note: 台帳 12-6。12-17。
- [x] MQ18-205 (SS10.12) GROUP_ORDER が Descending の FETCH は、最も新しい Group から返さなければならず(Group の中の Object は昇順のまま)、本文のデコードに失敗した FETCH は PROTOCOL_VIOLATION でセッションを閉じなければならない。
  - test: `tests/app/moqtrun_fetch_test.c` —
    `test_moqtrun_fetch_descending_group_order`
  - test: `tests/app/moqtrun_fetch_test.c` — `test_moqtrun_fetch_malformed_closes`
  - note: 台帳 10-6。これらのシナリオは、draft-18/19 の FETCH の本文で、draft-18 を含むすべてのドラフトで動く。不正な形式の FETCH は未知の Fetch Type を持つ(§10.12)。
- [x] MQ18-206 (SS5.1.4) ライブの Track に加わった遅れて来た購読者は、Location Filter の開始 Group から始めなければならない。ライブの先頭より前の開始位置は現在の Group に切り詰め、未来の開始位置はその Group まで配信を待たせる。
  - test: `tests/app/moqtrun_sub_test.c` —
    `test_moqtrun_sub_live_attach_filter_start`
  - note: 台帳 10-7。最初の Group の中にある開始 Object は、Subgroup ストリームで Object ごとに切る(`test_moqtrun_sub_filter22_start_object_*`、`test_moqtrun_sub_filter22_ring_*`)。シナリオは draft-18 を含むすべてのドラフトで動く。

## 未実装

draft-18 のリレーとしては対象内ですが、まだ実装していないものです。これらのどれかを必要とするピアには NOT_SUPPORTED を返します(注記がある場合は別の動作になります)。予約済みの名前空間、SUBSCRIBE_TRACKS、PUBLISH_SKIPPED(PUBLISH_BLOCKED)、FETCH の GROUP_ORDER、FETCH と名前空間リクエストへの REQUEST_UPDATE は、台帳 10 章で実装する(MQ18-028、MQ18-201 から MQ18-206)まで、ここに載せていました。

上の `[ ]` の項目(それぞれ `gap:` を付けています)のほかにはありません。

## 対象外

このハブリレーのサブセットが実装しない機能と要件です。上のカバレッジの分母から除いています。

- (SS10.11) 従来の制御ストリームで行った購読に対する PUBLISH_DONE: 設計上の理由による。PUBLISH_DONE は Request ID を持たないので、複数の購読が共有するストリームでは、どの購読が終わったかを示せない。購読は保持し、パブリッシャーが加わり直したときに結び付け直す。

- (SS1.5, SS1.5.1) 名前空間と Track の名前を人が読める文字列として表示・解析すること: 運用者やログの関心事。この SDK は名前を生のバイト列としてだけ比較する。
- (SS2.4.2, SS12.7-12.9) 受信側の Malformed Track の条件の一覧の残り(Subgroup ID をまたいだ Publisher Priority の不一致、Subgroup の最後の Object より後の Object ID、FIN で閉じたストリーム間で食い違う最後の Object、Forwarding Preference の変化、入れ子の Immutable Properties、Prior Group/Object ID Gap の違反): 仕様は条件を「検出した場合」として挙げている。ハブが検出するのは END_OF_GROUP / END_OF_TRACK より後の Object と、キャッシュと食い違う上流の FETCH の Object である(MQ18-207)。
- (SS3.1, SS3.1.1-3.1.6) `moqt` の URI スキーム、フラグメント識別子、MOQT の URI の参照解決: サーバー専用のハブにとってはクライアント側の関心事。ネイティブ QUIC のセッションそのもの(SS3.1.4: ALPN `moqt-18`、PATH/AUTHORITY の Setup Option、CONNECTION_CLOSE による終了)は実装している(`wired_moqt_on_session_raw`、`tests/app/moqtrun_raw_test.c`)。実際のピアのトレースで固定したテストができるまでは、プロセス内でだけ確かめている。
- (SS3.6, SS9.4.1, SS9.5.1) 上で扱った GOAWAY の仕組みを超えるセッションの移行と、リレーの穏やかな切り替え: これは単一のハブで、切り替え先の上流のリレーがない。
- (SS5.1.3, SS5.1.4) Range Filter(SUBGROUP_FILTER、OBJECTID_FILTER、PRIORITY_FILTER、OBJECT_PROPERTY_FILTER、TRACK_PROPERTY_FILTER)と Setup Option の MAX_FILTER_RANGES: **これらは draft-18 にはまったく存在しない**(draft-19 で新設。`draft18-vs-19-diff.md` の §5 を参照)。draft-18 のセッションがこれらのパラメーター型を受信すると、未知の型としてプロトコル違反で閉じる(MQ18-065)。Setup Option としての MAX_FILTER_RANGES は未知のものとして無視する(MQ18-075)。
- (SS10.9) MAX_REQUEST_UPDATES のクレジットの上限と TOO_MANY_REQUEST_UPDATES: **draft-19 で新設**(`draft18-vs-19-diff.md` の §6-7)。draft-18 には REQUEST_UPDATE のフロー制御の仕組みがないので、Q18-06(まとめられた更新に対するクレジットの回復数)はこのドラフトには当てはまらない。ハブのクレジットの確認は `MOQVER_CAP_MAX_REQUEST_UPDATES` で切り替える。1 つのリクエストストリームで応答していない REQUEST_UPDATE が 4 個を超える draft-18 のピアも閉じず、どの更新にも応答する(台帳 12-5、`tests/app/moqtrun_vgate_test.c` — `test_moqtrun_vgate_update_credit`)。
- (SS10.9) Range Filter を持つパブリッシャー側の REQUEST_UPDATE(Q18-07): Range Filter は draft-18 に存在しないので、問題にならない。
- (SS7, SS7.1--7.3) 優先度: スケジューリングのアルゴリズムは WebTransport の送信ポンプで動く(Subscriber、次に Publisher Priority、次に 1 つの購読の中での Group の順序と「ライブより埋め戻しが先」。MQ18-186)。残っている点: すでにキューに入った 1 回きりのストリームは REQUEST_UPDATE のあとも元のクラスを保つ。データグラムはストリームのクラスを通らない。FETCH 自身の SUBSCRIBER_PRIORITY は保持しない(128 として順位を付ける)。購読をまたいで同じクラスのものは、ポンプの 1 回ごとにラウンドロビンで分け合う。
- (SS10.2.10) EXPIRES: レジストリでデコードするが、それに基づく動作はしない(値は参考情報)。FILL_TIMEOUT、RENDEZVOUS_TIMEOUT、NEW_GROUP_REQUEST は項目 MQ18-227、MQ18-228、MQ18-229 で扱う。
- (SS10.3.1.3, SS10.3.1.4) ハブが送る Setup Option としての MAX_AUTH_TOKEN_CACHE_SIZE と AUTHORIZATION TOKEN: 告知しない。ハブはトークンのキャッシュを持たないので、Alias を使うトークンはセッションを閉じる(MQ18-189)。AUTHORIZATION TOKEN オプションの受信は MQ18-226 で扱う。
- (SS11.5.2) パディングのデータグラム: 送らない。
- (SS12.5-12.9) DEFAULT_PUBLISHER_GROUP_ORDER と DYNAMIC_GROUPS のスケジューリング上の意味、Prior Group/Object ID Gap: Property のワイヤー上の枠はそのままリレーする。ハブは DEFAULT_PUBLISHER_PRIORITY、SUBGROUP_DELIVERY_TIMEOUT、MAX_CACHE_DURATION を(Immutable Properties の中も含めて)読み、Group の順序と動的な Group の値の範囲を検証する。リレーがこれらの Property について負う MUST は、項目 MQ18-224、MQ18-238、MQ18-239 で扱う。
- (SS5.1.3.1, SS10.2.13) ハブ自身の Track での新しい Group の動的な開始: ハブ自身の Track は DYNAMIC_GROUPS を宣言しない。
- (SS10.4) クライアントの長さ 0 の New Session URI と、クライアントによるその URI の使い方: クライアントの規則(MQ18-082 は削除した。サーバー側の確認は MQ18-045)。
- (SS10.4, SS3.6) リクエストストリームでの GOAWAY の送信とその後にそのストリームをリセットする SHOULD、リクエストストリームの GOAWAY のあとのリクエストの再発行、SS3.6 の「上流の購読を解除する前に下流へ GOAWAY を送る」: ハブは制御ストリームでだけ GOAWAY を送り、ハブの drain は上流の購読を先に解除することがない。
- (SS10.11, SS10.18, SS10.19) ハブが送らない、または応答を待たないリクエストについての購読者側の規則: SUBSCRIBE_NAMESPACE / SUBSCRIBE_TRACKS のリクエスト元が行う最初のメッセージの確認と、NAMESPACE より前の NAMESPACE_DONE によるクローズ、PUBLISH_DONE のあとのタイマーと STOP_SENDING による後片付け、PUBLISH_NAMESPACE への重複した応答によるクローズ(ハブは PUBLISH_NAMESPACE を送らない)。
- (SS10.2.2) トークンの送信側の規則(再利用するときだけ登録する、USE_ALIAS / DELETE の順序)、期限切れのトークンの保持、MALFORMED_AUTH_TOKEN: ハブはトークンを送らず、キャッシュも持たず、トークンの有効性はアプリケーションの認可の処理に任せる(UNAUTHORIZED、MQ18-189)。
- (SS8, SS11.4.3) トランスポートの再送の前の配信タイムアウトの確認と、RESET_STREAM_AT の reliable_size: QUIC スタックは MOQT 層に再送のフックを提供せず、ハブは RESET_STREAM でだけリセットする。
- (SS10.2.13, SS10.6.2, SS10.10) NEW_GROUP_REQUEST についての購読者の義務、Retry Interval による間隔の調整、望まない PUBLISH の UNINTERESTED による拒否: ハブは下流の購読者が求めていない NEW_GROUP_REQUEST を自分から出すことはなく(上流へリレーする。MQ18-229)、拒否されたリクエストを再試行せず、空きがある限り認可済みの PUBLISH をすべて受け入れる(MQ18-156)。
- (SS13) セキュリティの考慮事項(購読による増幅、通信のセキュリティ、認可、メディアのセキュリティ、リソースの枯渇、タイムアウト、リレーのセキュリティ、実装のフィンガープリンティング): 運用・配備の指針であり、この台帳がテストするワイヤー上の動作ではない。
- (SS15) IANA の考慮事項: レジストリの管理であり、実装の動作ではない。
- バージョンごとの対象範囲(台帳 4-4): このハブはセッションごとに draft-18、-19、-22、-23 をネゴシエートする(`moqver.c`)。上の Range Filter、MAX_FILTER_RANGES、MAX_REQUEST_UPDATES の項目が対象外なのは draft-18 だけである。draft-19 と draft-22 のセッションでは、ハブは Range Filter を検証し、リクエストの更新のクレジットを適用する(MOQT-206 から MOQT-208、MQ22-199 から MQ22-201 を参照)。SUBSCRIBE_TRACKS そのものはすべてのバージョンで扱う(MQ18-201)。違うのはパラメーターの組だけで、draft-18 では AUTHORIZATION TOKEN と FORWARD、draft-19 と draft-22 ではすべての Subscription パラメーターである(`moqctl.c` の `MOQCTL_PARAM_RULES`)。
- 実際のリレーの動作としての REDIRECT(リクエスト元を別の URI や対象へ移すために送ること、上流からの REDIRECT に応じること): これは単一のハブで、リダイレクトの行き先や送り元になる上流のリレーや兄弟のインスタンスがない。理由は上のセッションの移行の項目と同じである。Redirect 構造のワイヤー形式は確かめている(MQ18-085 から MQ18-089)。
- draft-18 自身のアプリケーション固有の Property の予約範囲 0x38-0x3F(1 バイトのレジストリ。draft-19 で 0x78-0x7F に広がった。`draft18-vs-19-diff.md` の §11 を参照): draft-18 に固有の境界のテストはない(MQ18-026 は共有の grease のテストを使う)。これは共有の実装に対して追跡している参考情報としてのギャップで、ここでバージョンごとに改めて論じることはしない。
