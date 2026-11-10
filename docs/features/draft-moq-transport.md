[ドキュメント](../README.md) › [機能](README.md) › draft-ietf-moq-transport-19

# draft-ietf-moq-transport-19: Media over QUIC Transport

仕様の本文(`tasks/specs/draft-ietf-moq-transport-19.txt`。git には含まない)から抽出した EARS 形式の要件台帳です。対象は、この SDK が実装する MOQT のサブセットです。WebTransport 上の単一の中央ハブリレーとして、SETUP、GOAWAY、PUBLISH、SUBSCRIBE(Location Filter と Range Filter、FORWARD、優先度、2 種類の配信タイムアウトを含む)、SUBSCRIBE・FETCH・名前空間リクエストに対する REQUEST_UPDATE、TRACK_STATUS、FETCH(単独と joining の両方。Group 単位のキャッシュから返す)、PUBLISH_NAMESPACE / SUBSCRIBE_NAMESPACE、SUBSCRIBE_TRACKS(ハブが始める PUBLISH または PUBLISH_SKIPPED)、PUBLISH_DONE、Subgroup ストリームと Object Datagram による Object の配信を実装しています。ハブは WebTransport のサブプロトコル(`moqt-18`/`moqt-19`/`moqt-22`。サブプロトコルがなければ draft-19)からセッションごとに draft-18、draft-19、draft-22 のいずれかを選びます。このファイルは draft-19 の台帳で、[draft-18](draft-moq-transport-18.md) と [draft-22](draft-moq-transport-22.md) には別の台帳があります。各要件には、それを確かめるテストを付けています。チェックがなくテスト行もない項目は、未解決のギャップです。まだ足りないものは [未実装](#未実装) にまとめています。

ハブはすべてのセッション、Track、キャッシュを 1 つのプロセスのメモリに持ちます。`examples/moqt_chat` と同じく、単一プロセス(`--workers`、`--cores`、AF_XDP のファンアウトなし)で動かしてください。

凡例:

- `[x]`: 挙げたテストで確認済み
- `[~]`: 間接的に確認(専用のテストはなく、evidence 行で確かめ方を説明)
- `[ ]`: まだどのテストでも確認していない

**カバレッジ: テスト済み 211/248、間接 35、未テスト 2。**

## SS1.4.1 可変長整数

- [x] MOQT-001 実装は MOQT の可変長整数を、先頭バイトの先頭から続く 1 のビット数で符号化長(1〜9 バイト)を決め、残りのビットと後続のバイトにネットワークバイトオーダーで値を持つものとしてデコードしなければならない。
  - test: `tests/app/moqvi_test.c` — `test_moqvi_decode_official_examples`
  - test: `tests/app/moqvi_test.c` — `test_moqvi_decode_zero_all_lengths`
  - test: `tests/app/moqvi_test.c` — `test_moqvi_decode_nine_byte_padded`
- [x] MOQT-002 実装は 64 ビットの符号なし整数(0〜2^64-1)すべてを MOQT の可変長整数でエンコードしなければならない。
  - test: `tests/app/moqvi_test.c` — `test_moqvi_encode_official_examples`
  - test: `tests/app/moqvi_test.c` — `test_moqvi_encode_boundaries`
- [x] MOQT-003 (SS1.4.1) 実装は可変長整数を、使えるビットに値が収まる長さのうち最小のものでエンコードしなければならない(ドラフトはそのような長さならどれでも許しており、最短を選ぶのはこのエンコーダーの方針である)。
  - test: `tests/app/moqvi_test.c` — `test_moqvi_roundtrip`
  - test: `tests/app/moqvi_test.c` — `test_moqvi_encode_official_examples`
- [x] MOQT-004 可変長整数が必要最小限より多いバイト数でエンコードされている場合でも、実装は正しい値にデコードしなければならない(最小でないエンコードも有効である)。
  - test: `tests/app/moqvi_test.c` — `test_moqvi_decode_zero_all_lengths`
  - test: `tests/app/moqvi_test.c` — `test_moqvi_decode_nine_byte_padded`
- [x] MOQT-005 可変長整数の符号化長が残りのバイト数を超える場合、実装は入力の終わりを越えて読まず、デコードを不足として報告しなければならない。
  - test: `tests/app/moqvi_test.c` — `test_moqvi_decode_truncated`
- [x] MOQT-006 実装は可変長整数を、自身の符号化長を越えてバイトを消費せずにデコードし、入力の後続バイトをそのまま残さなければならない。
  - test: `tests/app/moqvi_test.c` — `test_moqvi_decode_ignores_trailing`
- [x] MOQT-007 書き込み先のバッファーが値の符号化長に足りない場合、実装はバッファーの終わりを越えて書かず、エンコードを失敗させなければならない。
  - test: `tests/app/moqvi_test.c` — `test_moqvi_put_too_small`

## SS1.4.2 Location の構造

- [x] MOQT-008 実装は Location を連続する 2 つの可変長整数(Group, Object)としてエンコード・デコードしなければならない。
  - test: `tests/app/moqctl_test.c` —
    `test_moqctl_location_roundtrip_and_order`
- [x] MOQT-009 実装は 2 つの Location A と B を、A.Group < B.Group であるか、A.Group == B.Group かつ A.Object < B.Object であるときに限り A < B となるように比較しなければならない。
  - test: `tests/app/moqctl_test.c` —
    `test_moqctl_location_roundtrip_and_order`

## SS1.4.3 Key-Value-Pair の構造

- [x] MOQT-010 実装は Key-Value-Pair の Type を、直前までの累積 Type に Delta Type を足した値(最初のペアでは 0 に足す)としてデコードしなければならない。
  - test: `tests/app/moqkvp_test.c` — `test_moqkvp_take_even_num`
  - test: `tests/app/moqkvp_test.c` — `test_moqkvp_take_delta_accumulates`
- [x] MOQT-011 Key-Value-Pair の累積 Type が 2^64-1 を超える場合、実装はプロトコル違反を報告しなければならない。
  - test: `tests/app/moqkvp_test.c` — `test_moqkvp_take_type_overflow`
- [x] MOQT-012 実装は Type が奇数の Key-Value-Pair の Value を Length バイトとして、Type が偶数のペアの Value を 1 つの可変長整数としてデコードしなければならない。
  - test: `tests/app/moqkvp_test.c` — `test_moqkvp_take_even_num`
  - test: `tests/app/moqkvp_test.c` — `test_moqkvp_take_odd_raw`
- [x] MOQT-013 Key-Value-Pair の Length フィールドは 2^16-1 バイトを超えてはならない。それより大きい長さを受信した場合、実装はプロトコル違反を報告しなければならない。
  - test: `tests/app/moqkvp_test.c` — `test_moqkvp_take_len_65535_accepted`
  - test: `tests/app/moqkvp_test.c` — `test_moqkvp_take_len_65536_violation`
  - vuln: V-0799
- [x] MOQT-014 (SS1.4.3) 実装が理解する Type の Key-Value-Pair で、Value がその Type のシリアライズ形式に合わない場合、サーバーはセッションを KEY_VALUE_FORMATTING_ERROR で閉じなければならない。
  - test: `tests/app/moqtrun_sess_test.c` — `test_mtss_request_token_kvfmt`
  - test: `tests/app/moqtrun_sess_test.c` — `test_mtss_setup_token_alias`
- [x] MOQT-015 実装は Key-Value-Pair の Delta Type や偶数 Type の Value が最小のエンコード長であることを、デコードの条件にしてはならない(最小でないエンコードも有効である)。
  - test: `tests/app/moqkvp_test.c` — `test_moqkvp_take_nonminimal_delta`
  - test: `tests/app/moqkvp_test.c` — `test_moqkvp_take_nonminimal_even_value`
- [x] MOQT-016 (SS1.4.3) Key-Value-Pair が、それ自身の既知のバイト境界の内側で途切れている場合、実装は入力を消費せずに不足として報告し、閉じるかどうかの判断は呼び出し元に任せなければならない。
  - test: `tests/app/moqkvp_test.c` — `test_moqkvp_take_truncated_insufficient`
- [x] MOQT-017 実装は Key-Value-Pair を呼び出し元が渡したバイト境界を越えて読まずにデコードし、Type の順序を保った、往復変換できる Key-Value-Pair のリストをエンコードしなければならない。
  - test: `tests/app/moqkvp_test.c` — `test_moqkvp_roundtrip`

## SS1.4.4 Reason Phrase の構造

- [x] MOQT-018 実装は Reason Phrase を、可変長整数の Length と、それに続く同じバイト数の UTF-8 バイト列としてデコードしなければならない。
  - test: `tests/app/moqctl_test.c` — `test_moqctl_reason_boundary`
  - vuln: V-0800
- [~] MOQT-019 (SS1.4.4) Reason Phrase の Length が 1024 バイトを超える場合、実装はセッションをプロトコル違反で閉じなければならない。
  - evidence: コーデックは VIOLATION を返し(`test_moqctl_reason_boundary`)、ハブはリクエストのデコードに失敗すると PROTOCOL_VIOLATION で閉じる(`test_moqtrun_fillfix_malformed_subscribe`、`test_moqtrun_setup_malformed_closes`)。ただし、この条件そのものを起こすハブのテストはない。

## SS2.4.1 Track の命名

- [x] MOQT-020 実装は Track Namespace を、可変長整数のフィールド数と、それに続く同じ数の長さ付き Track Namespace Field としてデコードしなければならない。
  - test: `tests/app/moqctl_test.c` — `test_moqctl_ftn_decode_basic`
- [~] MOQT-021 (SS2.4.1) Track Namespace Field の Length が 0 の場合、実装はセッションをプロトコル違反で閉じなければならない。
  - evidence: コーデックは VIOLATION を返し(`test_moqctl_ns_field_len_zero_rejected`)、ハブはリクエストのデコードに失敗すると PROTOCOL_VIOLATION で閉じる(`test_moqtrun_fillfix_malformed_subscribe`、`test_moqtrun_setup_malformed_closes`)。ただし、この条件そのものを起こすハブのテストはない。
- [~] MOQT-022 (SS2.4.1) Track Namespace の Track Namespace Field が 32 個を超える場合、実装はセッションをプロトコル違反で閉じなければならない。
  - evidence: コーデックは VIOLATION を返し(`test_moqctl_ns_fields_32_accept_33_reject`)、ハブはリクエストのデコードに失敗すると PROTOCOL_VIOLATION で閉じる(`test_moqtrun_fillfix_malformed_subscribe`、`test_moqtrun_setup_malformed_closes`)。ただし、この条件そのものを起こすハブのテストはない。
- [~] MOQT-023 (SS2.4.1) Full Track Name(Track Namespace と Track Name を合わせたもの)が 4096 バイトを超える場合、実装はセッションをプロトコル違反で閉じなければならない。
  - evidence: コーデックは VIOLATION を返し(`test_moqctl_ftn_4096_accept_4097_reject`)、ハブはリクエストのデコードに失敗すると PROTOCOL_VIOLATION で閉じる(`test_moqtrun_fillfix_malformed_subscribe`、`test_moqtrun_setup_malformed_closes`)。ただし、この条件そのものを起こすハブのテストはない。
- [x] MOQT-024 実装は Track Namespace Field と Track Name を、バイト列の完全一致で比較しなければならない。
  - test: `tests/app/moqtrun_sub_test.c` — `test_moqtrun_track_key_exact_match`

## SS2.4.2 不正な Track

- [x] MOQT-025 (SS2.4.2) ハブが購読者として Malformed Track(Track の END_OF_TRACK や Group の END_OF_GROUP より後の Object、または食い違う再送)を検出したとき、ハブはそのパブリッシャーに対する、その Track の購読と FETCH を取り消さなければならない。
  - test: `tests/app/moqtrun_done_test.c` —
    `test_moqtrun_pubdone_malformed_after_end_of_track`
  - test: `tests/app/moqtrun_upfetch_test.c` —
    `test_moqtrun_upfetch_malformed_past_end`
- [x] MOQT-209 (SS2.4.2) ハブが Malformed Track を検出したとき、ハブはその Track の下流の購読をすべて PUBLISH_DONE MALFORMED_TRACK で終え、その Track の FETCH ストリームを MALFORMED_TRACK でリセットしなければならない。
  - test: `tests/app/moqtrun_done_test.c` —
    `test_moqtrun_pubdone_malformed_after_end_of_track`
  - test: `tests/app/moqtrun_done_test.c` —
    `test_moqtrun_pubdone_malformed_after_end_of_group`
  - test: `tests/app/moqtrun_done_test.c` —
    `test_moqtrun_pubdone_malformed_resets_fetch`
- [x] MOQT-210 (SS2.4.2) ハブは Malformed Track の状態を引き起こした Object をキャッシュしてはならない。
  - test: `tests/app/moqtrun_upfetch_test.c` —
    `test_moqtrun_upfetch_malformed_past_end`

## SS2.5 Property / SS2.5.1 必須の Track Property

- [~] MOQT-026 (SS2.5) ハブはアプリケーション固有の範囲 0x78-0x7F と 0x3800-0x3FFF の Property を、解釈せずにそのまま転送しなければならない。
  - evidence: DEFAULT_PUBLISHER_PRIORITY と配信タイムアウト以外の Property は、すべて中身を見ないスパンとして中継する(MOQT-211)。この範囲のコードポイントを使うテストはない。
- [~] MOQT-027 (SS2.5.1) 実装は Property の型 0x4000-0x7FFF を Mandatory Track Property に分類しなければならない。
  - evidence: `moqtrun_tprops_check` がこの範囲を分類する。`test_moqtrun_upfetch_mandatory` は型 0x4000 を、`test_moqtrun_sub_publish_mandatory_refused` は 0x7FFF を使う。範囲のすぐ外側(0x3FFF、0x8000)はテストしていない。
- [x] MOQT-211 (SS2.5, SS9.6) ハブは解釈しない Track Property と Object Property をそのまま転送し、キャッシュした Track や Object と一緒に保持し、送信する SUBSCRIBE_OK と FETCH_OK に Track の Property を含めなければならない。
  - test: `tests/app/moqtrun_sub_test.c` —
    `test_moqtrun_sub_include_properties_1_forwards`
  - test: `tests/app/moqtrun_upfetch_test.c` —
    `test_moqtrun_upfetch_no_track_waits_ok`
  - test: `tests/app/moqtrun_upfetch_test.c` — `test_moqtrun_upfetch_reencode`
- [x] MOQT-212 (SS2.5.1) Object が Mandatory Track Property を Object Property として持っている場合、ハブはその Track を Malformed として扱わなければならない。
  - test: `tests/app/moqtrun_done_test.c` — `test_moqtrun_pubdone_malformed_mandatory_obj_prop`
- [x] MOQT-213 (SS2.5.1) PUBLISH が、ハブの理解しない Mandatory Track Property を持っている場合、ハブは REQUEST_ERROR UNSUPPORTED_EXTENSION を返し、その Track を転送してはならない。
  - test: `tests/app/moqtrun_sub_test.c` — `test_moqtrun_sub_publish_mandatory_refused`
- [x] MOQT-214 (SS2.5.1) 上流の SUBSCRIBE_OK が、ハブの理解しない Mandatory Track Property を持っている場合、ハブは上流の購読を取り消し、応答待ちの下流の購読者に REQUEST_ERROR UNSUPPORTED_EXTENSION を返さなければならない。
  - test: `tests/app/moqtrun_upsub_test.c` — `test_moqtrun_upsub_ok_mandatory_refused`
- [x] MOQT-215 (SS2.5.1) 上流の FETCH_OK が、ハブの理解しない Mandatory Track Property を持っている場合、ハブは上流の FETCH を取り消し、まだ応答していない下流の FETCH には REQUEST_ERROR UNSUPPORTED_EXTENSION を返し、データを送り始めた FETCH はリセットしなければならない。
  - test: `tests/app/moqtrun_upfetch_test.c` — `test_moqtrun_upfetch_mandatory`

## SS3.2.1 予約された名前空間 / SS3.2.2 セッションレベルの Track

- [x] MOQT-028 リクエストが、最初のフィールドがピリオド 1 文字の Track Namespace を参照している場合、実装はそれを DOES_NOT_EXIST で拒否しなければならない。
  - test: `tests/app/moqtrun_sub_test.c` — `test_moqtrun_reserved_ns_rejected`
  - test: `tests/app/moqtrun_ns_test.c` — `test_moqtrun_ns_reserved_rejected`
  - test: `tests/app/moqtrun_sub_test.c` — `test_moqtrun_other_dot_ns_served`
  - note: `moqtrun_ns_reserved`(台帳 10-1)は、最初のフィールドがちょうど `.` または `.session` のものを、PUBLISH、SUBSCRIBE、PUBLISH_NAMESPACE、SUBSCRIBE_NAMESPACE で DOES_NOT_EXIST により拒否する。`.` で始まるそれ以外のフィールドは通常の名前空間と同じく扱う。この検査はバージョンに依存しない。

## SS3.3 セッションの初期化

- [x] MOQT-029 サーバーは単方向の制御ストリームを 1 本開き、最初のメッセージとして SETUP を送信しなければならない。
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_token_session_opens_uni_ctl`
  - test: `tests/app/moqtrun_test.c` — `test_moqtrun_client_uni_ctl_accepted`
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_refused_uni_ctl_open_retries`
  - note: WT トークンが空のセッション(サブプロトコルを提示しないクライアント。たとえば WebTransport の `protocols` に対応していないブラウザー)では、以前のドラフトと同じく双方向の制御ストリーム 1 本を使い続ける(`test_moqtrun_empty_token_keeps_bidi_ctl`)。
- [x] MOQT-030 (SS3.3) 両方のエンドポイントが SETUP を送受信し終えたら、セッションは Established にならなければならない。
  - test: `tests/app/moqtrun_test.c` — `test_moqtrun_client_uni_ctl_accepted`
  - test: `tests/app/moqsess_test.c` — `test_moqsess_establish`
- [x] MOQT-031 (SS3.3) 双方向のリクエストストリームは、最初に置ける型のメッセージ(TRACK_STATUS、SUBSCRIBE、PUBLISH、FETCH、PUBLISH_NAMESPACE、SUBSCRIBE_NAMESPACE、SUBSCRIBE_TRACKS)のいずれかで始まらなければならない。そうでない場合、実装はセッションをプロトコル違反で閉じなければならない。
  - test: `tests/app/moqtrun_sub_test.c` —
    `test_moqtrun_req_bad_first_message_closes`
- [x] MOQT-032 (SS3.3) Object を運ぶ単方向ストリームや双方向のリクエストストリームが、両方の制御ストリームで SETUP が完了する前に届いた場合、ハブはそれをバッファーに保持し、SETUP の完了後に処理しなければならない。
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_token_requests_held_until_established`
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_token_object_stream_held_until_established`
- [x] MOQT-033 (SS3.3) SETUP がまだ完了しておらず、リクエストストリームをバッファーに保持できない場合、ハブはそれをリセット(EXCESSIVE_LOAD)しなければならない。
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_token_unbufferable_request_reset`
- [~] MOQT-034 (SS10.3) ピアは、自分の SETUP の後、ハブの SETUP を待たずにリクエストをパイプライン送信してもよい。
  - evidence: ハブはセッションを開いた時点で自分の SETUP を送り、クライアントの SETUP が届きしだいそのクライアントのリクエストを処理する(`test_moqtrun_token_requests_held_until_established`)。パイプライン送信のケースそのものは、セッションモデルでしか固定していない(`test_moqsess_pipeline_before_peer_setup`)。
- [x] MOQT-035 (SS3.3) セッションの存続中に制御ストリームがトランスポート層で閉じられた場合、実装はセッションをプロトコル違反で閉じなければならない。
  - test: `tests/app/moqtrun_test.c` — `test_moqtrun_ctl_fin_violates`
  - test: `tests/app/moqtrun_test.c` — `test_moqtrun_ctl_reset_violates`
- [x] MOQT-036 (SS3.3) 同じピアが 2 本目の制御ストリームを開いた場合、実装はセッションをプロトコル違反で閉じなければならない。
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_second_ctl_stream_violates`
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_on_session_twice_is_idempotent`
- [~] MOQT-216 (SS3.3) ハブはネゴシエーションが必要な Message Parameter を、ピアの SETUP を受信する前に使ってはならない。
  - evidence: ハブの最初のメッセージは自分の SETUP であり(MOQT-029)、ハブが始めるリクエスト(上流への SUBSCRIBE/FETCH、SUBSCRIBE_TRACKS に応じた PUBLISH)はすべて Established のピアからのリクエストの後に来る。この順序だけを取り出したテストはない。
- [x] MOQT-217 (SS3.3.2, SS3.3.3) ハブは応答(Established の購読では PUBLISH_DONE も)を送信する前に、リクエストストリームの自分の方向を FIN してはならず、REQUEST_ERROR または最終応答の後はすみやかに FIN しなければならない。
  - test: `tests/app/moqtrun_sub_test.c` —
    `test_moqtrun_req_refusal_fins_and_frees`
  - test: `tests/app/moqtrun_sub_test.c` — `test_moqtrun_req_fin_keeps_request`
  - test: `tests/app/moqtrun_done_test.c` — `test_moqtrun_pubdone_one_sub`
  - test: `tests/app/moqtrun_rdv_test.c` — `test_moqtrun_rdv_s2_timeout`

## SS3.5 終了: エラーコード(使用するサブセット)

- [~] MOQT-037 (SS3.5) 実装はドラフトの表にあるセッション終了のエラーコード(NO_ERROR、INTERNAL_ERROR、PROTOCOL_VIOLATION、INVALID_REQUEST_ID、KEY_VALUE_FORMATTING_ERROR、INVALID_PATH、MALFORMED_PATH、GOAWAY_TIMEOUT、AUTH_TOKEN_CACHE_OVERFLOW、UNKNOWN_AUTH_TOKEN_ALIAS、INVALID_AUTHORITY、MALFORMED_AUTHORITY、TOO_MANY_REQUEST_UPDATES)を、ドラフトの値で使わなければならない。
  - evidence: 各コードは使う場所(moqctl.h / moqtrun.h)で `#define` しており、このファイルの各違反箇所でそれぞれ動かしている。表全体を列挙するテストはない。

## SS3.4 単方向ストリームの型

- [x] MOQT-038 実装は単方向ストリームの先頭の可変長整数を、SETUP (0x2F00)、FETCH_HEADER (0x05)、SUBGROUP_HEADER (0b0XX1XXXX)、PADDING (0x132B3E28) のいずれかに分類しなければならない。
  - test: `tests/app/moqdata_test.c` — `test_moqdata_classify_golden`
- [x] MOQT-039 (SS3.4) エンドポイントが未知の単方向ストリーム型を受信した場合、実装はセッションをプロトコル違反で閉じなければならない。
  - test: `tests/app/moqtrun_sess_test.c` — `test_mtss_unknown_uni_closes`
  - test: `tests/app/moqtrun_sess_test.c` — `test_mtss_padding_stream_kept`
- [x] MOQT-040 実装は先頭の型フィールドが途切れている単方向ストリームを、その途切れた位置を越えてバイトを消費せずに分類し、分類結果を不足として報告しなければならない。
  - test: `tests/app/moqdata_test.c` — `test_moqdata_classify_truncated`

## SS3.5 終了

- [x] MOQT-041 サーバーは WebTransport 上の MOQT セッションを、CLOSE_WEBTRANSPORT_SESSION の仕組みで閉じなければならない。
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_ctl_unknown_type_closes_session`
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_ctl_pool_exhausted_closes`
  - test: `tests/app/moqtrun_sub_test.c` —
    `test_moqtrun_req_bad_first_message_closes`
  - evidence: ハブは io テーブルの `close_session` 操作(本番では `wired_server_wt_close_session`)を通し、ドラフトの終了コードで閉じる。WT_CLOSE_SESSION カプセル自体は WebTransport の台帳で確認している。

## SS3.6 セッションの移行 / SS10.4 GOAWAY(セッションのライフサイクル)

- [x] MOQT-042 (SS10.4) GOAWAY を送信または受信したエンドポイントは、セッションを開いたまま、エンドポイントが終了処理中であることを示すエラーで新しいリクエストを拒否してもよい。
  - test: `tests/app/moqtrun_drain_test.c` —
    `test_moqtrun_goaway_late_rejected`
- [x] MOQT-043 (SS10.4) 制御ストリームで GOAWAY を受信したエンドポイントは、自分から新しいリクエストを始めてはならない。ただし、GOAWAY だけを理由にセッションを閉じることはない。
  - test: `tests/app/moqtrun_upfetch_test.c` —
    `test_moqtrun_upfetch_upsub_skips_goaway`
- [x] MOQT-044 (SS3.6, SS10.4) ピアが GOAWAY のタイムアウト内にセッションを閉じない場合、送信側はセッションを GOAWAY_TIMEOUT で閉じなければならない。
  - test: `tests/app/moqtrun_drain_test.c` —
    `test_moqtrun_goaway_timeout_flush_then_close`
- [x] MOQT-045 (SS10.4) サーバーが、New Session URI Length が 0 でない GOAWAY を受信した場合、実装はセッションをプロトコル違反で閉じなければならない。
  - test: `tests/app/moqtrun_drain_test.c` — `test_moqtrun_peer_goaway_uri`
- [x] MOQT-046 (SS10.4) 同じ制御ストリームで GOAWAY を 2 回以上受信した場合、実装はセッションをプロトコル違反で閉じなければならない。
  - test: `tests/app/moqtrun_drain_test.c` — `test_moqtrun_peer_goaway_twice`
- [x] MOQT-047 (SS10.4) GOAWAY を制御ストリームではなくリクエストストリームで受信した場合、実装はセッションを閉じずにそれを受け入れなければならない。ただし、同じリクエストストリームでの 2 回目の GOAWAY は、やはりプロトコル違反としなければならない。
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_goaway_on_request_stream_produces_no_reply`
  - test: `tests/app/moqtrun_sub_test.c` —
    `test_moqtrun_req_second_goaway_closes`
- [~] MOQT-218 (SS3.6) ハブがドレインするとき、ハブは上流のパブリッシャーへの購読を解除する前に、下流の購読者へ GOAWAY を送信するべきである。
  - evidence: `wired_moqt_goaway` は全セッションへ一斉に GOAWAY を送り(`test_moqtrun_goaway_once_per_session`)、上流の購読はタイムアウト時にはじめて取り消す。この 2 つの順序を確かめるテストはない。
- [x] MOQT-235 (SS10.4) GOAWAY を送信した後、ハブは移行に必要な場合を除き、新しいリクエストを始めることを避けるべきである。
  - evidence: `moqtrun_up_ga_skip` / `moqtrun_upf_owner_free` は、ハブが GOAWAY を送ったピアを上流の SUBSCRIBE / FETCH の相手から外す。例外は、上流を失った購読の経路を付け直す場合(移行)だけである。`test_moqtrun_upfetch_upsub_skips_goaway`、`test_moqtrun_upfetch_owner_excluded`(ケース 4)、`test_moqtrun_upfetch_drain_failover` が両側を固定している。
  - test: `tests/app/moqtrun_upfetch_test.c` — `test_moqtrun_upfetch_upsub_skips_goaway`

## SS9 リレー(SS9.4/9.6/9.7 の転送の決まり)

- [x] MOQT-048 リレーは複数の Object を運ぶストリームで受信した Object を購読者へ転送するとき、順序を入れ替えたり Object を落としたりしてはならない。
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_object_relay_to_subscriber`
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_object_relay_two_subscribers_two_objects`
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_relay_forwards_bytes_as_they_arrive`
- [x] MOQT-049 (SS9.7, SS2.1) リレーは転送するとき Object のフィールド(Location、状態、Property)やペイロードを変更してはならない。再エンコードするのは、後から開いたストリームのストリームヘッダーだけである(FIRST_OBJECT を下ろし、モード 0b01 の Subgroup ID を明示し、最初の Object ID を絶対値にする)。
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_object_relay_preserves_bytes`
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_late_subscriber_gets_late_opened_stream`
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_late_open_sgid_mode1_explicit`
- [x] MOQT-050 リレーは下流の SUBSCRIBE に SUBSCRIBE_OK で応答する前に、上流の購読を Established にしておかなければならない。
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_subscribe_matching_publish_replies_ok`
  - test: `tests/app/moqtrun_upsub_test.c` —
    `test_moqtrun_upsub_ok_after_upstream`
- [x] MOQT-051 リレーが、どのパブリッシャーも PUBLISH していない Track への SUBSCRIBE を受信した場合、実装はその Track の名前空間またはそのプレフィックスを PUBLISH_NAMESPACE したセッション(購読者自身のもの以外)へ上流の SUBSCRIBE を送り(SS9.5)、その時点で送るか、保留した SUBSCRIBE なら PUBLISH_NAMESPACE が届いた時点で送り、上流の購読が Established になったら SUBSCRIBE_OK を、そうでなければ上流のコードで REQUEST_ERROR を返さなければならない。そのようなパブリッシャーがいない(かつ RENDEZVOUS_TIMEOUT もない)場合、実装は REQUEST_ERROR DOES_NOT_EXIST を返さなければならない。
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_subscribe_without_publish_replies_error`
  - test: `tests/app/moqtrun_upsub_test.c` —
    `test_moqtrun_upsub_ok_after_upstream`,
    `test_moqtrun_upsub_error_relayed`,
    `test_moqtrun_upsub_hold_then_announce`,
    `test_moqtrun_upsub_own_namespace`, `test_moqtrun_upsub_prefix`,
    `test_moqtrun_upsub_cross_draft`
  - note: 上流の SUBSCRIBE は、Full Track Name ごとに 1 本、最初に一致したアナウンス元へ送る。ただし `wired_moqt_hub.multi_publisher` が有効なら、一致するパブリッシャーそれぞれへ 1 本ずつ送る(SS9.5、`tests/app/moqtrun_mpub_test.c`)。下流で誰も必要としなくなった上流の購読は取り消す(`test_moqtrun_upsub_last_cancel_cancels_upstream`)。
- [x] MOQT-052 (SS9.4) 複数の購読者が同じ Track を要求したとき、リレーはその Track への認可済みの購読をまとめ、上流の 1 つの Object を、一致する下流の購読者全員へ転送してもよい。
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_chat_object_relays_to_all_three_subscribers`
  - test: `tests/app/moqtrun_upsub_test.c` — `test_moqtrun_upsub_two_share_one`
- [x] MOQT-226 (SS9.1) ハブが保持しているものと異なるペイロードで Object が再び届いた場合、ハブはその Track を Malformed として扱い、その Object を中継してはならない。
  - test: `tests/app/moqtrun_upfetch_test.c` —
    `test_moqtrun_upfetch_malformed_conflict`
- [x] MOQT-227 (SS9.1) ハブが、ある Object は存在しないと記録している場合、後からその Object が届いても、ハブはそれをキャッシュも転送もするべきではない。
  - test: `tests/app/moqtrun_fetch_test.c` —
    `test_moqtrun_fetch_late_nonexistent_not_cached`
  - test: `tests/app/moqtrun_cut_test.c` —
    `test_moqtrun_stream_skips_gone_object`
  - note: 記録とはキャッシュのことである(閉じた Group の Location は、存在しないものとして返す)。Subgroup ストリーム上ではそのような Object を切り取り、次の Object の Object ID Delta をつなぎ直す。そのような Object で始まるストリームは中継せず、1 回きりのストリームは最初のそのような Object の位置で切る。
- [x] MOQT-228 (SS9.2, SS9.5) ハブが下流の SUBSCRIBE のために上流へ購読するとき、ハブは Forward 1(FORWARD を省略)を使わなければならない。
  - test: `tests/app/moqtrun_upsub_test.c` —
    `test_moqtrun_upsub_ok_after_upstream`
- [~] MOQT-224 (SS7.3, SS10.2) ハブは下流の購読の Message Parameter(Subscriber Priority、Group Order、配信タイムアウト)を、上流の SUBSCRIBE へ写してはならない。
  - evidence: `test_moqtrun_upsub_ok_after_upstream` は上流の SUBSCRIBE がパラメーターを持たないことを確かめているが、下流の SUBSCRIBE もパラメーターを持っていない。
- [x] MOQT-229 (SS9.4, SS9.5, SS10.12.3, SS10.13) キャッシュが範囲を保証できない FETCH は、Track の所有者(ハブが保持していない Track では、それを含む名前空間のアナウンス元。この場合 FETCH_OK は上流の FETCH_OK が届くまで返さず、その内容を写す)への上流の FETCH 1 本で補完しなければならない。配信は、上流が応答するか予算が尽きるまで、欠けた位置で止まる。
  - test: `tests/app/moqtrun_upfetch_test.c` — `test_moqtrun_upfetch_budget`
  - test: `tests/app/moqtrun_upfetch_test.c` —
    `test_moqtrun_upfetch_gap_to_owner`
  - test: `tests/app/moqtrun_upfetch_test.c` —
    `test_moqtrun_upfetch_no_track_waits_ok`
  - test: `tests/app/moqtrun_upfetch_test.c` —
    `test_moqtrun_upfetch_upstream_draft`

## SS10 制御メッセージ: 共通の外枠

- [x] MOQT-053 実装はすべての制御メッセージを Message Type(varint)+ Message Length(16 ビット)+ Message Body としてエンコード・デコードしなければならない。
  - test: `tests/app/moqctl_test.c` — `test_moqctl_peek_type_setup`
  - test: `tests/app/moqctl_test.c` — `test_moqctl_setup_roundtrip`
- [x] MOQT-054 実装は Message Type の表のうち実装している項目、SETUP (0x2F00)、GOAWAY (0x10)、SUBSCRIBE (0x3)、SUBSCRIBE_OK (0x4)、PUBLISH (0x1D)、PUBLISH_DONE (0xB)、REQUEST_OK (0x7)、REQUEST_ERROR (0x5) を認識しなければならない。
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
  - evidence: FETCH (0x16)、FETCH_OK (0x18)、TRACK_STATUS (0xD)、REQUEST_UPDATE (0x2)、PUBLISH_NAMESPACE (0x6)、SUBSCRIBE_NAMESPACE (0x50)、NAMESPACE (0x8)、NAMESPACE_DONE (0xE) は、それぞれ専用のコーデック(fetch/、ns/、tstat/)でエンコード・デコードし、どれもゴールデンベクターで固定している。
- [x] MOQT-055 エンドポイントが未知の Message Type を受信した場合、実装は呼び出し元がセッションを閉じられるよう、それを区別して報告しなければならない。
  - test: `tests/app/moqctl_test.c` — `test_moqctl_peek_type_unknown`
- [x] MOQT-056 実装は外枠の先読みでは自らデコードしない既知の Message Type(REQUEST_UPDATE、FETCH、TRACK_STATUS、PUBLISH_NAMESPACE、SUBSCRIBE_NAMESPACE、SUBSCRIBE_TRACKS など)を、まったく未知のものと区別し、呼び出し元がセッションを閉じる代わりにそれを振り分けるか NOT_SUPPORTED を返せるようにしなければならない。現在のハブは、SUBSCRIBE_TRACKS も含め、これらすべてに応答する(MOQT-200)。
  - test: `tests/app/moqctl_test.c` —
    `test_moqctl_peek_type_known_unimplemented`
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_unknown_first_type_gets_not_supported`
- [x] MOQT-057 制御メッセージが宣言する Length が、実際に読める Message Body の長さと合わない場合、実装はそのメッセージを完全なものとして扱ってはならない(本体を越えて誤読せず、不足として報告する)。
  - test: `tests/app/moqctl_test.c` — `test_moqctl_peek_type_length_mismatch`
  - test: `tests/app/moqctl_test.c` — `test_moqctl_peek_type_truncated`
- [x] MOQT-058 実装は全長が 2^16-1 バイトまでの制御メッセージに対応しなければならない。
  - test: `tests/app/moqctl_test.c` — `test_moqctl_peek_type_max_len_field`

## SS10.1 Request ID

- [~] MOQT-059 (SS10.1) クライアントは 0 から始まる偶数の Request ID を、サーバーは 1 から始まる奇数の Request ID を生成し、新しいリクエストごとに 2 ずつ増やさなければならない。
  - evidence: `test_moqtrun_upfetch_gap_to_owner` と `test_moqtrun_upsub_ok_after_upstream` は、ハブ自身の Request ID が奇数であることを確かめている。2 ずつ増えること(`request_id_next`)は確かめていない。
- [x] MOQT-060 (SS10.1) エンドポイントが、最下位ビットが送信側に合わない Request ID を受信した場合、実装はセッションを INVALID_REQUEST_ID で閉じなければならない。
  - test: `tests/app/moqtrun_sess_test.c` — `test_mtss_rid_parity_closes`
- [x] MOQT-061 (SS10.1) エンドポイントが重複した Request ID を受信した場合、実装はセッションを INVALID_REQUEST_ID で閉じなければならない。
  - test: `tests/app/moqtrun_sess_test.c` — `test_mtss_rid_duplicate_closes`
  - test: `tests/app/moqtrun_sess_test.c` — `test_mtss_rid_out_of_order_ok`
  - test: `tests/app/moqtrun_sess_test.c` — `test_mtss_rid_window_slides`

## SS10.2 Message Parameter

- [x] MOQT-062 実装は Message Parameter を、Type Delta(varint。直前の Parameter Type からの累積)と、それに続く Value としてデコードしなければならない。Value のエンコード(uint8、varint、Location、長さ付きバイト列)は Type ごとに決まっている。
  - test: `tests/app/moqctl_test.c` — `test_moqctl_params_forward_roundtrip`
  - test: `tests/app/moqctl_test.c` —
    `test_moqctl_params_delivery_timeout_decode`
- [~] MOQT-063 (SS10.2) パラメーターは Type の昇順でシリアライズしなければならない。累積の Parameter Type が 2^64-1 を超える場合、実装はセッションをプロトコル違反で閉じなければならない。
  - evidence: コーデックは VIOLATION を返し(`test_moqctl_params_type_overflow_violation`)、ハブはリクエストのデコードに失敗すると PROTOCOL_VIOLATION で閉じる(`test_moqtrun_fillfix_malformed_subscribe`、`test_moqtrun_setup_malformed_closes`)。ただし、この条件そのものを起こすハブのテストはない。
- [x] MOQT-064 (SS10.2) エンドポイントが未知の Message Parameter Type を受信した場合、実装はセッションをプロトコル違反で閉じなければならない。
  - test: `tests/app/moqctl_test.c` —
    `test_moqctl_params_unknown_type_violation`
  - test: `tests/app/moqtrun_fillfix_test.c` —
    `test_moqtrun_fillfix_malformed_subscribe`
- [~] MOQT-065 (SS10.2) 送信側が 1 つのメッセージで同じ Parameter Type を繰り返した場合、実装はセッションをプロトコル違反で閉じなければならない。
  - evidence: コーデックは VIOLATION を返し(`test_moqctl_params_duplicate_type_violation`、`test_moqctl_params_repeatable_filters`)、ハブはリクエストのデコードに失敗すると PROTOCOL_VIOLATION で閉じる(`test_moqtrun_fillfix_malformed_subscribe`、`test_moqtrun_setup_malformed_closes`)。ただし、この条件そのものを起こすハブのテストはない。
- [x] MOQT-066 (SS10.2.1) Message Parameter が、それが現れたメッセージとは別のメッセージ型向けに定義されている場合、実装はセッションをプロトコル違反で閉じなければならない。
  - test: `tests/app/moqctl_test.c` — `test_moqctl_params_scope_violation`
  - test: `tests/app/moqtrun_upd_test.c` — `test_moqtrun_upd_bad_and_control`
- [x] MOQT-233 (SS10.2.2) AUTHORIZATION TOKEN の Token 構造をデコードできない場合、ハブはセッションを KEY_VALUE_FORMATTING_ERROR で閉じなければならない。
  - test: `tests/app/moqtrun_sess_test.c` — `test_mtss_request_token_kvfmt`
- [~] MOQT-067 (SS10.2) SUBSCRIBE、PUBLISH_OK、FETCH の Message Parameter によって、パブリッシャーが送信する Object のペイロードを変えてはならない。
  - evidence: ペイロードを中継するとき、パラメーターの値はどれも参照しない。`test_moqtrun_object_relay_preserves_bytes` はペイロードが同一であることを示すが、パラメーターは変えていない。

## SS10.2.3/10.2.4 SUBGROUP_DELIVERY_TIMEOUT / OBJECT_DELIVERY_TIMEOUT

- [x] MOQT-068 実装は Message Parameter の SUBGROUP_DELIVERY_TIMEOUT (0x06) と OBJECT_DELIVERY_TIMEOUT (0x02) を varint としてデコードし、値 0 はタイムアウトを設定しないことを意味するものとしなければならない。
  - test: `tests/app/moqctl_test.c` —
    `test_moqctl_params_delivery_timeout_decode`
- [x] MOQT-069 ハブは自分が返す SUBSCRIBE_OK / REQUEST_OK / PUBLISH_DONE に配信タイムアウトのパラメーターを入れてはならない(ロスのない単一ハブのサブセットでは、配信タイムアウトを設定しない)。
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_subscribe_ok_carries_no_timeout_param`
- [x] MOQT-070 SUBSCRIBE が 0 でない SUBGROUP_DELIVERY_TIMEOUT パラメーターを持つ場合、ハブはそれを受け入れ、パブリッシャーの Track Property(10-4)との min() を取って、その購読で有効な Subgroup のタイムアウトとして記録しなければならない。0 でない OBJECT_DELIVERY_TIMEOUT も同様に受け入れて適用する(MOQT-189)。
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_subscribe_nonzero_timeout_accepted`
  - test: `tests/app/moqtrun_upd_test.c` — `test_moqtrun_timeout_accepted`
  - test: `tests/app/moqtrun_sub_test.c` —
    `test_moqtrun_sub_subgroup_timeout_min`

## SS10.2.5/10.2.6 FILL_TIMEOUT / RENDEZVOUS_TIMEOUT、SS8 Subgroup のタイマー

- [x] MOQT-231 (SS10.2.6, SS9.5) パブリッシャーのいない Track への SUBSCRIBE が 0 でない RENDEZVOUS_TIMEOUT を持つ場合、ハブはそれを(上限付きで)保留し、Track の配信が始まったら SUBSCRIBE_OK を返し(その購読者に同じ Track の PUBLISH は送らない)、タイムアウトが過ぎたら REQUEST_ERROR TIMEOUT を返さなければならない。値が 0 またはパラメーターがない場合、ハブはただちに DOES_NOT_EXIST を返さなければならない。
  - test: `tests/app/moqtrun_rdv_test.c` — `test_moqtrun_rdv_s1_one_answer`
  - test: `tests/app/moqtrun_rdv_test.c` — `test_moqtrun_rdv_s2_timeout`
  - test: `tests/app/moqtrun_rdv_test.c` — `test_moqtrun_rdv_s3_zero_is_dne`
  - test: `tests/app/moqtrun_rdv_test.c` — `test_moqtrun_rdv_s4_resolve`
  - test: `tests/app/moqtrun_rdv_test.c` — `test_moqtrun_rdv_s6_clamp`
  - test: `tests/app/moqtrun_rdv_test.c` —
    `test_moqtrun_rdv_s12_subtracks_skips_held`
- [~] MOQT-232 (SS10.2.5) ハブは上流の FETCH を待つ時間を FILL_TIMEOUT(自分の予算で頭打ちにする。パラメーターがないときもこの予算を使う)で区切り、まだ欠けている分を不明な範囲として報告しなければならない。FILL_TIMEOUT が 0 なら、ハブはまったく待ってはならない。
  - evidence: `test_moqtrun_upfetch_budget` は draft-19 の要求元で上限を示している。FILL_TIMEOUT が 0 のケース(`test_moqtrun_upfetch_fill_timeout_zero`)は draft-22 の要求元でしか動かしていない。
- [~] MOQT-225 (SS8) SUBGROUP_DELIVERY_TIMEOUT が 0 でない場合、ハブは上流の FIN からその時間内に配信し終えなかった Subgroup ストリームをリセットし、そのようなデータグラムを捨てなければならない。
  - evidence: ハブは、有効な Subgroup のタイムアウトを OBJECT_DELIVERY_TIMEOUT と同じく経過時間の上限として適用する(`test_moqtrun_sub_subgroup_timeout_gates_delivery`)。上流の FIN でタイマーを起動し、まだ確認応答されていない下流のストリームをリセットする(`test_moqtrun_sub_subgroup_timeout_after_fin`)。データグラムには経過時間の上限しかない。

## SS10.2.17 FORWARD パラメーター

- [x] MOQT-071 実装は FORWARD パラメーター(Type 0x10)を、値が 0(転送しない)または 1(転送する)の uint8 としてエンコード・デコードし、省略時は 1 としなければならない。
  - test: `tests/app/moqctl_test.c` — `test_moqctl_params_forward_roundtrip`
- [x] MOQT-072 (SS5.1, SS10.10) PUBLISH で FORWARD=0 を送ったパブリッシャーは、購読者が Forward State を 1 にするまで Object を送信してはならない。購読への Object の転送は、その購読の Forward State で止めたり通したりする。
  - test: `tests/app/moqtrun_misc_test.c` —
    `test_moqtrun_misc_pub_forward0_then_update`
  - test: `tests/app/moqtrun_sub_test.c` —
    `test_moqtrun_sub_reattach_keeps_state`

## SS10.3 SETUP

- [x] MOQT-073 実装は SETUP の Setup Option を、メッセージのペイロード全体にわたる Key-Value-Pair のリストとしてエンコード・デコードしなければならない。
  - test: `tests/app/moqctl_test.c` — `test_moqctl_setup_roundtrip`
- [x] MOQT-074 (SS10.3) エンドポイントは認識できない Setup Option を、未知のオプションの重複も含めて無視しなければならない。
  - test: `tests/app/moqctl_test.c` —
    `test_moqctl_setup_unknown_option_ignored`
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_setup_unknown_options_ignored`
- [~] MOQT-075 (SS10.3) 送信側はオプションが複数のインスタンスを明示的に許していない限り、1 つのメッセージで同じ Setup Option Type を繰り返してはならない。
  - evidence: `moqctl_setup_encode` は作りとして各オプションを高々 1 回しか書かない(`test_moqctl_setup_roundtrip` は各オプション 1 つずつで往復させる)。エンコードした SETUP に重複がないかを調べるテストはない。

## SS10.3.1.1 AUTHORITY / SS10.3.1.2 PATH / SS10.3.1.5 MOQT_IMPLEMENTATION

- [x] MOQT-076 実装は Setup Option の PATH (0x01) と AUTHORITY (0x05) をバイト列の値としてデコードしなければならない。
  - test: `tests/app/moqctl_test.c` — `test_moqctl_setup_path_option_decode`
- [x] MOQT-077 (SS10.3.1.1, SS10.3.1.2) WebTransport を使っているときに PATH または AUTHORITY のオプションを受信した場合、実装はセッションをそれぞれ INVALID_PATH または INVALID_AUTHORITY で閉じなければならない。
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_setup_path_closes_invalid_path`
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_setup_authority_closes_invalid_authority`
  - test: `tests/app/moqraw_test.c` — `test_moqraw_wt`
- [x] MOQT-234 (SS10.3.1.1, SS10.3.1.2) ネイティブ QUIC のセッションでは、ハブは URI の規則に反する PATH や AUTHORITY には MALFORMED_PATH / MALFORMED_AUTHORITY で、自分が扱わない PATH や AUTHORITY には INVALID_PATH / INVALID_AUTHORITY で閉じなければならない。
  - test: `tests/app/moqraw_test.c` — `test_moqraw_path`
  - test: `tests/app/moqraw_test.c` — `test_moqraw_authority`
  - test: `tests/app/moqraw_test.c` — `test_moqraw_hook`
- [x] MOQT-237 (SS10.3.1.5) ハブは自分の名前とバージョンだけを持つ MOQT_IMPLEMENTATION の Setup Option を送信するべきである。
  - test: `tests/app/moqtrun_test.c` — `test_moqtrun_setup_sends_implementation`
- [x] MOQT-078 実装は Setup Option の MOQT_IMPLEMENTATION (0x07) を UTF-8 のバイト列の値としてデコードしなければならない。
  - test: `tests/app/moqctl_test.c` — `test_moqctl_setup_roundtrip`

## SS10.4 GOAWAY(ワイヤー形式)

- [x] MOQT-079 実装は GOAWAY を Type (0x10) + Length + New Session URI Length + New Session URI + Timeout としてエンコード・デコードしなければならない。
  - test: `tests/app/moqctl_test.c` — `test_moqctl_goaway_roundtrip`
- [~] MOQT-080 (SS10.4) New Session URI Length が 8192 バイトを超える場合、実装はセッションをプロトコル違反で閉じなければならない。
  - evidence: コーデックは VIOLATION を返し(`test_moqctl_goaway_uri_boundary`)、デコードに失敗した GOAWAY では PROTOCOL_VIOLATION で閉じる(`test_moqtrun_peer_goaway_uri`、不正な GOAWAY)。長すぎる URI を送るハブのテストはない。
- [~] MOQT-081 (SS10.4) ハブの GOAWAY は、WebTransport のセッションではアプリケーションの New Session URI を、ネイティブ QUIC のセッションでは長さ 0 の URI(現在の URI を再利用)を持ち、現在のスキームを保たなければならない。
  - evidence: `test_moqtrun_raw_goaway_uri_empty`(セッションは moqt-22 で参加しているが、エンコードはドラフトに依存しない)と `test_moqtrun_goaway_once_per_session`。

## SS10.5 REQUEST_OK

- [x] MOQT-082 実装は REQUEST_OK を Type (0x7) + Length + Number of Parameters + Parameters + Track Properties(メッセージの残りのバイト)としてエンコード・デコードしなければならない。
  - test: `tests/app/moqctl_test.c` — `test_moqctl_request_ok_roundtrip`
- [x] MOQT-083 (SS10.5) Track Properties が空でなければならない REQUEST_OK(PUBLISH_OK、REQUEST_UPDATE_OK、SUBSCRIBE_NAMESPACE_OK、PUBLISH_NAMESPACE_OK)が Track Properties を持っている場合、実装はセッションをプロトコル違反で閉じなければならない。
  - test: `tests/app/moqtrun_sess_test.c` — `test_mtss_publish_ok_props_closes`
  - evidence: このうちハブが受信しうるのは PUBLISH_OK だけである。ハブは REQUEST_UPDATE、SUBSCRIBE_NAMESPACE、PUBLISH_NAMESPACE を送信しない。

## SS10.6 REQUEST_ERROR

- [x] MOQT-084 実装は REQUEST_ERROR を Type (0x5) + Length + Error Code + Retry Interval + Error Reason + 任意の Redirect としてエンコード・デコードしなければならない。
  - test: `tests/app/moqctl_test.c` — `test_moqctl_request_error_roundtrip`
  - test: `tests/app/moqctl_test.c` —
    `test_moqctl_request_error_redirect_roundtrip`
- [x] MOQT-085 Redirect 構造は、Error Code が REDIRECT のときにだけ存在しなければならない。
  - test: `tests/app/moqctl_test.c` —
    `test_moqctl_request_error_redirect_roundtrip`
- [x] MOQT-086 (SS10.6.1) ハブが、Connect URI Length が 0 でない Redirect、または名前空間単位のリクエストに対して空でない Track Name を持つ Redirect を受信した場合、ハブはセッションをプロトコル違反で閉じなければならない。
  - test: `tests/app/moqtrun_sess_test.c` — `test_mtss_publish_error_redirect_closes`
  - test: `tests/app/moqtrun_upsub_test.c` — `test_moqtrun_upsub_redirect_uri_closes`
  - test: `tests/app/moqtrun_upfetch_test.c` — `test_moqtrun_upfetch_error_redirect_uri_closes`
  - evidence: ハブは名前空間単位のリクエストを送らないので、Track Name の規則が当てはまる REQUEST_ERROR はない。
- [x] MOQT-087 実装は自分が使う REQUEST_ERROR のコード、INTERNAL_ERROR、NOT_SUPPORTED、GOING_AWAY、INVALID_FILTER、UNINTERESTED、DOES_NOT_EXIST、UNAUTHORIZED、REDIRECT を認識しなければならない。
  - test: `tests/app/moqctl_test.c` —
    `test_moqctl_unknown_error_normalizes_to_internal`
- [x] MOQT-088 エンドポイントが認識できない REQUEST_ERROR のコードを受信した場合、実装はセッションを閉じずに、それを INTERNAL_ERROR として扱わなければならない。
  - test: `tests/app/moqctl_test.c` —
    `test_moqctl_unknown_error_normalizes_to_internal`

## SS10.7 SUBSCRIBE / SS10.8 SUBSCRIBE_OK

- [x] MOQT-089 実装は SUBSCRIBE を Type (0x3) + Length + Request ID + Track Namespace + Track Name + Number of Parameters + Parameters としてエンコード・デコードしなければならない。
  - test: `tests/app/moqctl_test.c` — `test_moqctl_subscribe_roundtrip`
- [x] MOQT-090 (SS5.1, SS10.7) 購読が成功したとき、パブリッシャーはちょうど 1 つの SUBSCRIBE_OK で応答しなければならない。
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_subscribe_matching_publish_replies_ok`
  - test: `tests/app/moqtrun_sub_test.c` —
    `test_moqtrun_req_subscribe_answered_on_its_stream`
- [x] MOQT-091 実装は SUBSCRIBE_OK を Type (0x4) + Length + Track Alias + Number of Parameters + Parameters + Track Properties としてエンコード・デコードしなければならない。
  - test: `tests/app/moqctl_test.c` — `test_moqctl_subscribe_ok_roundtrip`
- [x] MOQT-092 (SS5.1) ハブが、自分の SUBSCRIBE に対する SUBSCRIBE_OK または REQUEST_ERROR を 2 つ以上、あるいは自分の PUBLISH に対する REQUEST_OK または REQUEST_ERROR を 2 つ以上受信した場合、ハブはセッションをプロトコル違反で閉じなければならない。
  - test: `tests/app/moqsess_test.c` —
    `test_moqsub_duplicate_response_is_session_fault`
  - test: `tests/app/moqtrun_misc_test.c` —
    `test_moqtrun_misc_pub_second_ok_closes`
  - test: `tests/app/moqtrun_upsub_test.c` —
    `test_moqtrun_upsub_second_ok_closes`
  - test: `tests/app/moqtrun_misc_test.c` —
    `test_moqtrun_misc_pub_error_after_ok_closes`
- [~] MOQT-093 (SS5.1.1) パブリッシャーが SUBSCRIBE を REQUEST_ERROR で拒否した場合、その購読には Object を 1 つも送信してはならない。
  - evidence: 拒否した SUBSCRIBE は購読を作らない(`test_moqtrun_subscribe_without_publish_replies_error`、`test_moqtrun_sub_ns_must_match`)ので、そこへ中継されるものはない。拒否の後に Object を送るテストはない。

## SS10.10 PUBLISH

- [x] MOQT-094 実装は PUBLISH を Type (0x1D) + Length + Request ID + Track Namespace + Track Name + Track Alias + Number of Parameters + Parameters + Track Properties としてエンコード・デコードしなければならない。
  - test: `tests/app/moqctl_test.c` — `test_moqctl_publish_roundtrip`
- [x] MOQT-095 (SS5.1, SS10.5) PUBLISH で始まる購読が成功したとき、購読者はちょうど 1 つの PUBLISH_OK(REQUEST_OK)で応答しなければならない。
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_publish_replies_request_ok`
  - test: `tests/app/moqtrun_test.c` — `test_moqtrun_peer_publishes_two_tracks`
- [~] MOQT-096 (SS5.1) パブリッシャーは PUBLISH で始まる購読で、PUBLISH_OK を受信する前に Object の送信を始めてもよい。
  - evidence: ハブは PUBLISH にただちに応答し、その後に続く Object を中継する(`test_moqtrun_object_relay_to_subscriber`)。Object が REQUEST_OK より先に届くケースを固定したテストはない。
- [~] MOQT-097 (SS10.10) 購読者が PUBLISH を REQUEST_ERROR UNINTERESTED で拒否した場合、その購読は Object が 1 つも送信されないまま終了しなければならない。
  - evidence: ハブが送った PUBLISH への REQUEST_ERROR は、そのスロットを解放する(`test_subtracks_publish_error_frees_slot`)。その後に Object を送るテストはない。

## SS10.11 PUBLISH_DONE

- [x] MOQT-098 実装は PUBLISH_DONE を Type (0xB) + Length + Status Code + Stream Count + Error Reason としてエンコード・デコードしなければならない。
  - test: `tests/app/moqctl_test.c` — `test_moqctl_publish_done_roundtrip`
- [x] MOQT-099 (SS5.1.1, SS10.11) 送信側はその購読のために開いたデータストリームをすべて閉じるまで、PUBLISH_DONE を送信してはならない。
  - test: `tests/app/moqtrun_done_test.c` —
    `test_moqtrun_pubdone_waits_open_stream`
  - test: `tests/app/moqtrun_drain_test.c` —
    `test_moqtrun_done_resets_streams_first`
- [x] MOQT-100 (SS10.11) PUBLISH_DONE と、購読の双方向ストリームを閉じることによって、購読は終了しなければならない。その後、送信側は購読の状態を破棄してもよい。
  - test: `tests/app/moqtrun_done_test.c` — `test_moqtrun_pubdone_fin_after`
  - test: `tests/app/moqtrun_done_test.c` — `test_moqtrun_pubdone_one_sub`
- [~] MOQT-101 (SS5.1, SS10.11) 購読者が応答を送信する前に PUBLISH_DONE が届いた場合、購読者は FIN する前に、遅れた PUBLISH_OK をちょうど 1 つ返さなければならない。
  - evidence: ハブはすべての PUBLISH にただちに応答するので、応答していない PUBLISH を抱えることはない。この規則を固定するテストはない。
- [x] MOQT-102 実装は自分が使う PUBLISH_DONE のステータスコード、INTERNAL_ERROR、TRACK_ENDED、GOING_AWAY を認識しなければならない。
  - test: `tests/app/moqctl_test.c` —
    `test_moqctl_unknown_error_normalizes_to_internal`
- [x] MOQT-103 (SS10.11) パブリッシャーが購読のためにデータストリームを 1 本も開かなかった場合、パブリッシャーは PUBLISH_DONE の Stream Count を 0 にしなければならない。
  - test: `tests/app/moqtrun_done_test.c` —
    `test_moqtrun_pubdone_datagram_only`
- [x] MOQT-239 (SS10.11) ハブはパブリッシャーの PUBLISH_DONE を各購読者へ中継しなければならない。その際、ステータスはパブリッシャーのものを使い、ストリーム数はハブがその購読者のために開いたストリームの正確な数にする。中継するのは、パブリッシャーが数えたストリームをすべて終わりまで中継し終えてからとし、その待ち時間には上限を設ける。
  - test: `tests/app/moqtrun_done_test.c` — `test_moqtrun_pubdone_one_sub`
  - test: `tests/app/moqtrun_done_test.c` — `test_moqtrun_pubdone_n_groups`
  - test: `tests/app/moqtrun_done_test.c` —
    `test_moqtrun_pubdone_waits_late_stream`
  - test: `tests/app/moqtrun_done_test.c` — `test_moqtrun_pubdone_wait_bounded`
  - test: `tests/app/moqtrun_done_test.c` —
    `test_moqtrun_pubdone_status_passthrough`

## SS10 制御メッセージで共有する Reason Phrase / Location / Track Namespace の構造

- [x] MOQT-104 実装は Message Parameter、Location、Reason Phrase を、それらを含むすべての制御メッセージで一貫してエンコード・デコードしなければならない。
  - test: `tests/app/moqctl_test.c` — `test_moqctl_params_forward_roundtrip`
  - test: `tests/app/moqctl_test.c` —
    `test_moqctl_location_roundtrip_and_order`
  - test: `tests/app/moqctl_test.c` — `test_moqctl_reason_boundary`
  - vuln: V-0800

## SS5.1.2 Location Filter(購読のフィルタリング)

- [x] MOQT-105 実装は Location Filter の Filter Type を Next Group Start (0x1)、Largest Object (0x2)、AbsoluteStart (0x3)、AbsoluteRange (0x4) のいずれかとしてデコードし、フィールドの配置(Start Location、End Group Delta)を型に従って決めなければならない。
  - test: `tests/app/moqctl_test.c` —
    `test_moqctl_locfilter_next_group_and_largest`
  - test: `tests/app/moqctl_test.c` —
    `test_moqctl_locfilter_abs_start_and_range_roundtrip`
- [~] MOQT-106 (SS5.1.2) AbsoluteRange フィルターの End Group(Start.Group + End Group Delta)が 2^64-1 を超える場合、実装はセッションをプロトコル違反で閉じなければならない。
  - evidence: コーデックは VIOLATION を返し(`test_moqctl_locfilter_end_group_overflow_violation`)、ハブはリクエストのデコードに失敗すると PROTOCOL_VIOLATION で閉じる(`test_moqtrun_fillfix_malformed_subscribe`、`test_moqtrun_setup_malformed_closes`)。ただし、この条件そのものを起こすハブのテストはない。
- [~] MOQT-107 (SS5.1.2) エンドポイントが、定義された 4 つの値以外の Location Filter Type を受信した場合、実装はセッションをプロトコル違反で閉じなければならない。
  - evidence: コーデックは VIOLATION を返し(`test_moqctl_locfilter_unknown_type_violation`)、ハブはリクエストのデコードに失敗すると PROTOCOL_VIOLATION で閉じる(`test_moqtrun_fillfix_malformed_subscribe`、`test_moqtrun_setup_malformed_closes`)。ただし、この条件そのものを起こすハブのテストはない。
- [x] MOQT-108 (SS5.1.2, SS5.1.4) パブリッシャーは Forward State と Location Filter の両方を満たす Object だけを転送しなければならない(Pass = Forward AND Filters)。
  - test: `tests/app/moqtrun_sub_test.c` —
    `test_moqtrun_sub_reattach_keeps_state`
  - test: `tests/app/moqtrun_upd_test.c` —
    `test_moqtrun_filter_groups_delivered`
  - test: `tests/app/moqtrun_sub_test.c` —
    `test_moqtrun_sub_filter_from_largest`
  - test: `tests/app/moqtrun_fetch_test.c` —
    `test_moqtrun_fetch_no_replay_before_start`
- [x] MOQT-222 (SS5.1.2) SUBSCRIBE の Location Filter を満たせない場合(たとえば End Group がすでにすべて配信済みの場合)、ハブは REQUEST_ERROR INVALID_RANGE を返すべきである。
  - evidence: `moqtrun_filter_past`(End Group が Largest Group より前)と `test_moqtrun_sub_range_past_invalid`。draft-22 の逆転したフィルターは `test_moqtrun_sub_filter22_inverted` が確かめる。
  - test: `tests/app/moqtrun_sub_test.c` — `test_moqtrun_sub_range_past_invalid`

## SS14 グリース

- [x] MOQT-109 実装はグリース値を予約しているレジストリ(Setup Option、Property、エラーコードとステータスコードの表)で、0 以上の整数 N に対するグリース値のパターン 0x7f*N + 0x9D を認識しなければならない。
  - test: `tests/app/moqctl_test.c` — `test_moqctl_grease_pattern`
- [x] MOQT-110 (SS14) エンドポイントはグリースされたレジストリ(Setup Option、エラーコード)で未知の値を受信したことだけを理由に、セッションを閉じてはならない。
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_setup_unknown_options_ignored`
  - test: `tests/app/moqctl_test.c` —
    `test_moqctl_unknown_error_normalizes_to_internal`

## SS11.1 Track Alias

- [x] MOQT-111 パブリッシャーは同じセッションで、同じ Track Alias を 2 つの異なる Track に同時に使ってはならない。
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_chat_and_audio_get_different_aliases`
- [x] MOQT-112 (SS11.1) ハブが、そのセッションの別の Established の購読にすでに結び付いている Track Alias を再利用する PUBLISH または上流の SUBSCRIBE_OK を受信した場合、ハブはセッションを DUPLICATE_TRACK_ALIAS で閉じなければならない。
  - test: `tests/app/moqtrun_sess_test.c` — `test_mtss_publish_dup_alias_closes`
  - test: `tests/app/moqtrun_upsub_test.c` — `test_moqtrun_upsub_dup_alias_closes`

## SS11.3.1 Object Datagram / SS11.5.2 パディングのデータグラム

- [x] MOQT-243 (SS11, SS11.3.1) データグラムの Type が未知または不正な場合、ハブはセッションを PROTOCOL_VIOLATION で閉じなければならない。
  - test: `tests/app/moqtrun_sess_test.c` — `test_mtss_datagram_invalid_closes`
- [x] MOQT-244 (SS11.3.1) 実装は OBJECT_DATAGRAM を Type のビット(PROPERTIES、END_OF_GROUP、ZERO_OBJECT_ID、DEFAULT_PRIORITY、STATUS)に従ってデコードし、不正な Type(STATUS と END_OF_GROUP の組み合わせ、0b00X0XXXX の範囲外)、ビットが立っているのに空の Properties、Normal 以外の状態に付いた Properties を拒否しなければならない。
  - test: `tests/app/moqdg_test.c` — `test_moqdg_type_valid_accepts`
  - test: `tests/app/moqdg_test.c` — `test_moqdg_type_valid_rejects`
  - test: `tests/app/moqdg_test.c` — `test_moqdg_take_basic`
  - test: `tests/app/moqdg_test.c` — `test_moqdg_take_zero_oid_eog`
  - test: `tests/app/moqdg_test.c` — `test_moqdg_take_props`
  - test: `tests/app/moqdg_test.c` — `test_moqdg_take_reject_golden`
- [~] MOQT-246 (SS11.5.2) ハブはパディングのデータグラム(Type 0x132B3E29)を捨てなければならない。
  - evidence: Type が OBJECT_DATAGRAM の Type でないデータグラムは丸ごと捨てる(`test_moqtrun_dg_malformed_counts_bad`)。パディングの Type そのものを送るテストはない。

## SS11.2.1.1 Object Status

- [x] MOQT-113 実装は Object Status の値 0x0(Normal)、0x3(End of Group)、0x4(End of Track)を認識しなければならない。
  - test: `tests/app/moqdata_test.c` — `test_moqdata_obj_take_status_values`
- [x] MOQT-114 (SS11.2.1.1) Object が登録されていない Status の値を持つ場合、実装はセッションをプロトコル違反で閉じなければならない。
  - test: `tests/app/moqtrun_sess_test.c` — `test_mtss_subgroup_object_violations`
- [x] MOQT-115 Object は、Object Status が Normal (0x0) でない限り、空のペイロードを持たなければならない。Object Status フィールドは、Payload Length が 0 のときにだけ存在しなければならない。
  - test: `tests/app/moqdata_test.c` — `test_moqdata_subhdr_take_status_eog`
  - test: `tests/app/moqdata_test.c` —
    `test_moqdata_obj_take_status_eog_stream`

## SS11.2.1.2 Object Property

- [x] MOQT-116 (SS11.2.1.2) エンドポイントが、Status が Normal でない Object で Object Property を受信した場合、実装はセッションをプロトコル違反で閉じなければならない。
  - test: `tests/app/moqtrun_sess_test.c` — `test_mtss_subgroup_object_violations`
- [x] MOQT-117 Object Property は、Properties Length(varint)と、それに続く Key-Value-Pair のリストとしてシリアライズしなければならない。
  - test: `tests/app/moqdata_test.c` — `test_moqdata_obj_take_properties`

## SS11.4.2 Subgroup Header

- [x] MOQT-118 SUBGROUP_HEADER で開いたストリーム上の Object はすべて、Object Forwarding Preference が Subgroup であり、ヘッダーが宣言する Track Alias、Group ID、Subgroup ID に属していなければならない。
  - test: `tests/app/moqdata_test.c` — `test_moqdata_subhdr_take_basic`
- [x] MOQT-119 (SS11.4.2) SUBGROUP_HEADER の Type フィールドは 0b0XX1XXXX の形(ビット 4 は常に立つ)でなければならない。それ以外の形で受信した場合、実装はセッションをプロトコル違反で閉じなければならない。
  - test: `tests/app/moqtrun_sess_test.c` — `test_mtss_unknown_uni_closes`
- [x] MOQT-120 実装は SUBGROUP_ID_MODE フィールド(ビット 1-2)を次のようにデコードしなければならない。0b00 は Subgroup ID がなく 0、0b01 は Subgroup ID がなく最初の Object の Object ID と等しい、0b10 はヘッダーに Subgroup ID がある。
  - test: `tests/app/moqdata_test.c` — `test_moqdata_subhdr_take_mode2`
  - test: `tests/app/moqdata_test.c` — `test_moqdata_subhdr_take_mode1_resolve`
- [x] MOQT-121 (SS11.4.2) SUBGROUP_ID_MODE が 0b11 の場合、実装はセッションをプロトコル違反で閉じなければならない。
  - test: `tests/app/moqtrun_sess_test.c` — `test_mtss_subgroup_mode3_closes`
- [~] MOQT-122 実装は SUBGROUP_HEADER の Type フィールドの PROPERTIES ビット (0x01)、END_OF_GROUP ビット (0x08)、DEFAULT_PRIORITY ビット (0x20)、FIRST_OBJECT ビット (0x40) をデコードしなければならない。
  - test: `tests/app/moqdata_test.c` — `test_moqdata_type_bits_golden`
  - gap: 本番は END_OF_GROUP と FIRST_OBJECT のビットを判定しない。Type のバイトのままリレーし、Subgroup の途中から開くストリームでは FIRST_OBJECT を下ろす。
- [x] MOQT-123 DEFAULT_PRIORITY が立っている場合、Publisher Priority フィールドはヘッダーから省かなければならず、Subgroup は購読の制御メッセージから優先度を引き継がなければならない。
  - test: `tests/app/moqdata_test.c` — `test_moqdata_subhdr_take_basic`
- [~] MOQT-124 (SS11.4.2) END_OF_GROUP ビットが立っていて、ストリームが FIN で終わる場合、実装は同じ Group ID でより大きな Object ID を持つ Object は存在しないと推定しなければならない。
  - evidence: ビットはデコードしている(MOQT-122)。Malformed Track の検査は、この推定ではなく END_OF_GROUP の状態を使う(`test_moqtrun_pubdone_malformed_after_end_of_group`)。
- [x] MOQT-125 (SS2.2, SS11.4.2) ハブは、その Subgroup で最初に配信された Object から始まる Subgroup では FIRST_OBJECT ビットを転送し、Subgroup の途中から開くストリームではそのビットを下ろさなければならない。
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_late_subscriber_gets_late_opened_stream`
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_object_relay_preserves_bytes`
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_late_subscriber_gets_late_opened_stream`
- [x] MOQT-126 実装は SUBGROUP_HEADER を、ワイヤー上のフィールド(Type、Track Alias、Group ID、任意の Subgroup ID、任意の Publisher Priority)とバイト単位で一致するようにエンコード・デコードしなければならない。
  - test: `tests/app/moqdata_test.c` — `test_moqdata_subhdr_put_golden`
  - test: `tests/app/moqdata_test.c` — `test_moqdata_subhdr_put_errors`
- [x] MOQT-127 SUBGROUP_HEADER が、宣言したフィールドがすべてそろう前に途切れている場合、実装はデコードを不足として報告しなければならない。
  - test: `tests/app/moqdata_test.c` — `test_moqdata_subhdr_take_truncated`
- [x] MOQT-128 実装はモード 0b01(後で決まる)の Subgroup ID を、最初の Object の Object ID をデコードした時点でそこから決めなければならない。
  - test: `tests/app/moqdata_test.c` — `test_moqdata_subhdr_take_mode1_resolve`

## SS11.4.2 Subgroup の Object のフィールド

- [x] MOQT-129 実装は Subgroup の Object を Object ID Delta + 任意の Properties + Object Payload Length + 任意の Object Status + 任意の Object Payload としてエンコード・デコードしなければならない。
  - test: `tests/app/moqdata_test.c` — `test_moqdata_obj_take_basic_stream`
  - test: `tests/app/moqdata_test.c` — `test_moqdata_obj_put`
- [x] MOQT-130 Object ID は、Subgroup の最初の Object では Object ID Delta そのもの、それ以降の Object では直前の Object ID に Delta と 1 を足した値でなければならない。
  - test: `tests/app/moqdata_test.c` — `test_moqdata_obj_take_delta_chain`
- [x] MOQT-131 (SS11.4.2) 累積した Object ID が 2^64-1 を超える場合、実装はセッションをプロトコル違反で閉じなければならない。
  - test: `tests/app/moqtrun_sess_test.c` — `test_mtss_subgroup_object_violations`
- [x] MOQT-132 Subgroup の Object のストリームが、シリアライズされた Object の途中で FIN により終わった場合、実装はその途中までの Object を完全なものとして扱ってはならない。
  - test: `tests/app/moqdata_test.c` — `test_moqdata_obj_take_truncated`
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_decode_loop_stops_at_truncation`
- [x] MOQT-133 Subgroup の Object のストリームで、Object ごとのデコードがプロトコル違反を報告した場合、実装はそのストリームの以降の Object のデコードをその時点で止めなければならない。
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_decode_loop_stops_at_violation`
- [x] MOQT-134 実装は 1 つのストリームバッファーから複数の Object を順にデコードし、その結果は各 Object を個別にデコードした結果と一致しなければならない。
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_decode_loop_single_object_matches_one_shot`
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_decode_loop_multiple_objects`

## SS11.4.3 Subgroup ストリームを閉じる

- [x] MOQT-135 送信側が Subgroup のすべての Object を送り終えた場合、送信側はストリームを FIN で閉じなければならない。
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_chat_split_data_then_bare_fin_relays_and_closes`
- [x] MOQT-136 ストリームの FIN を観測した実装は、購読の開始以降、その Subgroup のすべての Object を受信したことが保証される。
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_torn_object_cut_through`
- [x] MOQT-137 リレーは、その Subgroup の次の Object でない限り、既存の Subgroup ストリームで Object を転送してはならない(2 回に分かれて届いた Object は、送信済みの部分が終わった位置からちょうど続ける)。
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_fresh_delivery_tail_cut_through`
  - test: `tests/app/moqtrun_test.c` — `test_moqtrun_frag_overflow_counted`
- [x] MOQT-138 新しい Object のバイトを伴わないパブリッシャーのストリームの FIN は、空のデータ送信(拒否される)ではなく、何も載せない FIN によって、対応するリレーのストリームを閉じなければならない。
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_chat_split_data_then_bare_fin_relays_and_closes`
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_audio_split_data_then_bare_fin_closes`
- [x] MOQT-139 同じ Track で重なり合う 2 本のパブリッシャーのストリームは、それぞれ独立したストリームで中継し、それぞれ自分のパブリッシャーの FIN によってだけ閉じなければならない。
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_interleaved_chat_messages_close_independently`
- [x] MOQT-140 (SS11.4.3) Subgroup ストリームが始まった後に参加した購読者にも、中継のストリームを開いて届けなければならない。そのストリームは、送信済みの SUBGROUP_HEADER を FIRST_OBJECT を下ろした形で載せて開く。
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_late_subscriber_gets_late_opened_stream`
- [ ] MOQT-247 (SS11.4.3) 購読者が Subgroup の中継ストリームに STOP_SENDING を送ったとき、ハブはそのストリームをリセットし、その Subgroup の残りのために新しいストリームを開くべきではない。
  - gap: 中継のデータストリームに STOP_SENDING を送るテストはない。

## SS11.5.1 パディングのストリーム

- [x] MOQT-141 実装はパディングのストリーム(Type 0x132B3E28)で受信したデータをすべて捨てなければならない。
  - test: `tests/app/moqtrun_test.c` — `test_moqtrun_padding_stream_discarded`

## SS11.4.2 Subgroup Header: フロー制御の優先度

- [x] MOQT-142 エンドポイントは接続のフロー制御のクレジットを、データストリームより先に制御ストリームへ割り当てなければならない。受信側が、届くのにフロー制御を必要とする制御メッセージを待ってデッドロックしないようにするためである。
  - test: `tests/app/moqtrun_drain_test.c` — `test_moqtrun_prio_control_first`
    (ハブの制御ストリームは urgency 2 で、リクエストストリームの 3 と Object ストリームの 4..7 より上)
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_wt_priority_conn_credit_to_urgent`(WT の送信処理は、接続の最後のクレジットを urgency の高いほうのクラスに渡す)

## SS11.4.2 Subgroup の Object のフィールド(エンコーダーのバイト単位の一致)

- [x] MOQT-143 実装は Subgroup の Object の Object ID Delta、Payload Length、そして明示的な Object Status(ペイロードが空のとき)またはペイロードのバイト列を、ワイヤー形式とバイト単位で一致するようにエンコードしなければならない。
  - test: `tests/app/moqdata_test.c` — `test_moqdata_obj_put`
- [~] MOQT-144 1 メッセージのビルダーは、Object を 1 つ運ぶ SUBGROUP_HEADER を 1 つ、ワイヤー形式とバイト単位で一致するように組み立て、書き込み先のバッファーが小さすぎるときは途中まで書かずに失敗しなければならない。
  - test: `tests/app/moqdata_test.c` — `test_moqdata_blob_build_golden`
  - gap: 本番は `moqdata_blob_build` と `moqtrun_live_head` で SUBGROUP_HEADER と Object を組み立てる。バイト列はゴールデンと一致することを確かめているが、`moqdata_blob_build` は小さすぎるバッファーに途中まで書くことがある。
  - test: `tests/app/moqdata_test.c` —
    `test_moqdata_put_path_status_eog_golden`

## SS5.1 購読(状態機械、追加のカバレッジ)

- [x] MOQT-145 (SS5.1) 購読が Established である間、どちらの側(SUBSCRIBE または PUBLISH)が始めた購読であっても、その購読への Object の転送を許さなければならない。
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_object_relay_to_subscriber`
  - test: `tests/app/moqtrun_misc_test.c` — `test_moqtrun_misc_pub_ok_relays`
- [x] MOQT-146 (SS5.1, SS10.9) Established の購読で受信した REQUEST_UPDATE は、購読を Established のままにしなければならない。
  - test: `tests/app/moqtrun_upd_test.c` — `test_moqtrun_upd_forward_toggles`
  - test: `tests/app/moqtrun_upd_test.c` — `test_moqtrun_upd_params_replace`
- [x] MOQT-147 (SS3.3.2) リクエストを送った直後、応答を待たずに自分の方向を FIN した要求元について、そのリクエストを失敗扱いにしてはならない。
  - test: `tests/app/moqtrun_sub_test.c` — `test_moqtrun_req_fin_keeps_request`
- [x] MOQT-148 (SS3.3.3, SS5.1) 購読者はリクエストストリームを取り消すことで Established の購読を終了できなければならない。
  - test: `tests/app/moqtrun_sub_test.c` —
    `test_moqtrun_req_reset_unsubscribes`
- [~] MOQT-149 (SS3.3.3) ハブが自分の送ったリクエストを取り消すとき、ハブは開いている送信方向をリセットし、受信方向に STOP_SENDING を送らなければならない(自分の方向を FIN 済みなら STOP_SENDING だけを送る)。
  - evidence: `test_moqtrun_upsub_last_cancel_cancels_upstream` は、上流のストリームに RESET_STREAM と STOP_SENDING が送られることを確かめている。FIN 済みのケースを固定するテストはない。
- [x] MOQT-150 (SS3.3.2) 応答側が応答を一度も送らずに自分の方向を FIN した場合、要求元はそのリクエストを失敗として扱わなければならない。
  - evidence: `test_moqtrun_upsub_fin_unanswered_fails` と `test_moqtrun_upfetch_fin_unanswered`。応答の前に FIN された上流の SUBSCRIBE / FETCH は、REQUEST_ERROR を受けたときと同じく失敗する(`moqtrun_up_rx`、`moqtrun_upf_rx`)。
  - test: `tests/app/moqtrun_upsub_test.c` — `test_moqtrun_upsub_fin_unanswered_fails`
- [x] MOQT-220 (SS5.1.1, SS5.2) 要求元が購読や FETCH を取り消したとき、ハブはそのために開いているデータストリームをリセットしなければならない。
  - evidence: `test_moqtrun_fetch_cancelled_by_request_reset` は FETCH のデータストリームのリセットを、`test_moqtrun_req_reset_resets_data_streams` は購読の開いている Subgroup ストリームのリセットを確かめている(`moqtrun_cancel_peer_subs`)。
  - test: `tests/app/moqtrun_fetch_test.c` — `test_moqtrun_fetch_cancelled_by_request_reset`

## SS10 制御メッセージ: セッション状態機械の望ましくない振る舞い(追加のカバレッジ)

- [x] MOQT-151 (SS10) 制御ストリームが未知のメッセージ型や Length と Body の不一致を含む場合、実装はセッションをプロトコル違反で閉じなければならない。
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_ctl_unknown_type_closes_session`
  - test: `tests/app/moqctl_test.c` — `test_moqctl_peek_type_length_mismatch`
- [x] MOQT-152 (SS3.5) セッションが閉じた後のイベントは、何もしない操作でなければならない(閉じた理由は固定される)。
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_ctl_unknown_type_closes_session`
  - test: `tests/app/moqsess_test.c` — `test_moqsess_closed_is_sticky`

## ハブのリレー: PUBLISH/SUBSCRIBE の振り分け(SS9 リレー、SS10.5/10.7/10.10 の適用)

- [x] MOQT-153 PUBLISH が成功したとき、ハブは同じ制御ストリームで、それを閉じずに REQUEST_OK を返さなければならない。
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_publish_replies_request_ok`
- [x] MOQT-154 ピアは、互いに異なる複数の Track を(実装のピアごとの Track 容量まで)PUBLISH してもよく、それぞれが独立に REQUEST_OK を受け取る。
  - test: `tests/app/moqtrun_test.c` — `test_moqtrun_peer_publishes_two_tracks`
- [x] MOQT-155 ピアが、実装のピアごとの容量を超える数の異なる Track を PUBLISH しようとした場合、実装は既存の Track を黙って上書きせず、REQUEST_ERROR を返さなければならない。
  - test: `tests/app/moqtrun_test.c` — `test_moqtrun_sixth_publish_gets_error`
- [x] MOQT-156 すでにスロットを使っている Track Name を再び PUBLISH したときは、新しいスロットを使わず、そのスロットを再利用しなければならない。
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_republish_same_name_reuses_slot`
- [x] MOQT-157 ピアが PUBLISH した Track を指す SUBSCRIBE には、割り当てた Track Alias 付きの SUBSCRIBE_OK を返さなければならない。
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_subscribe_audio_track_replies_ok`
- [x] MOQT-158 同じ振り分け呼び出しで届いた 2 つの SUBSCRIBE メッセージには、一方が他方を上書きすることなく、それぞれの応答をキューに入れなければならない。
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_two_subscribe_oks_one_dispatch_no_overflow`

## ハブのリレー: 一致する購読者だけへの Object の転送(SS9.4, SS11.1)

- [x] MOQT-159 Object は、その Track Alias が指す Track の購読者だけに転送し、同じセッションのほかの Track の購読者には転送してはならない。
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_chat_object_relays_only_to_chat_subscriber`
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_audio_object_relays_only_to_audio_subscriber`
- [x] MOQT-160 Object の Track Alias が、パブリッシャーの宣言したどの Track とも一致しない場合、実装はそれをどの購読者にも転送してはならない。
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_unknown_alias_object_relays_nowhere`
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_unbound_stream_id_relays_nowhere`
- [x] MOQT-161 同じ Track への複数の購読に一致する Object は、一致する購読ごとに 1 回ずつ送信しなければならない。
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_chat_object_relays_to_all_three_subscribers`
- [x] MOQT-162 ある購読者への Object の転送が失敗した(下位のトランスポートが送信を拒否した)場合でも、実装は一致するほかの購読者全員へそれを転送し、損失を黙って見過ごさずに数えなければならない。
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_chat_one_of_three_subscribers_refused`
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_send_uni_failure_counts_open_drop`
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_stream_send_rejection_drops_frame_not_fatal`
- [x] MOQT-163 Forwarding Preference が Subgroup で送られた Object は、パブリッシャーのストリームの区切りに合わせ、中継の 1 回の送信ごとに SUBGROUP_HEADER と Object をそろえた 1 単位として中継しなければならない。
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_multi_object_stream_relays_in_one_send_uni`
- [x] MOQT-164 長く続く Subgroup ストリームの後続のデータ(SUBGROUP_HEADER を繰り返さずに届く)は、すでに結び付けた同じ中継ストリームに追記しなければならず、新しいヘッダーと誤読してはならない。
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_data_stream_continues_across_calls_without_header`
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_audio_first_object_opens_then_appends`
- [x] MOQT-165 パブリッシャーの Subgroup ストリームが FIN したとき、実装は対応する中継ストリームを閉じ、新しいパブリッシャーのストリームで来る次の Subgroup には新しいストリームを開かなければならない。境界をまたいで追記してはならない。
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_audio_publisher_fin_closes_and_reopens`
- [x] MOQT-166 実装は各 Subgroup を、その届き方に合ったトランスポートの基本操作で一貫して中継しなければならない(1 回で届く Subgroup は open+send+FIN を 1 度に、長く続く Subgroup は FIN なしで開いて後から追記する)。
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_chat_still_uses_send_uni_every_object`
- [x] MOQT-167 同じ Track の 2 人の購読者には、それぞれ独立した中継ストリームを与え、一方への配信が他方のストリームの結び付けに影響しないようにしなければならない。
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_audio_two_subscribers_independent_streams`

## ハブのリレー: 拒否が続くストリームの切り捨て(SS11.4.3 のリセットの決まりの適用)

- [x] MOQT-168 購読者の中継ストリームが、実装のしきい値を超えて busy(拒否)の状態を続けた場合、実装は古い滞留を抱え続けず、そのストリームをリセットし、次の配信で新しいストリームを開き直さなければならない。
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_busy_streak_sheds_after_threshold`
- [x] MOQT-169 busy が続く途中で配信が受け入れられたら、busy の連続回数のカウンターをリセットし、散発的な一時的拒否が積み重なって切り捨てに至らないようにしなければならない。
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_busy_streak_success_resets`
- [x] MOQT-170 ストリームを切り捨てた後、その放棄したストリーム宛てに届いたパブリッシャーの何も載せない FIN を、そこへ転送してはならない。
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_shed_stream_skips_publisher_fin`
- [x] MOQT-171 busy の連続回数のカウンターは購読者ごとに持ち、詰まった 1 人の購読者の切り捨てが、ほかの購読者の正常なストリームに影響しないようにしなければならない。
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_busy_shed_isolated_per_subscriber`
- [x] MOQT-172 リセットそのものが下位のトランスポートに拒否された場合、実装はそれを完了扱いにせず、次の busy の回で切り捨てを再試行しなければならない。
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_shed_refused_retries_next_round`
- [x] MOQT-173 Track を再び PUBLISH したときは、以前の Track で積み上がった busy の連続回数のカウンターも含め、その中継の状態を消去しなければならない。
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_republish_clears_busy_streak`

## ハブのリレー: セッションの後片付け(SS3.5 終了のリレー状態への適用)

- [x] MOQT-174 セッションが閉じたとき、実装はそのピアのスロットを解放し、後で同じ下位のセッションポインターで再接続してきたものを、死んだピアではなく新しいピアとして扱わなければならない。
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_close_frees_peer_for_reregistration`
- [x] MOQT-175 購読者のセッションが閉じたとき、実装はほかのすべてのピアの Track にあるその購読者の購読エントリを無効にし、後から来た Object が死んだセッションへ中継されないようにしなければならない。
  - test: `tests/app/moqtrun_test.c` — `test_moqtrun_close_drops_subscriptions`
- [x] MOQT-176 実装が登録していないセッション(またはすでに閉じたセッション)を閉じる操作は、ほかのピアに影響しない、何もしない操作でなければならない。
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_close_unknown_session_noop`
- [x] MOQT-177 実装のピアテーブルの容量を超えて登録と閉じる操作を繰り返しても、スロットを漏らしてはならず、再接続のたびに SETUP を受け取れなければならない。
  - test: `tests/app/moqtrun_test.c` — `test_moqtrun_close_reregister_churn`

## ハブのリレー: 制御ストリームとリクエストストリーム

- [x] MOQT-178 (SS10.2, SS10.2.1) 実装はすべての Message Parameter を、draft-19 のレジストリ(値のエンコード、現れてよいメッセージ、許される値の範囲)に従ってデコードしなければならない。メッセージや範囲から外れたパラメーターでは、セッションをプロトコル違反で閉じなければならない。
  - test: `tests/app/moqctl_test.c` — `test_moqctl_params_registry_scope`
  - test: `tests/app/moqctl_test.c` — `test_moqctl_params_uint8_value_ranges`
  - test: `tests/app/moqctl_test.c` — `test_moqctl_params_repeatable_filters`
  - test: `tests/app/moqctl_test.c` — `test_moqctl_golden_subscribe_params`
  - test: `tests/app/moqtrun_upd_test.c` — `test_moqtrun_upd_bad_and_control`
  - test: `tests/app/moqtrun_fillfix_test.c` —
    `test_moqtrun_fillfix_malformed_subscribe`
- [x] MOQT-179 複数回のストリーム配信に分かれて届いた制御メッセージは、組み立て直して 1 回だけ処理しなければならない。1 KiB を超えるメッセージ(65535 バイトまで)は共有の再組み立てバッファで受け取り、そのバッファが尽きたときはセッションを INTERNAL_ERROR で閉じなければならない。
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_ctl_split_subscribe_answered_once`
  - test: `tests/app/moqtrun_test.c` — `test_moqtrun_ctl_message_then_half`
  - test: `tests/app/moqtrun_test.c` — `test_moqtrun_ctl_max_length_accepted`
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_ctl_pool_exhausted_closes`
- [x] MOQT-180 制御ストリームがまったく未知の Message Type を含む場合、ハブはセッションをプロトコル違反で閉じなければならない。
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_ctl_unknown_type_closes_session`
- [x] MOQT-181 それぞれ専用の双方向ストリームで開いたリクエストには、そのストリームで応答しなければならない。ストリームのリセットはリクエストを取り消す(購読の解除・PUBLISH の取り消し)が、FIN だけでは取り消さない。1 つのセッションが開いておけるリクエストは最大 32 個とする(それを超えるものは EXCESSIVE_LOAD でリセットする)。
  - test: `tests/app/moqtrun_sub_test.c` —
    `test_moqtrun_req_subscribe_answered_on_its_stream`
  - test: `tests/app/moqtrun_sub_test.c` —
    `test_moqtrun_req_two_streams_answered_apart`
  - test: `tests/app/moqtrun_sub_test.c` — `test_moqtrun_req_reset_unsubscribes`
  - test: `tests/app/moqtrun_sub_test.c` — `test_moqtrun_req_fin_keeps_request`
  - test: `tests/app/moqtrun_sub_test.c` — `test_moqtrun_req_per_session_cap`
  - test: `tests/app/moqtrun_sub_test.c` — `test_moqtrun_req_pool_full_resets`

## ハブのリレー: 購読

- [x] MOQT-182 SUBSCRIBE は、配信されている Track を完全な Track Name(名前空間と名前)で照合しなければならない。名前空間が違えば、同じ名前でも別の Track である。
  - test: `tests/app/moqtrun_sub_test.c` — `test_moqtrun_sub_ns_must_match`
  - test: `tests/app/moqtrun_sub_test.c` —
    `test_moqtrun_sub_same_name_other_ns_coexist`
- [x] MOQT-183 ハブは各購読の Request ID、SUBSCRIBER_PRIORITY、GROUP_ORDER、FORWARD、配信タイムアウト、フィルターの開始位置を記録し、パブリッシャーが参加し直しても保持し、Track に Object ができたら SUBSCRIBE_OK で LARGEST_OBJECT を報告しなければならない。
  - test: `tests/app/moqtrun_sub_test.c` — `test_moqtrun_sub_params_recorded`
  - test: `tests/app/moqtrun_sub_test.c` —
    `test_moqtrun_sub_reattach_keeps_state`
  - test: `tests/app/moqtrun_sub_test.c` — `test_moqtrun_sub_ok_largest`
  - test: `tests/app/moqtrun_sub_test.c` —
    `test_moqtrun_sub_largest_from_datagram`
- [x] MOQT-184 Object は、共有のバッファープールから各購読者へ確実に中継しなければならない。遅い購読者がプールを引き止めるのはウォーターマークまでとし、止まった購読者はタイムアウト後に外し、末尾を捨てたストリームは続けない(続けると購読者との同期が崩れる)。
  - test: `tests/app/moqtrel_test.c` — `test_moqtrel_append_hold_at_watermark`
  - test: `tests/app/moqtrel_test.c` — `test_moqtrel_reclaim_follows_slowest`
  - test: `tests/app/moqtrel_test.c` — `test_moqtrel_stalled_after_timeout`
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_poison_survives_reset_and_close`
- [x] MOQT-185 購読者の優先度は、その購読者の中継ストリームの WebTransport ストリームの urgency に対応させなければならない。優先度を変える REQUEST_UPDATE は以降のストリームに適用し、その購読の開いたままのストリームと fill のストリームのクラスも付け直す。io の stream_sched フックがあれば、ハブは各 Object ストリームのクラス全体(urgency 4、Subscriber << 8 | Publisher Priority、group order と fill を live より先にする順で並べた購読ごとのフロー)を設定し、送信ポンプはそれに従ってスケジュールする。
  - test: `tests/app/moqtrun_drain_test.c` — `test_moqtrun_sched_relay_keys`
  - test: `tests/app/moqtrun_drain_test.c` — `test_moqtrun_sched_update_reclasses`
  - test: `tests/app/moqtrun_drain_test.c` — `test_moqtrun_sched_fill_shares_flow`
  - test: `tests/app/srvrun_test.c` — `test_srvrun_wt_sched_fill_before_live`
  - test: `tests/app/moqtrun_drain_test.c` — `test_moqtrun_prio_per_subscriber`
  - test: `tests/app/moqtrun_drain_test.c` — `test_moqtrun_prio_update_applies`
  - test: `tests/app/moqtrun_drain_test.c` — `test_moqtrun_prio_op_absent`
- [x] MOQT-186 (SS10.9) SUBSCRIBE に対する REQUEST_UPDATE は、その購読のリクエストストリームで、パラメーターを全部かゼロかで置き換えなければならない。含まれるものは置き換え、含まれないものはそのままにし、拒否した更新ではどれも変えない(その後、購読は終わる。MOQT-238)。
  - test: `tests/app/moqtrun_upd_test.c` — `test_moqtrun_upd_forward_toggles`
  - test: `tests/app/moqtrun_upd_test.c` — `test_moqtrun_upd_params_replace`
  - test: `tests/app/moqtrun_upd_test.c` —
    `test_moqtrun_upd_failed_changes_nothing`
  - test: `tests/app/moqtrun_upd_test.c` — `test_moqtrun_upd_survives_rejoin`
- [x] MOQT-238 (SS10.9.1) ハブがパブリッシャー側にいる購読への REQUEST_UPDATE が失敗したとき、ハブは REQUEST_ERROR を返し、購読を PUBLISH_DONE UPDATE_FAILED で終え、リクエストストリームを FIN しなければならない。
  - test: `tests/app/moqtrun_misc_test.c` —
    `test_moqtrun_misc_pub_update_failed_fins`
  - test: `tests/app/moqtrun_upd_test.c` —
    `test_moqtrun_upd_failed_changes_nothing`
- [x] MOQT-223 (SS7.2) ハブは制御ストリームを最初に、次にリクエストストリーム、その後に Object のデータをスケジュールするべきである。
  - test: `tests/app/moqtrun_drain_test.c` — `test_moqtrun_prio_control_first`
  - note: リクエストストリームはトランスポートの既定の urgency 3 のままで、制御ストリームの 2 と Object ストリームの 4..7 の間に入る。
- [x] MOQT-187 TRACK_STATUS には、Track の最大の位置(空なら位置なし)を載せた REQUEST_OK で応答し、Track が未知であるか認可関数が拒否した場合は REQUEST_ERROR で応答しなければならない。
  - test: `tests/app/moqtrun_upd_test.c` — `test_moqtrun_tstat_ok_largest`
  - test: `tests/app/moqtrun_upd_test.c` — `test_moqtrun_tstat_ok_empty`
  - test: `tests/app/moqtrun_upd_test.c` — `test_moqtrun_tstat_unknown_and_blob`
  - test: `tests/app/moqtrun_upd_test.c` — `test_moqtrun_tstat_authorized`
- [x] MOQT-188 (SS9.4, SS9.5, SS10.2.2) アプリケーションが認可関数を組み込んだ構成では、すべての SUBSCRIBE、TRACK_STATUS、PUBLISH、PUBLISH_NAMESPACE、SUBSCRIBE_NAMESPACE をそれに渡し、拒否は REQUEST_ERROR UNAUTHORIZED としなければならない。Alias を使う認可トークンでは、セッションを閉じなければならない(ハブはトークンのキャッシュを持たない。SS10.3.1.3)。REGISTER は AUTH_TOKEN_CACHE_OVERFLOW で、DELETE と USE_ALIAS は UNKNOWN_AUTH_TOKEN_ALIAS で閉じる。
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_subscribe_requires_authorization`
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_subscribe_alias_token_rejected`
  - test: `tests/app/moqtrun_ns_test.c` — `test_moqtrun_ns_authorization`
  - test: `tests/app/moqtrun_upd_test.c` — `test_moqtrun_tstat_authorized`
  - test: `tests/app/moqtrun_upd_test.c` —
    `test_moqtrun_publish_requires_authorization`
  - vuln: V-0786, V-0792, V-0793, V-0839

## ハブのリレー: 配信タイムアウト

- [x] MOQT-189 0 でない OBJECT_DELIVERY_TIMEOUT(SUBSCRIBE または REQUEST_UPDATE で指定)があるとき、期限内に配信できなかった Object は諦めなければならない。そのストリームは DELIVERY_TIMEOUT (0x2) でリセットし、データグラムなら捨てる。
  - test: `tests/app/moqtrun_upd_test.c` — `test_moqtrun_timeout_live`
  - test: `tests/app/moqtrun_upd_test.c` — `test_moqtrun_timeout_datagram`
  - test: `tests/app/moqtrun_upd_test.c` — `test_moqtrun_timeout_by_update`
  - test: `tests/app/moqtrun_upd_test.c` — `test_moqtrun_timeout_torn_object`
  - test: `tests/app/moqtrun_upd_test.c` — `test_moqtrun_timeout_zero`

## ハブのリレー: キャッシュと FETCH

- [x] MOQT-190 キャッシュのアリーナを取り付けている(`wired_moqt_cache_attach`)とき、ハブは Group 単位でだけキャッシュし、予算を超えたら最も古い Group を追い出し、単独で予算を超える Group は捨てなければならない。
  - test: `tests/app/moqcache_test.c` — `test_moqcache_evicts_oldest_group`
  - test: `tests/app/moqcache_test.c` — `test_moqcache_group_over_budget_dropped`
  - test: `tests/app/moqtrun_fetch_test.c` — `test_moqtrun_fetch_cache_attach`
  - test: `tests/app/moqtrun_fetch_test.c` —
    `test_moqtrun_fetch_cache_default_off`
- [x] MOQT-191 単独の FETCH にはキャッシュから返さなければならない。追い出された範囲や一度もキャッシュしていない範囲は、黙って飛ばさず、End of Unknown Range のマーカーとして報告しなければならない。
  - test: `tests/app/moqtrun_fetch_test.c` — `test_moqtrun_fetch_serves_cached`
  - test: `tests/app/moqtrun_fetch_test.c` —
    `test_moqtrun_fetch_evicted_group_unknown`
  - test: `tests/app/moqtrun_fetch_test.c` —
    `test_moqtrun_fetch_no_cache_unknown`
  - test: `tests/app/moqfetch_test.c` — `test_moqfetch_stream_end_of_range`
- [x] MOQT-240 (SS10.12, SS10.13) 実装は FETCH(Standalone、Relative Joining、Absolute Joining)と FETCH_OK をエンコード・デコードし、それ以外の Fetch Type ではセッションを閉じなければならない。ハブは、まだ何も配信されていない、Start が Largest Object より後ろ、または End が Start より後ろでない Standalone FETCH を INVALID_RANGE で拒否し、Largest より後ろの End は {Largest.Group, Largest.Object + 1} に切り詰めなければならない。
  - test: `tests/app/moqfetch_test.c` — `test_moqfetch_standalone_golden`
  - test: `tests/app/moqfetch_test.c` — `test_moqfetch_joining_golden`
  - test: `tests/app/moqfetch_test.c` — `test_moqfetch_bad_type_and_scope`
  - test: `tests/app/moqfetch_test.c` — `test_moqfetch_ok_golden`
  - test: `tests/app/moqfetch_test.c` —
    `test_moqfetch_req19_standalone_roundtrip`
  - test: `tests/app/moqtrun_fetch_test.c` —
    `test_moqtrun_fetch_nothing_published`
  - test: `tests/app/moqtrun_fetch_test.c` —
    `test_moqtrun_fetch_range_against_largest`
  - test: `tests/app/moqtrun_fetch_test.c` —
    `test_moqtrun_fetch_end_before_start`
- [x] MOQT-245 (SS11.4.4) 実装は FETCH_HEADER のストリームをエンコード・デコードしなければならない。対象は、Subgroup のエンコードとフィールドの有無を表すビットを持つ Serialization Flags、Datagram ビット、End of Non-Existent / Unknown Range、最初の Object の絶対 ID である。未知のフラグ値、前の Object がないのに前の Object を参照するもの、範囲外の Group / Object ID では PROTOCOL_VIOLATION としなければならない。
  - test: `tests/app/moqfetch_test.c` — `test_moqfetch_hdr`
  - test: `tests/app/moqfetch_test.c` — `test_moqfetch_stream_golden`
  - test: `tests/app/moqfetch_test.c` — `test_moqfetch_obj_flags_reject`
  - test: `tests/app/moqfetch_test.c` — `test_moqfetch_obj_after_eor_reject`
  - test: `tests/app/moqfetch_test.c` — `test_moqfetch_obj_subgroup_modes`
  - test: `tests/app/moqfetch_test.c` — `test_moqfetch_obj_group_order`
  - test: `tests/app/moqfetch_test.c` — `test_moqfetch_obj_overflow`
- [x] MOQT-192 joining FETCH(relative または absolute)は、参加先の購読を基準に解決し、FETCH と SUBSCRIBE の間に隙間が残らないようにしなければならない。範囲が不正な場合や参加先のリクエストが未知の場合は拒否しなければならない。
  - test: `tests/app/moqtrun_fetch_test.c` —
    `test_moqtrun_fetch_relative_join_no_gap`
  - test: `tests/app/moqtrun_fetch_test.c` — `test_moqtrun_fetch_absolute_join`
  - test: `tests/app/moqtrun_fetch_test.c` —
    `test_moqtrun_fetch_join_invalid_range`
  - test: `tests/app/moqtrun_fetch_test.c` —
    `test_moqtrun_fetch_join_unknown_request`
- [x] MOQT-193 (SS5.2) FETCH は、要求元が取り消したとき、データストリームが止められたとき、パブリッシャーか要求元が去ったとき、配信が止まったときに、スロットを解放しなければならない。
  - test: `tests/app/moqtrun_fetch_test.c` —
    `test_moqtrun_fetch_cancelled_by_request_reset`
  - test: `tests/app/moqtrun_fetch_test.c` —
    `test_moqtrun_fetch_data_stream_stopped`
  - test: `tests/app/moqtrun_fetch_test.c` —
    `test_moqtrun_fetch_publisher_leaves`
  - test: `tests/app/moqtrun_fetch_test.c` —
    `test_moqtrun_fetch_requester_leaves`
  - test: `tests/app/moqtrun_fetch_test.c` —
    `test_moqtrun_fetch_stall_gives_up`
- [x] MOQT-221 (SS5.2) ハブが上流の FETCH を取り消すとき、ハブはそのリクエストストリームをリセットし、STOP_SENDING を送らなければならない。
  - test: `tests/app/moqtrun_upfetch_test.c` — `test_moqtrun_upfetch_mandatory`
  - test: `tests/app/moqtrun_upfetch_test.c` — `test_moqtrun_upfetch_budget`
- [x] MOQT-242 (SS10.13) 上流の FETCH_OK の End Location が FETCH の Start Location より小さい場合、ハブはそのセッションを PROTOCOL_VIOLATION で閉じなければならない。
  - test: `tests/app/moqtrun_upfetch_test.c` — `test_moqtrun_upfetch_bad_end`

## ハブのリレー: 名前空間の探索

- [~] MOQT-194 PUBLISH_NAMESPACE はパブリッシャーごとに受け入れなければならない(複数のパブリッシャーが同じ名前空間を共有してよい)。SUBSCRIBE_NAMESPACE には、一致するすべての名前空間について NAMESPACE を送り、その後はパブリッシャーの出入りに合わせて NAMESPACE / NAMESPACE_DONE を送らなければならない。
  - test: `tests/app/moqtrun_ns_test.c` — `test_moqtrun_ns_publish_accepted`
  - test: `tests/app/moqtrun_ns_test.c` — `test_moqtrun_ns_initial_set`
  - test: `tests/app/moqtrun_ns_test.c` — `test_moqtrun_ns_live_join_and_cancel`
  - test: `tests/app/moqtrun_ns_test.c` — `test_moqtrun_ns_publisher_leaves`
  - test: `tests/app/moqtrun_ns_test.c` — `test_moqtrun_ns_multiple_publishers`
  - test: `tests/app/moqtrun_ns_test.c` — `test_moqtrun_ns_prefix_overlap`
  - evidence: `[~]` にしているのは、PREFIX_OVERLAP を厳しく解釈しているためである。1 つのセッション内では、どちらかのプレフィックスが空であるか、最初のフィールドが等しければ 2 つのプレフィックスは重なるとみなすので、ドラフトが求めるより多くを拒否する。

## ハブのリレー: GOAWAY と PUBLISH_DONE

- [~] MOQT-195 `wired_moqt_goaway` は、セッションごとに 1 回 GOAWAY を送信しなければならない。その後に届いたリクエストは GOING_AWAY で拒否する。タイムアウトが切れたら、ハブは PUBLISH_DONE を送り、処理中のものに応答し、GOAWAY_TIMEOUT で閉じる。
  - test: `tests/app/moqtrun_drain_test.c` —
    `test_moqtrun_goaway_once_per_session`
  - test: `tests/app/moqtrun_drain_test.c` — `test_moqtrun_goaway_late_rejected`
  - test: `tests/app/moqtrun_drain_test.c` —
    `test_moqtrun_goaway_timeout_flush_then_close`
  - test: `tests/app/moqtrun_drain_test.c` — `test_moqtrun_goaway_retried_on_tick`
  - evidence: io テーブルに対する単体テストだけで、GOAWAY とドレインの一連の流れを第三者の MOQT ピアと動かしたことはまだない。
- [x] MOQT-196 ピアからの 2 回目の GOAWAY、またはクライアントからの New Session URI 付きの GOAWAY では、セッションをプロトコル違反で閉じなければならない。
  - test: `tests/app/moqtrun_drain_test.c` — `test_moqtrun_peer_goaway_twice`
  - test: `tests/app/moqtrun_drain_test.c` — `test_moqtrun_peer_goaway_uri`
- [x] MOQT-197 ハブは PUBLISH_DONE の前に購読のデータストリームをリセットしなければならない。パブリッシャーのセッションが終わると、その購読者に PUBLISH_DONE TRACK_ENDED を送る。
  - test: `tests/app/moqtrun_drain_test.c` —
    `test_moqtrun_done_resets_streams_first`
  - test: `tests/app/moqtrun_drain_test.c` — `test_moqtrun_done_track_ended`
- [~] MOQT-198 ピアからの WebTransport の WT_DRAIN_SESSION(`wired_moqt_on_session_draining`)は、そのセッションだけについて MOQT の GOAWAY の流れを始めなければならない。
  - test: `tests/app/moqtrun_drain_test.c` — `test_moqtrun_drain_one_session`
  - evidence: 単体テストだけで、実際のピアとはまだ動かしていない。

## ハブのリレー: Object Datagram

- [x] MOQT-199 (SS11.3) Object Datagram は、その Alias が指す Track の購読者全員へバイト単位で同一のまま中継しなければならない。Alias が送信者のどの Track も指さないデータグラムは、捨てて数えなければならない。
  - test: `tests/app/moqdg_test.c` — `test_moqdg_roundtrip_golden`
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_dg_relays_identical_bytes_to_subscriber`
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_dg_relays_to_all_three_subscribers`
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_dg_unknown_alias_counts_bad`

## マルチドラフト対応の作業で完成したハブの機能(台帳 10 章)

- [x] MOQT-200 (SS10.19) ハブは SUBSCRIBE_TRACKS に、そのリクエストストリームでちょうど 1 つの REQUEST_OK で応答し、Track Namespace Prefix が同じセッションの確立済みの SUBSCRIBE_TRACKS と重なるものは PREFIX_OVERLAP で拒否しなければならない。
  - test: `tests/app/moqtrun_subtracks_test.c` — `test_subtracks_ok_once`
  - test: `tests/app/moqtrun_subtracks_test.c` — `test_subtracks_prefix_overlap`
  - test: `tests/app/moqns_test.c` — `test_moqns_subscribe_tracks_param_scope`
- [x] MOQT-201 (SS10.19) 確立済みの SUBSCRIBE_TRACKS のプレフィックスに一致し、購読者自身が PUBLISH したものではない Track それぞれについて、ハブは新しい双方向ストリームでその Track を指す PUBLISH を 1 つ開き、SUBSCRIBE_TRACKS の FORWARD の値を載せなければならない。SUBSCRIBE_TRACKS を取り消すと新しい PUBLISH は止まるが、確立済みのものは残る。応答の前に消えた Track は PUBLISH のストリームをリセットし、REQUEST_ERROR の応答はスロットを解放する。PUBLISH_OK(REQUEST_OK)の応答は、PUBLISH の Track Alias で購読者の購読を開き、PUBLISH のパラメーターから始める(FORWARD 0 なら Object を止めておく)。そのストリームでの購読者の REQUEST_UPDATE は SUBSCRIBE のものと同じく適用し、そのストリームで応答する(台帳 12-11、12-18)。SUBSCRIBE_TRACKS の Object の Range Filter がその購読の初期値になり(SS10.19.1 "copied over as the default Subscription parameters")、Range Filter が不正、重複、または MAX_FILTER_RANGES を超える SUBSCRIBE_TRACKS は INVALID_FILTER で拒否する(SS5.1.3、台帳 12-26)。更新が失敗したら PUBLISH_DONE UPDATE_FAILED で購読を終え、ハブは PUBLISH のストリームを FIN する(SS10.9.1、SS10.11、台帳 12-27)。2 つ目の REQUEST_OK または REQUEST_ERROR では、セッションを PROTOCOL_VIOLATION で閉じる(SS5.1、台帳 12-28)。
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
  - note: 台帳 10-2 (E-2)。ハブが始める PUBLISH の経路。TLA+ で検査した設計は `tasks/loopeng/moqt/MoqtHubPublish/`(git には含まない)にある。
- [x] MOQT-202 (SS10.20) ハブがそのような PUBLISH のための双方向ストリームを開けない場合、ハブは代わりに SUBSCRIBE_TRACKS のリクエストストリームで PUBLISH_SKIPPED(Track Namespace Suffix、Track Name)を送信し、同じ Track の同じ世代について後から PUBLISH を送信してはならない。
  - test: `tests/app/moqtrun_subtracks_test.c` —
    `test_subtracks_skip_then_no_publish`
  - test: `tests/app/moqns_test.c` — `test_moqns_pub_skipped_roundtrip`
  - test: `tests/app/moqns_test.c` — `test_moqns_pub_skipped_rejects`
- [x] MOQT-219 (SS5.1.3, SS6.3) SUBSCRIBE_TRACKS の TRACK_PROPERTY_FILTER は、Track Property の値が範囲内にある Track だけを購読者へ PUBLISH させなければならない。
  - test: `tests/app/moqtrun_misc_test.c` —
    `test_moqtrun_misc_subtracks_track_prop_filter`
- [ ] MOQT-230 (SS10.19) 認可関数を組み込んだ構成では、すべての SUBSCRIBE_TRACKS をそれに渡し、拒否は REQUEST_ERROR UNAUTHORIZED としなければならない。
  - gap: 認可のフックが扱うのは SUBSCRIBE、TRACK_STATUS、PUBLISH、PUBLISH_NAMESPACE、SUBSCRIBE_NAMESPACE だけである。
- [~] MOQT-241 (SS10.19.1) ハブが SUBSCRIBE_TRACKS のために送る PUBLISH は、その SUBSCRIBE_TRACKS の GROUP_ORDER を持たなければならない。
  - evidence: `test_moqtrun_misc_d22_publish_params` は PUBLISH のバイト列を draft-22 のセッションでしか固定していない。
- [x] MOQT-203 (SS10.9, SS10.9.2) FETCH、PUBLISH_NAMESPACE、SUBSCRIBE_NAMESPACE に対する、そのリクエストストリームでの REQUEST_UPDATE を処理しなければならない。受け入れた更新には確認応答を返し(SUBSCRIBE_NAMESPACE の新しいプレフィックスは、それ以降のアナウンスから有効になる)、拒否した名前空間の更新(たとえば PREFIX_OVERLAP)ではリクエストストリームを閉じ、古いプレフィックスをそのまま残す。受け入れた FETCH の更新が失敗することはない(Token Alias はデコード時にセッションを閉じる)ので、SS10.9.1 の FETCH データストリームのリセットは起こらない。
  - test: `tests/app/moqtrun_upd_test.c` — `test_moqtrun_upd_on_fetch_stream`
  - test: `tests/app/moqtrun_upd_test.c` —
    `test_moqtrun_upd_on_fetch_stream_refused`
  - test: `tests/app/moqtrun_upd_test.c` — `test_moqtrun_upd_ns_prefix_changes`
  - test: `tests/app/moqtrun_upd_test.c` —
    `test_moqtrun_upd_ns_prefix_overlap_refused`
- [x] MOQT-203a (SS10.9) 送信者自身の PUBLISH に対する REQUEST_UPDATE("The sender of a request (SUBSCRIBE, PUBLISH, FETCH, ...) can later send a REQUEST_UPDATE")には、Track を保ったまま REQUEST_OK で応答しなければならない。更新できるリクエスト以外での REQUEST_UPDATE(制御ストリーム上、または TRACK_STATUS のストリーム上)では、セッションを PROTOCOL_VIOLATION で閉じなければならない("other than in the two cases above MUST close the session")。
  - test: `tests/app/moqtrun_vgate_test.c` — `test_moqtrun_vgate_update_kinds`
  - test: `tests/app/moqtrun_misc_test.c` — `test_moqtrun_misc_stray_update`
  - note: 台帳 12-6。12-17 は `MOQVER_CAP_UPDATE_STRAY_CLOSE` で切り替える。
- [x] MOQT-204 (SS10.2.8, SS10.12) GROUP_ORDER が Descending の FETCH には、新しい Group から順に返さなければならない(Group 内の Object は昇順のまま)。本体のデコードに失敗した FETCH では、セッションを PROTOCOL_VIOLATION で閉じなければならない。
  - test: `tests/app/moqtrun_fetch_test.c` —
    `test_moqtrun_fetch_descending_group_order`
  - test: `tests/app/moqtrun_fetch_test.c` — `test_moqtrun_fetch_malformed_closes`
  - note: 台帳 10-6。
- [x] MOQT-205 (SS5.1.4) ライブの Track に途中から参加した購読者は、Location Filter の開始 Group から始めなければならない。ライブの先端より前の開始位置は現在の Group に切り上げ、未来の開始位置ならその Group まで配信を止めておく。
  - test: `tests/app/moqtrun_sub_test.c` —
    `test_moqtrun_sub_live_attach_filter_start`
  - note: 台帳 10-7。最初の Group 内の開始 Object は、Subgroup ストリーム上で Object 単位で切り取る(`test_moqtrun_sub_filter22_start_object_*`、`test_moqtrun_sub_filter22_ring_*`)。
- [x] MOQT-206 (SS10.3.1.6, SS10.3.1.7) ハブの SETUP は、MAX_FILTER_RANGES と MAX_REQUEST_UPDATES(どちらも 4。`WIRED_MOQTRUN_MAX_FILTER_RANGES` / `WIRED_MOQTRUN_MAX_REQ_UPDATES`)を告知し、ピアのものをデコードしなければならない。オプションがなければドラフトの既定値 0 のままとする。
  - test: `tests/app/moqtrun_test.c` — `test_moqtrun_setup_advertises_limits`
  - test: `tests/app/moqctl_test.c` — `test_moqctl_setup_limit_options_roundtrip`
  - test: `tests/app/moqctl_test.c` — `test_moqctl_setup_limit_options_default_zero`
  - note: 台帳 10-11。
- [x] MOQT-207 (SS10.3.1.7, SS10.9) 応答していない REQUEST_UPDATE をすでに MAX_REQUEST_UPDATES 個抱えているリクエストストリームで、さらに 1 つ届いたら、セッションを TOO_MANY_REQUEST_UPDATES で閉じなければならない。応答をまとめて送り出したら、まとめた更新すべての分のクレジットを戻す。
  - test: `tests/app/moqtrun_upd_test.c` — `test_moqtrun_upd_credit_too_many`
  - test: `tests/app/moqtrun_upd_test.c` —
    `test_moqtrun_upd_credit_restored_by_flush`
  - test: `tests/app/moqtrun_vgate_test.c` — `test_moqtrun_vgate_update_credit`
  - note: 台帳 10-10。`MOQVER_CAP_MAX_REQUEST_UPDATES` で切り替える(12-5)。
- [x] MOQT-208 (SS5.1.3, SS10.2.10-10.2.14) Range Filter のパラメーターは、差分を解決してデコードし、検証しなければならない。デコードできない値、1 つのメッセージ内での (Type, SetID) の重複、告知した MAX_FILTER_RANGES を超える Range の総数(SUBSCRIBE、FETCH、REQUEST_UPDATE)は INVALID_FILTER とする。REQUEST_UPDATE は、指定されたフィルターの型を丸ごと置き換え、長さ 0 の値はそれを取り除く。SetID 同士は OR で結び、OBJECTID_FILTER はデータグラムで転送する各 Object を通すかどうかを決める。
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
  - note: 台帳 10-9。配信を絞るのは OBJECTID_FILTER だけで、それも Object 単位(データグラム)の関門だけである。ほかのフィルターの型は検証して保存するが、すべて通す(「対象外」を参照)。
- [x] MOQT-236 (SS10.2.12, SS10.2.13, SS10.2.14) PRIORITY_FILTER の値が 255 を超える場合、または OBJECT_PROPERTY_FILTER / TRACK_PROPERTY_FILTER が奇数の Property Type を指す場合、ハブは REQUEST_ERROR INVALID_FILTER を返さなければならない。
  - test: `tests/app/moqtrun_sub_test.c` — `test_moqtrun_sub_rngf_value_checks`

## 未実装

draft-19 のリレーの範囲内ですが、まだ実装していないものです。これらを必要とするピアには NOT_SUPPORTED を返します(注記がある場合は別の振る舞いになります)。

次の規則は満たしていません。それぞれ上の未解決の `[ ]` 項目です。

- 制御ストリームをデータより先にスケジュールすること(MOQT-223)。
- SUBSCRIBE_TRACKS の認可(MOQT-230)。
- Subgroup の中継ストリームでの STOP_SENDING への対応(MOQT-247)。

## 対象外

このハブリレーのサブセットが実装しない機能と要件です。上のカバレッジの分母から除いています。

- (SS10.11) 旧来の制御ストリームで作られた購読に対する PUBLISH_DONE。設計上の判断です。PUBLISH_DONE は Request ID を持たないので、複数の購読が共有するストリームでは、どの購読が終わったのかを示せません。購読は残しておき、パブリッシャーが参加し直したときに付け直します。

- (SS1.5, SS1.5.1) 名前空間と Track の名前を人が読める文字列として表示・解析すること。運用者やログの関心事で、この SDK は名前を生のバイト列としてだけ比較します。
- (SS2.4.2) 受信側での Malformed Track の検出の一般的な一覧(Subgroup ID 内での Publisher Priority の不一致、Subgroup/Group/Track の最終値を超える Object ID、FIN したストリーム間での最終値の食い違い、Forwarding Preference の変更)。デコード時の違反(未知の Object Status、Object ID のオーバーフロー)のほかに検出するのは、END_OF_GROUP / END_OF_TRACK より後の Object と、上流の FETCH で出会った食い違う再送だけです(MOQT-209、MOQT-226)。
- (SS3.1, SS3.1.1-3.1.6) `moqt` URI スキーム、フラグメント識別子、MOQT URI の参照解決。サーバー専用のハブにとってはクライアント側の関心事です。ネイティブ QUIC のセッションそのもの(SS3.1.5: ALPN `moqt-19`、PATH/AUTHORITY の Setup Option、CONNECTION_CLOSE による終了)は実装済みです(`wired_moqt_on_session_raw`、`tests/app/moqtrun_raw_test.c`)。ただし、実際のピアのトレースで固定したテストができるまでは、プロセス内でしか確かめていません。
- (SS3.6, SS9.4.1, SS9.5.1) 上で扱った GOAWAY の仕組みを超えるセッションの移行と、リレーの穏やかな切り替え。このハブは単一で、切り替え先の上流リレーがありません。
- (SS5.1.3, SS5.1.4) 配信時に SUBGROUP_FILTER、PRIORITY_FILTER、OBJECT_PROPERTY_FILTER に従って絞り込むこと(TRACK_PROPERTY_FILTER は SUBSCRIBE_TRACKS の PUBLISH を絞り込む。MOQT-219)、およびストリームで転送する Object に OBJECTID_FILTER を適用すること。これらはデコード、検証、MAX_FILTER_RANGES への算入、更新まで行います(MOQT-208)が、Group 単位のストリームの関門には絞り込みに使うフィールドが届かないので、すべて通ります。データグラムで転送する Object には OBJECTID_FILTER を適用します。
- (SS7, SS7.1--7.3) 優先度。スケジューリングのアルゴリズムは WebTransport の送信ポンプで動きます(Subscriber Priority、次に Publisher Priority、1 つの購読の中では group order と fill を live より先にする順。MOQT-185)。残っているのは次の点です。キューに入った 1 回きりのストリームは REQUEST_UPDATE の後もクラスを保つ、データグラムはストリームのクラスを経由しない、FETCH 自身の SUBSCRIBER_PRIORITY は保持しない(128 として扱う)、購読をまたいで同じクラスのものはポンプの各回をラウンドロビンで分け合う。
- (SS9.3) 1 つの Track の複数のパブリッシャー。draft-18/22 で `wired_moqt_hub.multi_publisher` のもとで実装済みです(MQ18-223、MQ22-229、コードは共通)。既定では無効で、その場合は各 Track のパブリッシャーは 1 つのままです。
- (SS10.2.15) EXPIRES。レジストリでデコードしますが、それに従って動作はしません。NEW_GROUP_REQUEST (SS10.2.18) は draft-18 と同じく上流へ中継します(MQ18-229、コードは共通)。(FILL_TIMEOUT と RENDEZVOUS_TIMEOUT には従って動作します。MOQT-231、MOQT-232。)
- (SS6.3.1) フィルターを集約して上流へ伝えること。ハブは Track ごとにパラメーターなしの上流の SUBSCRIBE を 1 つ送ります(MOQT-224)。
- (SS8, SS11.4.3) 再送前の配信タイムアウトの確認と RESET_STREAM_AT。再送とリセットは MOQT 層より下で起き、MOQT 層は RESET_STREAM でしかリセットしません。
- (SS10.2.2) トークンの有効性(MALFORMED_AUTH_TOKEN、有効期限)。アプリケーションの認可関数に任せており、認可関数は UNAUTHORIZED で拒否することしかできません。
- (SS10.3.1.3, SS10.3.1.4) MAX_AUTH_TOKEN_CACHE_SIZE と、Setup Option としての AUTHORIZATION TOKEN。告知しません。ハブはトークンのキャッシュを持たないので、Alias を使うトークンではセッションを閉じます(MOQT-188)。(MAX_FILTER_RANGES と MAX_REQUEST_UPDATES は告知します。MOQT-206。)
- (SS11.5, SS11.5.2) パディングのストリームとデータグラム。送信しません。
- (SS12, SS12.1--12.9) Track/Object の Property としての MOQT の Property(MAX_CACHE_DURATION、DEFAULT_PUBLISHER_GROUP_ORDER、DYNAMIC_GROUPS、Immutable Properties、Prior Group/Object ID Gap)。Properties のワイヤー上の枠は汎用的にデコードし、そのまま中継します。ハブが読むのは DEFAULT_PUBLISHER_PRIORITY(Publisher Priority を省いたヘッダーのストリームの urgency)、SUBGROUP_DELIVERY_TIMEOUT、MAX_CACHE_DURATION で、Immutable Properties の中にあるものも読みます。範囲外の DEFAULT_PUBLISHER_GROUP_ORDER / DYNAMIC_GROUPS ではセッションを閉じ、Mandatory Track Property は拒否します(MOQT-212〜MOQT-214)。group order と dynamic groups のスケジューリング上の意味は適用しません。
- (SS13) セキュリティに関する考慮事項(購読による増幅、通信のセキュリティ、認可、メディアのセキュリティ、リソースの枯渇、タイムアウト、リレーのセキュリティ、実装のフィンガープリンティング)。運用・配備の指針で、この台帳がテストするワイヤー上の振る舞いではありません。
- (SS15) IANA に関する考慮事項。レジストリの管理で、実装の振る舞いではありません。
- バージョンごとの範囲(台帳 4-4)。このハブはセッションごとに draft-18、-19、-22、-23 をネゴシエーションします(`moqver.c`)。この台帳が扱うのは draft-19 です。Range Filter、MAX_FILTER_RANGES、MAX_REQUEST_UPDATES(MOQT-206〜MOQT-208)は draft-18 にはないので、draft-18 のセッションでは Range Filter のパラメーターをプロトコル違反として拒否し、2 つの Setup Option はピアに無視されます。draft-22 のセッションでは draft-19 と同じく振る舞います。SUBSCRIBE_TRACKS は、draft-19 と draft-22 のセッションではすべての購読パラメーターを受け入れますが、draft-18 のセッションでは AUTHORIZATION TOKEN と FORWARD だけを受け入れます(`moqctl.c` の `MOQCTL_PARAM_RULES`)。それぞれのドラフト独自の一覧は [draft-18](draft-moq-transport-18.md) と [draft-22](draft-moq-transport-22.md) を見てください。
- 実際のリレーの振る舞いとしての REDIRECT(要求元を別の URI や宛先へ移すために送ること、または上流からの REDIRECT に対応すること)。このハブは単一で、リダイレクトする先や元になる上流リレーや兄弟インスタンスがありません。理由は上のセッションの移行の項目と同じです。Redirect 構造のワイヤー形式は確認しています(MOQT-084〜MOQT-088)。
