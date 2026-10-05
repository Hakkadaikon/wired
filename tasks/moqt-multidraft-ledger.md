# MoQT マルチドラフト対応 台帳(draft-18 / 19 / 22)

発行: 2026-10-03。進捗の正はこの台帳。調査レポートは参照専用(数値を転記しない)。

目的: wired の MoQT(現状 draft-19 専用)を、セッションごとに draft-18 / 19 / 22(2026-10 時点の最新)を交渉して話せる作りへ改める。版の差分は可能な限り表(データ)で吸収し、版で構造が違う所だけ別ロジックにする。

凡例: `[ ]` 未着手 / `[~]` 部分完了(残りを同じ行に書く) / `[x]` 完了(成果物と検証の証跡あり)

## 0. 調査(済)

- [x] 0-1 仕様取得: moq-transport draft-18 / 20 / 21 / 22 の txt と kramdown を取得。
  - 証跡: `tasks/specs/draft-ietf-moq-transport-{18,22}.txt`、`tasks/loopeng/moqt/draft-ietf-moq-transport-{18,20,21,22}.md`
- [x] 0-2 webtrans-http3 draft-16 を取得(MoQT draft-19 以降はこれを参照する)。
  - 証跡: `tasks/specs/draft-ietf-webtrans-http3-16.txt`
- [x] 0-3 draft-18 と 19 の全差分カタログ。
  - 証跡: `tasks/loopeng/moqt/draft18-vs-19-diff.md`(版で切り替えて吸収できるものと別ロジックが要るものの分類は §15)
- [x] 0-4 draft-19 と 22 の全差分カタログ(20 / 21 での導入版つき)。
  - 証跡: `tasks/loopeng/moqt/draft19-vs-22-diff.md`(分類は §14、draft-22 の曖昧点 Q-01〜11 は §15)
- [x] 0-5 wired の draft-19 依存箇所の棚卸し(file:line、継ぎ目、リスク)。
  - 証跡: `tasks/moqt-multidraft-codesurvey.md`
- [x] 0-6 先行実装の調査(moq-dev、stitcher-moq、moxygen、imquic)。
  - 証跡: `tasks/moqt-multidraft-priorart.md`
- [x] 0-7 webtrans-http3 draft-15 と 16 の差分(全 29 項目)と、wired への影響。
  - 証跡: `tasks/webtrans-15-vs-16-diff.md`(ワイヤ値は不変。受信検証とエラー時の挙動が変わり、不適合 4 件を 6 章へ反映済み)

### 調査で確定した前提

- 版を見分ける手段は WT subprotocol / ALPN の `moqt-NN` だけ。SETUP(0x2F00)は 18 / 19 / 22 でバイト単位まで同一なので、SETUP からは版を判定できない。
- データプレーンについて:
  - 18 と 19 はバイト単位で同一。
  - 19 と 22 は、SUBGROUP_HEADER と OBJECT_DATAGRAM の有効な型の集合が同一。差は fetch 側の 0x20C(End of Timed-Out Range)だけ。
  - したがって中継(SUBGROUP / datagram の素通し)は版をまたいでも成り立つ見込み。これは 5-1 で検証する。
- 制御ストリームを単方向(uni)の組にする変更は draft-17 で入った。18 / 19 / 22 はすべて uni の組。
  - wired は今も双方向(bidi)のストリーム 1 本で、相手の SETUP を読んでいない。draft-18 / 22 への対応以前に、ここが共通の前提作業になる(1 章)。
- Range Filter、MAX_FILTER_RANGES、MAX_REQUEST_UPDATES、SUBSCRIBE_TRACKS は draft-19 でもスコープ外か NOT_SUPPORTED。そのため 18 と 19 の振る舞い差の多くは実装しなくてよい(4 章で「拒否のまま」と明記する)。
- 先行実装はどれも、メッセージ単位の版間翻訳をしていない。版に依存しない内部モデルを持ち、送信先セッションの版でエンコードし直している。片方の版にしかない機能は拒否している。

## 1. 前提修正: draft-19 制御ストリームへの準拠(MOQT-029)

ここが終わらないと、どの版とも厳密な相互接続ができない。

- [x] 1-1 設計: 制御ストリームの組(サーバが開く uni と、相手が開く uni)のライフサイクルを TLA+ で固める。
  - 2026-10-04: `tasks/loopeng/moqt/control-pair-design.md`(MoqtSessionMV 拡張、安全性16+VersionFixed・活性2 が ReqMax 1/2 で No error、witness 24、mutation 29/29 killed、ログ `MoqtSessionMV/logs/`)。規則: hub の制御ストリームは1本、トークン有→uni 0x2F00、空→従来の hub 開設 bidi。SETUP は1回。受信は peer uni / peer bidi / hub bidi のどれでも最初の SETUP を受理。loop-engineering-reviewer 合格(2026-10-04、軽微1件=トレーサビリティ表の witness 名誤記を修正済み。`logs/uni-always-live.out:36` で uni 一本化案の活性違反を確認)。設計は確定、実装は 1-2〜1-4(フェーズ C)。
  - 既存の `tasks/loopeng/moqt/MoqtSession.tla` はすでに uni の組をモデル化しているので、実装との乖離を確認する差分検査から始める。
- [x] 1-2 hub が SETUP を uni(type 0x2F00)で送る(`moqtrun.c:164-202`)。**完了(2026-10-04、Phase C)。** interop example の回避コードも削除済み(`refactor(moqt_interop): drop the uni-in-bidi-slot control workaround`)。
  - あわせて interop example の回避コード(`examples/moqt_interop/wired_server.c` の ponytail コメント)を外す。
  - 着手点調査済み: `moqtrun_send_setup`(`moqtrun.c:164-171`)の `io->open_bidi_stream(...)` を `io->open_uni_stream(...)` に変えるだけで済む(`wired_moqt_io` には既に uni を開くエントリがある、`moqtrun.h:67`)。`wired_moqt_on_stream_data` の `control_stream_id` 一致判定(`moqtrun.c:4304`)は id しか見ていないので変更不要。この変更が終われば `examples/moqt_interop/wired_server.c:54-68` の回避コード(`open_bidi_stream` スロットに uni 実装を差し込むトリック)は不要になり外せる。
- [x] 1-3 相手が開いた uni の 0x2F00 を制御ストリームとして受理し、SETUP を `moqsess`(RECV_SETUP)へ流す。**完了(2026-10-04、Phase C)。** 受け入れテスト5(uni受理)・6(SETUP先頭bidi受理)・7(legacy bidi書き戻し受理)・8(2本目でPROTOCOL_VIOLATION)で検証済み、両レビュー合格。
  - **実機バグ修正(2026-10-05)**: Phase C の実装・テストは「uni の Stream Type varint(0x2F00)と SETUP Message 自身の Type フィールド(0x2F00)は別の2バイト列」という誤解で統一されており、送信側(`moqtrun_ctl_open`)が重複して2回書き、受信側(`moqtrun_fresh_uni_ctl`)も2回目を期待していたため自己整合的に `just test` は green だったが、実際の仕様(FETCH_HEADER 11.4.4 と同じ「1つの varint が stream-type 判定とメッセージ Type を兼ねる」)と食い違い、他実装(moq-dev-rs 等、1回しか書かない)との相互運用が初手の SETUP で failしていた(`moq-interop-runner` 実機対向、`announce-only` 等が無言タイムアウト)。self-loopback では両端が同じ誤りを共有するため検出できない典型例(`rfc-and-verification-layers.md` の教訓どおり)。修正: 送信側は `moqtrun_envelope_put` の1回書き込みのみに、受信側は `moqdata_classify` が消費したオフセットを捨てて生データを渡すように変更(`src/app/moqt/run/moqtrun.c`)。テストヘルパー `mtctl_uni_ctl`(`tests/app/moqtrun_test.c`)も同じ誤解を体現していたため同時に修正。`just test` 全green、`moq-interop-runner` 実機対向で確認(moq-dev-rs 6/6, stitcher-moq(d22) 6/6 pass; draft-18 client は setup/announce 系7件pass、残り11件は別の未実装機能(10-2/10-8等)によるタイムアウトで本バグとは無関係)。
  - 現状は `moqtrun.c:4045` で捨てているので、ここを直す。
  - 着手点調査済み: 挿入点は `moqtrun_resolve_fresh_stream_track`(`moqtrun.c:4038-4048`)。現状 `kind != MOQDATA_STREAM_SUBGROUP` の場合は即 `return 0`(捨てる)なので、`kind == MOQDATA_STREAM_CONTROL` の分岐を新設する。`moqsess` の `MOQSESS_EV_RECV_SETUP` イベント自体はハンドラ(`moqsess.c:34-36`)・テスト(`moqsess_test.c` に16箇所)とも完成済みで「呼ぶだけ」で良いが、呼ぶまでの経路(分類→受理→フレーミング→デコード→対象 peer の特定)が全て新規。相手の incoming 制御ストリーム id を覚える新規フィールドが `wired_moqtrun_peer` に要る(既存の `control_stream_id` は hub 自身の送信方向)。2回目の CONTROL 分類ストリームは `MOQSESS_EV_SECOND_CTRL`(ハンドラは PROTOCOL_VIOLATION で既に完成)に流す。
- [x] 1-4 相手の Setup Options(AUTHORITY、PATH、MAX_REQUEST_ID ほか)を読み、保持する。**完了(2026-10-04、Phase C)。** 受け入れテスト9(PATH/AUTHORITY拒否)・10(未知option無視)で検証済み。MAX_REQUEST_IDは削除済み仕様のため実装なし(訂正どおり)。
  - **訂正(2026-10-04、仕様本文で確認)**: MAX_REQUEST_ID は draft-17 で削除済み(#1471)で 18/19/22 に存在しない。PATH/AUTHORITY は WebTransport 上で受けたら INVALID_PATH(0x8)/INVALID_AUTHORITY(0x19)でセッションを閉じる(draft-19 Setup Options の MUST、18/22 も同じ)。保持するのは MOQT_IMPLEMENTATION 等、未知 Option は無視。MAX_FILTER_RANGES/MAX_REQUEST_UPDATES は 10-11。
  - 着手点調査済み: `moqctl_setup` 構造体(`moqctl.h:305-312`)に PATH/AUTHORITY は既にフィールドがある(`has_path`/`path`/`has_authority`/`authority`)。MAX_REQUEST_ID はまだフィールドが無く新設が要る。`wired_moqtrun_peer` には相手の SETUP 値を保存する場所が無い(現在のフィールドは全て hub 自身の状態)。新規フィールド(例 `moqctl_setup peer_setup`、コピーで保持。view は呼び出しの外に出ると dangle する)を追加し、1-3 の新分岐から `moqctl_setup_take` を呼んだ結果をそこに格納する。
- [x] 1-5 SETUP を送ってこない既存クライアント(moqt_chat の frontend)の扱いを決めて実装する。案は次の 2 つ。
  - (a) frontend を uni の組へ移行する(1-6)
  - (b) 版が空のセッションに限り、旧来の bidi を互換として残す
  - **裁定(2026-10-05): (b)を採用、実装済み(9-3/1-2〜1-4で完了)。(a)は今回のマルチドラフト対応計画のスコープ外として先送りする。** 理由: 1-6の調査(2026-10-03)で確定した制約により、ブラウザの`WebTransport`コンストラクタはJSからWTサブプロトコル(`moqt-18`/`-19`/`-22`)を選択する手段を持たない。つまりfrontendをuniの組へ移行しても、版選択という本来の目的(マルチドラフト対応)には寄与しない——frontendは移行後もサブプロトコル無し(空トークン)のまま接続し、hub側の保守的デフォルト(`moqtrun_negotiated_ver`、空トークン→draft-19)で応答され続ける。1-6の実利は「将来bidi互換経路を削除できる」ことだが、9-3で bidi 互換経路は明示的に維持すると決定済みなので、1-6を実施する技術的必要性が無い。frontend(TypeScript)・Go guideクライアントの移行作業(62+62+39件のテスト影響、9個のe2eシナリオ)は、得られる価値に対してコストが不釣り合いに大きいと判断し、本計画では着手しない。
- [x] 1-6 moqt_chat の frontend(`moqtClient.ts:617-640`)と Go の guide クライアント(`guide/moqtclient/moqtclient.go`)を、uni の組と WT `protocols` 指定へ移行する。**裁定(2026-10-05): 1-5の裁定どおりスコープ外として着手しない。**
  - **重要な制約(調査済み、2026-10-03)**: ブラウザの `WebTransport` コンストラクタには `protocols` 相当のオプションが無い(`WebTransportOptions` は `allowPooling`/`congestionControl`/`requireUnreliable`/`serverCertificateHashes` のみ、`protocol` getter も無し)。WT-Available-Protocols/WT-Protocol のサブプロトコル交渉は HTTP ヘッダレベルの仕組みで、ブラウザは JS に公開していない。**frontend(ブラウザ側)は WT サブプロトコルで版を交渉できない** — 決定 9-3(bidi 互換経路を残す)が実質的に frontend の唯一の恒久手段になる。
  - Go 側(`webtransport-go`)は `Dialer.ApplicationProtocols []string` を持ち、`guide/snippets/wt-session/client.go:18-20` で実証済み。Go の moqt guide クライアントはこちらを使って版交渉できる。
  - frontend 側の着手点: `moqtClient.ts:461-464`(WebTransport constru築、`protocols` は使えないので変更なし)、`#openControlStream`(:619-640、`incomingBidirectionalStreams` → `incomingUnidirectionalStreams` + `classifyStreamType`(moqtWire.ts:748)で `0x2F00` を判定)。SETUP の送受信は frontend に現状無く新規実装。
  - テスト: `fakeWebTransport.ts` に uni の SETUP 用フェイクを追加(既存の bidi フェイクは 9-3 により削除しない、両経路とも維持)。`moqtClient.test.ts`(62件)と `useMoqtChat.test.ts`(62件)は `connect()` を呼ぶ全件が影響。`moqtChatStore.test.ts`(39件)は無関係。
  - e2e: `s21-sigterm-goaway.mjs` が最も密結合(GOAWAY が制御ストリーム経由)。次に `s5/s5b/s4/s8/s9/s12/s14/s16/s18` の再接続・join系。
  - 見積もり: medium。bidi 経路を残す二重化が主な複雑さ。
- [x] 1-7 `docs/features/draft-moq-transport.md` の MOQT-029 を `[x]` にし、「Not implemented」節から外す。**完了(2026-10-04、Phase C commit `59c09516`)。** `docs/features/draft-moq-transport.md:184` で確認済み。

## 2. 版の基盤(交渉と版テーブル)

**完了(2026-10-03)。** `moqver.c` を実装し、`moqtrun.c`/`.h` に結線した(commit `7b531a36`、`78e4560f`)。`just test` の失敗は 12 件→2 件(残り2件は無関係の既存事項、6-1 の WT-draft-16 未着手分)。

- [x] 2-1 版テーブルを情報源の 1 か所にまとめる。
  - `src/app/moqt/ver/moqver.c` の `moqver_table[MOQVER_COUNT]`(`static const`、`{ver, tok, caps}`)。`moqver_find`/`moqver_caps`/`wired_moqt_wt_protocols` の3関数全てがこの1つの表だけを読む(moxygen の ALPN 一覧ズレ事故と同種の二重管理を避けた)。
- [x] 2-2 `wired_moqt_on_session` の `protocol` 引数から版を決め、`wired_moqtrun_peer` に保存する。
  - `wired_moqtrun_peer.ver`(新規フィールド)。空トークンと未知トークンはどちらも `MOQVER_D19` にフォールバック(`moqtrun_negotiated_ver`)。`moqtrun_init_peer` の唯一の構築箇所を更新済み。新規テスト `test_moqtrun_on_session_stores_negotiated_ver`(d18/d22/空/bogus の4パターン)で検証。
- [x] 2-3 srvrun の交渉(`srvrun_wt_select`)はそのまま流用で確認済み、変更不要。
- [x] 2-4 caps ビットを定義し、分岐は `peer->caps & CAP_X` の1判定に限る。
  - `moqver.h` の14ビット全てを `moqver_table` に反映済み(`moqver_caps` は範囲外で0を返す)。CCN<=3 は `moqver_find_row`/`moqver_valid`/`moqver_offer_len`/`moqver_offer_write` への分割で確保。実際にこの caps を読んで分岐するのは3〜4章の今後の実装。
- [x] 2-5 版を混在させない設定で既存の振る舞いが変わらないことを確認。
  - `just test` を独立に3点セット(test/ninja/lizard)+ fmt で確認。新規failureゼロ、既存テストの振る舞いは不変。

## 3. codec の版化(表で吸収できる差分)

- [x] 3-1 run 層が `MOQCTL_T_*` / `MOQCTL_PARAM_*` / `MOQCTL_ERR_*` のマクロ(約 70 箇所)と生の 16 進値を直接参照している所を、版ごとの表を引く形に置き換える。**実装済み確認(2026-10-05)。** 記載の着手点(`moqtrun.c:2337-2341`、`moqctl.c:1073-1084`、`0x70`系)は台帳作成後の別作業(D-2 fill fetch等)で既に表引き化済み。`moqtrun.c:2686`相当・`moqdata.c:315`相当にも生の16進値は残っていない(grep確認)。
  - 生の 16 進値は `moqtrun.c:2337-2341`、`moqctl.c:1073-1084`、`0x70` が `moqdata.c:315` と `moqtrun.c:2686`。
- [x] 3-2 メッセージ型の表を版ごとに持つ。**実装済み確認(2026-10-05)。** `moqctl.h:39-43`(`MOQCTL_T_PUBLISH_OK18`=0x1E、`MOQCTL_T_PUBLISH_STATE_NOTIFY`=0x22)、`moqctl.c:1709-1714`(版ごとの型解決テーブル)。
  - 18: 0x1E の扱い。spec の表の誤記で、本文は REQUEST_OK の別名としている。
  - 22: PUBLISH_STATE_NOTIFY 0x22 を既知の型に加える。
- [x] 3-3 パラメータの登録表に、版ごとの「載せてよいメッセージ」マスクを持たせる。**実装済み確認(2026-10-05)。** `moqctl.c:865-887`の`MOQCTL_PARAM_RULES`テーブル({d22,d19,d18}の3列マスク)で、`FILL_PARAMETERS`(d22のみ非ゼロ)、`SUBGROUP_FILTER`等のRange Filter系(d18のみ0)、`INCLUDE_PROPERTIES`(d22のみ非ゼロ)、`EXPIRES`/`GROUP_ORDER`の版別マスクが全て反映済み。
  - 18: 0x25〜0x29 は未知。EXPIRES と GROUP_ORDER のマスクが違う。
  - 22: FILL_PARAMETERS 0x23 と INCLUDE_PROPERTIES 0x35 を追加。PUBLISH / PUBLISH_OK / FETCH / SUBSCRIBE_TRACKS / REQUEST_UPDATE の許可リストが変わる。
- [x] 3-4 エラーコード表を版ごとに持つ。**実装済み確認(2026-10-05)。** `moqctl.c:63-82`の`MOQCTL_ERR_ROWS`/`MOQCTL_DONE_ROWS`(cap付き版別読み替え、DUPLICATE_SUBSCRIPTION/CONFLICTING_FILTERS/INVALID_FILTER/SUBSCRIPTION_ENDED)。
  - 18: REQUEST_ERROR 0x19 があり、0x35 / 0x36 と session 0x1B が無い。
  - 22: 0x15、0x32、PUBLISH_DONE 0x3 が無い。
  - 受信側は未知のコードを許容するので、送信側の表として持つ。
- [x] 3-5 GOAWAY: draft-18 に限り、制御ストリーム上の GOAWAY の末尾に `[Request ID]` を載せる。encode と decode の両方。**実装済み確認(commit `21e67d1f`)。** encode/decode とも `moqctl_goaway18_encode`/`_take`(moqctl.c:1474-1486)で完成、`moqtrun_goaway_encoder`/`moqtrun_goaway_decoder`(moqtrun.c:2944, 5849)が `MOQVER_CAP_GOAWAY_REQID` で版分岐。テスト: codec round-trip `test_moqctl_goaway18_request_id`(moqctl_test.c:516)、hub→peer 送信側 `test_moqtrun_goaway_request_id_d18`、peer→hub 受信側(Request ID 有無・PROTOCOL_VIOLATION)`test_moqtrun_peer_goaway_d18`(moqtrun_drain_test.c)。追加作業なし。
- [x] 3-6 LOCATION_FILTER のデコーダを 2 系統にし、1 つの内部範囲モデルへ写像する。**実装完了(commit `fc97a2e5`)。**
  - 19 は length 前置で type 1〜4。22 は length 無しで明示 type 0x00〜0x05。
  - 同じ数値が版によって別の意味を持つので、最大の地雷になる。
  - 設計提案済み(2026-10-03、既存 `tasks/fv/moqt/Moqt/Filter.lean` の `SK`/`EK`/`Rng` と1対1対応するよう設計):
    - `moqctl_rsk`(start kind: REL_GROUP/NEXT_OBJ/ABS)と `moqctl_rek`(end kind: UNBOUNDED/GROUP/OBJ)の2つの小さい enum に分ける(9通りの組み合わせ中5通りしか正当でないため、1つの enum だとテーブルが疎になる)。
    - `moqctl_rangeloc { moqctl_rsk sk; u64 start_group, start_object; moqctl_rek ek; u64 end_group, end_object; }`。end_group は絶対値で保持(delta は decoder 内で解決、Lean モデルと同じ選択)。既存の `moqctl_loc`/`moqctl_locfilter`(draft-19 専用の wire 構造体、そのまま残す)とは別の第三の型。
    - decode/encode: `moqctl_rangeloc19_take/_put`(absence はパラメータ非出現で表現)、`moqctl_rangeloc22_take/_put`(`int* has_filter` で type 0x00 の「フィルタなし」を表現。Lean の `dec19: P Rng` vs `dec22: P (Option Rng)` という非対称性をそのまま反映)。
    - `MOQCTL_RSK_REL_GROUP(n>0)` と `ABS+OBJ終端` は draft-22 専用(draft-19 では表現不可)。Lean の `only22_iff` 定理と一致。
    - Q-04a/Q-04b の拒否判定は `moqctl_rangeloc_q04a_violation`/`_q04b_violation` という名前付き述語にする(CCN対策、将来 Lean 側が同じ名前を証明の対象にできる)。**疑義は解消済み(2026-10-04、draft-22 §9.20.9 本文で確認)**: type 0x03(Absolute Start, Group End)は `EndObject` を持たず(終端は `StartGroup+EndGroupDelta` の group 全体の最後の Object)、type 0x04(Absolute Range)だけが明示的な `EndObject` を持つ。line 256 の Q-04a が「type 0x04」と記載しているのは正しい。`moqctl_rangeloc` では `MOQCTL_REK_GROUP`(0x03、EndObject なし)と `MOQCTL_REK_OBJ`(0x04、EndObject あり)を分けているので、Q-04a の判定は `ek == MOQCTL_REK_OBJ && end_object < start_object`(EndGroupDelta=0 すなわち `end_group == start_group` の場合に限る)になる。
    - 証跡: subagent 報告(このコミットの直前のやり取り)に完全な C 構造体案・grep による名前衝突確認済み。7-2(Lean 側の拡張)はこの構造体をそのまま証明対象にできる設計。
  - Lean で round-trip と写像の一致を証明する対象(7-2)。
- [x] 3-7 FETCH 本体のデコーダを 2 系統にする。**実装完了(commit `53a66346`, `a8e0eef2`)。**
  - 19 は Fetch Type と Standalone / Joining の構造。22 は NS、Name、Params で、範囲は LOCATION_FILTER に入る。
  - 内部の FETCH モデルは上位集合にする。
  - `moqfetch_req`(`moqctl_rangeloc` を内蔵、`is_joining`はd19専用)+ `moqfetch_req19_take/_encode`/`moqfetch_req22_take/_encode`。既存の `moqfetch_fetch`(d19専用)は無変更。
  - 副産物: d22 の LOCATION_FILTER パラメータ(0x21)はd19と違い length 前置が無く、かつ FETCH コンテキストで出現を許可する必要があったため、`moqctl_params_take22`(版分岐した汎用パラメータデコーダ)を新設した。既存の `moqctl_params_take`(d19)は無変更。
  - 設計判断: d22 の FETCH で LOCATION_FILTER が省略された場合は「全範囲を要求」として扱う(拒否ではない、仕様の「省略時はフィルタなし」規定どおり)。encode 時、decode後の「元々absentだった」情報はモデルに残らないため、常に明示的なfilterパラメータとして再構築する(バイト同一ではなく意味的に同値、コメント・テストに明記済み)。
  - 残課題: 3-8(FETCH_OK の End Location 正規化、19 exclusive+1 vs 22 inclusive)は未着手。FETCH *request* 側の End Location 正規化は本タスクで実装済みだが、FETCH_OK 側は別。
- [x] 3-8 FETCH_OK の End Location の正規化。19 は exclusive の +1 で、Object 0 は group 全体。22 は inclusive。**実装済み確認。** `moqfetch_end19_incl`/`moqfetch_end19_wire`(moqfetch.c:370-376)+ `moqfetch_ok19_encode`(moqfetch.c:385-389)が変換。本番消費側は `moqtrun_end_excl`(moqtrun.c:1444-1454、wraparound の object==0 を次groupへ正しく進める)。テスト: golden round-trip `test_moqfetch_ok19_end_inclusive`、whole-group 両方向+トップ値(`MOQFETCH_OBJ_GROUP_END` = 2^64-1)のラップアラウンド境界を `test_moqfetch_end19_whole_group`(moqfetch_test.c:173-199)が確認済み(Lean `end19_top` が証明する性質と同じ境界)。追加作業なし。
- [x] 3-9 PUBLISH_DONE の Stream Count の「不明」番兵値: 19 は 2^62-1、22 は 2^64-1(9 バイトの vi64 が要る)。**N/A 判定(番兵は撤去済み)。** `MOQTRUN_DONE_STREAMS_UNKNOWN` は repo 全体で grep 0件、該当なし。D-2 のフェーズで `wired_moqtrun_sub.stream_count` が実カウントへ置き換わった(commit `1caee4d1` feat(moqtrun): real PUBLISH_DONE Stream Count per subscription、`5b8be56e` でfillストリームも加算)。`moqtrun_done_emit`/`moqtrun_sub_done` の全呼び出し元(`moqtrun_update_sub`/`moqtrun_sub_done_slot`/`moqtrun_fill_opened`、moqtrun.c)を調査、全経路が実カウントを送る。唯一「カウント不明になりうる」経路(サブスクライバ自身のセッションが突然切れる `wired_moqt_on_session_close` → `moqtrun_drop_peer_subs`)は、相手が既に居ないため PUBLISH_DONE 自体を送らない(送り先が無いので番兵も不要)。追加作業なし。
- [x] 3-10 fetch のシリアライズ marker 0x20C を、22 でだけ受理する(19 では PROTOCOL_VIOLATION)。**実装済み + テスト1件追加(commit `32172307`)。** `MOQFETCH_EOR_TIMED_OUT`(0x20C、moqfetch.h:161)、ゲートは `moqfetch_is_eor`(moqfetch.c:599-602、`moqfetch_seq.eor_timed_out` を参照)。実体の版ゲートは `moqtrun_fetch_accept`(moqtrun.c:1882-1883、`MOQVER_CAP_EOR_TIMED_OUT`)。既存コーデックテスト `test_moqfetch_eor_timed_out`(moqfetch_test.c:311、`eor_timed_out=0`でVIOLATION/`=1`でOKの両方を確認済み)はあったが、本番側の draft-19 ゲート出力(`eor_timed_out==0`)を確認するアサーションが `test_moqtrun_fetch_d22_served` に無かったので追加(moqtrun_fetch_test.c:627、ゲートを壊すRed確認済み→元に戻してGreen)。
- [x] 3-11 hub 全体で共有している事前構築済みのワイヤ(`hub->blob_wire`、live の head)が、版によって変わらないことを確認する。変わるなら版ごとに持つ。**調査済み、5-1 の結論がそのまま当てはまることを確認。追加作業不要。**
  - `blob_wire`(`moqtrun.h:632`)は構築直後に `moqtrun_subgroup_scan` でスキャンされており(`moqtrun.c:2619-2622`)、内容は SUBGROUP_HEADER + Object のバイト列そのもの。5-1 で確定済みの「データプレーンは18/19/22で全てバイト単位で同一」がそのまま当てはまる。制御プレーン要素(LOCATION_FILTER、serialization flags等)は含まれていない。
- [x] 3-12 unity build の名前衝突を避ける方針を決める。**調査済み、現状は衝突リスクが実体化していないことを確認。**
  - `find src/app/moqt -type d` で版ごとのサブディレクトリ(`ctl/v18/` 等)はまだ誰も作っていない。注意すべき既存の習慣として `moqtrel.c:14` の `rel_used` のような無接頭辞 `static` ヘルパーがある(ファイルスコープなので今は無害だが、将来ファイル分割する場合の悪い手本)。方針は実装時に決めてよい(ponytail: 2つ目の版が本当にファイル分割を要求するまで、1つの codec の中で差分フィールドだけ表で分岐させる方針を既定にする)。
  - 版ごとのファイル複製は避け、1 つの codec の中で差分フィールドだけを表で分岐させる方針を推奨。
  - 版専用ファイルが要る場合は、module token を分ける(`moq22fetch_` など)。

## 4. 版ごとの振る舞い(別ロジックが要る差分)

### draft-18

- [x] 4-1 GOAWAY の watermark: 「未処理の Request ID の最小値」以上の要求を GOING_AWAY で拒否する。**完了(2026-10-04、D-1)。** 版非依存の既存 `moqtrun_is_late` で実装(GOAWAY送信後の全拒否は watermark 以上の拒否と等価、GOAWAY は1回のみ送信)。parity 項は対象外(ruling で除外)。
  - 着手点調査済み: GOAWAY に Request ID フィールドが無い(`moqctl.h:404-408`、`moqctl.c:1037-1065`)。3-5(GOAWAY への Request ID 追加)が前提。watermark は `wired_moqtrun_peer` に新設(`moqtrun.h:564` 付近、`goaway_deadline` の隣)。チェックは各ハンドラの `moqctl_*_take` 直後に個別追加(`moqtrun_ctl_drain` は型のみで Request ID をまだ見ていないので一元化できない)。起点は `moqtrun_handle_subscribe`(`moqtrun.c:1263`)。
- [x] 4-2 1 Track につき subscription は 1 つ。DUPLICATE_SUBSCRIPTION(0x19)で拒否する。**完了(2026-10-04、D-1)。** `moqtrun_sub_held_reply`(cap分岐)。
  - 19 の「1 Track に複数 subscription」を 18 のセッションには適用しない。
  - 着手点調査済み: 現状は再送を冪等に SUBSCRIBE_OK で再応答するだけ(拒否していない)。`moqtrun_subscribe_peer_track`(`moqtrun.c:1150-1168`)の `if (held)` 分岐(line 1157)に版ガードを追加。`MOQCTL_ERR_DUPLICATE_SUBSCRIPTION`(0x19)がまだ `moqctl.h` に無いので追加が要る。
- [x] 4-3 リクエストストリームの FIN の意味: 18 では SUBSCRIBE_NAMESPACE / TRACKS の FIN はキャンセル、19 では half-close。**完了(2026-10-04、D-1)。** `moqtrun_req_fin_cancels`(FIN_CANCEL_NS cap + SUBSCRIBE_NAMESPACE/TRACKS 限定)。PUBLISH_NAMESPACE は非拡張(ruling どおり)。
  - 着手点調査済み: 現状は draft-19 の half-close 動作のみ実装済み(`moqtrun_dispatch_req_stream`、`moqtrun.c:4262-4276` の `q->fin_in |= fin;`)。キャンセル動作の既存コードは無いので `moqtrun_req_cancel` を新設し、RESET_STREAM/STOP_SENDING の既存経路を再利用する(実装前に grep で確認)。
- [x] 4-4 18 と 19 の差のうちスコープ外の機能を、明示的に「拒否のまま」とする。**完了(2026-10-05)。** SETUP の MAX_FILTER_RANGES/MAX_REQUEST_UPDATES を `moqtrun_setup_limits` で cap ビットゲート(d18 では省略)。テスト `test_moqtrun_xver_setup_d18_omits_d19_options`/`_d19_d22_carry_options`。docs/features の版注記はドキュメント監査で実施。
  - 対象の前提修正: この項目の「SUBSCRIBE_TRACKS」は E-2(10-2) 着手前の古い前提(当時はSUBSCRIBE_TRACKS自体がdraft-19でもNOT_SUPPORTED)を引用したもの。実際はdraft-18にもSUBSCRIBE_TRACKSという機能自体は存在する(`draft-ietf-moq-transport-18.txt` 10.19章)。18/19の違いは機能の有無ではなく、**SUBSCRIBE_TRACKSに許されるパラメータの集合**(18はAUTH/FORWARDのみ、19は全subscriptionパラメータ継承+GROUP_ORDER echo+TRACK_PROPERTY_FILTER)。
  - **確認済み(実装済み)**: Range Filter(0x25〜0x29)・GROUP_ORDER(SUBSCRIBE_TRACKSコンテキスト)は `moqctl.c:865-887` の `MOQCTL_PARAM_RULES`(`ctx[d22,d19,d18]`、`MOQCTL_PCTX_SUBSCRIBE_TRACKS`=0x1000 とのビットANDで判定)で、d18列がこれらのビットを持たないため、draft-18のSUBSCRIBE_TRACKSにこれらのパラメータが来れば `moqctl_param_admit` がPROTOCOL_VIOLATIONとして拒否する(受信側ゲート、正しく実装済み)。
  - **新規発見の実バグ(未修正、4-15と同じ `moqtrun.c` 編集中のため作業待ち)**: `moqtrun_ctl_open`(`moqtrun.c:184-197`)が送信するSETUPは `p->ver` を見ずに常に `max_filter_ranges`/`max_request_updates` の両 Setup Option(0x06/0x08、draft-19/22専用)を設定している。draft-18のピアにもこれを送ってしまう。draft-18は「未知のSetup OptionsをMUST ignore」(`draft-ietf-moq-transport-18.txt:3521,6407,6541`)と規定しているため**相互運用性を壊す実害は無い**(ピアは無視する)が、意図が不明瞭な無駄なバイト送信であり、版ゲートの抜け漏れとして直すべき。対応: `moqtrun_ctl_open` で `p->ver` の `MOQVER_CAP_RANGE_FILTERS` 相当(または新設のcapビット)を見て、draft-18のセッションではこの2つのSetup Optionを省略する。
  - `docs/features` の Out of scope に版の注記を入れる。
  - 着手点調査済み: 前者3つは draft-19 自体でも未実装(10-9/10-10/10-11/10-2)なので現状どの版でも自然に拒否されている。各々を実装するときに `MOQVER_CAP_RANGE_FILTERS`/`MOQVER_CAP_MAX_REQUEST_UPDATES` 等のゲートを足せばよく、今すぐの作業は不要。GROUP_ORDER の移動は Q18-02(個別規定優先)の決定により版分岐は不要と判明(no-op化)。
- [x] **(解消 2026-10-04: 2章完了 `7b531a36`/`78e4560f` で解除)** 2-1/2-2 は未完了。`src/app/moqt/ver/moqver.{h,c}` は存在するが `moqver.c` は全関数が `-1`/`0` を返すスタブのまま(2026-10-03 検証済み)。`src/` のどこからも呼ばれていない(`moqtrun.c` の `wired_moqt_on_session` はまだ `(void)protocol;` のまま、`wired_moqtrun_peer` に版フィールドも無い)。4-1〜4-14 はすべてこれに依存するので、フェーズ B(2-1/2-2)を実コードで仕上げるのが次の最優先。

### draft-22

- [x] 4-5 Joining FETCH の廃止: 22 のセッションで Joining の構造を受けたら PROTOCOL_VIOLATION にする。**完了(2026-10-04、D-2)。** `moqtrun_fetch_route`(cap bit キー)。
  - 19 の joining 状態(保留中 subscription のバッファ、INVALID_JOINING_REQUEST_ID)は 19 専用にする。
  - 着手点調査済み: デコーダ自体(`moqfetch_fetch_take`)は版非依存の上位集合として両方の type を読める設計(3-7 の決定どおり)。版チェックは decode 後、`moqtrun_handle_fetch`(`moqtrun.c:1616`)の Standalone/Joining 分岐の前に挿入する。`MOQVER_CAP_JOINING_FETCH` ビットは定義済みだが、2-1/2-2 未完了のため今は読めない。
- [x] 4-6 fill fetch stream を実装するか、NOT_SUPPORTED にするかを決める。(9-2 で「実装する」に決定済み)**完了(2026-10-04、D-2)。** T-01〜T-35 全項目実装・テスト済み(review PASS、Spec ✅ 35/35)。fetch_waits 容量境界は上記 ruling で承認。
  - 実装する場合に必要なもの:
    - FILL_PARAMETERS の入れ子パラメータのスコープ(曖昧点 Q-01)
    - FETCH_HEADER の Request ID が SUBSCRIBE や REQUEST_UPDATE を指す経路
    - Stream Count への加算
    - fill と購読配信の間のスケジューリング
    - FILL_TIMEOUT による Timed-Out 範囲
  - TLA+ の対象(7-1)。
  - 着手点調査済み:
    - `wired_moqtrun_fetch`(`moqtrun.h:450-466`)と `wired_moqtrun_sub`(`moqtrun.h:171-205`)の間に相互参照が無い。両方に新規フィールドが要る(fetch→所有する sub への back-reference、sub→複数の fill stream ハンドルの集合)。
    - FILL_TIMEOUT(0x0A)は登録済み(`moqctl.h:88`, `moqctl.c:374`)だが FETCH 専用スコープ。FILL_PARAMETERS(0x23)は未登録、かつ Q-01 の決定(件数+Parameters列)により LOCATION_FILTER のような単純な値型ではなく `moqctl_params` の入れ子になる(`moqctl_param` への新規 `fp` フィールドが必要、単純なコピペでは済まない)。
    - PUBLISH_DONE の Stream Count は現状 `MOQTRUN_DONE_STREAMS_UNKNOWN` のハードコード(`moqtrun.c:4632`)で、10-3(実数化)が前提。
    - TLA+(`tasks/loopeng/moqt/MoqtFill/`): 0段の抽出(`MoqtFill.extract.md`)は完了済みで再利用可。`MoqtFill.tla` は構文エラー1箇所のみ(line 383、`[][...]_vars` の antecedent に括弧が無い。他の同種行は全て括弧あり)でパース不能。**やり直しは不要**、1行の構文修正で再開できる見込み(未確定、次の担当が検証)。
    - Ruling(controller、2026-10-04、D-2 完了判定時): `fetch_waits[]`(8 スロット、`fetches[]` と合計 16 本)が両方満杯のとき、17 本目以降の fill 要求は `moqtrun_fill_wait_put` で何もせず戻る(`moqtrun.c` の `ponytail:` コメントで明記済み)。これは「保留中の fill を黙って捨てない」という MUST 違反ではない。TLA+ モデルは K(同時 fill 本数)1〜2 の小さい有限値でしか検査しておらず、固定長配列の容量境界はモデルの検査範囲外(無限の状態空間 vs 実装の有限配列、というモデルと実装の間の層でのみ生じる制約)。受理済みの fill が後から消えるのではなく、要求受付の時点で枠が無いだけなので、程度としては「サーバのリソース上限で新規要求を捌けない」という通常のサーバ実装の制約と同種。現状は無言で捨てるのでクライアントには見えないが、これを直すなら「容量上限超えの REQUEST_UPDATE/SUBSCRIBE に REQUEST_ERROR を返す」(ruling の「保持中は REQUEST_ERROR を送らない」は held 状態に入った後の話なので矛盾しない)。発生させるには同時 16 本以上の fill が必要で、通常運用では稀。**対応: 今回は現状のまま承認、容量を増やすか明示エラーにするかは別チケットで良い(YAGNI、今の 8+8 スロットで実害が出た実績は無い)。**
- [x] 4-7 PUBLISH のパラメータの流れ。**完了(2026-10-04、D-1 commit `041b9ef4`)。**
  - Ruling(controller): draft-19 §3.3.1 の規範は「PUBLISH_OK か REQUEST_ERROR をちょうど1つ返す」だけで、PUBLISH_OK にパラメータを載せるのは MAY(can)。draft-22 の「PUBLISH に発行側初期値、購読側は REQUEST_UPDATE で送る」は publisher 側の送出義務であり、常時中継・無優先度のこの hub には観測可能な義務を課さない。必須コード変更は「d22 の REQUEST_UPDATE を PUBLISH stream に開放する」1点のみで、`MOQVER_CAP_UPDATE_ON_PUBLISH` cap により実装済み・テスト済み(レビュー確認済み)。`moqtrun_handle_publish` が LARGEST_OBJECT 以外(FORWARD/priority/filter/timeout)を未読のままなのは、それらを読んで分岐させる動作要件がどの版にも無いため Missing ではない。
  - 19: PUBLISH_OK に購読側のパラメータが載る。
  - 22: PUBLISH に発行側の初期値が載り、購読側は PUBLISH_OK の後に REQUEST_UPDATE で送る。
  - 着手点調査済み: `moqctl_publish` の wire decoder は元から汎用 `params` フィールドを持つ(19/22でバイト同一)ので codec 側の変更は不要。純粋に hub の振る舞いの欠落。`moqtrun_handle_publish`(`moqtrun.c:779-798`)は `LARGEST_OBJECT` しか読んでおらず、FORWARD/priority/filter/timeout 等は未適用。PUBLISH_OK の応答も汎用の `moqtrun_queue_request_ok` 止まりで購読側パラメータを一切送っていない(19 でも未実装)。`moqtrun_handle_update`(REQUEST_UPDATE ハンドラ、`moqtrun.c:1906-1931`)は現状 SUBSCRIBE のストリームだけに限定(`moqtrun.c:1910`)、22 では PUBLISH のストリームにも開放する必要がある。
- [x] 4-8 22 では、Location Filter の終端を過ぎても subscription を終わらせない(SUBSCRIPTION_ENDED は廃止)。**調査済み、既に対応済み(no-op)と判明。**
  - SUBSCRIPTION_ENDED というステータスコード自体が `src/` のどこにも存在しない。`moqtrun_sub_wants_group`(`moqtrun.c:982-984`)は Location Filter の終端を配信のゲートとしてのみ使い、購読終了(PUBLISH_DONE 送信)には一切繋がっていない。つまり wired はそもそも 19 の「終端で終わらせる」挙動自体を実装していないので、22 向けに廃止する作業は不要。今後 19 の挙動を実装する場合に備え、この gate 関数に終了トリガーを足さないよう注意書きのみ残す。
- [x] 4-9 PUBLISH_NAMESPACE を prefix として照合する(22)。relay の照合表は完全一致から prefix 一致へ変わる。**調査済み、既に対応済みと判明。**
  - relay の namespace 照合(`moqtrun_disc_under`/`moqtrun_disc_starts`/`moqtrun_disc_overlap`、`moqtrun.c:1938-1978`)はすでにバイト前方一致(prefix)で実装されている(完全一致ではない)。22 の仕様変更はフィールド名が「Track Namespace Prefix」になる命名上の変更のみで、符号化・照合アルゴリズムは不変。完全一致を使っている箇所(`moqtrun_disc_same`/`moqtrun_ns_eq` 等)は「既に押した announcement と同じか」の重複判定用で、これは版に関係なく正しい。実装変更は不要、確認のみで済んだ。
- [x] 4-10 PUBLISH_STATE_NOTIFY(0x22)の受信処理: 方向を検査し、応答は返さない。MAX_REQUEST_UPDATES の計数からは外す。**完了(2026-10-04、D-1)。** `moqtrun_dispatch_pub_notify`、方向チェック3経路テスト済み。
  - 着手点調査済み: 型自体が未登録(`moqctl.h` に定数が無い)。現状は未知型として `moqtrun_dispatch_close` に落ち、セッションを閉じる(想定通り)。`moqtrun_ctl_table[]`(`moqtrun.c:2324-2343`)に行を追加し、`moqtrun_dispatch_skip` と同じ「応答なし」系のハンドラにする。`moqtrun_req_first[]` には入れない(購読ストリーム上の後続メッセージなので `moqtrun_req_done_ok` 同様の follow-on 判定が要る、`moqtrun.c:2421-2431`)。MAX_REQUEST_UPDATES 計数は 10-10 がまだ無いので今は先送りメモのみ。
- [x] 4-11 OBJECT_DELIVERY_TIMEOUT の起点: 19 は最初の payload バイト、22 は最後のヘッダバイト。**完了(2026-10-04、D-1)。** Ruling(controller): この hub は Object をアトミックに decode し、header 末尾/payload 先頭の境界バイト単位の情報を持たないため、19/22 の差は観測不能(両版で同一値になり版ゲートは死にコード)。版ゲートの追加ではなく、見つかった実バグ(ring 経路が `born_ms` を無視して append 完了時刻で打刻していた)を `moqtrun_rel_take` への `born_ms` 貫通で修正。brief の「既存打刻点にゲートを追加する」字義からの逸脱だが、前提(両版で観測可能な差がある)が偽なので妥当。
  - 着手点調査済み: 現状の実装は draft-19 の「最初のバイト」とも違う第三の挙動(オブジェクト全体を追記し終えた時点で打刻、`moqtrel_mark`、`moqtrun.c:3281`)。この箇所にはすでに `ponytail:` コメントで「正確な打刻が要るならヘッダ境界の offset/timestamp を渡す分割が要る」と明記されている。版ゲートはまだ無い(`MOQVER_CAP_*` 相当のビットも未定義)。
- [x] 4-12 REDIRECT で NS と Name が空のときの意味(22 は文字どおり空を指す)。Retry Interval 0 の扱い。**完了(2026-10-04、D-1)。** 対象外(N/A)として確認: hub は REDIRECT を送らず受信しても反応しない(未変更)。`docs/features/draft-moq-transport.md` の Out of scope へ版非依存の relay-behavior 除外として追記(既存 Session Migration 項と同形式、MOQT-NNN 行数・総数は不変、1spec=1file の形式違反なし)。
  - 着手点調査済み: REDIRECT は decode/encode の codec としてのみ存在し(`moqctl_redirect_take/_put`、`moqctl.c:918-924,973-978`)、`moqtrun.c` 側に送信・受信いずれの振る舞いも無い(`has_redirect` を立てる箇所が無く、受信して反応する箇所も無い)。空NS/Name・Retry Interval=0 のどちらも現状は特別扱いせず素通りする。19/22の意味の違いを実装する前に、まず「このhubがREDIRECTを使う経路」自体を決める必要がある。
- [x] 4-13 FETCH 受信側の gap 解釈(22 の Range Filter と降順の規則)。relay の FETCH 挙動(19 の「確認まで保留」を廃止)。**完了(2026-10-04、D-2 で N/A 再確認)。** 4-6 に統合済みという既存結論のとおり、対象外(N/A)であることを D-2 完了判定で再確認(grep 証跡つき)。コード変更なし。
  - **調査済み、両方とも対象外または統合すべきと判明**: 「確認まで保留」の廃止は、そもそも wired が upstream への FETCH 転送(FETCH-of-FETCH)を一切実装していないため削除対象の挙動自体が存在しない。この半分は **4-6(fill fetch)に統合**し、独立項目として扱わない。FETCH 受信側の gap 解釈も、wired が FETCH クライアント役を持たない(`moqfetch_obj_take` が定義されているが呼び出し元が無い、デッドコード)ため現状は **対象外(N/A)**。4-6 が upstream fetch 機能を持つなら、その時に `moqfetch_obj_take` を拡張する。
- [x] 4-14 セキュリティ節(22): 他者へのなりすまし防止(識別子ごとの namespace 認可)。Reason Phrase と MOQT_IMPLEMENTATION をログに出す前のサニタイズ。**完了(2026-10-04、D-1)。** 4-14a: `moqtrun_publish_refused`(`moqtrun_subscribe_refused` と対称、V-0839 のギャップを解消、3版+alias token 拒否テスト済み)。4-14b: ログ呼び出し自体が存在しないため実装なし、設計制約コメントのみ(YAGNI、ruling どおり)。
- [x] 4-15 (2026-10-04 追加、3-6/3-8 の配線中に判明) d22 の LOCATION_FILTER type 0x04(Absolute Range)は End Object を Object 単位で持つが、配信ゲートは group 単位のまま。1本の subgroup ストリームに複数 Object が載る場合、End Object を超えた Object が届く(d22 §3.3.1 / d19 §5.1.2 付近「publisher MUST NOT send objects outside the requested range」違反、datagram は Object 単位で正しく遮断済み)。**完了(2026-10-05)。** End 側のみ修正: 新設 `moqtrun_wire_cutoff`(+ `moqtrun_end_object_in_group`/`moqtrun_cutoff_scan`)が宛先ごとに End Object までの byte offset を再計算し、`moqtrun_hdr_cutoff`(ヘッダ付き wire、`moqtrun_relay_object`/`moqtrun_relay_open_one` が使用)と `moqtrun_relay_end_cut`(ヘッダ無し継続 round、`moqtrun_relay_append_one` が使用、`moqtrun_relay_normalize` が返す round 先頭時点の seq を使用)の2系統でラウンドを宛先ごとに切り詰める。End Object 到達で `relay->sub_expired` ビットをセットし、その宛先のストリームを `stream_fin`/`fin=1` で閉じて以後のラウンドをスキップ(`moqtrun_relay_skips` が既存のビットを再利用)。reliable ring 経路(`moqtrun_rel_give_up`、moqtrel 使用時のみ)は対象外(YAGNI、ring は絶対バイト offset の共有バッファで宛先ごとの終端を持たせるには構造変更が要る、既存の Group 粒度のまま、ponytail コメントで明記)。テスト: `test_moqtrun_sub_filter22_end_object_mid_round_{oneshot,keepopen,append}`(fresh 一撃/fresh keep-open/継続 append の3経路)+ `test_moqtrun_sub_filter22_end_object_per_sub`(2宛先で別々の End Object、独立に切り詰められることを確認)、`tests/app/moqtrun_sub_test.c`。開始側(start Object)の同種の粒度問題(`moqtrun.c:1018-1023`→現 `moqtrun_sub_gets` 直前のコメント)は**対象外(別タスク)**: SUBSCRIBE 時に解決される `start` は常に「まだ来ていない将来の Object」を指すため実運用での発生頻度が低く、かつ修正には「ラウンド先頭を SUBGROUP_HEADER を残したまま re-frame する」End 側と質的に異なる設計が要るため、同じ diff に含めず既存の ponytail コメントとして残した。三点ゲート+`just test` 全て green(`.claude/worktrees/fix-moqt-loc-filter-end-object` で検証、本線 `moqtrun.c` には他 agent の並行作業があったため専用 worktree に退避して実装)。

## 5. 版をまたぐ中継

- [x] 5-1 データプレーンのバイト互換を、18 / 19 / 22 の全組み合わせで検証する。
  - 対象: SUBGROUP_HEADER、Object、OBJECT_DATAGRAM、padding。
  - 互換なら素通しのまま、互換でなければ購読者ごとの再エンコードにする。
  - **結論(2026-10-03、仕様テキスト直接比較で確認済み)**: データプレーンは 18/19/22 の全組み合わせでバイト互換。`moqtrun.c` の素通し中継(SUBGROUP ストリーム、reliable ring、datagram fanout)はそのまま使える。再エンコードは不要。
    - SUBGROUP_HEADER・OBJECT_DATAGRAM・Object body(KVP/Properties含む)・padding・varint は全てバイト単位で同一。
    - draft-22 の差分は2点ともバイト形式の変更ではなく受信側検証の強化のみ: (a) `Type` → `Type Flags` への改名とビット範囲規則の一般化(有効な18/19の値はどれも新しい予約ビット規則に違反しない、enumeration で確認済み)、(b) FETCH 専用の 0x20C マーカー追加(18/19 は未知値として規定通り PROTOCOL_VIOLATION で拒否する。そもそも FETCH は cache 経由で購読者ごとに再エンコードする既存設計のため、この素通し判断には影響しない)。
    - 証跡: subagent 報告(直前のやり取り)。仕様の行番号つきで18/19/22 全てを直接比較済み。
  - 素通しを支える経路: `moqtrun_relay_*`、`moqtrel` の ring、datagram の fanout。
- [x] 5-2 制御プレーンは版に依存しない内部モデル(購読、track、範囲、FETCH)を経由させ、送信先の版で encode する。
  - **完了(2026-10-05、コード変更不要と確認)。** `moqtrun_envelope_put` の全10呼び出しを確認: REQUEST_ERROR/FETCH_OK/PUBLISH_DONE/GOAWAY は宛先 `p->ver` で encoder 選択済み、SETUP/REQUEST_OK/SUBSCRIBE_OK/NAMESPACE/PUBLISH/PUBLISH_SKIPPED は 18/19/22 でバイト同一(d18 は 0xF を PUBLISH_BLOCKED と呼ぶが同一バイト)。ピア間でメッセージバイトを素通しする経路は無い。hub は上流へ何も転送しない(fill/Joining は cache から要求元へのみ応答、d22 Joining は `moqtrun_fetch_route` で拒否済み)ため「片方の版にしか無い機能の上流転送」は N/A(4-13 と整合)。
  - 片方の版にしか無い機能は、その版の NOT_SUPPORTED で拒否する。例: 22 の fill を 19 の上流へ、19 の Joining を 22 の上流へ。
  - 着手点調査済み: `wired_moqtrun_sub`/`wired_moqtrun_fetch` は既にほぼ版非依存(`moqctl_loc` で LOCATION_FILTER 由来の状態を保持)。版依存の生バイトが残っているのは namespace(`wired_moqtrun_track.ns`/`wired_moqtrun_req.ns`/`wired_moqtrun_peer.sub_ns`、「wire 上のまま」と明記されたコメントあり)だけだが、4-9 で namespace の符号化自体は版間で不変と確認済みなので問題にならない。制御プレーンの「送信毎に再エンコード」という規律は既に `moqtrun_envelope_put`(`moqtrun.c:137-151`、関数ポインタ経由で毎送信時に新規エンコード)という1つのチョークポイントで成立済み。残る作業は、この関数ポインタを「版ごとの表から選ぶ」形に変えるだけ(呼び出し箇所は `moqtrun.c:166,357,523,1073,2138,4633,4713` の7箇所、行番号は2026-10-03時点のものなので着手時に再確認すること)。LOCATION_FILTER の範囲モデルは 3-6(`moqctl_rangeloc`)で完成済み。**訂正(2026-10-05): 「ブロッカーは2-1/2-2と同じ」という記述は古い。2-1/2-2は既に完了済み(`wired_moqtrun_peer.ver`に版が保存されている)なので、このブロッカーは解消済み。着手可能。**
- [x] 5-3 FETCH の cache はデコード済みで持ち、要求ごとに encode し直している(`moqtrun.c:1338-1376`、行番号は2026-10-03時点のものなので着手時に再確認すること)。ここで版ごとの encoder に差し替える。
  - **再調査結果(2026-10-05)**: `moqfetch_obj_put`(`moqfetch.c:765`、FETCH応答に載せるOBJECT自体のエンコーダ)は版引数を取らない単一実装のまま。確認したところ、これは5-1の結論(FETCH応答のObject自体=データプレーンはバイト単位で版不変)と一致しており、**そもそも版ごとに分ける必要が無い**可能性が高い。台帳のこの項目が指す「版ごとのencoder差し替え」は、3-6/3-7/3-8で既に対応済みのFETCH **メッセージ構造**(Fetch Type/Location、LOCATION_FILTERパラメータ化等、`moqfetch_req`/`moqfetch_ok`系)の話であり、`moqfetch_obj_put`(データ部分)とは別物の可能性がある。着手前に「この項目が指すのが具体的にどの関数か」を再確認すること(5-1/3-6/3-7/3-8が既にカバーしている範囲と重複していないか、`moqtrun_fetch_send_one`周りを実際に読んで判断する)。本当に版ごとの差し替えが必要な未対応箇所が見つからない場合はこの項目をN/A(対応済み・対象なし)として閉じる可能性がある。
  - **N/A として完了(2026-10-05)。** `moqtrun_fetch_send_one` は版不変の `moqfetch_obj_put` を使い 5-1 と整合。fetch stream 上の版依存要素は 0x20C マーカーのみで、要求元の版(`MOQVER_CAP_EOR_TIMED_OUT`)でゲート済み。メッセージ構造は `moqtrun_fetch_take`/FETCH_OK encoder で要求元の版ごとに処理済み。
  - `wired_moqtrun_fetch` への版情報の持たせ方自体は、5-2と同じく2-1/2-2完了(`peer->ver`)により解消済み(必要になればここから渡せる)。
- [x] 5-4 版をまたぐ relay のテストを用意する(pub 18 / sub 22、pub 22 / sub 18、pub 19 / sub 22)。先行実装のどれにも無い領域。**完了(2026-10-05)。** `tests/app/moqtrun_xver_test.c`: `test_moqtrun_xver_relay_pub18_sub22`/`_pub22_sub18`/`_pub19_sub22`(SUBSCRIBE_OK を購読側の版で decode、SUBGROUP/DATAGRAM はバイト同一)、`_goaway_per_destination`、`_location_filter_each_draft`、`_fetch_in_requester_draft`、`_joining_d19_sub_of_d22_pub`。
  - **派生調査(未解決)**: relay は SUBGROUP/DATAGRAM ヘッダの Track Alias を publisher のまま素通しするが、SUBSCRIBE_OK では購読者ごとに `moqtrun_next_alias` で別の alias を通知している疑い。版非依存。interop 影響の有無を調査中。

## 6. WebTransport draft-16 への追従

MoQT draft-19 以降は webtrans-http3-16 を参照している。ワイヤ値は 15 と同一なので、版交渉への影響は無い。以下は 16 の新しい MUST への不適合と、既存のバグ。詳細は `tasks/webtrans-15-vs-16-diff.md` を参照。

**状態(2026-10-05 再検証): 6-1〜6-7 は実装済み。2026-10-03 時点の「全項目未着手」は古い記述で、その後(`29e489c1` 以降、2026-10-04 付近)のコミット群で実装済みだったが、本台帳が更新されずに取り残されていた見落とし。** 6-8/6-9/6-10 のみ記述どおり本当に未着手。

- [x] 6-1 WT_SESSION_GONE と WT_BUFFERED_STREAM_REJECTED を、アプリエラー範囲へ写像した値で送っている。正しくは HTTP/3 エラーコードの生値で送る(既存バグ)。**実装済み確認(commit `29e489c1`)。** `WTERR_SESSION_GONE`/`WTERR_BUFFERED_STREAM_REJECTED` は生の HTTP/3 コード値(`errmap.h:47-48`)で定義され、`srvrun.c:3593,3605,3626,3657,3658,2267` で `wired_wterrmap_to_http3` を経由せず直接使用。テスト `test_srvrun_wt_bidi_stream_buffer_full_sends_reset` 他。ドキュメント WTH3-074 も `[x]`(`docs/features/draft-webtrans-http3.md:689`)。
- [x] 6-2 WT_MAX_STREAMS と WT_MAX_DATA は、値が増えていないもの(同値と減少)を WT_FLOW_CONTROL_ERROR で session close にする。2^60 を超えたときも同じ。WT_STREAMS_BLOCKED にも同じ上限を検査する。**実装済み確認。** `srvrun_wt_rx_capsules_one` 系で非増加値・2^60超えを WT_FLOW_CONTROL_ERROR で close。テスト `test_srvrun_wt_nonincreasing_flow_control_capsule_closes_session`(`srvrun_test.c:16275`)、`test_srvrun_wt_max_streams_over_ceiling_closes_session`(:16302)、`test_srvrun_wt_streams_blocked_over_ceiling_closes_session`(:16323)。ドキュメント WTH3-069/070/071 も `[x]`(:534,548,591)。
- [x] 6-3 WT_CLOSE_SESSION の受信時に、メッセージが 1024 バイト以下で正しい UTF-8 かを検査する。違反なら H3_MESSAGE_ERROR で reset する。**実装済み確認(commit `c0eb5adc`)。** `srvrun_wt_close_body_ok`(`srvrun.c:3448-3459`)が検査、違反時 H3_MESSAGE_ERROR で reset(:3591)。テスト `test_srvrun_wt_close_message_too_long_resets_and_closes`/`_invalid_utf8_resets_and_closes`(`srvrun_test.c:20102,20131`)。ドキュメント WTH3-072 も `[x]`(:665)。
- [x] 6-4 WT_CLOSE_SESSION の送信時の切り詰めを、UTF-8 の文字境界で行う。**実装済み確認。** `wtcapsule_utf8_truncate_len`(`wtcapsule.c:272`)、`srvrun.c:5254` で使用。テスト `test_srvrun_wt_close_session_truncates_at_utf8_boundary`(`srvrun_test.c:16584`)。ドキュメント WTH3-073 も `[x]`(:679)。
- [x] 6-5 拒否時の推奨ステータスが 404 から 405 に変わった。**実装済み確認。** `srvrun.h:115-117` のコメントが変更を明記、`guide/snippets/wt-session/main.c:30`・`golden.txt:8` が405、テスト(`srvrun_test.c:5700-5727`、WTH3-016明記)も405基準。
- [x] 6-6 `docs/features/draft-webtrans-http3.md` を 16 に改版する。**実装済み確認。** 表題が既に draft-16、WTH3-001 の値は1(:20-21)、§5.6系(WTH3-069/070/071)・WTH3-072/073のCLOSE受信検証項目も記載済み。
- [x] 6-7 未検証の懸念を確認する。`dispatch.c:860-880` は 1 ステップに最後の reset 1 件しか保持しないので、同じステップに複数届くと取りこぼすおそれがある。**検証済み、意図的に受容(YAGNI)。** `dispatch.c:860-862` の `gather_one_wt_reset` に `ponytail:` コメントでこの制約を明記(`29e489c1`)。`e2caadd0` が同種の取りこぼし上限を `srvloop.c`/`srvrun.c` にも記録。upgrade path(固定長queue化)もコメントに明記済み、追加実装は不要。
- [x] 6-8 (2026-10-04 追加、6-2 の修正中に判明した既存の不適合) draft-16 §5.1: フロー制御が無効なセッションでは flow-control capsule を無視する(MUST)。現状は無効でも適用している。直すと peer SETTINGS を持たない既存 capsule テストの前提が逆転するので、テストの前提ごと直す。**完了(2026-10-05、commit `6c3d569f`)。** `srvrun_wt_capsule_ignored`(flow_control未設定時にWT_MAX_DATA/WT_MAX_STREAMS/WT_STREAMS_BLOCKEDを無視、WT_CLOSE/DRAIN_SESSIONは対象外)。既存の6-2テスト群はflow_control有効化を明示するよう前提修正、新規Red→Greenテスト3本追加。
- [x] 6-9 (同上) フロー制御が無効なとき、2 本目以降の WT セッションを H3_REQUEST_REJECTED で拒否する。現状は 2 本まで受け付ける。**完了(2026-10-05、commit `6c3d569f`)。** `srvrun_wt_single_session_full`(`!flow_control && wt_active`)を`srvrun_wt_free_slot`のガードに追加。既存の多重セッションテスト群はflow_control有効化の前提を明示、新規テスト`test_srvrun_second_wt_connect_rejected_when_flow_control_disabled`追加。
- [x] 6-10 (同上) サーバ発の WT ストリームが上限で開けないとき WT_STREAMS_BLOCKED を送る。開く関数は -1 を返すだけで、再試行は呼び出し側の責務(フェーズ C の uni SETUP 送信はここに依存)。**完了(2026-10-05、commit `6c3d569f`)。** `srvrun_wt_notify_streams_blocked`新設、ストリーム数上限で拒否された場合のみ送信(データ上限・QUICレベル拒否では送らない)。再試行は呼び出し側の責務のまま変更なし。新規テスト4本(uni/bidi送信確認、データ上限/QUICレベル拒否で送らないことの確認)。

- [x] 7-2 Lean: LOCATION_FILTER の 2 系統のデコーダ、FETCH 本体の 2 系統、End Location の正規化について、内部モデルへの写像の一致と round-trip を証明する。**完了(2026-10-04)**: `tasks/fv/moqt/Moqt/{Filter,RangeV,Fetch22,CheckV22}.lean`。68定理、`sorry`/`native_decide`無し、axiom監査クリーン。
  - 証明中に見つかった実装バグ D1(d22 FETCH encode が GROUP_ORDER 等の大きい type のパラメータと共存する LOCATION_FILTER を挿入できず encode 失敗)を修正・テスト追加・commit `5e25a554`。
  - D2(d22 take 経路に Full Track Name ≤4096 の複合検査が無い、d19 は有り)**修正済み(2026-10-05)**: `moqfetch_req22_take_head` を既存 `moqctl_ftn_take` 経由に変更。SUBSCRIBE/PUBLISH は版共通で既に検査済み。テスト `test_moqctl_limits_req22_ftn_boundary`(4096 受理/4097 拒否)。
  - D3(d19 req encode が UNBOUNDED 範囲で壊れたワイヤを出す)**修正済み(2026-10-05)**: draft-19 §10.12.1 Standalone は絶対 Start + 有界 End のみ表現可能なので、UNBOUNDED 終端/非ABS 開始は `moqfetch_req19_unrepresentable` で encode を拒否(0 返却)。テスト `test_moqctl_limits_req19_unrepresentable`。

## 7. 検証の三層

- [x] 7-1 TLA+: 次の 3 つをモデル検査する。**完了(2026-10-05)。** `tasks/loopeng/moqt/{MoqtVerCtl,MoqtFillLife,MoqtXRelay}/`(各 EXTRACT.md/RESULT.md/counterexample.feature)。基本構成は全て無違反(VerCtl 32,041 / FillLife 18,751 / XRelay 最大 357,336 distinct states)、変異モデルは全て検出。反例から実装の不一致 4 件+裁定の前提誤り 1 件を発見 → 12-12〜12-16。
  - 版交渉と制御ストリームの組(1-1)
  - 22 の fill fetch のライフサイクル(4-6 を実装する場合)
  - 版をまたぐ relay の購読と FETCH の対応(5-2)
  - 反例は Gherkin を経てテストへ落とす。
- [x] 7-2 Lean: LOCATION_FILTER の 2 系統のデコーダ、FETCH 本体の 2 系統、End Location の正規化について、内部モデルへの写像の一致と round-trip を証明する。**完了(上記0章末尾の完了記録と同一項目、2026-10-04)。**
  - 既存の `tasks/fv/moqt/Fetch*.lean` を版対応に拡張する。
- [x] 7-3 golden vector を `{版, メッセージ, バイト列}` の表にし、全版をループで検査する。**完了(2026-10-05、commit `e4be35ab`)。** JSONに`versions`キー方式で版差分を追加(大多数のエントリはバイト列が版非依存なので無変更)。版差分3件: GOAWAY(d18のみRequest ID付加)、SUBSCRIBE_TRACKS(d22のLOCATION_FILTERエンコーディング差)、FETCH(d22の本体構造差)。`tests/app/moqt_multidraft_golden_test.c`新設、1テスト関数でMOQVER_D18/D19/D22をループして検査。三点ゲート+フルunity build全green(自分で再検証済み)。副産物: `fetch_standalone`の既存ノートの誤記(「whole of Group 0」→正しくは「whole of Group 1」)を修正。
  - `examples/moqt_chat/testvectors/moqt_golden.json` と `scripts/gen_moqt_golden.py` を版対応にする。
- [x] 7-4 既存の moqt テスト(542 関数)のうち、セッションのシナリオ系を全版で回す。**完了(2026-10-05)。** `moqtrun_test.c` に `g_moqtrun_test_ver` + `moqtrun_test_session`(67 箇所の on_session を置換)+ `moqtrun_test_vers(need,deny,fn)`/`moqtrun_test_allver` を新設。8 ファイル 372 関数中 308 が D18/D19/D22 全版、30(d19 FETCH 本体)が D18/D19、5(Range Filter)が D19/D22、1 が D19、28 は自前で版固定。版ごとの実行数 D22 313 / D19 344 / D18 338。デコーダは peer の実版で読み、LOCATION_FILTER は d22 では型付き形式へ変換、DUPLICATE_SUBSCRIPTION/GOAWAY Request ID は cap ビットで期待値分岐。実装バグは検出されず(D18/D22 の失敗は全てテストの d19 前提)。
- [x] 7-5 fuzz: `fuzz_moqt` に版の選択バイトを足し、版ごとの codec を通す。dg、cache、run が未収録という既存の穴も記録する。**完了(2026-10-05)。** 先頭1バイト `%MOQVER_COUNT` で版選択、version引数/capビット(GOAWAY_REQID, FETCH_BODY_V22, EOR_TIMED_OUT)で moqtrun と同じ codec を選ぶ。旧ハーネスが `MOQCTL_KNOWN_UNIMPLEMENTED` で打ち切っていたため FETCH/NAMESPACE/TRACK_STATUS/REQUEST_UPDATE 本体が未到達だった穴も解消。moqdg(decode→encode→decode の round-trip trap)、moqcache(append/release/skip 走査、カーソル非前進で trap)を新規収録。run は codec でないため対象外(ハーネス冒頭コメントに明記)。既存 corpus 992 件に版バイト 0x01(d19)を前置、手書き seed 3 件追加。`just fuzz-smoke` rc=0、120s+60s で約490万 exec・クラッシュ無し、corpus coverage 521→862 edges。
- [x] 7-6 interop: moq-interop-runner の `implementations.json` で、wired の `draft_versions` を `["draft-18","draft-19","draft-22"]` に広げる。
  - commit `a93b3f1b`(moq-interop-runner fork)、push済み。
  - `interop-wired.yml` を手動実行(run 37222986434、2026-10-04)、`make interop-relay RELAY=wired` で14クライアントと対向(draft-18 10本、draft-19 1本、draft-22 1本の at-target/ahead組み合わせ)。
  - 結果: **4/14 PASS**(moq-dev-js, moq5, moq-dev-rs(d19), stitcher-moq(d22))、**10/14 FAILED**(aiomoqt, imquic, moq-rs-draft-18, moqlivemock, moqx, moxygen, xquic-draft-18, moqtopus, moq-playa, quic-zig、いずれも draft-18)。Vercel への deploy 自体は成功(Deployment Protection が有効なため公開URLは認証必須、閲覧には Vercel ログインが必要)。
  - **原因調査(ローカル再現、2026-10-04)**: `make test RELAY_IMAGE=... CLIENT_IMAGE=...` で個別に再現。
    - aiomoqt: 6テスト中5 PASS、`announce-subscribe` のみ FAIL(`SUBSCRIBE_ERROR: upstream subscribe failed`)。
    - moq-rs-draft-18: 18テスト中7 PASS(`setup-only`/`publish-namespace-*`/`subscribe-*`/`publish-track-only`)、11 FAIL(`publish-track-subscribe`, `rendezvous-timeout`, `moq-test-subgroup-per-group`, `moq-test-subgroup-per-group-eog`, `moq-test-subgroup-per-object`, `moq-test-two-subgroups-eog`, `moq-test-datagram`, `moq-test-datagram-eog`, `moq-test-extensions`, `moq-test-increments`, `moq-test-forward-zero`)。失敗メッセージは一貫して `subscriber setup failed before generation started` / relay側 `Not found`。
    - **当初の結論(誤り、2026-10-04時点)**: 「relayが自発的にPUBLISHを送る経路が必要なシナリオでのみ失敗している、E-2(10-2/10-8)のスコープそのもの」と判定したが、**E-2実装後の再検証(2026-10-05、下記)でこの原因特定は誤りと判明**。
  - **E-2実装後の再検証(2026-10-05、run 37250572657)**: `interop-wired.yml`を再実行。結果: **3/14 PASS**(moq-dev-js, moq5, moq-dev-rs(d19))、**11/14 FAILED**。stitcher-moq(d22)が新たにFAILに回り、PASS数が4→3に減少。ローカル再現(`make test`)の結果:
    - stitcher-moqのFAIL原因は`announce-subscribe`/`subscribe-before-announce`(`message: "track subscription rejected: not found"`)。E-2実装の副作用による退行ではなく、**元から存在する別の機能ギャップが、今回たまたまこのクライアントの別シナリオで露出した**(前回run時はこのクライアントの別の非決定的な実行順序でたまたま通っていた可能性がある、またはクライアント側イメージの`:latest`タグ更新による挙動変化の可能性もある。いずれにせよwired側のE-2実装の退行ではないことをコード読解で確認済み、下記)。
    - aiomoqtの`announce-subscribe`、moq-rs-draft-18の`publish-track-subscribe`/`rendezvous-timeout`/`moq-test-*`(9件)は**全てE-2実装前と全く同じ結果のまま不変**(PASS数・FAIL内容ともに変化なし)。E-2(SUBSCRIBE_TRACKS/PUBLISH_SKIPPED)は正しく実装されているが、これらの失敗とは無関係だったことが判明。
    - **正しい原因**: これらは全て通常の**SUBSCRIBE**(SUBSCRIBE_TRACKSではない)が「まだpublishされていないtrack」に対して送られ、relayがそれを即座にDOES_NOT_EXISTで拒否している(`moqtrun_route_peer_subscribe`、`moqtrun.c:1492-1505`)ことが原因。これらのテストシナリオは、SUBSCRIBEに`RENDEZVOUS_TIMEOUT`パラメータ(draft 10.2.6)を付け、relayがpublisherの到着をそのタイムアウトまで待ってから解決する(または真にタイムアウトしたらTIMEOUTエラーを返す)ことを期待している。
    - `RENDEZVOUS_TIMEOUT`は**既にdecodeは実装済み**(`moqctl.c:869`、`MOQCTL_PARAM_RENDEZVOUS_TIMEOUT`)だが、この値を使った実際の待機・保留ロジックが`moqtrun.c`に存在しない。これは`docs/features/draft-moq-transport.md:1314-1316`のOut of scope節に**既に明記されている既知の意図的な未実装**(「decoded by the registry, not acted on」)であり、draft-19でも同様に未対応。版(18/19/22)に依存しない、マルチドラフト対応計画そのものとは別軸の機能ギャップ。
  - **結論(訂正)**: E-2実装によるinterop結果の改善は確認できなかった。理由はE-2のスコープが対象クライアントの失敗原因と最初から一致していなかったため(原因特定の誤り)。rendezvous機構(SUBSCRIBEのRENDEZVOUS_TIMEOUTを使った保留・タイムアウト処理)を実装すれば、aiomoqtの`announce-subscribe`、moq-rs-draft-18の`publish-track-subscribe`/`rendezvous-timeout`、stitcher-moqの`announce-subscribe`/`subscribe-before-announce`が改善する可能性が高い。`moq-test-*`系9件(moq-rs-draft-18)は`moq-test-subgroup-per-group`等のシナリオ名からrendezvous待ちに加えてMoQT独自のテストプロトコル拡張(`moq-test`ネームスペースの合成トラック生成)への追従も必要な可能性があり、rendezvous実装だけで全解決するかは未確認。
  - **次にやること(このマルチドラフト対応計画のスコープ外、別タスクとして切り出す)**: rendezvous機構(SUBSCRIBEのRENDEZVOUS_TIMEOUTパラメータを見て、該当trackが存在しない場合はタイムアウトまで購読を保留し、その間にPUBLISHが来れば通常のSUBSCRIBE_OKへ、タイムアウトしたらREQUEST_ERROR(TIMEOUT)を返す)の実装。
  - quic-interop-runner(QUIC + WebTransport)も同時に実施: run 37219504844(2026-10-04)、全46ジョブ success。QUIC: wired server vs 13クライアント(+chrome, go-x-net)で `connectionmigration` が多数のクライアントで一貫して failed(wired の connection migration 未実装/不完全を示唆、別途調査要)。`ecn`/`v2` は元々 unsupported 扱い(テストケース対象外)。WebTransport: wired server vs 5クライアントで webtransport-go/flupke/ngtcp2 がほぼ全成功、firefox は handshake のみ失敗、chrome は全滅だが原因はログ上 `digest-mismatch: error`(Docker イメージ pull のCI環境起因、wired実装とは無関係)。
  - 両runnerとも fork 上の実行であり、本家の公開結果(interop.seemann.io 等)には反映されない。これは意図的な範囲(自分のforkでの検証)。

## 8. 周辺の更新

- [x] 8-1 `docs/features/`: 版ごとの EARS 台帳(draft-18 / 22)を作るか、既存の台帳に版の列を足すか決めて実施する。現状は 199 件で、すべて draft-19。**完了(2026-10-05、commit `c7fbe1ef`)。** 新規ファイル方式(`draft-moq-transport-18.md`/stem `MQ18`、`draft-moq-transport-22.md`/stem `MQ22`)。既存draft-19台帳(MOQT-001〜199)を土台に、`draft18-vs-19-diff.md`/`draft19-vs-22-diff.md`を参照して版差分のある項目を書き分け。Coverage: MQ18 197/208 tested+9 indirect+2 untested、MQ22 187/203 tested+10 indirect+6 untested。`tasks/specs/check_features.py`で新設2ファイルにエラー無し確認済み。
  - 方針確認済み(2回の独立調査で一致): 新規ファイル方式(`draft-moq-transport-18.md`/`-22.md`)が適切。`docs/features/README.md` のどの節も「1仕様=1ファイル」で統一されており、版の列を既存ファイルに足す前例が無い。`tasks/specs/FORMAT.md` のルール1は既に draft-19→`MOQT` という stem 対応を想定しているので、18/22 用に別の stem(例 `MQ18`/`MQ22`)を割る必要がある点だけ実装時に明記する。
  - **既知の残課題(本項目のスコープ外として先送り)**: 作業中に既存のdraft-19台帳(`draft-moq-transport.md`)のドリフトを発見。SUBGROUP_DELIVERY_TIMEOUT関連で`test_moqtrun_subscribe_nonzero_timeout_rejected`という実在しない関数名を引用しており(実際は`_accepted`に改名・挙動も「拒否」から「受理して適用」に変化)、`check_features.py`がこれをFUNC NOT IN FILEエラーとして検出する。別途修正が必要。
- [x] 8-2 `docs/security/vuln-ledger.md` の draft-19 由来の行(19 行、V-0784〜V-0802)を版ごとに見直す。調査完了(2026-10-03)、全19行の結論が出た。**反映完了(commit `d1356192`、`scripts/vulnaudit/ledger_check.py` exit 0)。V-0839(§16.3.4 なりすまし防止)は `triaged` で新設、実装は 4-14。**
  - wire format 境界値の4行(V-0799 KVP Length 2^16-1、V-0800 Reason Phrase 1024、V-0801 Track Namespace 32フィールド/4096バイト、V-0802 AbsoluteRange Group ID 2^64-1)はいずれも draft-18/19/22 で数値・意味が同一。4行とも分割せず、draft-18/22 の節番号を引用に追加するだけでよい。
    - V-0801 は draft-22 で節番号が移動(§8.7 "Track Namespace Structure")。
    - V-0802 は draft-22 で LOCATION_FILTER が型指定方式に変わったため、同じ上限を §9.20.9(新 wire 層)と §3.3.1(意味定義)の両方に引用する必要がある。実装側(`moqctl.c:87-91` の `u64_add_ok` オーバーフローチェック)はデコード後の値に対する汎用チェックなので変更不要、デコーダだけ版で分岐すればよい(3-6 と同じ話)。
  - 残り15行(V-0784〜V-0798、SS13 セキュリティ考慮事項由来)もすべて確認済み。draft-18/19 は Security Considerations が §13(同一構成)。draft-22 では全体再構成により §16 に移動し、サブ節も再編(§16.1〜16.4 が旧 §13.1〜13.4 に対応、新設 §16.3.4 Preventing Impersonation ほか §16.5〜16.9 が追加)。
    - V-0784〜V-0790、V-0793〜V-0797: 内容・規範ともに同一(節番号だけ移動)。引用節番号を追加するだけでよい。
    - V-0791、V-0792、V-0798: 文言・節構成が変わるが、規範上の結論(mTLS は identity のみで認可では無い、E2E メディア保護は仕様外で SFRAME/Secure Objects が外部機構)は不変。V-0792 は draft-22 §16.3.1 で RFC 9525 証明書検証の具体的要求が追加されている点を証跡に追記するとよい。
    - **新規行が必要**: draft-22 §16.3.4 "Preventing Impersonation" は既存のどの行にも無い新しい規範(**発行側**の namespace/track 認可を relay が検証する MUST。V-0786/V-0792 は購読側の話で、これは書き込み側の鏡像)。次の空き番号(例 V-0839)で追加する。評価対象は PUBLISH/ANNOUNCE の受理経路(`moqtrun.c` で発行側の認可チェックが無いか、V-0786 と同じパターンで未実装である可能性が高い。実装確認は別途必要)。
- [x] 8-3 guide の moqt 系 snippet 8 本と mdx(en / ja)の版の記述を更新する。版指定の例を 1 本足すかどうかも決める。**完了(2026-10-05)。** 調査した結果、`hub.mdx`(en/ja)だけが「draft-ietf-moq-transport-19」固定のプロトコル紹介文を持っていた(他の discovery/delivery/authorize/fetch/priority-goaway は単発の節番号引用のみで、該当節自体が18/19/22でバイト単位同一のため修正不要)。hub.mdx の冒頭を18/19/22交渉の説明に更新、あわせて「双方向の制御ストリームを開く」という古い記述(Phase C の uni 移行で古くなっていた既存のドキュメント負債)も単方向+bidi互換の正しい記述に修正。**版指定の例を1本足すかどうかの裁定: 追加しない。** `wired_moqt_wt_protocols` の使用例は既に `examples/moqt_interop/wired_server.c:150-154` という実機で動く実例があり、`docs/api-stability.md`にも用途を明記済み(8-4)。guideへの新規snippet追加はビルド・実行・golden生成・`guide-verify`のCI通過という検証コストに対し効果が薄く、YAGNI。
  - 着手点調査済み(2026-10-03): 結論は「今は `moqtclient.go` に版パラメータを追加しない」(YAGNI)。多版 Go テストが1つも存在せず、投機的な汎用化になる。
    - `moqtclient.go` は全関数がフリー関数(receiver 無し)。将来版パラメータが要るなら `Client` 構造体ではなく、確実に版依存とわかっている関数(Fetch/Location 系のみ、`moqctl_rangeloc` 絡みで22のみ表現可能な形がある)にだけ `version int` を1引数追加する。`Subscribe`/`ReadSubscribeReply`/`ReadObject` が実際に版で変わるかは未確認、実装前に draft 差分カタログで確認すること。
    - `moqt-publish/client.go` は `moqtclient` を import せず `varint`/`readMsg`/`str`/`check` を独自実装している(重複、版とは無関係のバグ)。先にこの重複を消すのが最短路(`moqtclient.Varint` 等への置き換え)。
    - 他4スニペットのローカル生リテラル(PUBLISH 0x1D、PUBLISH_NAMESPACE 0x6、GOAWAY 0x10 等)は draft-19 節番号を引用するコメント追加のみで足りる(1本のスニペットしか使わない機能を共有関数に足すのは過剰)。
    - `moqt-priority-goaway/client.go` の `Subscribe` 重複1箇所は呼び出し規約の不一致(直接書き込み vs reply待ちラッパー)があり、コメントのみで留保(判断を人に預ける)。
    - mdx の節番号引用は未確認(draft-19 本文を開いていない)、実装時に埋める。
- [x] 8-4 `docs/api-stability.md`: 版の追加は「0 なら従来どおり」の追加ルールの範囲で行い、その旨を明記する。**完了(2026-10-05)。** 「MOQT is not on this map」節の draft-19 限定の記述を draft-18/19/22 交渉に更新し、`wired_moqt_wt_protocols` を呼ばない/空トークンの場合は従来の draft-19 固定動作のままという追加ルールを明記した段落を追加(`moqtrun_negotiated_ver` のコメントどおりの保守的デフォルト)。
- [x] 8-5 README と interop の README の版の表記を更新する。**完了(2026-10-05)。** `README.md:126`(moqt_interop の説明、draft-19固定→draft-18/19/22を交渉)、`interop/README.md:52-54`(MoQT relay mode の説明、同様)を更新。

## 9. 判断事項(2026-10-03 確定、ユーザー選択)

- [x] 9-1 対応する版: 18 / 19 / 22 のみ。20 と 21 は対象外。
- [x] 9-2 22 の fill fetch: 実装する。
- [x] 9-3 双方向(bidi)制御ストリームの互換経路: 残す。版トークンが空のセッションと、bidi で SETUP を送ってきた相手に使う。
- [x] 9-4 draft-22 の曖昧点の決め打ち(すべて推奨案)。
  - Q-01 FILL_PARAMETERS の値: 先頭に件数 Number of Parameters を置き、その後に Parameter を並べる(通常のメッセージの Parameters と同じ形)。
  - Q-02 FILL 内の LOCATION_FILTER: 送信は type 0x00。受信は 0x00 とゼロ長のどちらも「フィルタなし」として受理する。
  - Q-03 EndObject を持たないフィルタでの FETCH_OK の End Location: 実際に返す最後の Object の Location。範囲が Largest Object に届くなら、その時点の Largest Object。
  - Q-04a type 0x04 で EndGroupDelta=0 かつ EndObject < StartObject: REQUEST_ERROR INVALID_RANGE。
  - Q-04b type 0x05 で FETCH: REQUEST_ERROR INVALID_RANGE。
  - Q-05 SUBSCRIBE_TRACKS のパラメータ: 受信は購読パラメータをすべて受け付けて PUBLISH に引き継ぐ(§3.6.2)。送信は §9.18 の許可リストにあるものだけ。
  - Q-06 PUBLISH で始まった購読の既定値: SUBSCRIBER_PRIORITY は 128、GROUP_ORDER は発行元の既定値(SUBSCRIBE と同じ)。
  - Q-07 PUBLISH で始まった購読の fill: 送信側は REQUEST_UPDATE でだけ要求する。受信側は PUBLISH の ID を参照する fetch stream も、その購読に紐づけて受け入れる。
  - Q-08 fill の reset コード: 購読の取り消しは CANCELLED、FILL_TIMEOUT は DELIVERY_TIMEOUT、上流の失敗は INTERNAL_ERROR。
  - Q-09 MAX_FILTER_RANGES: fill の Range Filter は購読本体と別に数える。
  - Q-10 RENDEZVOUS_TIMEOUT と FILL_TIMEOUT: varint のミリ秒として読む。
  - Q-11 SUBSCRIBE_TRACKS_OK の Track Properties: 送信は空にする。受信で空でなければ中身を無視して受け入れる。
- [x] 9-5 draft-18 と 19 の曖昧点(`draft18-vs-19-diff.md` §13)の決め打ち(2026-10-03 確定、ユーザー選択)。
  - Q18-01(0x1E の扱い、`draft18-vs-19-diff.md` §13-1): **-18 相手互換のため 0x1E も受理**。送信は常に 0x7(REQUEST_OK)。受信時のみ、draft-18 セッションに限り 0x1E を 0x7 と同じに扱う(推奨の「常に未知タイプとして拒否」ではなく、相互運用性を優先)。
  - Q18-02(GROUP_ORDER と PUBLISH の矛盾、§13-2): 個別規定(§10.19.1)を優先し、SUBSCRIBE_TRACKS 由来の PUBLISH には GROUP_ORDER パラメータを含める。許可リストの矛盾は無視する。
  - Q18-03(パラメータ削除可否、§13-3): Range Filter だけ Length=0 で削除可能。他の一般パラメータは削除不可のまま(PROTOCOL_VIOLATION)。
  - Q18-04(Range Filter の符号化、§13-4): SetID/Property Type は Length=0(削除)の場合のみ省略。Length は SetID・Property Type を含む全バイト数。食い違いは INVALID_FILTER で拒否。
  - Q18-05(データグラムでの delivery timeout Object Property、§13-5): 未定義入力として PROTOCOL_VIOLATION で拒否。
  - Q18-06(MAX_REQUEST_UPDATES のクレジット回復数、§13-6): coalesce した REQUEST_UPDATE の件数分だけクレジットを回復する。
  - Q18-07(publisher 側 REQUEST_UPDATE への Range Filter、§13-7): PROTOCOL_VIOLATION でセッションを閉じる。
- [x] 9-6 対象範囲は「18 / 19 / 22 を漏れなく」。draft-19 で未実装の項目(`docs/features/draft-moq-transport.md` の Not implemented 節)も実装対象に含める(10 章)。

## 10. draft-19 の未実装項目の完遂(9-6 により対象範囲に追加)

- [x] 10-1 予約された namespace と `.session` の拒否(MOQT-028)。E-1 完了: `moqtrun_ns_reserved` を追加し `moqtrun_disc_verdict` と `moqtrun_route_subscribe` の両方に配線(cabe7717)。
  - 着手点調査済み: 現状どの namespace 受理経路にも予約プレフィックス検査が無い。仕様の規範は2つだけ(先頭フィールドが `.` 単体 → DOES_NOT_EXIST、`.session` → このhubにはApplication側のセッショントラック機構が無いので常に未認識 = DOES_NOT_EXIST)。新規述語 `moqtrun_ns_reserved` を1つ作り、`moqtrun_disc_verdict`(`moqtrun.c:2055-2064`、PUBLISH_NAMESPACE と SUBSCRIBE_NAMESPACE 両方がここを通る)に差し込むのが最短路。プレーンな PUBLISH/SUBSCRIBE の埋め込み namespace(`moqtrun_route_subscribe`、`moqtrun.c:1197`)にも同じ述語を通す必要がある。
- [x] 10-2 SUBSCRIBE_TRACKS(現状は NOT_SUPPORTED)。PUBLISH の生成、パラメータの引き継ぎ、PUBLISH_SKIPPED を含む。**完了(2026-10-05、E-2、commit `26c0c138`/`816511eb`)。** TLA+設計検証(`tasks/loopeng/moqt/MoqtHubPublish/`、safety/liveness共にmodel checkでNo error、外部レビュー合格)→実装。T-01〜T-12の受け入れテストが`tests/app/moqtrun_subtracks_test.c`(9件)+`tests/app/moqns_test.c`(3件)で対応。三点ゲート+フルunity build全green。
  - **着手点調査済み、他の10章項目より規模が大きいと判明。** 核心の欠落は decode ではなく、「hub が自発的に PUBLISH を開始する」経路が一切存在しないこと。`moqctl_publish_encode` は存在するが呼び出し元がゼロ(現状の hub は常に PUBLISH を受信する側で、送る側になったことが無い)。この新しい送信経路(track ごとに新規ストリームを開いて PUBLISH または PUBLISH_SKIPPED を送る)の設計自体が前提として要る。
    - decode: `moqctl_subscribe_tracks` 構造体が未定義。`moqns_subscribe_take`(`moqns.c:19-22`、request_id+ns+params の同形)を手本にする。
    - パラメータ引き継ぎの規則は Q-05/Q18-02 で決定済み(受信は全パラメータ許容、送信は許可リストのみ、GROUP_ORDER は個別規定優先で含める)。抽出ヘルパーは `moqtrun_sub_scalars`(`moqtrun.c:940-954`)を流用できる。
    - namespace の prefix 照合は `moqtrun_disc_starts` が既存で再利用可能。track 側の namespace は `wired_moqtrun_track.ns/ns_len`(`moqtrun.h:486-490`)。
    - PUBLISH_SKIPPED(10-8と共通)も同じ「hub発の新規送信経路」が無ければ送れない。
- [x] 10-3 PUBLISH_DONE の Stream Count を実際の数で送る。旧来の制御ストリーム上の購読への PUBLISH_DONE をどう扱うか決める。E-1 で検証のみ(再実装不要、D-2 で既に完了済みと確認): Stream Count 実数化は D-2(`moqtrun_sub_done`/`moqtrun_done_emit`、`moqtrun.c:6221-6258`)が既に完了、`MOQTRUN_DONE_STREAMS_UNKNOWN` は残存ゼロ。残課題「旧来 bidi 購読の扱い」も検証: `p->legacy`(`wired_moqtrun_peer`)は制御ストリームの開設方式(bidi 即時 vs uni+SETUP type prefix)のみに影響し(`moqtrun_ctl_open`/`moqtrun_init_peer`、`moqtrun.c:181-229`、使用箇所は `moqtrun.c:187,192,214,5488` の4箇所のみ)、`wired_moqtrun_sub`/`wired_moqtrun_req`/`stream_count` 系(`moqtrun.c:1198,1366,2260,2309,3996,4127,5122,6226,6247` の全increment/送信箇所)はどこも `legacy` を分岐条件にしていない。両経路は確立後は同一構造体・同一送信経路(`moqtrun_req_queue`)を共有しており統一済み。
- [x] 10-4 SUBGROUP_DELIVERY_TIMEOUT(0 以外の値)。発行側の Track Property の timeout と購読側の値の min() を取る。E-1 完了: `wired_moqtrun_track` に timeout フィールド追加、`moqtrun_sub_late` に track を渡して `u64_min`(a16bf538)。
  - 着手点調査済み: 現状は非ゼロの SUBGROUP_DELIVERY_TIMEOUT を即 NOT_SUPPORTED で拒否している(`moqtrun.c:229-237`、SUBSCRIBE/REQUEST_UPDATE 双方)。発行側の Track Property 値は `moqctl_publish.track_properties` が未解析の生バイトのまま(`moqctl.h:343-349`)で、`wired_moqtrun_track` にも timeout フィールドが無い。着手は `moqtrun_handle_publish`(`moqtrun.c:779-798`)で発行側タイムアウトを decode して `wired_moqtrun_track` に新規フィールドとして持たせ、`moqtrun_sub_late`(`moqtrun.c:1000-1004`、現状 track を受け取っていない)に track を渡して `u64_min` する。NOT_SUPPORTED のゲート自体を外すかどうかも合わせて決める。
- [x] 10-5 PUBLISH、FETCH、namespace 系リクエストへの REQUEST_UPDATE。失敗した namespace の更新ではリクエストストリームを閉じる。E-1 完了: PUBLISH は D-1(041b9ef4)で既に開放済みと確認(スコープ外)。FETCH/PUBLISH_NAMESPACE/SUBSCRIBE_NAMESPACE への REQUEST_UPDATE を開放、ctx を `wired_moqtrun_req.kind` で分岐、失敗時は FETCH はデータストリームリセット、namespace 系は `moqtrun_upd_close_ns` で bidi クローズ(eaccec2a, d70046ed)。副産物の根本修正: `moqtrun_disc_rel` の重複/overlap走査が自分自身を含んでいたバグ(update時に常に自己overlapする)を self-exclusion で修正。
  - 着手点調査済み: `moqtrun_handle_update`(`moqtrun.c:1906-1920`)は `moqtrun_upd_is_sub` で SUBSCRIBE 以外を即 NOT_SUPPORTED にしている。`wired_moqtrun_req.kind`(`moqtrun.h:397`)は既に全リクエスト種別を保持しているので分岐の材料はすでにある。codec 側も `MOQCTL_PCTX_UPDATE_FETCH`/`UPDATE_SUBSCRIBE_NAMESPACE`/`UPDATE_SUBSCRIBE_TRACKS`/`UPDATE_PUBLISH_NAMESPACE` のコンテキストを `moqctl.h:119-123` に持つ(ただし `UPDATE_PUBLISH` は無く新設が要る)。namespace 更新失敗時にストリームを閉じる関数 `moqtrun_upd_close_ns`(`moqtrun.c:1892-1896`)は実装済みだが、現在は「NOT_SUPPORTED の一括拒否」経路でしか呼ばれておらず、実際に namespace 更新を試みて失敗した場合の呼び出しに置き換える必要がある。
- [x] 10-6 FETCH の GROUP_ORDER(降順)。不正な FETCH はセッションを閉じる。E-1 完了: `moqfetch_group_down` を配信側に配線、decode失敗は `moqtrun_close_with` でセッションクローズ(31b0ad43)。
  - 着手点調査済み: GROUP_ORDER パラメータは decode はされる(`moqctl.c:378`)が FETCH の処理では読まれていない。明示的な `ponytail:` コメントで「常に昇順、GROUP_ORDER は参照しない」と書かれている(`moqtrun.c:1614` 付近)。降順の算出ロジック自体は `moqfetch_group_down`(`moqfetch.c:167-171`)としてデコード側に既にあるが、hub の配信側(`moqtrun_fetch_obj_of`、`moqtrun.c:1338-1350`)はこれを呼んでいない。不正な FETCH(`moqfetch_fetch_take` の decode 失敗)は現状 `moqtrun_handle_fetch`(`moqtrun.c:1619`)で無言で `return` するだけ、セッションは閉じない(REQUEST_UPDATE の同種失敗は `moqtrun_close_with` を呼んでおり、こちらを手本にすればよい)。2つの修正は独立している。
- [x] 10-7 後から来た購読者を live に接続するとき、Location Filter の開始 Object から始める(MOQT-108)。E-1 完了: `moqtrun_live_attach` が `slot->start.group`(現在groupにクランプ)を使うよう1箇所修正(0349a918)。
  - 着手点調査済み: SUBSCRIBE 解決時点では `wired_moqtrun_sub.start` に正しいフィルタ開始値が格納される(`moqtrun_sub_filter`、`moqtrun.c:925-936`)。以降の定常ティックは `moqtrun_live_due`/`moqtrun_sub_wants_group` 経由で正しく `start.group` を尊重している。ギャップは attach 直後の **初回送信 1 回だけ**: `moqtrun_live_attach`(`moqtrun.c:2769-2783`)が `slot->start` を無視して常に「現在の group」を送っている。修正はこの1箇所、`moqtrun_live_send_one` への引数を `slot->start.group`(現在groupより前なら現在groupにクランプ)に変えるだけ。
- [x] 10-8 PUBLISH_SKIPPED の送受信。**完了(2026-10-05、E-2、10-2と同じ実装・コミット)。** Skip選択条件の裁定(design.md section5): 新規PUBLISH用のbidi streamを確保できないときに限定(「trackにデータが無い」はSkip理由にしない)。
  - 着手点調査済み: 完全に未実装(送受信とも)。`docs/features/draft-moq-transport.md:1276` の記載と一致。
    - decode/encode: `moqctl_publish_skipped` 構造体と `_take`/`_encode` が `moqctl.h`/`.c` に無い。`moqctl_publish_done_take`/`_encode`(`moqctl.h` 400行付近)と同じ形で新設する。
    - 受信: `moqtrun_ctl_table[]` の `{0xF, moqtrun_dispatch_skip}`(`moqtrun.c:2340`)が中身を読まずに捨てている。専用ハンドラに置き換える。
    - 送信: 既存のギャップ検出箇所は2つ(`moqtrun_live_gap`、`moqtrun.c:2699-2706`、live track 用。`moqtrun_relay_skips`、`moqtrun.c:3094-3109`、peer-relay 用)が、どちらも統計カウンタに積むだけで PUBLISH_SKIPPED を送っていない。送信関数は `moqtrun_sub_done`(PUBLISH_DONE 送信、`moqtrun.c:4564` 付近)と同じ `moqtrun_envelope_put` + `moqtrun_req_queue` の形で新設する。
- [x] 10-9 Range Filter(0x25〜0x29)の評価、MAX_FILTER_RANGES、REQUEST_UPDATE での置き換えと削除。E-1 完了: `MOQCTL_PENC_RANGEFILTER` 新設、Length=0削除を一般実装、`moqctl_param_dup` を (type,SetID) 単位に修正、配信ゲート配線(7236422f, 5a01816b, f14a20a7)。
  - 着手点調査済み: `moqctl.c:365-386` の `MOQCTL_PARAM_RULES[]` は5行とも登録済みだが enc が `MOQCTL_PENC_BYTES`(生バイトのまま、未解釈)。`moqctl_locfilter`/`MOQCTL_PENC_LOCFILTER`(`moqctl.c:479-490`, `moqctl.h:186-196`)を複製して `MOQCTL_PENC_RANGEFILTER` を追加するのが最短路。Length=0 削除(Q18-03/Q18-04)は現状どのパラメータにも無い概念で新規実装が要る。
  - 配信ゲートは `moqtrun_sub_gets`/`moqtrun_sub_gets_loc`(`moqtrun.c:991-998`)の1箇所に集約。呼び出し元は `moqtrun_relay_append_all`(:3100)、`moqtrun_dg_fanout`(:4355)、ほか2箇所(:2867, :3851)。解決は `moqtrun_sub_filter`(:925-936、SUBSCRIBE/REQUEST_UPDATE 時に1回)、評価は配信時、という既存の Location Filter と同じ分離パターンを複製する。保存先は `wired_moqtrun_sub`(`moqtrun.h:171-205`)。
  - 同一 SetID の重複フィルタの一意性チェック(`moqctl_param_dup`、`moqctl.c:524-535`)は type だけで判定しており `(type, SetID)` 単位になっていない既存の穴。
- [x] 10-10 MAX_REQUEST_UPDATES のクレジットと TOO_MANY_REQUEST_UPDATES。E-1 完了: `wired_moqtrun_req.pending_updates` 追加、`moqtrun_handle_update` でゲート、クレジット回復は `moqtrun_req_flush` 成功時にリセット(b954eae0)。
  - 着手点調査済み: 既存のクレジット系カウンタは無い(grep 済み、"credit" はすべて QUIC/WT の流量制御で無関係)。`wired_moqtrun_req`(`moqtrun.h:392-426`)に `pending_updates` を追加し、`moqtrun_handle_update`(`moqtrun.c:1906-1920`)でゲートする。
  - Q18-06(coalesce した件数分のクレジット回復)の実装場所は `send_bufs`/`armed_idx` のまとめ返信機構(`moqtrun.h:401-405`、コメントが既にこの coalescing を指している)。
- [x] 10-11 Setup Options(AUTHORIZATION TOKEN、MAX_FILTER_RANGES、MAX_REQUEST_UPDATES)を広告し、受け取る。E-1 完了: `moqctl_setup` に両フィールド追加、decode/encode配線(1852080a, 99c8ad04)。
  - 着手点調査済み: `MAX_FILTER_RANGES`(0x06)、`MAX_REQUEST_UPDATES`(0x08)は `moqctl.h:76-78` に定義が無い(現状は PATH/AUTHORITY/MOQT_IMPLEMENTATION の3つのみ)。`moqctl_setup`(`moqctl.h:305-312`)に u64 フィールドを追加し、decode は `moqctl_setup_apply_kvp`(`moqctl.c:703-709`)、encode は `moqctl_setup_encode`/`moqctl_setup_put_opt`(`moqctl.c:739-767`)。varint 値か raw span かは `moqkvp` の `is_raw` を実装時に要確認。

## 11. 実行順序(フェーズ)

各フェーズで、テストリストの作成 → Red → Green → Refactor の順に回す。コミット前の門は `.claude/rules/build-and-verify.md` に従う。

1. **A 設計の固定**(並行): TLA+(1-1、4-6、5-2)、Lean(3-6、3-7、3-8)、draft-18 と 22 の EARS 抽出(8-1 の材料)。
2. **B 基盤**: 2 章(版テーブルと交渉)と 1 章(uni の制御ストリーム、bidi 互換経路)。
3. **C codec の版化**: 3 章。
4. **D draft-19 の完遂**: 10 章。
5. **E draft-18 の振る舞い**: 4-1〜4-4。
6. **F draft-22 の振る舞い**: 4-5〜4-14(fill fetch を含む)。
7. **G 版をまたぐ中継**: 5 章。
8. **H WebTransport draft-16**: 6 章(B〜G と並行してよい。触るのは srvrun だけ)。
9. **I クライアントと検証資産**: 1-6、7-3〜7-5。手法選定の下調べ済み: `tasks/loopeng/moqt/test-method-assignment.md`(X18/X22/X19U 計223項目の手法割り当てと懸念タイプ分類。`hymme:test-catalog` 本番ワークフローの入力)。
10. **J ドキュメントと guide**: 8 章。
11. **K 対向試験**: 7-6。draft の対象外以外の理由で落ちたケースは調査して直し、台帳に原因、修正コミット、ログの所在を記録する。

## 12. interop 全 PASS とレビューで判明した追加項目(2026-10-05 追加、ゴール: 台帳全完了 + CI green + docs 整合 + moq-interop-runner 全 PASS(クライアント起因を除く))

- [ ] 12-1 rendezvous(RENDEZVOUS_TIMEOUT、d18/19 §10.2.6、d22 §9.20.6)。設計・TLA+ 済み(`tasks/loopeng/moqt/Rendezvous/`、MC_main 332,392 distinct states で安全性+活性 OK、MC_bug が `moqtrun_req_answered` の `kind && !live` による held SUBSCRIBE の無応答クローズを再現)。実装中。
- [x] 12-2 publisher の PUBLISH_DONE を各購読者へ転送。**完了(2026-10-05)。** `moqtrun_dispatch_pub_done`: status は購読者の版で `moqctl_publish_done_for` 変換、Stream Count は hub が各購読者へ開いた本数。d18/19 §10.11・d22 §9.9 の「全ストリームを閉じてから PUBLISH_DONE」に従い、publisher の申告本数の上流ストリームを観測し relay が空くまで待機(上限 `WIRED_MOQTRUN_PUBDONE_WAIT_MS`=2000ms、超過時は残ストリームを reset)。RESET/セッション close 待機中は publisher の status で即送信。テスト `tests/app/moqtrun_done_test.c`(12 シナリオ×3版+pub×sub 3×3)。既知の穴: ヘッダ+FIN のみの上流ストリームは track に解決されず計数外(2s 上限で吸収)。
- [ ] 12-3 PUBLISH_NAMESPACE を出した publisher への上流 SUBSCRIBE(d18/19 §9.4、d22 §7.4: relay MUST send SUBSCRIBE upstream、上流確立後に SUBSCRIBE_OK)。interop `announce-subscribe`(aiomoqt, stitcher)/`subscribe-before-announce`(stitcher) が依存。12-1 の hold 表に接続する。
- [x] 12-4 Track Alias の不一致(5-4 作業中に発見)。**バグ確定・修正済み(2026-10-05)。** SUBSCRIBE_OK は track ごとのカウンタ(`moqtrun_next_alias`)で alias を出し、relay は publisher の alias のまま素通ししていた。さらに 1 セッション内で 2 track が同じ alias 0 になり DUPLICATE_TRACK_ALIAS 違反(d22 §3.1.3 / d19 §11.1)。修正: `moqtrun_session_alias` が購読側セッションで publisher の alias が空いていればそれを、衝突時は最小の空き番号を割当て、`moqtrun_alias_splice` が relay ヘッダの alias だけを書き換え(一撃/keep-open/ring 初回・遅延参加/datagram)。再 attach は通知済み alias を維持、E-2 の hub 発 PUBLISH も同じ割当て。テスト `tests/app/moqtrun_alias_test.c`(9本、Red で 12 CHECK 失敗を確認)、`test_moqtrun_chat_and_audio_get_different_aliases` を正しい期待値(!=)へ修正。
- [ ] 12-11 E-2 の hub 発 PUBLISH は REQUEST_OK 後に `q->live` を立てるだけで購読スロットを作らず、Object が relay されない疑い(12-4 作業中に発見)。
- [x] 12-5 MAX_REQUEST_UPDATES の credit 検査が版ゲートされていない(d18 には無い制限で 0x1B close される、`moqtrun.c` の credit 検査)。docs 監査で発見。
  - 完了: `moqtrun_upd_over_credit` を `MOQVER_CAP_MAX_REQUEST_UPDATES` でゲート。d18 は 5 件積んでも閉じず全件 REQUEST_OK(`tests/app/moqtrun_vgate_test.c` `test_moqtrun_vgate_update_credit`)、既存 `test_moqtrun_upd_credit_too_many` は cap 保有版のみで実行。
- [x] 12-6 REQUEST_UPDATE で自分の PUBLISH を更新する経路が d18/d19 で拒否される(`moqtrun_upd_is_pub` が d22 のみ許可)が、d18/d19 §10.9 は PUBLISH を更新可能な要求に含む疑い。SUBSCRIBE_TRACKS の更新も NOT_SUPPORTED。仕様を再確認して修正。
  - 完了: d18/d19 §10.9・d22 §9.5 は逐語で同文「The sender of a request (SUBSCRIBE, PUBLISH, FETCH, PUBLISH_NAMESPACE, SUBSCRIBE_NAMESPACE, SUBSCRIBE_TRACKS) can later send a REQUEST_UPDATE」。d22 §9.8 に PUBLISH 更新の記述は無く cap の根拠が無いため `MOQVER_CAP_UPDATE_ON_PUBLISH` を削除し全版で受理。SUBSCRIBE_TRACKS の更新は「MUST respond with exactly one REQUEST_OK or REQUEST_ERROR」を NOT_SUPPORTED で満たす(受理義務なし)ので文書化のみ。`test_moqtrun_vgate_update_kinds`。残: d19/d22 の「other than in the two cases above MUST close the session with a PROTOCOL_VIOLATION」(TRACK_STATUS/制御ストリームの REQUEST_UPDATE は現状 NOT_SUPPORTED)、hub 発 PUBLISH stream 上の購読者 REQUEST_UPDATE が無応答(`moqtrun_pubst_route` が読み捨て)。
- [x] 12-7 hub 発 PUBLISH は版非依存の `moqctl_publish_encode` で encode、受信側 `moqctl_publish_take` は版引数あり。d18/d22 ピアへのワイヤが正しいか固定テストで確認。
  - 完了: PUBLISH のワイヤは d18/19 §10.10・d22 §9.8 で同一レイアウト(版非依存 encode で正しい)。固定バイト照合+購読者の版での decode テスト `test_moqtrun_vgate_hub_publish`。発見した不具合: d19 の GROUP_ORDER 許可集合に PUBLISH が無く、d19 §10.19.1「will include the GROUP_ORDER parameter」の hub 発 PUBLISH を d19 decoder が拒否していた。Q18-02 の裁定は d19 本文(§10.19.1 は d19 にのみ存在、d18 §10.19 は FORWARD のみ反映)なので、GROUP_ORDER ctx を d19=0x1015、d18=0x19(§10.2.8: SUBSCRIBE, PUBLISH_OK, FETCH)に修正。残(未対応): d22 §3.6.2 は SUBSCRIBE_TRACKS の全 Subscription パラメータを PUBLISH で「explicitly communicated」とするが hub は FORWARD/GROUP_ORDER のみ反映。
- [x] 12-8 古いコメント/ログの修正: `moqtrun.h:15`、`moqtrun.h:791-796`、`moqfetch.h:7`、`moqns.h:7`、`moqtstat.h:7`、`moqdata.h:8`、`moqdg.h:9`、`moqctl.h:49`、`moqtrun.c` の「non-zero SUBGROUP_DELIVERY_TIMEOUT を拒否」コメント、`moqver.c:7`(選好順の記述が実装と不一致)、`examples/moqt_chat/wired_server.c:331` のログ。
  - 完了: 各 .h の版記述を 18/19/22 に、authorize hook の呼び出し範囲(SUBSCRIBE/TRACK_STATUS/PUBLISH)、`moqtrun_subscribe_checked` コメント、moqver の「選好順」(実際は srvrun_wt_select がクライアントの offer 順で選ぶ)、moqt_chat の案内文(サブプロトコル交渉なし=draft-19)を修正。`just docs` 通過。
- [x] 12-9 MoQT 以外の features 台帳の古いテスト参照: `docs/features/rfc8446.md:270,329`(`test_sdrv_psk_ticket_open_fails_falls_back`)、`rfc9220.md:87`(`test_h3cancel_request`)、`rfc9368.md:63`(`test_verselect_pick`)。
  - 完了: rfc9368/rfc9220/rfc8446-044 は現存テストへ付け替え。8446-053(未知 PSK は無視して full handshake)は E.6 を優先して decrypt_error で abort する意図的逸脱のため `[ ]` + gap に変更(README 集計更新)。
- [ ] 12-10 moq-interop-runner をローカルで全クライアントと対向させ、全 PASS(クライアント起因を除く)を `logs_*` 付きで記録。ベースライン計測中。

- [ ] 12-17 (12-6 で発見) d19/d22「上記 2 ケース以外の REQUEST_UPDATE を受けたら PROTOCOL_VIOLATION で close」(MUST)。TRACK_STATUS ストリーム・制御ストリーム上の REQUEST_UPDATE に hub は NOT_SUPPORTED を返している。
- [ ] 12-18 (12-6 で発見) hub が開いた PUBLISH ストリーム上で購読者が送った REQUEST_UPDATE を `moqtrun_pubst_route` が黙って捨てる(「ちょうど 1 つ応答」違反)。
- [ ] 12-19 (12-7 で発見) d22 §3.6.2: SUBSCRIBE_TRACKS の全パラメータを PUBLISH で明示的に伝える。hub は FORWARD と GROUP_ORDER のみコピー。
- [x] 12-12 (7-1 F-A1) **修正済み(2026-10-05)**: 最初の varint が切れた配送は `moqtrun_pre_stash` で保留し、次の配送で完成させてから分類(uni/bidi 両経路、hold 再生も `moqtrun_dispatch_held` 経由)。テスト `tests/app/moqtrun_ctlfix_test.c`(1 バイト分割/1 バイトずつ、3 版)。 制御ストリームの最初の配送が SETUP の 2 バイト型の 1 バイト目(0xAF)だけだと、hold に入って二度と再生されずセッションが確立しない(`moqtrun_fresh_uni_ctl`/`moqtrun_hold_has`、bidi 側 `moqtrun_bidi_is_setup` も同型)。RFC 9000 §2.2 で分割は合法。修正案「完全な varint を待ってから分類」は TLC `MC_splitfix` で検証済み。
- [x] 12-13 (7-1 F-C1) **修正済み(2026-10-05)**: `moqtrun_take_or_close` で PUBLISH/SUBSCRIBE/TRACK_STATUS/PUBLISH_NAMESPACE・SUBSCRIBE_NAMESPACE/SUBSCRIBE_TRACKS の decode 失敗を PROTOCOL_VIOLATION close に統一。`test_moqtrun_goaway_request_id_ignores_malformed` は空本文 SUBSCRIBE が close されることを期待するよう修正。 送信者の版に無いパラメータ付きの SUBSCRIBE(d19 の FILL_PARAMETERS、d18 の Range Filter 等)を黙って捨て、無応答でストリームが宙づり。d18/19/22 とも PROTOCOL_VIOLATION で close(d19 §10.2)。同型: PUBLISH、TRACK_STATUS、PUBLISH_NAMESPACE/SUBSCRIBE_NAMESPACE、SUBSCRIBE_TRACKS。FETCH/REQUEST_UPDATE は正しく close 済み(手本)。
- [ ] 12-14 (7-1 F-B1) FILL_PARAMETERS に LOCATION_FILTER が無い場合、d22 §3.4 は購読の Location filter を使うが、hub は track 全体を fill(`moqfetch_fill_filter_of` が「無し」を 0x00 と同一視)。
- [ ] 12-15 (7-1 F-B2) 不正な FILL_PARAMETERS を黙って無視(SUBSCRIBE_OK 送信後に `moqtrun_fill_from_param` が return)。d22 §9.20.15/§9.20 は PROTOCOL_VIOLATION close。
- [ ] 12-16 (7-1 F-B3) fill 表満杯時、受理済み(SUBSCRIBE_OK/REQUEST_OK 送信済み)の fill を開かずリセットもしない(d22 §3.4.1 違反)。4-6 の 2026-10-04 裁定は「受付時点で拒否」という誤った前提に立っていたので見直す。あわせて track retire 時に fill が INTERNAL_ERROR reset でなく timed-out marker+FIN で終わる件(Q-08)も確認。

## 13. raw QUIC 上の MoQT(2026-10-05 ユーザー指示で追加)

- [x] 13-0 計画: `tasks/loopeng/moqt/RawQuic/plan.md`(版ごとの仕様 R1-R17、runner 連携、アーキテクチャ、TLA+ 対象、並列分割、TDD リスト、リスク K1-K14)。
- [x] 13-1 インタフェース凍結(S0a)**完了(2026-10-05)。** `salpn_raw.h`/`rawq.h`/`moqraw.h`/`moqrawio.h` 新設(宣言のみ)、`SALPN_RAW`、`wired_srvboot_id.raw_alpns`、`wired_srvrun_opt.raw_on_session/raw_session_ctx`、`wired_server_session_is_raw`。plan §4.2 からの差分 5 件と各宣言の担当ステップは `tasks/loopeng/moqt/RawQuic/INTERFACES.md`。: `salpn_raw.h`/`rawq.h`/`moqraw.h`/`moqrawio.h` と srvrun.h/srvboot.h の追加宣言。名前は plan §4.2、着手前に再 grep。
- [ ] 13-2 TLA+ `MoqtRawConn`(S0b/S5): 接続→raw セッション生成・配送・クローズ・スロット再利用。安全性 SessBeforeData/CloseOnce/CloseIffSession/NoGhost/NoH3OnRaw/RawCloseShape/PathRule、活性 2、ミューテーション 4 件で反例確認、reviewer 合格。
- [ ] 13-3 ALPN 選択(S1+S6+S8): `SALPN_RAW`、`wired_srvboot_id.raw_alpns`、クライアント選好順で h3/hq/moqt-NN を混在選択、EE と ticket に選択トークン、raw ALPN では 0-RTT 拒否(d18 §3.3.1 / d22 §6.3.1 の relay MAY)。固定バイト T-A4。
- [ ] 13-4 raw 束縛ヘルパ(S2): `app/rawquic/rawq_*`(ストリーム経路、reset コードの無変換/WT 写像、datagram 前置なし、uni 初番 3)。T-B1〜B4。
- [ ] 13-5 srvloop の raw 経路(S7): raw ALPN 接続ではクライアントの全 bidi/uni を sig_len 0 で WT スロットへ、h3 要求/QPACK 経路に入れない。T-E3。
- [ ] 13-6 srvrun の暗黙セッション(S9): 確認時に生成し `raw_on_session`、H3 制御/QPACK を開かない、uni id 3 起点、datagram に qsid なし、reset コード無変換、クローズは CONNECTION_CLOSE 0x1d(MoQT コード)、on_session_close はちょうど 1 回。T-E1〜E10(E5/E6/E7 は固定バイト)。
- [ ] 13-7 MoQT raw ポリシー(S3): PATH(0x01)/AUTHORITY(0x05) を raw では受理、不正形式は MALFORMED_PATH 0x9 / MALFORMED_AUTHORITY 0x1A、フック拒否は 0x8/0x19、WT は従来どおり 0x8/0x19(d18 §10.3.1.1-2、d19 §10.3.1.1-2、d22 §9.1.1-2)。T-C1〜C5。
- [ ] 13-8 io 多重化(S4): `wired_moqraw_io()`、WT セッションだけ signal 前置、moqt_interop/moqt_chat の `open_signalled` 重複を除去。T-D1〜D4。
- [ ] 13-9 hub(S10、他エージェントの moqtrun.c 作業のマージ後): `wired_moqt_on_session_raw`、peer.raw、`moqtrun_setup_opt_bad` を moqraw へ委譲、`hub.raw_policy`。T-F1〜F4。
- [ ] 13-10 example/interop(S11): moqt_interop が同一ポートで h3 と moqt-22/19/18 を受ける、run_endpoint_moqt.sh の `MOQT_TRANSPORT`、runner fork に `wired-quic`(`moqt://relay:4443`、同一イメージの再タグ)を追加し `wired` の notes から "WebTransport only" を外す。
- [ ] 13-11 検証: in-process raw ループバック T-L1、実ピア固定トレース T-L2(xquic-draft-18 と moqtopus の SETUP/ALPN を golden 化)、runner 行列 T-L3(moqtopus/xquic-draft-18/mlmtest/quic-zig/moq5/aiomoqt → wired-quic、`results/<ts>/` ログ付き)。T-L2 が揃うまでワイヤに出る項目は `[~]` のまま。
- [ ] 13-12 配線・文書・ゲート(S12): run.c 配線、`docs/api-stability.md`(新 `wired_*`)、features ページの transport 行、moqtrun.h の WT 前提コメント、`just docs`/`just fuzz-smoke`/三点ゲート/`just test`、valgrind 1 回。
- 対象外(再登録条件つき): raw 上の 0-RTT 受理(条件: 0-RTT を要求する対向が現れたとき)、トランスポート別の GOAWAY URI(条件: 混在環境で https:// 前提の WT クライアントへ移行先を出す必要が出たとき)、wired 側 raw MoQT クライアント(条件: relay 以外の role を runner に登録するとき)、`moq-00`(draft-14 以前)の ALPN。

## 14. printf 互換の出力関数(2026-10-05 ユーザー指示で追加、他の全項目完了後に着手)

- [ ] 14-1 SDK に printf 互換関数を追加する(libc 非依存)。対応: 10進(%d/%i/%u、長さ修飾子)、16進(%x/%X)、小数(%f 系)、アドレス(%p)、文字列(%s、英語 ASCII)、文字(%c)、%%、可変引数。幅・精度・0埋め・左寄せの基本フラグ。
- [ ] 14-2 guide のサンプル、examples、デバッグ出力など、文字列を組み立てて出力している箇所をすべて 14-1 に置き換える。

## 対象外

- draft-14〜17 への対応。制御ストリームの形と varint が違う別時代で、先行実装でも adapter が必要になっている。
  - 再登録の条件: interop の対向で 17 以下しか話さない主要実装を拾う必要が出たとき。
- raw QUIC(ALPN `moqt-NN`)での MoQT。wired の MoQT は WebTransport 専用。
  - 再登録の条件: interop の raw QUIC 列を埋めると決めたとき。
