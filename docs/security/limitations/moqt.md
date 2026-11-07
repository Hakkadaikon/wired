# 既知の制限: MoQT

[ドキュメント](../../README.md) › [セキュリティ設計](../README.md) › [既知の制限](README.md) › MoQT

| 項目 | 内容 |
|---|---|
| 目的 | MoQT のハブ(リレー)の制限を示す |
| 読む人 | ハブを変更するコントリビューター、ハブを本番に入れる人 |
| 前提文書 | [既知の制限](README.md) |
| 関連文書 | [既知の制限: MoQT のドラフトと raw QUIC](moqt-drafts.md)、[既知の制限: MoQT の Track 切り替え](moqt-switching.md)、[容量の上限](capacity.md)、[draft-22 の台帳](../../features/draft-moq-transport-22.md) |

## 1. 用語

MoQT のデータモデルの用語(Track、Group、Subgroup、Object)は guide の「[MoQT へのメディアの載せ方](https://hakkadaikon.github.io/wired/guide/ja/concepts/media-mapping/)」に従う。

| 語 | 意味 |
|---|---|
| ハブ | wired に組み込んだ MoQT のリレー。パブリッシャーから Object を受け取り、購読者へ転送する([MoQT ハブ](https://hakkadaikon.github.io/wired/guide/ja/moqt/hub/)) |
| d18 / d19 / d22 | draft-ietf-moq-transport-18 / -19 / -22 |
| 上流 SUBSCRIBE | 購読者が求めた Track を得るために、ハブがパブリッシャーへ送る SUBSCRIBE(d18/d19 9.4、d22 7.4) |
| ランデブー | その Track のパブリッシャーが現れるまで、ハブが断らずに保留する SUBSCRIBE |
| 信頼リング | 遅れて参加した購読者にストリームを再送するため、ハブが Track ごとに持つバッファー |
| カーソル | 信頼リングの中の、購読者ごとの読み出し位置 |
| 到着マーク | 配送のタイムアウトを適用するために信頼リングが持つタイムスタンプ |
| フィル | SUBSCRIBE が求める履歴 |
| FETCH | 過去の Object の範囲を求めるリクエスト([過去の Object の取得](https://hakkadaikon.github.io/wired/guide/ja/moqt/fetch/)) |
| レッグ | FETCH 1 つのために、ハブが上流へ出す FETCH |

## 2. MoQT リレー(ハブ)

ハブは 1 つの部屋の参加者に合わせた大きさの、単一プロセスのリレーである。上流のリレーも兄弟のリレーも持たない。

### 2.1 Track ごとのパブリッシャーは既定で 1 つ

影響: `wired_moqt_init` の既定値のハブ(moqt_chat)で、複数のパブリッシャーが同じ Track を告知する場合。

既定では Full Track Name ごとに Track を 1 つ持ち、最も新しいセッションが所有する。d22 7.6 の「一致するすべてのパブリッシャーに SUBSCRIBE メッセージを送らなければならない (MUST)」が成り立つのは、`wired_moqt_hub.multi_publisher = 1` のとき(examples/moqt_interop が設定)だけである。

`multi_publisher = 1` では、あとから告知したものを含め、一致するパブリッシャーすべてを購読し、各 Object を各購読へ合流させる。重複の除去は Subgroup のストリーム単位とデータグラム単位で、64 項目の窓で行う。最初のパブリッシャーが途中で終えた Subgroup を、もう一方のコピーで補うことはしない。

参照: `moqtrun_supersede_name`、`moqtrun_mpub.c`、`moqtrun_mpub_dd.c`、`moqtrun_up_fan.c`

### 2.2 フェイルオーバーで待つのは最大 1.5 秒

影響: Track のパブリッシャーが切れ、その名前空間の別のパブリッシャーが告知されている場合の、その Track の購読者。

1. 上流 SUBSCRIBE がパブリッシャー側で終わる。GOING_AWAY か INTERNAL_ERROR の PUBLISH_DONE、ハブのストリームのリセット、パブリッシャーのセッションの終了のいずれかである。
1. 下流の購読は最大 `WIRED_MOQTRUN_RDV_MAX_MS`(1.5 秒)待つ。
1. その間に、ハブはその名前空間を告知している別のパブリッシャーへ 1 つずつ SUBSCRIBE を送る。
1. 最初の SUBSCRIBE_OK で、待っていた購読を、すでに持っている Track Alias(購読者が Track を指す短い番号)のまま通知せずにつなぎ直す。期限までにどこも応答しなければ、各購読に終了時のステータスを付けた PUBLISH_DONE を送る。

ほかのステータスの PUBLISH_DONE と、Malformed Track(Track の規則を破ったパブリッシャー。[2.24](#224-malformed-track-の検出は一部だけ))は、購読をすぐに終わらせる。

参照: `moqtrun_track_ended`

### 2.3 新しい経路を待つ購読はランデブーのテーブルを共有する

影響: パブリッシャーが切れたときに購読者の多い Track。

待っている購読はそれぞれ、ハブ全体の `WIRED_MOQTRUN_MAX_RDV`(16)のテーブルのスロットを 1 つ使う。セッションあたりは最大 `WIRED_MOQTRUN_RDV_PER_SESSION`(4)で、各スロットが Track の期限のコピーを持つ。

待っている購読者が空きスロットより多い Track は、一部だけがフェイルオーバーする。残りには終了時のステータスを付けた PUBLISH_DONE をすぐに送る。テーブルが埋まっている間(最大 1.5 秒)は、新しいランデブーの保留をすべて EXCESSIVE_LOAD で断る。待機と Track 切り替えの関係は [Track 切り替え](moqt-switching.md) にある。

参照: `moqtrun_rp_wait`

### 2.4 SUBSCRIBE_OK の前に保持する SUBGROUP ストリームは 1 本

影響: ハブの SUBSCRIBE に応答する前に送り始めるパブリッシャー。

上流の SUBSCRIBE_OK より先に届いた SUBGROUP ストリームは、パブリッシャーのセッションごとに 1 本、`WIRED_MOQTRUN_EARLY_BUF` = 2048 バイトまで保持し、OK が届いた時点で中継する。2 本目のストリームと、バッファーに収まらないストリームは捨てる。

参照: `moqtrun_early_stash`

### 2.5 信頼リングからの遅れた再送には限りがある

影響: ストリームの途中で参加する購読者。

リングがストリームを保持している間に来た購読者には、そのストリームを再送する。再送は購読者の開始 Object 以降で最初のそのストリームの Object から始める。条件は次の 3 つで、満たさなければそのストリームは購読者に送らない。

- リングが一周していない。
- そのストリームのヘッダーより先まで回収されていない。
- 開始 Object 以降の Object がすでに届いている。

参照: `moqtrun_rel_replay_ok`、`moqtrun_rel_replay`(ponytail)

### 2.6 最初の配送が分断されたストリームを、遅れて参加した購読は飛ばす

影響: ヘッダーが Subgroup ID モード 0b01(Subgroup ID がストリームの最初の Object の ID になる)を使うストリームに参加する購読者。

「分断」は、1 つの Object が 2 回の配送に分かれて届くことを指す。こうしたストリームの最初の配送が最初の Object の途中で終わると、ハブはストリームのヘッダーを保存しない。そのため、あとから参加した購読者にはそのストリームを送らない。

参照: `moqtrun_relay_save_hdr`(ponytail)

### 2.7 購読者のいないリングがパブリッシャーを止める

影響: まだ誰も購読していない信頼 Track のパブリッシャー。

どのカーソルも参加していないリングは、パブリッシャーを最大 `WIRED_MOQTREL_STALL_MS`(10000 ミリ秒)止めることがある。

参照: `moqtrun_rel_drain_one`(ponytail)

### 2.8 リングの到着マークが追記をまとめる

影響: 配送のタイムアウトを使う Track。

`WIRED_MOQTREL_MARKS`(8)を使い切ると、以降の追記は最新のマークにまとめる。そのため、配送のタイムアウトはそのマークからの経過時間を上限として早く発火することがある。

参照: `moqtrel_mark`(ponytail)

### 2.9 フィルと FETCH は容量を超えると断る

影響: 多くの購読者が同時に履歴を求める部屋。

`fetches[]` + `fetch_waits[]`(8 + 8。どちらも `WIRED_MOQTRUN_MAX_FETCHES` で決まる)を超えたフィルは、OK を送る前に REQUEST_ERROR INTERNAL_ERROR で断る。通知なしに捨てることはない。

参照: `moqtrun_fill_room`、`moqtrun_fill_wait_put`(ponytail)

### 2.10 FETCH 自身の Subscriber Priority は使わない

影響: 複数の FETCH の間で優先度を付けるクライアント。

フィルはその購読の Subscriber Priority を使い、Standalone FETCH は既定値を使う。

参照: `moqtrun_fetch_sub_prio`(ponytail)

### 2.11 上流への FETCH は FETCH 1 つにつき 1 回で、そのまま中継する

影響: ハブのキャッシュがすべては持っていない範囲への FETCH。

FETCH の範囲の先頭がキャッシュにないと、ハブは上流に 1 回だけ問い合わせる。上流はその Track のパブリッシャーで、いなければその Track を含む名前空間の告知元である。届いた Object は順にそのまま中継し、まとめも再試行もキャッシュもしない。

| 場面 | 動作 |
|---|---|
| 同じ範囲への 2 つの FETCH | 1 つの上流 FETCH にまとめない |
| 上流のリクエストストリームで GOAWAY を受ける | 出し直さずにレッグを終える |
| 中継した Object | キャッシュしない |
| レッグの持ち時間 | `WIRED_MOQTRUN_UPFETCH_BUDGET_MS`(2000 ミリ秒)に固定。FILL_TIMEOUT のほうが短ければそちら |
| Object の途中で終わったレッグ | 下流の fetch ストリームを INTERNAL_ERROR でリセット(キャッシュ側は Object の途中から再開できない) |
| d19 の Joining FETCH(進行中の購読を基準に始まる FETCH) | キャッシュだけから応える |
| ハブが持っていない Track への Descending FETCH(新しい Group から順に返す FETCH) | 上流 FETCH が失敗するとリセット(ハブはその範囲を知らず、印を付けられない) |

レッグが Object の途中で終わるのは、上流が Object を途中で切ったとき、一部が書き込み待ちのうちに持ち時間が尽きたとき、保持していた末尾が収まらなかったときである。

キャッシュ側は FETCH の Range Filter を Object ID だけで適用する。キャッシュは Subgroup、優先度、Properties を保持しないので、それらのどれかを指定したフィルターの組はキャッシュ済みの Object を 1 つも通さず、印のない(不明の)欠落を残す。

Joining FETCH は Range Filter を適用しない(`moqtrun_fsel_skip`、MQ22-137。`moqtrun_live.c` の `moqtrun_fetch_joining` が捨てる)。

バッファリングの詳細は次のとおりである。

- `WIRED_MOQTRUN_RELAY_FRAG_MAX`(16 KiB)より小さい Object は、分断されている間は丸ごと保持する。
- それより大きい Object のペイロードは届いた順に流し、トランスポートが拒んだ書き込みは次の tick か次の配送で再試行する。
- レッグが保持するものはハブ全体で 1 つのバッファーに置く。同時にそれを必要とした 2 本目のレッグは上流 FETCH を諦める。
- FETCH_HEADER が複数の配送に分かれて届き、相手の早着スロット(1 つ)がすでに使われていると、その相手への上流 FETCH のうちデータストリームを待っているものはすべて終わる。

参照: `moqtrun_upf_*`。要件は [draft-moq-transport-22.md](../../features/draft-moq-transport-22.md) の MQ22-213 から MQ22-219 と MQ22-137。

### 2.12 Object キャッシュはアリーナを走査する

影響: FETCH のキャッシュが大きいハブ。

キャッシュは、アプリケーションが渡すアリーナ(1 つのメモリブロック)に置く。追い出しは memmove を 1 回通してアリーナを詰め、検索はアリーナを線形に走査する。1 項目の再開位置を持つので、1 つの Track を前へたどる走査は前回の検索が止まった所から続く。

FETCH や FETCH_OK の走査のコストは、1 回の走査につき O(arena) と、越える欠落 1 つにつき O(arena)(欠落の確認でもう一度走査する)である。異なる Track への FETCH を交互に処理すると再開位置を取り合い、先頭から走査し直す。

Group は Track ごとに昇順で届く前提なので、古い Group の Object は新しいものとしてキャッシュする。キャッシュできるペイロードの最大は `MOQCACHE_OBJ_MAX`(65472 バイト)である。

参照: `moqcache.h` の先頭のコメント、`moqtrun_fetch_last`

### 2.13 発見の同期は 2 乗のコスト

影響: 名前空間の購読が多いハブ([名前空間の発見](https://hakkadaikon.github.io/wired/guide/ja/moqt/discovery/))。

SUBSCRIBE_NAMESPACE の追いつきはイベントごとに O(reqs^2) の走査、SUBSCRIBE_TRACKS の同期は O(sessions x tracks x reqs) である。上限は固定の容量で決まる。

参照: `moqtrun_disc_sync`、`moqtrun_subtracks_sync_track`

### 2.14 Range Filter はストリーム単位か Track 単位

影響: ストリームより細かい単位で絞り込む購読者。

Range Filter は配送するストリームや Object を絞る SUBSCRIBE のパラメーターである(d19 と d22)。ハブは中継するストリームから個々の Object を切り出さない。

| フィルター | 動作 |
|---|---|
| SUBGROUP_FILTER、PRIORITY_FILTER | 購読者へストリームを開く時点で、ヘッダーの Subgroup ID と Publisher Priority でストリーム全体を通すか決める |
| TRACK_PROPERTY_FILTER | SUBSCRIBE_TRACKS に提示する Track を、96 バイトまでの Track Properties で選ぶ(2.20) |
| OBJECTID_FILTER | データグラムだけに効く |
| OBJECT_PROPERTY_FILTER | 評価しない |

SUBSCRIBE_TRACKS が複数のフィルターの組を持ち、ある組の TRACK_PROPERTY_FILTER が通らず別の組がその Track を通したときは、通らなかった組の Object のフィルターも Object を通す。

参照: `moqtrun_sub_rngf_stream`、`moqtrun_subtracks_tp_pass`

### 2.15 エイリアスによる認可トークンのキャッシュはない

影響: エイリアスで認可トークンを送るクライアント([購読者の認可](https://hakkadaikon.github.io/wired/guide/ja/moqt/authorize/))。

認可トークンはエイリアスで送れる(REGISTER で登録、USE_ALIAS で参照、DELETE で削除)。ハブは MAX_AUTH_TOKEN_CACHE_SIZE を広告しないので、キャッシュは 0 バイトである。

REGISTER はセッションを AUTH_TOKEN_CACHE_OVERFLOW で、DELETE と USE_ALIAS は UNKNOWN_AUTH_TOKEN_ALIAS で閉じる(d22 8.9)。FETCH と SETUP のトークンは検査しない。

参照: `moqtrun_take_tok_or_close`

### 2.16 OBJECT_DELIVERY_TIMEOUT は Object の先頭バイトから数える

影響: 別のバイトからタイムアウトを測る相手。

d19 は最初のペイロードのバイト、d22 は最後のヘッダーのバイトで時計を始める。ハブは Object をまとめて復号するので、どちらも同じ時点になる。

参照: `moqtrun_relay_born`(ponytail)、[draft-moq-transport-22.md](../../features/draft-moq-transport-22.md) MQ22-070a(テストなし)

### 2.17 優先度によるスケジューリング

影響: 購読の途中で優先度を変える購読者([優先度と GOAWAY](https://hakkadaikon.github.io/wired/guide/ja/moqt/priority-goaway/))。

- 送信ポンプは Object のストリームを Subscriber Priority、Publisher Priority、Group の順序の順で並べる。
- 1 つの購読の中では、フィルを進行中の配信より先に送る。
- キューに入った単発のストリームは、REQUEST_UPDATE で優先度を付け直さない。
- データグラムはストリームの区分を通らず、すぐに送る。
- 購読をまたいで優先度が等しいものは、ポンプの 1 回分をラウンドロビンで分け合う。

参照先は次のとおり。

- `moqtrun_upd_resched`(ponytail)
- MoQT の台帳の対象外の節(7 節 / 5 節)([d19](../../features/draft-moq-transport.md)、[d18](../../features/draft-moq-transport-18.md)、[d22](../../features/draft-moq-transport-22.md))。

### 2.18 Properties は中身を見ない

影響: リレーが Properties に従って動くと期待するアプリケーション。

次の Properties は解釈せずにそのまま中継する。

- MAX_CACHE_DURATION、DEFAULT_PUBLISHER_GROUP_ORDER、DYNAMIC_GROUPS、Immutable Properties、Prior Group/Object ID Gap
- d22 の TIMESTAMP、VIDEO_FRAME_MARKING、AUDIO_CONFIG、ENCRYPTED_LIST、PADDING

参照: MoQT の台帳の対象外の節

### 2.19 FILL_TIMEOUT と EXPIRES は復号するが、それに従って動かない

影響: これらのパラメーターに頼るクライアント。

FILL_TIMEOUT はあるかどうかで、欠けた範囲に「End of Timed-Out Range」(d22: ハブが時間内に取得できなかった範囲)の印を付けるかを決めるだけである。上流 FETCH の持ち時間([2.11](#211-上流への-fetch-は-fetch-1-つにつき-1-回でそのまま中継する))を短くすることもある。EXPIRES は解析して無視する。

一方、NEW_GROUP_REQUEST は上流へ中継する(d18 10.2.13、d19 10.2.18。ハブ自身の SUBSCRIBE に入れるか、Track が Established になったあとは REQUEST_UPDATE で送る。`moqtrun_ngr.c`)。

RENDEZVOUS_TIMEOUT にも従う([ドラフトと raw QUIC](moqt-drafts.md#13-意図した逸脱-ランデブーの保留は-15-秒が上限))。

参照: MoQT の台帳の対象外の節

<a id="220-track-properties-は-subscribe_ok-でだけ転送し32-バイトまで"></a>

### 2.20 Track Properties は SUBSCRIBE_OK でだけ転送し、96 バイトまで

影響: Track Properties を読む購読者。

パブリッシャーの Track Properties は、購読者が INCLUDE_PROPERTIES(0x35、d22 9.20.21)= 0 を送っていない限り、その購読者への SUBSCRIBE_OK に入る。

`WIRED_MOQTRUN_TRACK_PROPS_MAX`(96)より長いブロックは空にして転送する。TRACK_STATUS_OK、FETCH_OK、SUBSCRIBE_TRACKS による PUBLISH には入れない。

参照: `moqtrun_queue_subscribe_ok`

### 2.21 Padding Datagram は送らない

影響: トラフィックのパディングが必要な運用。

参照: MoQT の台帳(11.5 節)

### 2.22 Session Migration と REDIRECT の動作はない

影響: 別のリレーへ移されることを期待するクライアント。

ハブは REDIRECT を送らず、受けても反応しない。要求元を移す先の上流のリレーも兄弟のリレーもない。

参照: MoQT の台帳の対象外の節

### 2.23 SUBSCRIBE_TRACKS の REQUEST_UPDATE

影響: SUBSCRIBE_TRACKS を更新するクライアント。

TRACK_NAMESPACE_PREFIX と FORWARD は、その後に生成する PUBLISH に適用する。更新に入っている TRACK_PROPERTY_FILTER は受け付けるが適用せず、リクエストは元のものを使い続ける。

参照: `moqtrun_upd_ns_forward`、`moqtrun_upd_ns_prefix`

### 2.24 Malformed Track の検出は一部だけ

影響: Track の規則を破るパブリッシャーの購読者。

復号時の未知の Object Status と Object ID のオーバーフローのほかに、リレーが検出するのは次のものだけである。

- END_OF_TRACK の Object より後ろの Object と、その Group の最新の END_OF_GROUP の Object より後ろの Object。Status で判定し、END_OF_GROUP のストリームの FIN では判定しない。
- 同じ Subgroup の最新の Subgroup ヘッダーと Publisher Priority が異なる Subgroup ストリーム。交互に届いた古い Subgroup は覚えていない。
- Subgroup ストリームから来た Object をキャッシュがまだ持っているときの、同じ Object のデータグラム。データグラムは記録しないので、データグラムのあとにストリームで同じ Object が来ても検出しない。

購読の経路では、最終位置の食い違いと、ペイロードの異なる重複 Object は確認しない(確認には Object ごとのキャッシュ検索が要る)。検出のきっかけになった回の配送は、PUBLISH_DONE より先に購読者へ届くことがある。

参照: `moqtrun_track_obj`、`moqtrun_sgprio_gate`、`moqtrun_dg_mode_gate`(d22 12.1)

### 2.25 2^56 を超える Request ID は別の ID と重なる

影響: 2^56 を超えるリクエストを送るセッション。

ハブは各リクエストの流れを、セッションのスロットと Request ID の下位 56 ビットで識別する。

参照: `moqtrun_flow_of`(ponytail)

### 2.26 終わらせるセッションの猶予は固定

影響: GOAWAY の最中の遅い相手。

`WIRED_MOQTRUN_GOAWAY_GRACE_MS`(1000 ミリ秒)がPUBLISH_DONE の送り出しと GOAWAY_TIMEOUT による切断の間隔になる。確認応答を待たず、決まった時間だけ待つ。

参照: `WIRED_MOQTRUN_GOAWAY_GRACE_MS`(ponytail)
