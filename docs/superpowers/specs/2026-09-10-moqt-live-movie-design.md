# moqt_chat: サンプル動画を MoQT でライブ配信する

状態: 承認済みの設計(2026-09-10)。実装計画はこの仕様のあとに続きます。

## 目的

`examples/moqt_chat` のサーバーは現在、`assets/movie.mp4` を静的な MoQT Track 1 本として公開しています。ファイル全体を一度フレーム化し、サブスクライバーごとに 1 本のストリームで送る方式です。この変更ではライブの MoQT ストリームと同じ方式で動画を配信します。サーバーはキーフレームでそろえたメディアフラグメントを実時間に合わせて連続した MoQT Group として送り出します。視聴者は全員が同じ位置を見ます。途中から参加した視聴者は現在の Group から見始めます。遅れた視聴者は Group を取りこぼし、パブリッシャーを止めることはありません。ブラウザーのクライアントは届いたフラグメントを Media Source Extensions (MSE) で再生します。

このサンプルはこの SDK の上で MoQT の仕組みを示すデモのままです。メディアサーバーではありません。アセットは固定の 1 本、ビットレートは 1 種類で、カタログも FETCH もありません。

## アセット

`assets/movie-live.mp4`: `assets/movie.mp4` から作った fragmented MP4 (fMP4) で、リポジトリにコミットします。映像は H.264 High profile(854x480、24 fps、約 1.2 Mbps)、音声は AAC-LC です。すべてのフラグメントがキーフレームで始まるよう、GOP を 2 秒に固定して再エンコードします。

```sh
nix shell nixpkgs#ffmpeg-headless -c ffmpeg -i assets/movie.mp4 \
  -c:v libx264 -preset medium -profile:v high -g 48 -keyint_min 48 \
  -sc_threshold 0 -b:v 1200k -c:a aac -b:a 128k \
  -movflags +frag_keyframe+empty_moov+default_base_moof \
  -f mp4 assets/movie-live.mp4
```

構成(生成したファイルで確認済み): `ftyp` + `moov` が初期化セグメント(1,260 バイト、サンプルテーブルなし)で、そのあとに約 2 秒ずつの `moof`+`mdat` の組が 16 個続きます(10 KB から 405 KB。最後の 1 個は短い)。両方のトラックのサンプルが各 `moof` を共有します。

元の `assets/movie.mp4` は手を加えずにリポジトリに残します。

## ワイヤー上の Track モデル

ルームの固定の名前空間 `wired/moqt_chat` の下に、hub が持つ Track を 2 本置きます。

| Track 名     | Track Alias | 内容 | 配信方法 |
|--------------|-------------|---------|----------|
| `movie/init` | 9           | 初期化セグメント(`ftyp`+`moov`) | 既存の静的な blob Track(`wired_moqt_publish_blob`): ストリーム 1 本で、SUBSCRIBE を受けたらサブスクライバーごとに 1 回送る |
| `movie`      | 8           | Group ごとにメディアフラグメント(`moof`+`mdat`)1 個 | ライブ Track(新規): Group g はフラグメント `g mod 16` を Group g の唯一の Object(Object ID 0)として運ぶ。専用の単方向ストリームで、実時間が Group g に入ったときに送る |

Alias: chat 0..3、audio 4..7、movie 8、movie/init 9。今と同じく、フロントエンドとサーバーの Alias 定数は一致していなければなりません。

Group ID は折り返しません。hub は実時間から現在の Group を求めます。式は `group = (now_ms - t0_ms) / group_ms` で、`group_ms = 2000`、`t0_ms` はライブ Track を公開した時刻です。アセットはループします(Group g はフラグメント `g mod 16` に対応)が、Group ID は増え続けるので、サブスクライバーから見た「最大の Group」は常に単調増加です。

各 Group のストリームは SUBGROUP_HEADER 1 個(このサンプルのほかのすべてのストリームと同じ Type 0x70 の形: PROPERTIES なし、Subgroup ID モード 0b00、既定の優先度、FIRST_OBJECT あり、Track Alias 8、Group ID g)、続いてちょうど 1 個の Object(Object ID Delta 0、Payload Length = フラグメント長、ペイロード = フラグメントのバイト列)、最後に FIN です。

`movie` を SUBSCRIBE したサブスクライバーには、Track Alias 8 を載せた SUBSCRIBE_OK を返し、すぐに現在の Group を送ります(フラグメントはキーフレームで始まるので、すぐに再生を始められます)。その後は、実時間が次の Group に入るたびにその Group を受け取ります。この SDK の SUBSCRIBE_OK のコーデックは Largest Location を運ばないので、クライアントは最初の Group のヘッダーから開始位置を知ります。SUBSCRIBE のフィルターは無視します("largest object / next group" と同じ動作)。

## サーバー側の部品

### 1. `src/app/media/mp4frag/`(新しいドメイン、プレフィックス `mp4frag_`)

fMP4 のトップレベルのボックスをたどる、libc に依存しない純粋な処理です。

```c
typedef struct {
  wired_span init;                       /* ftyp..moov inclusive */
  wired_span frags[MP4FRAG_MAX_FRAGS];   /* each moof+mdat pair, contiguous */
  usz        n_frags;
} mp4frag_layout;

/* 1 on success; 0 when the bytes are not an fMP4 of the expected shape:
 * a truncated/oversized box, a moof without a following mdat, more than
 * MP4FRAG_MAX_FRAGS fragments, or no fragment at all. */
int mp4frag_scan(wired_span file, mp4frag_layout* out);
```

`MP4FRAG_MAX_FRAGS` は 64 で、隣にサイズの根拠を書きます(今は 16。上限は、フラグメント 2 秒で 2 分のループを組める大きさ)。ボックスサイズ 1(64 ビットの largesize)と 0(ファイル末尾まで)は、このサンプルの目的では VIOLATION 相当として拒否します。初期化セグメントのあとにある `moof`/`mdat` 以外のボックス(`free`、`sidx` など)は読み飛ばします。

### 2. srvrun への追加(`src/app/http3/server/srvrun/`)

- `wired_srvrun_opt.on_step` / `on_step_ctx`: アプリのコールバック `void (*)(void* ctx, u64 now_ms)`。`srvrun_step` からループの 1 ステップごとに 1 回、そのステップの受信・応答の処理のあと、PTO とデータグラムの吐き出しの前に、ループの単調時計を渡して呼びます。既定値 0 なら呼びません。ループのコールバックなので、`wired_server_wt_*` の送信 API はどれもここから呼べます。ループはコネクションが 1 本でも生きていれば上限つきのタイムアウト(`SRVRUN_PTO_MS`、25 ms)でポーリングしているので、誰かが接続している間は少なくともその間隔でコールバックが呼ばれます。コネクションが 1 本もないときは一度も呼ばれないこともありますが、ライブ Track の位置は tick の回数ではなく時計から求めるので問題ありません。
- `int wired_server_wt_stream_inflight(wired_wt_session* s, u64 stream_id)`: 送信スロットがまだ `stream_id` を保持している間(バイト列の ACK がまだそろっていないか、ストリームが追記のためにまだ開いている)は 1、スロットが回収されたか、その ID がこのセッションでサーバーが送ったストリームではないときは 0 を返します。VIEW として渡したペイロード(スロットのステージング容量を超えるもの)をいつ再利用してよいかを、アプリはこの値で知ります。

どちらも既存の `wt_on_*` コールバックと同じように、ほかのドライバー(workers/threads/xdp)がそのまま転送します。

### 3. hub のライブ Track(`src/app/moqt/run/moqtrun.[ch]`)

`wired_moqt_hub` に追加する状態:

```c
typedef struct {
  wired_moqtrun_track track;      /* name, own_alias, subs[] (peers subscribed) */
  const wired_span*   frags;      /* caller-owned fragment views */
  usz                 n_frags;
  u64                 t0_ms;
  u64                 group_ms;
  u64                 sent_group[WIRED_MOQTRUN_MAX_SUBS]; /* per sub slot: last Group sent */
  int                 sent_any[WIRED_MOQTRUN_MAX_SUBS];   /* 0 until the first Group */
} wired_moqtrun_live;
```

API:

```c
/* Publish a hub-owned live track: fragment i is sent as Group g's only
 * Object whenever g mod n_frags == i, Groups advancing every group_ms
 * from now_ms. frags must outlive the hub. Returns 0 on n_frags == 0 or
 * group_ms == 0. */
int wired_moqt_publish_live(wired_moqt_hub* hub, wired_span name,
    u64 track_alias, const wired_span* frags, usz n_frags,
    u64 group_ms, u64 now_ms);

/* Clock tick (wired_srvrun_opt.on_step): computes the current Group from
 * now_ms and sends it to every live subscriber that has not received it. */
void wired_moqt_tick(wired_moqt_hub* hub, u64 now_ms);
```

動作:

- `SUBSCRIBE movie`(ライブ Track の名前と一致したとき。blob Track のあと、ピアの Track の前に照合する): ピアを `subs[]` に記録し、ライブの Alias で SUBSCRIBE_OK を積み、現在の Group をすぐに送ります(`sent_group` = 現在)。空いている sub スロットがなければ REQUEST_ERROR INTERNAL_ERROR を返します。購読済みのピアから SUBSCRIBE が再び来たら、SUBSCRIBE_OK をもう一度返し、何も送りません。
- `wired_moqt_tick(now)`: `g = (now - t0) / group_ms`。有効な sub のうち `sent_group < g`(または `!sent_any`)のものについて、フラグメント `g mod n_frags` の Group ストリームを組み立てて `io.send_uni` を呼びます。受け付けられたら `sent_group = g` にします。拒否されたとき(セッションに空いたステージングスロットか送信スロットがない)は何も記録しません。実時間がまだ Group g にある間は次の tick で送り直し、実時間が先に進んだら諦めます(サブスクライバーごとに、飛ばした Group 1 個につき `stat_live_drop++`)。そのため、サブスクライバーが Group を順不同で受け取ることも、同じ Group を 2 回受け取ることもありません。
- セッションのクローズ: そのピアのライブの購読はほかの購読と同じように破棄します(再接続するとその時点の現在の Group から始まります)。
- 送信ごとのフレーム化: hub は SUBGROUP_HEADER + Object ID Delta + Payload Length を小さなスタックバッファーに組み立て、フレームのあとにフラグメントが続くペイロードを `io.send_uni` に渡します。io テーブルは連続した span を 1 つしか受け取らないので、サブスクライバーごとに 400 KB をコピーせずにフラグメントのバイト列の直前でフレーム化するには、`moqdata` の助けが要ります。example の io アダプターはすでにペイロードをセッションごとのステージングにコピーしている(4 を参照)ので、hub は新しい io エントリで 2 分割のペイロードを渡します。

  ```c
  /* wired_server_wt_open_uni-shaped, for a payload whose first part is a
   * short framing prefix and whose second part is a large body the hub
   * does not own a contiguous copy of. The adapter concatenates them. */
  i64 (*send_uni2)(wired_wt_session* s, wired_span head, wired_span body);
  ```

  既存の `send_uni` は chat/blob の経路のために残します。テストのスタブは `head||body` を記録します。

hub に追加するカウンター: `stat_live_sent`、`stat_live_drop`。終了時にリレーの統計と一緒にログに出します。

### 4. example のサーバー(`examples/moqt_chat/wired_server.c`)

- `--movie PATH` は fMP4 を受け取るようになります。起動時に `wired_fio_read` で 8 MiB の静的バッファーに読み込み、`mp4frag_scan` をかけ、`wired_moqt_publish_blob("movie/init", 9, init, ...)` と `wired_moqt_publish_live("movie", 8, frags, n, 2000, clock_mono_ms())` を呼びます。スキャンに失敗したら、フラグ名を示すメッセージを出して終了します。ログには 1 行で、フラグメント数、初期化セグメントのバイト数、Group の間隔を出します。
- `opt.run.on_step` = `wired_moqt_tick(&g_hub, now_ms)` を呼ぶ関数。
- セッションごとのステージングをリングにします。1 セッションあたり `LIVE_FRAG_MAX = 1 MiB` のスロットを `LIVE_RING = 3` 個(根拠: 最大のフラグメントは 405 KB。4 Mbps で 2 秒のフラグメントは 1 MB)、セッション数は今と同じ `BIG_SLOTS` です。`send_uni2` は、記録したストリームがもう `wired_server_wt_stream_inflight` でない最初のスロットを取り、シグナルのプレフィックス + head + body を書き込み、ストリームを開き、スロットにストリーム ID を記録します。空きスロットがないか、head+body がスロットより大きいときは -1 を返します(hub はドロップとして数えます)。セッションのクローズで、そのセッションのスロットをすべて解放します。
- blob 経路の 8 MB の大きなスロットプールは取り除きます。`movie/init` は 1.2 KB なので、既存の 2 KB のスタックの経路に載ります。`send_uni` はスタックのステージングを超えるペイロードを引き続き拒否します(そうしたペイロードを送る呼び出し元はもうありません)。

## ブラウザーのクライアント(`examples/moqt_chat/frontend`)

`src/lib/moqtLiveClient.ts`:

- 定数 `MOVIE_TRACK_NAME = "movie"`、`MOVIE_INIT_TRACK_NAME = "movie/init"`、`MOVIE_TRACK_ALIAS = 8n`、`MOVIE_INIT_TRACK_ALIAS = 9n`、`MOVIE_MIME = 'video/mp4; codecs="avc1.640015, mp4a.40.2"'`。(`avc1.640015` は生成したファイルの `avcC` を読んでから書きます: High profile 0x64、制約 0x00、480p24 のレベル 0x15。想定ではなく、実装中に確かめます。)
- `startLive(chat, video)`: `MediaSource` を作って `<video>` に付け、`sourceopen` で `SourceBuffer(MOVIE_MIME)` を 1 つ `mode = "sequence"` で追加します(アセットがループするとタイムスタンプが巻き戻ります。sequence モードは到着順に追記し、タイムスタンプを無視します)。先に `movie/init` を SUBSCRIBE し、そのバイト列が(既存の blob の読み取り経路で)届いたら追記し、そのあとで初めて `movie` を SUBSCRIBE します。
- Alias 8 で届く単方向ストリーム: EOF まで読み、Object をちょうど 1 個デコードし(`decodeBlobObjects` がすでにこの形を扱います)、ペイロードを追記キューに積みます。キューは一度に 1 バッファーずつ追記し、追記と追記の間で `updateend` を待ちます(SourceBuffer は同時の追記を拒否します)。キューはテストできる純粋な単位(`AppendQueue`)で、テストでは偽の SourceBuffer を与えます。
- バッファーの整理: 追記のたびに、`currentTime` より後ろに 60 秒より多くバッファーされていれば `remove(0, currentTime - 30)` を(追記と同じようにキューに積んで)実行します。長時間ループしてもメモリが一定の範囲に収まります。
- 再生: `<video data-testid="live" autoplay muted playsInline controls>`。ミュートした自動再生はユーザー操作なしで許されます。ユーザーはミュートを解除できます。
- エラー: 1 本のストリームでデコードに失敗したら、その Group を捨てます。`SourceBuffer` のエラーはストアのエラー文字列として出し、chat/voice を落とすことはありません。

`useMoqtChat.ts`: 動画の Blob の配線を、chat の接続後に `startLive` を呼ぶ形に置き換えます。Alias 9 は blob の読み取り(init)へ、Alias 8 はライブの読み取りへ回します。`leave()` で MediaSource を破棄します。ストアの `movieUrl` は `liveError: string | null` に変わり、`page.tsx` は接続後にメッセージ一覧の上に `<video>` を描画します。

## 検証

ライブの送信側が満たすべき性質(それぞれ少なくとも 1 つのテストにします):

- サブスクライバーが同じ Group を 2 回受け取ることはない。
- サブスクライバーは Group を厳密に増加する順で受け取る。実時間がすでに過ぎた Group を遅れて送ることはない。
- ストリームがまだ送信中のステージングスロットは上書きしない。スロットを再利用するのは、SDK がそのストリームの完了を報告したあとだけ。
- 拒否された送信が状態を失うことはない。実時間がその Group にある間は送り直し、実時間が先に進んだらドロップとして数える。
- スロットが解放され続けるなら、どのサブスクライバーも任意の Group より新しい Group をいずれ受け取る(あるサブスクライバーが別のサブスクライバーに飢えさせられることはない)。
- セッションのクローズで、そのピアの購読とスロットを解放する。再接続は時計の現在の Group から始まる。

これらは C のコードを書く前に状態モデルとして検査します(tick、SUBSCRIBE、クローズ、スロット解放の絡み合いが、順序のバグを最も隠しやすい部分だからです)。下のテストリストには性質ごとに 1 つのテストを入れます。それ以外はすべて、通常のテストファーストの開発です。

テストリスト(C):

- mp4frag: 合成した fMP4(ftyp、moov、moof+mdat × 2)をスキャンすると、init と 2 個のフラグメントが正確な span で得られる。フラグメントの間の `free` ボックスは読み飛ばす。mdat のない moof、途中で切れたボックス、largesize のボックス、サイズ 0 のボックス、上限を超える数は、いずれも 0 を返す。実際のアセットをスキャンすると、16 個のフラグメントと 1,260 バイトの init が得られる(バイト列ではなくサイズで固定)。
- srvrun: `on_step` はステップごとに 1 回、減少しない時刻で呼ばれる。セッションのストリームは `wired_server_wt_open_uni` の直後には `inflight` で、ループバックのピアが ACK したあとは inflight でなくなる。
- moqtrun のライブ: publish は n_frags 0 / group_ms 0 を拒否する。SUBSCRIBE には Alias 8 の SUBSCRIBE_OK を返し、現在の Group を正しいヘッダー(Alias 8、Group = 時計の Group)とフラグメント(Object 0)ですぐに送る。同じ Group の中の tick では何も送らない。次の Group に入った tick で次のフラグメントを送る。フラグメントは n_frags で折り返す。拒否された送信は同じ Group の次の tick で送り直し、Group が進んだら諦める(数える)。2 人のサブスクライバーは独立に扱う(片方は拒否、もう片方は拒否されない)。セッションのクローズで送信が止まり、再接続は現在の Group から始まる。blob Track `movie/init` とライブ Track `movie` は共存し、名前で振り分ける。`send_uni2` の head||body は同じフラグメントを `moqdata_msg_build` したものと等しい。
- example(実ブラウザーの e2e を通して): 下を参照。

テストリスト(TypeScript、vitest):

- AppendQueue は `updateend` をまたいで追記を直列化し、順序を保ち、`remove` を追記と同じようにキューに積む。init はどのフラグメントよりも先に追記する。init より先に届いたフラグメントは待つ。デコードの失敗で捨てるのは Group 1 個だけ。MIME 文字列はアセットの `avcC` と一致する(テストはコミットしたファイルの `avcC` のバイト列を読み、コーデック文字列を導く)。

実ブラウザーでの確認(`just e2e-live`、`e2e/run-live-check.mjs`): `--movie assets/movie-live.mp4` でサーバーを起動し、user1 を参加させ、`readyState >= 3` で `video.currentTime` が 4 秒を超えて進むまで待ちます。5 秒後に user2 を参加させ、user2 が最初に受け取った Group ID(video 要素の `data-first-group` で公開)が user1 のものより大きいことを求めます。両方とも再生が進み続け、サーバーの終了ログに `live_sent > 0` が出ることを確かめます。

## 対象外

複数のビットレートやカタログ Track、FETCH / 巻き戻し、SUBSCRIBE_OK の Largest Location、フレーム単位の Object(単位は Group あたりフラグメント 1 個)、パブリッシャー起点の PUBLISH による告知(このサンプルのほかのすべての Track と同じく、固定の名前で購読する方式のまま)、音声と映像の Track の分離、実行時のトランスコード。
