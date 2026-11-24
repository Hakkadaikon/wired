# app の詳細設計

[ドキュメント](../README.md) › [詳細設計](README.md) › app

| 項目 | 内容 |
|---|---|
| 目的 | app 層の設計(HTTP/3、QPACK、DATAGRAM、WebTransport、MoQT、生の QUIC、MP4 の分割)を示す |
| 読む人 | app のコードを変更・レビューするコントリビューター |
| 前提文書 | [詳細設計](README.md) |
| 関連文書 | [transport](transport.md)、[実装している仕様](specs.md) |

app は QUIC のストリームの上でアプリケーションプロトコルを扱う。

## 1. 依存と層の順序

| 項目 | 内容 |
|---|---|
| 依存先 | transport(ストリーム)、tls(セッションと鍵の状態)、crypto、common |
| 上にあるもの | アプリケーション |
| 逆向きの依存 1 | transport のフレームのコード、tls のサーバードライバーとトランスポートパラメーターのコードが、`app/datagram/` の DATAGRAM の定義と受信用の抽出関数を使う |
| 逆向きの依存 2 | TLS クライアントがサーバーのワイヤー用ヘルパー(`app/http3/server/srvwire/`)を再利用する |

```mermaid
flowchart BT
    quic[QUIC streams] --> h3[HTTP/3]
    h3 --> wt[WebTransport]
    wt --> moqt[MoQT]
    quic -.->|side path| dg[DATAGRAM]
    quic -.->|side path: raw QUIC| moqt
```

## 2. HTTP/3

HTTP/3 はリクエストとレスポンスをフレームに分け、1 回のやり取りごとに専用の双方向ストリームを割り当てる。設定は別の制御ストリームで運ぶ。

## 3. QPACK を使う理由

HTTP/2 の HPACK は最近のヘッダーフィールドを入れた動的テーブルを全ストリームで共有し、テーブルの更新が順番どおりに届くことを前提にする。QUIC のストリーム同士は順番どおりに届かない。

HPACK を QUIC で使うと、新しいエントリを参照するリクエストがエントリを作る更新より先に届いて待たされ、ヘッダー層でヘッドオブラインブロッキングが起きる。

| QPACK(RFC 9204)の仕組み | 内容 |
|---|---|
| 専用ストリーム | テーブルの更新はエンコーダーストリームで運び、デコーダーはデコーダーストリームで進み具合を報告する |
| Required Insert Count | 各ヘッダーブロックの先頭にあり、デコード前に受け取っておく挿入の数を示す。0 なら動的エントリを使わない |

デコーダーは `SETTINGS_QPACK_BLOCKED_STREAMS` で、挿入を待ってよいストリーム数を知らせる。wired はこれを 0 にするので、wired サーバーで待つストリームはない。ピアのエンコーダーが参照してよいのは、サーバーが確認応答した挿入だけである。

```mermaid
sequenceDiagram
    participant SC as wired control stream
    participant CE as Client encoder stream
    participant CR as Client request stream
    participant S as wired decoder
    participant SD as wired decoder stream
    SC-->>CE: SETTINGS: QPACK_MAX_TABLE_CAPACITY,<br/>QPACK_BLOCKED_STREAMS = 0
    CE->>S: Insert "user-agent: demo" (insert 1)
    S->>S: add entry to the dynamic table
    SD->>CE: Insert Count Increment 1
    Note over CE,CR: the client now knows insert 1 arrived,<br/>so a request may reference it
    CR->>S: HEADERS, Required Insert Count = 1
    alt Required Insert Count <= inserts received
        S->>S: decode the field section
        SD->>CE: Section Acknowledgment (stream id)
    else Required Insert Count > inserts received
        S-->>CR: close connection:<br/>QPACK_DECOMPRESSION_FAILED
    end
```

届いた数より多い挿入を指すブロックは接続エラー(`QPACK_DECOMPRESSION_FAILED`)にする。ブロックされるストリームが 0 なので、ピアはそのブロックを送ってはならないからである。サーバー自身のエンコーダーはテーブル容量を 0 に保つ。レスポンスは静的テーブルとリテラルだけを使うので、クライアントを待たせない。

## 4. DATAGRAM

DATAGRAM フレーム(RFC 9221、フレーム型 `0x30` と `0x31`)は信頼性と順序の保証を持たず、失ったデータグラムを再送しない。ライブ音声のフレームのように、遅れて届くと使えないデータに向く。

## 5. WebTransport

WebTransport(`src/app/webtransport/`)は、HTTP/3 の Extended CONNECT リクエストをセッションに変える。セッションは独自の双方向ストリーム、単方向ストリーム、データグラムを運ぶ。ネゴシエーションと多重化は HTTP/3 が受け持つ。

## 6. MoQT

MoQT(`src/app/moqt/`)は、ライブデータのための publish/subscribe プロトコルである。wired はリレーの役のサブセットを実装する。サーバーはメディアを作らず、パブリッシャーと購読者の間で Object を転送する。サブセットは SETUP、SUBSCRIBE、PUBLISH、FETCH、名前空間の探索である。

| トランスポート | ドラフトの選び方 | セッション |
|---|---|---|
| WebTransport | WebTransport のサブプロトコル(`app/moqt/ver/`)でセッションごとに 18、19、22、23 から選ぶ | Extended CONNECT で開く |
| 生の QUIC(`src/app/moqt/qraw/`) | ALPN がドラフトのトークン(`moqt-23`、`moqt-22`、`moqt-19`、`moqt-18`)になる | 接続がそのままセッションになる |

生の QUIC には Extended CONNECT がないので、クライアントは URI の authority と path を AUTHORITY と PATH の Setup Option で送る。アプリケーションは `moqraw_policy` で受け入れか拒否かを決める。

MoQT ハブ(`src/app/moqt/run/`)は、`wired_moqt_init` が用意するサーバー側のセッションと購読の状態である。ハブは I/O のためにトランスポートで分岐しない。`wired_moqraw_io` が両方に共通の I/O テーブルを 1 つ返し、トランスポートごとの違いはこのテーブルが扱う。

| 違い | WebTransport | 生の QUIC |
|---|---|---|
| ストリームの先頭 | WebTransport のストリームヘッダー(ストリーム型の varint とセッション ID) | MoQT のバイトから始まる |
| 送信の予算 | 残りのセッションクレジット(`WT_MAX_DATA`) | セッション単位のクレジットはない。接続の `MAX_DATA` が送信を制限する |

## 7. rawquic: 2 つのバインディングの見分け

`src/app/rawquic/` は状態を持たないヘルパーを置く。接続が生の QUIC か HTTP/3 上の WebTransport かという問いに、次の 5 か所で答える。

1. ストリームのルーティング(`rawq_route`)
2. RESET_STREAM と STOP_SENDING に入れるエラーコード
3. データグラムのフレーミング
4. サーバーの最初の単方向ストリーム ID
5. 暗黙のセッションの識別

生の QUIC には CONNECT リクエストがないので、接続全体が 1 つの暗黙のセッションになる。

ストリーム ID の下位 2 ビットが開いた側と方向を示すので、サーバーが開く単方向ストリームの ID は 3、7、11、15 と 4 ずつ進む。最初の単方向ストリームは生の QUIC では ID 3、HTTP/3 では 15 である。HTTP/3 では ID 3、7、11 を制御ストリームと QPACK のストリームが使う。

## 8. media: MP4 ファイルを Object に分ける

`src/app/media/mp4frag/` は、フラグメント化 MP4 ファイルのトップレベルのボックス構成を読む(`mp4frag_scan`)。初期化セグメント(`ftyp` から `moov` まで)と、`moof`+`mdat` のメディアフラグメントを、ファイルへのビューとして返す。コピーもサンプルテーブルの解析もしない。

パブリッシャーは各フラグメントを 1 つの MoQT Group として送る。

## 9. nostr: イベントと NIP-98 の検証

`src/app/nostr/` は Nostr のイベントを検証する。署名の検証は crypto の `bip340_verify` に任せる。サーバーからはまだ呼ばれない。

| API | 役割 |
|---|---|
| `nostrev_parse(ev, json, len, buf, cap)` | NIP-01 のイベント 1 件を厳密な JSON の部分集合として解析する。文字列は `buf` にデコードし、`ev` は `buf` の中の位置を持つ。`cap >= len` なら足りる |
| `nostrev_serialize(ev, sink)` | id を計算するための NIP-01 の直列化を `sink` に書く。エスケープしない 0x20 未満のバイトがあれば 0 を返す |
| `nostrev_compute_id(ev, id)` | 直列化の SHA-256 |
| `nostrev_verify(ev)` | id、次に BIP-340 の署名を確かめ、`NOSTREV_OK`、`NOSTREV_BAD_ID`、`NOSTREV_BAD_SIG` を返す |
| `nip98_check(rq, token, ev, buf, cap)` | 生の JSON か `Nostr <base64>` のトークンを、kind、時間の窓、u、method、payload、id、署名の順に確かめ、`nip98_verdict` を返す。id はリプレイキャッシュに登録しない。`cap` はトークンの長さの 2 倍で足りる |
| `nip98_replay_init(rc, window)`、`nip98_replay_admit(rc, id, created_at, now)` | 固定の大きさ(`NIP98_REPLAY_CAP`、既定 256)のリプレイキャッシュ。時間の窓は初期化で決まる(0 なら 60 秒)。項目は created_at + 窓まで有効で、有効な項目は追い出さず、満杯なら `NIP98_REPLAY_FULL` を返す |

`nip98_req` は、期待する u と method、body のハッシュ(なければ payload タグを見ない)、今の時刻、リプレイキャッシュ(窓だけを読む)を持つ。呼び出しの順は `nip98_check`、公開鍵の認可、`nip98_replay_admit` である。認可の前に登録すると、認可されない鍵でキャッシュが埋まる。今の時刻は両方の呼び出しで同じ時計を使い、1 つのキャッシュに対して戻してはならない。受け付ける JSON の範囲は [NIP-01 の台帳](../features/nip01.md) にある。

## 10. ドメイン

HTTP/3 のフレームと制御ストリーム、リクエストとレスポンスの組み立て、QPACK のエンコードとデコード、DATAGRAM、WebTransport、MoQT(WebTransport 上と生の QUIC 上)、生の QUIC のバインディング用ヘルパー、フラグメント化 MP4 の解析、Nostr のイベントと NIP-98 の検証。

## 11. ガイドの関連ページ

| 内容 | ページ |
|---|---|
| HTTP/3 のリクエストに応答する | [はじめての HTTP/3](https://hakkadaikon.github.io/wired/guide/ja/h3/hello/) |
| ストリームとデータグラムの選び方 | [ストリームとデータグラム](https://hakkadaikon.github.io/wired/guide/ja/concepts/streams-vs-datagrams/) |
| WebTransport のセッション | [WebTransport セッション](https://hakkadaikon.github.io/wired/guide/ja/wt/session/) |
| Track、Group、Subgroup、Object とメディアの対応 | [MoQT とメディアの対応](https://hakkadaikon.github.io/wired/guide/ja/concepts/media-mapping/) |
| MP4 の配信 | [ライブトラックを配信する](https://hakkadaikon.github.io/wired/guide/ja/moqt/live/) |
