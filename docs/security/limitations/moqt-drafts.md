# 既知の制限: MoQT のドラフトと raw QUIC

[ドキュメント](../../README.md) › [セキュリティ設計](../README.md) › [既知の制限](README.md) › MoQT のドラフトと raw QUIC

| 項目 | 内容 |
|---|---|
| 目的 | MoQT の対応ドラフト、仕様からの逸脱、raw QUIC 上の MoQT の制限を示す |
| 読む人 | ハブを変更するコントリビューター、ハブを本番に入れる人 |
| 前提文書 | [既知の制限: MoQT](moqt.md) |
| 関連文書 | [容量の上限](capacity.md)、[draft-22 の台帳](../../features/draft-moq-transport-22.md)、[draft-23 の台帳](../../features/draft-moq-transport-23.md) |

用語と d18 / d19 / d22 の略記は [既知の制限: MoQT](moqt.md#1-用語) にある。

## 1. バージョンと仕様からの逸脱


### 1.1 対応するドラフトは 18、19、22、23 だけ

影響: ほかのドラフトしか話さない相手。

ドラフト 14 から 17 とドラフト 20/21 は対象外である(制御ストリームの形と varint の使い方が異なる)。ALPN `moq-00` にも対応しない。

参照: `moqver_caps`

### 1.2 意図した逸脱: Filter Type 250 を Largest Object として受け付ける

影響: 250 を送って拒否されることを期待する相手。

moxygen は仕様にない独自の Filter Type 250(LargestGroup)を送る。PROTOCOL_VIOLATION で閉じると moxygen と相互運用できなかったので、ハブは 250 を Largest Object として扱う(`moqctl_locfilter_is_quirk`)。仕様に厳密に従わせるには、この分岐を取り除く。

参照: コミット `b217989`、`moqctl_locfilter_is_quirk`

### 1.3 意図した逸脱: ランデブーの保留は 1.5 秒が上限

影響: 購読者より 1.5 秒以上遅れて来るパブリッシャー。

imquic はミリ秒を期待する所に 500000(マイクロ秒)を送り、2 秒で諦める。保留を長くすると imquic と相互運用できなかった。そのため `WIRED_MOQTRUN_RDV_MAX_MS` は 1500 で、1.5 秒を超えるランデブーの待機は REQUEST_ERROR TIMEOUT で終わる。ドラフトはリレーがより短いタイムアウトを使うことを認めている(10.2.6)。

参照: コミット `03e69af`、`WIRED_MOQTRUN_RDV_MAX_MS`

### 1.4 draft-18 には Range Filter がない

影響: Range Filter を送る d18 のクライアント。

ハブはそれを送った d18 のセッションを閉じる(未知のパラメーター型のため)。

参照: [draft-moq-transport-18.md](../../features/draft-moq-transport-18.md)

### 1.5 Descending FETCH は存在しない Group の末尾を不明として印を付けることがある

影響: Descending FETCH で End of Unknown Range の印を読むクライアント。

これは d22 3.2.2 を文字どおりに読んだ動作で、逸脱ではない。ハブは存在しない Group と Object には印を付けず、存在を保証できない Group ごとに、その Group の終わりまでの End of Unknown Range の印を付ける。そのため、この印は 1 つ前の項目の Group の末尾を、存在しなくても不明として扱う。

参照: `moqtrun_fetch_descend`

## 2. Raw QUIC 上の MoQT

MoQT は HTTP/3 や WebTransport を使わず、ALPN `moqt-18`、`moqt-19`、`moqt-22`、`moqt-23` で QUIC の上で直接動かせる。raw のセッションは WebTransport のセッションとハブを共有する(`wired_moqt_on_session_raw`)。

検証はプロセス内のテスト、固定した xquic と moqtopus のバイト列との照合、このプロジェクトによる MoQT の相互運用性テストの実行である([テストと検証の抜け](testing.md))。

### 2.1 raw_policy は形式の正しい PATH/AUTHORITY をすべて受け付ける

影響: アクセス制御が必要な raw の運用。

ハブの `raw_policy`(`moqraw_accept_all`)は RFC 3986 の形だけを検証する(MALFORMED_PATH 0x9 / MALFORMED_AUTHORITY 0x1A)。アプリケーションがフックを入れない限り、形式の正しい値はすべて受け付ける。

参照: `moqraw_accept_all`

### 2.2 raw QUIC では GOAWAY の New Session URI が空

影響: raw のクライアントを別の宛先へ送る必要がある、両方を混ぜた運用。

アプリケーションが指定する URI は 1 つで、WebTransport のエンドポイントを指す。raw のセッションには空の URI を送る。これは「今の URI を使い続ける」という意味である。

参照: `moqtrun_goaway_uri`

### 2.3 raw の ALPN では 0-RTT を断る

影響: 0-RTT(再開した接続の最初の送信でデータを送ること)を使う raw のクライアント。

raw QUIC の接続は 0-RTT では受け入れない(d18 3.3.1 / d22 6.3.1 では、これはリレーの MAY)。NewSessionTicket から early_data 拡張を外すので、再開するクライアントは 0-RTT を試さない。

参照: `ticket_max_early_data`

### 2.4 切断理由は最小サイズのパケット 1 つに収まる長さまで

影響: なし。

ハブのアプリケーションの CONNECTION_CLOSE(0x1d)の理由文字列は、`SRVRUN_RAW_CLOSE_REASON_MAX` = 1148 バイトに(UTF-8 の境界で)切り詰める。これは 1200 バイトのデータグラムにフレームのオーバーヘッドと並べて収まる長さである。保持する WT の close メッセージ(最大 1024 バイト)は丸ごと送る。

参照: `SRVRUN_CLOSE_PL_MAX`

### 2.5 クライアントの単方向ストリームは接続あたり 9 本

影響: 多くの Subgroup を同時に開く raw のパブリッシャー。

raw の MoQT は Subgroup ごとに単方向ストリームを 1 本使う。サーバーはクライアントの単方向ストリームを 9 本と広告し、それぞれに受信スロットを持つ(`WIRED_SRVLOOP_MAX_WT_UNI_STREAMS` = 9。各スロットの窓は `WIRED_SRVLOOP_WT_BUF_CAP`)。

| セッション | WT のデータに使えるスロット |
|---|---|
| HTTP/3 上(WebTransport) | 6(3 個はクライアントの制御ストリームと QPACK のストリーム) |
| raw | 9 |

参照: `WIRED_SRVLOOP_MAX_WT_UNI_STREAMS`

### 2.6 raw でハブが満員のとき

影響: 満員のハブに参加する raw のクライアント。

空いているセッションのスロットがないと、raw のセッションはすぐに INTERNAL_ERROR で閉じる。

参照: `moqtrun_refuse_session`

### 2.7 raw の MoQT のクライアント役はない

影響: wired から raw QUIC で外へ接続するアプリケーション。

wired には raw QUIC の MoQT クライアントがなく、interop runner に登録しているのはリレー役だけである。クライアント役全般は [対象外と予定なし](scope.md) にある。
