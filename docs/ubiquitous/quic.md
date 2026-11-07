# ユビキタス言語: QUIC

[ドキュメント](../README.md) › [ユビキタス言語](README.md) › QUIC

出典は tex2e/rfc-translater の RFC 9000、9001、9002、8999、9221、9287、9368、9369、8899 の訳。規則の番号は [表記の決め方](README.md#1-表記の決め方) のもの。

## 1. 接続とストリーム

| 英語 | 表記 | 出典の訳 | 規則・備考 |
|---|---|---|---|
| connection | 接続 | 接続 1054、コネクション 7 | 3 |
| connection ID | 接続 ID | 接続ID 199、コネクションID 1 | 3 |
| connection error | 接続エラー | 接続エラー 130 | 3 |
| stream | ストリーム | ストリーム 489 | 3 |
| stream ID | ストリーム ID | ストリームID 48 | 3 |
| unidirectional stream | 単方向ストリーム | 単方向ストリーム 13 | 3 |
| bidirectional stream | 双方向ストリーム | 双方向ストリーム 17 | 3 |
| stream error | ストリームエラー | ストリームエラー 8 | 3 |
| endpoint | エンドポイント | エンドポイント 533 | 3 |
| peer | ピア | ピア 282、相手 1 | 3 |
| server | サーバー | サーバ 1126、サーバー 1102 | 3、5 |
| client | クライアント | クライアント 1011 | 3 |
| idle timeout | アイドルタイムアウト | アイドルタイムアウト 20 | 3 |
| stateless reset | ステートレスリセット | ステートレスリセット 59 | 3 |
| reset | リセット | リセット 97 | 3 |
| closing / draining(状態) | closing / draining | 閉鎖 9、排水 7 | 1。状態名 |
| flow control | フロー制御 | フロー制御 85 | 3 |

## 2. パケットとフレーム

| 英語 | 表記 | 出典の訳 | 規則・備考 |
|---|---|---|---|
| packet | パケット | パケット 890 | 3 |
| frame | フレーム | フレーム 527 | 3 |
| datagram | データグラム | データグラム 207 | 3。フレーム型を指すときは DATAGRAM |
| payload | ペイロード | ペイロード 96 | 3 |
| header | ヘッダー | ヘッダ 816、ヘッダー 791 | 3、5 |
| packet number | パケット番号 | パケット番号 144 | 3 |
| packet number space | パケット番号空間 | パケット番号スペース 41、パケット番号空間 8 | 4。space は「空間」(RFC 9002 の訳と、整数の範囲を指す意味に合わせる) |
| Initial / Handshake / 0-RTT / 1-RTT / Retry パケット | Initial パケットなど | 初期 297、Initial 22 | 1。パケット種別の名前 |
| retry(一般の再試行) | 再試行 | 再試行 104 | 3 |
| coalesce | 結合 | 合体 5 | 4。開発者の通常の言い方 |
| variable-length integer | 可変長整数 | 可変長整数 62 | 3 |
| transport parameter | トランスポートパラメーター | トランスポートパラメータ 71 | 3、5 |
| spin bit | スピンビット | スピンビット 21 | 3 |
| greasing | グリース | グリース 4 | 3 |
| version negotiation | バージョンネゴシエーション | バージョンネゴシエーション 117、バージョン交渉 7 | 3 |
| negotiation | ネゴシエーション | ネゴシエーション 214、交渉 58 | 3 |

## 3. 暗号化レベルと保護

| 英語 | 表記 | 出典の訳 | 規則・備考 |
|---|---|---|---|
| encryption level | 暗号化レベル | 暗号化レベル 28 | 3 |
| packet protection | パケット保護 | パケット保護 83 | 3 |
| header protection | ヘッダー保護 | ヘッダー保護 43、ヘッダ保護 15 | 3、5 |
| key update | 鍵更新 | キーアップデート 21、キー更新 9、鍵更新 3 | 4。key は [TLS と暗号](tls-crypto.md) に合わせて「鍵」。仕組みの名前として書くときは Key Update |
| amplification | 増幅 | 増幅 18 | 3 |
| anti-amplification limit | 増幅攻撃対策の上限 | 増幅防止 3、増幅対策 1 | 4。目的が分かる言い方 |

## 4. 損失回復と輻輳制御

| 英語 | 表記 | 出典の訳 | 規則・備考 |
|---|---|---|---|
| loss recovery | 損失回復 | 損失回復 16 | 3 |
| loss detection | 損失検出 | 損失検出 43 | 3 |
| acknowledgment | 確認応答 | 確認応答 80、承認 16 | 3。フレーム型を指すときは ACK |
| ack-eliciting | ACK 誘発 | ACK誘発 37 | 3 |
| retransmission | 再送 | 再送 26、再送信 20 | 3 |
| reordering | 順序の入れ替わり | 並べ替え 25 | 4。受信側で並べ直す意味に読まれないため |
| congestion control | 輻輳制御 | 輻輳制御 61 | 3 |
| congestion window | 輻輳ウィンドウ | 輻輳ウィンドウ 42 | 3 |
| in flight | 送信中 | 飛行中 11 | 4。開発者の通常の言い方。初出に (in flight) を添える |
| round-trip time | 往復時間(RTT) | 往復時間 10 | 3 |
| probe timeout | プローブタイムアウト(PTO) | プローブタイムアウト 10 | 3 |
| probe | プローブ | プローブ 110 | 3 |

## 5. パスと移動

| 英語 | 表記 | 出典の訳 | 規則・備考 |
|---|---|---|---|
| path(ネットワークの経路) | パス | パス 410、経路 31 | 3。HTTP の path は [HTTP](http.md) を参照 |
| connection migration | 接続の移行 | 移行 79、マイグレーション 9 | 3 |
| preferred address | 優先アドレス | 優先アドレス 23 | 3 |
| PMTU / DPLPMTUD | PMTU / DPLPMTUD | PMTU 54 | 1 |
| black hole | ブラックホール | ブラックホール 15 | 3 |
| retire(接続 ID) | リタイア | 引退 8、リタイア 3 | 4。RETIRE_CONNECTION_ID と対応させる |
