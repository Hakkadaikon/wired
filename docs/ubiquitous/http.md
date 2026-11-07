# ユビキタス言語: HTTP

[ドキュメント](../README.md) › [ユビキタス言語](README.md) › HTTP

| 項目 | 内容 |
|---|---|
| 目的 | HTTP、HTTP/3、QPACK、WebTransport の用語の表記を定める |
| 読む人 | ドキュメントを書く・直すすべての人 |
| 前提文書 | [ユビキタス言語](README.md)(表記の決め方) |
| 関連文書 | [ドキュメント規約](../standards/documentation.md) |

出典は tex2e/rfc-translater の RFC 9110、9114、9204、7541、9218、9220、9297 の訳。WebTransport はドラフトに訳がないので、[HTTP/3 の台帳](../features/rfc9114.md) と guide の日本語ページに合わせる。規則の番号は [表記の決め方](README.md#1-表記の決め方) のもの。

## 1. HTTP メッセージ

| 英語 | 表記 | 出典の訳 | 規則・備考 |
|---|---|---|---|
| request | リクエスト | リクエスト 428、要求 341 | 3 |
| response | レスポンス | 応答 522、レスポンス 11 | 4。request と対で使う。「応答」は返事一般(PATH_RESPONSE など)に使う |
| method | method | メソッド 149、方法 191 | 2 |
| scheme | scheme | スキーム 145 | 2 |
| authority | authority | 権限 23、オーソリティ 9 | 2 |
| path | path | — | 2。QUIC のネットワークのパスは [QUIC](quic.md) を参照 |
| query | query | — | 2 |
| body | body | 本文 7、ボディ 7 | 2 |
| status code | ステータスコード | ステータスコード 136 | 3 |
| header field | ヘッダーフィールド | ヘッダーフィールド 409 | 3、5 |
| field section | フィールドセクション | フィールドセクション 42 | 3 |
| pseudo-header | 擬似ヘッダー | 擬似ヘッダー 23、疑似ヘッダー 8 | 3、5。個々の名前は `:method` などコードのまま |
| trailer | トレーラー | トレーラー 51 | 3、5 |
| content | コンテンツ | コンテンツ 378 | 3 |
| origin | オリジン | オリジン 88、起源 12 | 3 |
| proxy | プロキシ | プロキシ 78 | 3 |
| intermediary | 仲介者 | 仲介者 57 | 3 |
| malformed | 不正な形式 | 不正な形式 5 | 3 |

## 2. HTTP/3

| 英語 | 表記 | 出典の訳 | 規則・備考 |
|---|---|---|---|
| control stream | 制御ストリーム | 制御ストリーム 15、コントロールストリーム 13 | 3 |
| request stream | リクエストストリーム | リクエストストリーム 10、要求ストリーム 6 | 3 |
| settings(SETTINGS フレームの中身) | 設定 | 設定 51、SETTINGS 38 | 3。フレーム型は SETTINGS |
| server push | サーバープッシュ | サーバープッシュ 36 | 3、5 |
| priority | 優先度 | 優先度 46、優先順位 39 | 3 |
| urgency | 緊急度 | 緊急 24 | 4。パラメーター名の意味が分かる言い方 |
| Extended CONNECT | Extended CONNECT | — | 1 |
| capsule | カプセル | カプセル 42 | 3 |

## 3. QPACK と HPACK

| 英語 | 表記 | 出典の訳 | 規則・備考 |
|---|---|---|---|
| compression | 圧縮 | 圧縮 62 | 3 |
| dynamic table | 動的テーブル | 動的テーブル 147 | 3 |
| static table | 静的テーブル | 静的テーブル 35 | 3 |
| encoder | エンコーダー | エンコーダ 94、エンコーダー 79 | 3、5 |
| decoder | デコーダー | デコーダ 82、デコーダー 77 | 3、5 |
| field line | フィールドライン | フィールドライン 46 | 3 |
| prefixed integer | プレフィックス付き整数 | プレフィックス整数 1、接頭辞付き整数 1 | 4。「7 ビットプレフィックス」という通常の言い方に合わせる |
| literal | リテラル | リテラル 83 | 3 |
| Huffman | ハフマン | ハフマン 28 | 3 |
| Required Insert Count / Base / Post-Base | 英語のまま | — | 1 |

## 4. WebTransport

| 英語 | 表記 | 出典 | 規則・備考 |
|---|---|---|---|
| session | セッション | guide | 3 |
| datagram | データグラム | guide | 3 |
| drain | ドレイン | 台帳 | 4 |
