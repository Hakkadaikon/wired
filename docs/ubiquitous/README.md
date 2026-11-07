# ユビキタス言語

[ドキュメント](../README.md) › ユビキタス言語

| 項目 | 内容 |
|---|---|
| 目的 | README.md と docs/ で使う技術用語の表記を 1 つに決める |
| 読む人 | ドキュメントを書く・直すすべての人 |
| 前提文書 | なし |
| 関連文書 | [要件台帳](../features/README.md)(用語の出典) |

## 1. 表記の決め方

用語の表記は次の順に決める。上の規則が優先する。

| 順 | 規則 | 例 |
|---|---|---|
| 1 | 仕様が名前として定める語は英語のまま書く(フレーム型、メッセージ名、パケット種別、パラメーター名、エラーコード、状態名) | STREAM、SUBSCRIBE、Initial、`SETTINGS_ENABLE_CONNECT_PROTOCOL`、`H3_REQUEST_CANCELLED`、draining |
| 2 | HTTP メッセージの構成要素は英語で書く | method、scheme、authority、path、query、body |
| 3 | 既存の日本語訳で最も多い表記を採る | connection → 接続、acknowledgment → 確認応答 |
| 4 | 3 の表記が開発者に誤解される場合だけ、理由を書いて別の表記にする | early data → 早期データ(初期データは Initial と紛れる) |
| 5 | カタカナの長音は付ける(-er、-or、-ar で終わる語) | サーバー、ヘッダー、エンコーダー、パラメーター |

既存の日本語訳は、`docs/features/` の要件台帳の元にした次の訳である。

| 対象 | 出典 |
|---|---|
| RFC | [tex2e/rfc-translater](https://tex2e.github.io/rfc-translater/) |
| FIPS、SP 800-38D | [tex2e/nist-translator](https://github.com/tex2e/nist-translator) |
| MoQT、WebTransport のドラフト | 訳がないので、guide の日本語ページの表記に合わせる |

各表の「出典の訳」列は、出典の英日対訳でその語を含む文のうち、各表記が使われた文の数である。

## 2. 用語集

| 文書 | 範囲 |
|---|---|
| [QUIC](quic.md) | トランスポート、損失回復、パス |
| [TLS と暗号](tls-crypto.md) | ハンドシェイク、鍵、証明書、暗号プリミティブ |
| [HTTP](http.md) | HTTP のセマンティクス、HTTP/3、QPACK、WebTransport |
| [MoQT](moqt.md) | Media over QUIC Transport |
| [プロジェクト](project.md) | この SDK の実装と開発で使う語 |

## 3. 変更の決まり

- 用語の表記を変えるときは、この用語集を先に直し、同じコミットで README.md と docs/ の該当箇所を直す。
- 用語集にない技術用語を使うときは、先に行を足す。
- `docs/features/` の RFC・FIPS・ドラフトの台帳は、外部の訳を元にしているので対象外とする。
