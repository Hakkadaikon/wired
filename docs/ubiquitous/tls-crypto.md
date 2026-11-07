# ユビキタス言語: TLS と暗号

[ドキュメント](../README.md) › [ユビキタス言語](README.md) › TLS と暗号

出典は tex2e/rfc-translater の RFC 8446、5280、5869、6066、6125、7301、8017、8032、8439 などの訳と、tex2e/nist-translator の FIPS 180-4、186-5、197、198-1、SP 800-38D の訳。規則の番号は [表記の決め方](README.md#1-表記の決め方) のもの。

## 1. ハンドシェイク

| 英語 | 表記 | 出典の訳 | 規則・備考 |
|---|---|---|---|
| handshake | ハンドシェイク | ハンドシェイク 536 | 3 |
| ClientHello / ServerHello / Finished など | 英語のまま | — | 1。メッセージ名 |
| extension | 拡張 | 拡張 546 | 3 |
| alert | アラート | アラート 95、警告 5 | 3 |
| cipher suite | 暗号スイート | 暗号スイート 32 | 3 |
| key exchange | 鍵交換 | 鍵交換 23、キー交換 19 | 3 |
| key schedule | 鍵スケジュール | 鍵スケジュール 16、キースケジュール 3 | 3 |
| pre-shared key(PSK) | 事前共有鍵 | 事前共有キー 11、事前共有鍵 2 | 4。key は「鍵」にそろえる |
| session resumption | セッション再開 | セッション再開 12 | 3 |
| ticket | チケット | チケット 44 | 3 |
| early data | 早期データ | 初期データ 28、早期データ 6 | 4。「初期」は Initial パケットと紛れる |
| secret | シークレット | 秘密 117、シークレット 40 | 4。TLS のシークレット(traffic secret など)は名前として扱う。秘密一般の意味なら「秘密」 |
| traffic secret | トラフィックシークレット | トラフィックシークレット 3 | 3 |
| exporter | エクスポーター | エクスポーター 9 | 3 |
| server name | サーバー名 | サーバー名 20 | 3 |
| application protocol | アプリケーションプロトコル | アプリケーションプロトコル 58 | 3 |
| replay | リプレイ | リプレイ 32、再生 17 | 3 |
| downgrade | ダウングレード | ダウングレード 25 | 3 |
| forward secrecy | 前方秘匿性 | 前方秘匿性 5 | 3 |
| session | セッション | セッション 84 | 3 |

## 2. 証明書

| 英語 | 表記 | 出典の訳 | 規則・備考 |
|---|---|---|---|
| certificate | 証明書 | 証明書 626 | 3 |
| certificate chain | 証明書チェーン | 証明書チェーン 16 | 3 |
| trust anchor | トラストアンカー | トラストアンカー 24 | 3 |
| issuer | 発行者 | 発行者 93 | 3 |
| subject | サブジェクト | サブジェクト 63、主体 55、主体者 52 | 3 |
| signature | 署名 | 署名 472 | 3 |
| authentication | 認証 | 認証 244 | 3 |

## 3. 鍵と暗号プリミティブ

| 英語 | 表記 | 出典の訳 | 規則・備考 |
|---|---|---|---|
| key | 鍵 | 公開鍵 258、秘密鍵 180 ほか | 3 |
| public key | 公開鍵 | 公開鍵 258 | 3 |
| private key | 秘密鍵 | 秘密鍵 180 | 3 |
| key derivation | 鍵導出 | 鍵導出 14、キー導出 3 | 3 |
| hash | ハッシュ | ハッシュ 355 | 3 |
| authenticated encryption | 認証付き暗号 | 認証付き暗号 45 | 3 |
| plaintext | 平文 | 平文 53 | 3 |
| ciphertext | 暗号文 | 暗号文 92 | 3 |
| block cipher | ブロック暗号 | ブロック暗号 52 | 3 |
| nonce | nonce | ナンス 8、nonce 6 | 4。コードの識別子と同じ綴り |
| salt | ソルト | ソルト 38 | 3 |
| tag | タグ | タグ 87 | 3 |
| padding | パディング | パディング 105 | 3 |
| curve | 曲線 | 曲線 218 | 3 |
| point | 点 | 点 135、ポイント 56 | 3 |
| scalar | スカラー | スカラー 13 | 3、5 |
| modulus | 法 | 法 34、モジュラス 26 | 3 |
| test vector | テストベクター | テストベクトル 21 | 4。ソフトウェアの用語として定着した表記 |
