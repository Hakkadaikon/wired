# 既知の制限

[ドキュメント](../../README.md) › [セキュリティ設計](../README.md) › 既知の制限

| 項目 | 内容 |
|---|---|
| 目的 | wired の既知の制限と、意図して仕様から外している点を層ごとに示す |
| 読む人 | wired を本番に入れる人、制限を外すコントリビューター |
| 前提文書 | [セキュリティ設計](../README.md) |
| 関連文書 | guide の「[現在の上限](https://hakkadaikon.github.io/wired/guide/ja/concepts/limits/)」、[要件台帳](../../features/README.md) |

最終確認日: 2026-11-03

## 1. 位置付け

テーブルはすべてビルド時に大きさを決める固定長の配列である。テーブルに収まる数を超えて求める相手は、新しいメモリで受け入れずに断る。

guide の「現在の上限」は、アプリケーションが最初に突き当たる容量と、MoQT の未実装の部分を挙げている。この文書群はあふれたときの動作、目に付きにくい制限、仕様から外した理由を加える。2 つが食い違うときは、この文書群の値を正とする。値は今のコードから取った(2026-11-03 に確認)。

## 2. 項目の出どころ

| 出どころ | 内容 |
|---|---|
| `src/` の `ponytail:` と `shortcut:` のコメント | 意図して受け入れた制限の目印。制限を外す方法の覚え書きが添えてある |
| `docs/features/` の仕様ごとの台帳 | 「未実装」と「対象外」の節、およびテストしていない項目 |
| BoringSSL のテストベクターのスキップ表 | [BoringSSL のベクター](../boringssl-vectors.md) |

各項目の「参照:」にはコードのシンボル(関数またはマクロ)か台帳のファイルを書く。「9.5」のような節番号は、その項目が挙げている仕様の節を指す。台帳の項目 ID(MQ22-137 など)は台帳の ID である。

## 3. 影響の大きい制限

| 制限 | 影響を受ける人 | 文書 |
|---|---|---|
| 動作環境は Linux x86-64 だけ | ほかの OS と CPU | [プラットフォームと I/O](platform.md) |
| クライアント役を出荷していない(TLS/QUIC/HTTP/3/WebTransport/MoQT) | クライアントが必要なアプリケーション | [対象外と予定なし](scope.md) |
| 接続テーブルは通常のビルドで 4 接続(`WIRED_CONNTABLE_CAP`。interop のイメージは 64) | 多くの接続が必要なサーバー | [QUIC](quic.md)、[容量の上限](capacity.md) |
| 固定のレスポンスの body は 1 回 15744 バイトまで | 大きなレスポンスを返すハンドラー | [HTTP/3 と WebTransport](http3.md) |
| `ticket_key` のシードを共有すると、0-RTT はサーバーごとに 1 回リプレイできる | 複数のサーバーで早期データを受け付ける運用 | [QUIC](quic.md)、[TLS と暗号](crypto.md) |
| チケットと Retry トークンの鍵は、既定では 1 つのプロセスの間だけ有効 | 再起動をまたいで再開する運用 | [TLS と暗号](crypto.md) |
| クライアント認証を使うと再開と 0-RTT が無効になる | 相互 TLS を使うアプリケーション | [TLS と暗号](crypto.md) |
| AF_XDP の経路は IPv4 だけ | IPv6 の運用 | [プラットフォームと I/O](platform.md) |
| MoQT は draft-18、19、22、23 だけ | ほかのドラフトしか話さない相手 | [MoQT のドラフトと raw QUIC](moqt-drafts.md) |
| MoQT の Track ごとのパブリッシャーは既定で 1 つ(`multi_publisher` で変更) | 同じ Track を複数のパブリッシャーが告知する部屋 | [MoQT](moqt.md) |
| MoQT のランデブーの保留は 1.5 秒が上限(仕様からの逸脱) | 遅れて来るパブリッシャー | [MoQT のドラフトと raw QUIC](moqt-drafts.md) |
| MoQT の Filter Type 250 を Largest Object として受け付ける(仕様からの逸脱) | 250 の拒否を期待する相手 | [MoQT のドラフトと raw QUIC](moqt-drafts.md) |
| Track 切り替えはループバックでしかテストしていない | 第三者の相手と組み合わせる人 | [MoQT の Track 切り替え](moqt-switching.md) |
| MoQT の相互運用性はこのプロジェクト自身の実行による | 相互運用性の結果を読む人 | [テストと検証](testing.md) |
| HTTP/3 のサーバープッシュとプロキシはない | プロキシやプッシュが必要なアプリケーション | [HTTP/3 と WebTransport](http3.md)、[対象外と予定なし](scope.md) |

## 4. 文書の一覧

| 文書 | 範囲 |
|---|---|
| [MoQT](moqt.md) | ハブ(リレー) |
| [MoQT のドラフトと raw QUIC](moqt-drafts.md) | 対応ドラフトと仕様からの逸脱、raw QUIC 上の MoQT |
| [MoQT の Track 切り替え](moqt-switching.md) | SWITCH_FROM と SSTS(実験的) |
| [HTTP/3 と WebTransport](http3.md) | WebTransport、HTTP/3、QPACK |
| [QUIC](quic.md) | 損失回復、パスと接続 ID、ECN と IP、0-RTT とトークンの記録 |
| [TLS と暗号](crypto.md) | TLS 1.3、証明書、暗号プリミティブ |
| [プラットフォームと I/O](platform.md) | 動作環境、ソケット、AF_XDP、`printf` 互換関数 |
| [容量の上限](capacity.md) | 固定長のテーブルとバッファーの一覧 |
| [テストと検証](testing.md) | テストと検証の抜け、出荷するサーバーから呼ばれないライブラリコード |
| [対象外と予定なし](scope.md) | 設計上の対象外と、実装しないと決めた機能 |
