# wired のドキュメント

このページは `docs/` ディレクトリの地図です。最初に読むページと、知りたいことごとの次の行き先を示します。wired を初めて使う人に向けて書いており、HTTP と TLS は知っていても QUIC は知らない読み手も想定しています。

wired は積み重なった 4 つのプロトコルのためのサーバー SDK です。QUIC(HTTP/3 の下にある、暗号化された UDP のトランスポート)、HTTP/3、WebTransport(HTTP/3 の上で、ブラウザーとサーバーの間にストリームとデータグラムを通すもの)、MoQT(Media over QUIC Transport。ライブメディアのための publish/subscribe 型のプロトコル)の 4 つです。

## どこから読むか

次の 3 つをこの順に読んでください。

1. [はじめに](getting-started.md): SDK をビルドし、サンプルのサーバーを動かし、自分の小さなサーバーを書きます。ほかのページはどれも、wired のサーバーが動くところを見たことがある前提で書いているので、ここから始めてください。
1. [wired ガイド](https://hakkadaikon.github.io/wired/guide/ja/): 機能ごとに 1 本、短くて完結したプログラムを載せています(HTTP/3 のルート、WebTransport のストリームとデータグラム、MoQT の publish と subscribe)。どれも、実際に動かしたときに出力された結果を添えています。「X はどう使うのか」を知りたいときは、いつでもここを見てください。
1. [アーキテクチャとデータの流れ](arch/overview.md): SDK の中で部品がどう組み合わさり、リクエストがその中をどう通るか。コードがなぜこの形になっているかを知りたくなったら読んでください。

`docs/` の残りのページは、ガイドが扱わないことを扱います。内部の構造、設計の理由、保証していること、SDK の検証方法です。

## 学ぶ

- [はじめに](getting-started.md): ビルドし、動かし、最初のサーバーを書く。
- [examples/](../examples/): 動かせるサーバー 4 つ。`word_list` は小さな HTTP/3 サーバー、`moqt_chat` は MoQT の上で動くブラウザーのチャットと音声ルーム、`webtransport_interop` と `moqt_interop` はほかの実装との相互接続テストで使うエンドポイント。

## 理解する

- [アーキテクチャとデータの流れ](arch/overview.md): 全体像とデータの流れ。
- [レイヤー構成](arch/layers.md): 5 つのレイヤー(common、crypto、transport、tls、app。最後の app が HTTP/3、WebTransport、MoQT を受け持つ)を 1 節ずつ説明。
- [メモリ配置とサイズの見積もり](arch/memory.md): サーバーのメモリがどこから来るか。バイナリのサイズとメモリが、コードの量や容量の定数ごとにどう増えるか。
- [実装している仕様とその理由](arch/rfcs.md): SDK が実装している仕様のすべて(RFC、ドラフト、暗号の標準である FIPS / NIST SP)と、サーバーにそれぞれが必要な理由。
- [MoQT のトラック切り替え](features/moqt-track-switching.md): 実験的な拡張で、明示的に有効にしたときだけ働きます。サブスクライバーが 1 つのトラックの 2 つの版(たとえば高解像度と低解像度の画面共有)を、映像のデコーダーがきれいに再生を始められる位置で切り替えられるようにします。別の MoQT 実装である moqtail とワイヤーフォーマットが一致し、MoQT draft-22 のセッションでだけ動きます。

## 依存先として使う

wired の上に製品を作る前に、次のページを読んでください。頼ってよいことと、アプリ側の仕事として残ることを説明しています。

- [SDK とアプリの役割分担](https://hakkadaikon.github.io/wired/guide/ja/concepts/responsibilities/): プロトコルの処理と、アプリが決めるポリシー・ストレージ・スケーリングとの境目。
- [現在の上限](https://hakkadaikon.github.io/wired/guide/ja/concepts/limits/): wired に組み込まれている固定の容量。
- [API の安定性](api-stability.md): どの関数なら安心して使えるか。
- [API リファレンス](https://hakkadaikon.github.io/wired/): ヘッダーのコメントから Doxygen で生成した完全なリファレンス。
- [システムコール](syscalls.md): SDK が呼ぶカーネルの呼び出しのすべて。
- [セキュリティ](security.md): SDK が保証すること、利用者に任せること。
- [セキュリティ文書](security/README.md): セキュリティのページの裏付けになる監査の記録。脆弱性台帳と、第三者による暗号のテストベクター。

## テストの度合いを確かめる

- [テストカバレッジ](test-coverage.md): 仕様ごとに、単体のテストベクターから実際のクライアントとの相互接続性まで、どこまでテストしたかをチェックボックス 1 つずつで示す。
- [機能: 仕様ごとの要件台帳](features/README.md): 仕様ごとに 1 つの要件リスト(全部で 45 の仕様。IETF の RFC とドラフトに加え、暗号アルゴリズムを定める米国政府の FIPS と NIST SP 標準)。各要件を、それを確かめるテストか、足りない部分に対応づけている。
- [相互接続性の検証結果](interop.md): 独立した実装との実行結果(主に quic-go と webtransport-go。一部のテストケースでは ngtcp2、picoquic、flupke-webtransport も)。wired が自分自身とだけでなく、他人のコードと通信できることを示せるのは、これだけです。

## 測る

- [実装の比較](performance/comparison.md)(生データは[ベンチマークの実行結果](performance/comparison-runs.md)): ほかの HTTP/3、WebTransport、MoQT の実装との、機能と実測の速さの比較。条件は固定している。
- [moqt_chat の wired_server: 4.5 時間のリソース監視](performance/monitoring.md): `moqt_chat` サンプルサーバーの 4.5 時間分のリソースの基準値(CPU、メモリ、ネットワーク)と、テストマシンの `lscpu` の出力。

## 変更する

- [開発](development.md): すべての変更が守るべきルールと、それがある理由、コードの足し方。

このディレクトリの `sdk/` は Doxygen の出力です(gitignore 済みで、上の API リファレンスとして公開しています)。変更するときは、生成された HTML ではなく、ヘッダーのドキュメントコメントを編集してください。
