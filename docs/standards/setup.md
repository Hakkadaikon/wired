# 開発環境の準備

[ドキュメント](../README.md) › [開発標準](README.md) › 開発環境の準備

| 項目 | 内容 |
|---|---|
| 目的 | ツールチェーンを入れ、ビルドとテストを通し、サンプルサーバーを動かすまでの手順を定める |
| 読む人 | リポジトリを初めてチェックアウトしたコントリビューター |
| 前提文書 | なし |
| 関連文書 | [ビルド](build.md)、[コミットゲート](commit-gate.md) |

## 1. ツールチェーンの準備

対象は x86_64-linux だけである。

| ツール | 役割 |
|---|---|
| clang | コンパイラー |
| `just` | コマンドランナー。ビルドの手順はすべて `just` のレシピである |
| `ninja` | レシピが呼ぶビルドツール |
| `lizard` | 複雑度の検査 |

入手方法は 2 つある。

| 方法 | 手順 | バージョン |
|---|---|---|
| A: Nix(推奨) | `just setup` のあと `nix develop` | devShell の clang、just、ninja、lizard、doxygen は CI と同じ |
| B: パッケージマネージャー | `apt install clang just ninja-build` と `pip install lizard` など | ホストのもの。ビルドとテストは通る |

```sh
just setup     # one-time: installs Nix (Determinate Systems installer) if absent
nix develop    # enter the pinned devShell
```

devShell は、Nix が固定したバージョンのツールを入れる一時的なシェルである。システムのほかの部分は変えない。

方法 B では、ホストの `clang-format` と `clang-tidy` が CI と違う整形や lint の結果を出すことがある。整形の検査で差が出たら、そのレシピだけを `just nix <recipe>` で固定したツールチェーンで実行する。

## 2. ビルドとテスト

```sh
just build     # format + compile + lint
just test      # run the whole test suite
```

`just check` は `ccn` と `test` を合わせたレシピである。レシピの一覧は [ビルド](build.md) にある。

## 3. サンプルサーバーの起動

```sh
cd examples/word_list
just run       # builds the SDK + the sample, binds 0.0.0.0:4433
```

UDP ポート 4433 に届くマシンから次を実行する。

```sh
curl --http3-only --insecure https://<host>:4433/
```

サンプルは自己署名証明書を提示するので `--insecure` が要る。curl が HTTP/3 に対応していなければ Docker 版を使う。

```sh
docker run --rm ymuski/curl-http3 \
    curl --http3-only --insecure -v https://<host>:4433/
```

[examples/](../../examples/) のサンプルはどれも `just run` で動く。

| サンプル | 中身 |
|---|---|
| [word_list](../../examples/word_list/) | HTTP/3 のメッセージログと静的ファイルのサーバー |
| [webtransport_interop](../../examples/webtransport_interop/) | [quic-interop-runner](https://github.com/quic-interop/quic-interop-runner) 用の WebTransport サーバーのエンドポイント |
| [moqt_chat](../../examples/moqt_chat/) | MoQT で作ったブラウザーのチャットと音声通話のルーム |
| [moqt_interop](../../examples/moqt_interop/) | moq-interop-runner 用の MoQT リレー |

アプリケーションの書き方は [インタラクティブガイド](https://hakkadaikon.github.io/wired/guide/ja/) にある。

## 4. ビルドが変わって見える理由

wired は libc を使わない。サーバーは Linux カーネルだけに依存する 1 つの静的バイナリになり、アプリケーションも freestanding でコンパイルする。理由は [概要書](../overview/README.md) にある。

ふだん libc が用意する次の 2 つは SDK が用意する。

| 名前 | libc での役割 | wired での用意 |
|---|---|---|
| `_start` | カーネルが最初に入るエントリポイント。`argc`/`argv` を準備して `main` を呼ぶ | SDK の `_start` が `wired_main` を呼ぶ |
| `memcpy`、`memset` | コンパイラーが構造体のコピーなどで自分で呼び出しを出す | SDK の shim が SDK のバイト操作ヘルパーに渡す |

shim と `_start` のスタブは `wired.h` をインクルードする前に `WIRED_MAIN` を定義した翻訳単位に出る。`WIRED_MAIN` を定義する翻訳単位は 1 つだけにする。2 つで定義するとリンクに失敗する。

リンクのコマンドは guide の [はじめての wired](https://hakkadaikon.github.io/wired/guide/ja/getting-started/hello/) にある。
