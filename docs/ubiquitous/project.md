# ユビキタス言語: プロジェクト

[ドキュメント](../README.md) › [ユビキタス言語](README.md) › プロジェクト

この SDK の実装と開発で使う語。外部の訳に出てこないので、プロジェクトの中で決める。

| 英語 | 表記 | 意味 |
|---|---|---|
| SDK | SDK | wired のライブラリ全体 |
| domain | ドメイン | `src/` の末端のディレクトリ |
| module token | モジュールのトークン | 内部 API の名前の接頭辞(`varint_` など) |
| slot | スロット | 固定サイズのテーブルの 1 要素 |
| view | ビュー | 範囲付きの参照(`wired_span` など) |
| driver | ドライバー | I/O の方式(poll、fork、threads、AF_XDP) |
| worker | ワーカー | fork したプロセス、またはスレッド |
| callback | コールバック | アプリケーションが渡す関数 |
| hot path | ホットパス | パケットごとに通る処理 |
| freestanding build | freestanding ビルド | `-ffreestanding -nostdlib` でのコンパイル |
| unity build | ユニティビルド | `tests/run.c` で全ソースを 1 つの翻訳単位にするテストのビルド |
| commit gate | コミットゲート | コミット前に通す検査 |
| requirement ledger | 要件台帳 | `docs/features/` |
| vulnerability ledger | 脆弱性台帳 | `docs/security/vuln-ledger.md` |
| interoperability / interop | 相互運用性 | tex2e の訳(相互運用性 42)に合わせる。テストを指すときは相互運用性テスト |
| implementation | 実装 | |
| specification | 仕様 | |
| interface | インターフェース | 規則 5 |
