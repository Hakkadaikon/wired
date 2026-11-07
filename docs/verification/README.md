# 試験と品質

[ドキュメント](../README.md) › 試験と品質

| 項目 | 内容 |
|---|---|
| 目的 | wired が仕様どおりに動くことを確かめる手段と、その結果の置き場所を示す |
| 読む人 | 要件の裏づけを確かめる、またはテストを足すコントリビューター |
| 前提文書 | [テスト](../standards/testing.md) |
| 関連文書 | [要件台帳](../features/README.md) |

## 1. 文書の一覧

| 文書 | 中身 |
|---|---|
| [テストの範囲](coverage.md) | 要件台帳の集計と、証拠の 4 つの段階(単体テスト、独立したベクター、ファジング、相互運用性) |
| [相互運用性テストの結果](interop.md) | 独立した実装を相手にした最新の実行の合否と、未解決の失敗 |
| [相互運用性テストの経緯](interop-history.md) | テストケースごとの過去の失敗、根本原因、修正、確認 |
| [実装の比較](../performance/comparison.md) | quic-go、quiche、ngtcp2、picoquic との性能と機能の比較 |
| [ベンチマークの実行結果](../performance/comparison-runs.md) | 実装の比較の生データ |
| [moqt_chat のリソース監視](../performance/monitoring.md) | `moqt_chat` の `wired_server` の 4.5 時間の CPU、メモリ、ネットワーク |

テストの書き方、検証の層(TLA+、Lean 4、TDD)の選び方、テストに入れる検査は [テスト](../standards/testing.md) にある。
