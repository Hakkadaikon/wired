---
paths:
  - "README.md"
  - "docs/**/*.md"
---

# README.md と docs/ の日本語ドキュメント

README.md と docs/ は日本語で書く。構成と書き方の正本は
[docs/standards/documentation.md](../../docs/standards/documentation.md)、用語の表記の正本は
[docs/ubiquitous/](../../docs/ubiquitous/README.md) である。ここには守る点の要約と、
機械検査に関わる制約だけを置く。

## 対象

| 対象 | 扱い |
|---|---|
| README.md(ルート)、docs/ | このルールに従う |
| docs/features/ の RFC・FIPS・SP・ドラフトの台帳 | RFC・FIPS・SP の訳文は外部の訳(出典は docs/ubiquitous/ の各ページ)から取ったもので、文体を直さない。ドラフトの要件文は仕様の本文から抜き出したもので、常体で書く。行を足すときは既存の行の書式に合わせる。地の文の文体は FORMAT.md 2.9(です・ます、要件文は常体)が正本で、下の「である調」より優先する |
| docs/sdk/ | doxygen の生成物で対象外。直すときはヘッダーのドキュメントコメントを編集する |
| guide/ | 対象外。文体は です・ます(guide-ja-persona.md) |

## 書き方

- 文体はである調。です・ますと「〜だ」「〜してください」は使わない。例外は docs/features/ の台帳の地の文で、FORMAT.md 2.9 に従う(上の表。「〜してください」も含めてです・ます調にする)。
- 事実・数値・出典だけを書く。「速い」「小さい」「安全」のような評価の語と比喩を書かない。
- 冒頭にパンくずと、目的・読む人・前提文書・関連文書の表を置く。見出しに章番号を付ける。
  ディレクトリ名には番号を付けない。1 文書が 300 行を超えたら章で分ける。
- 1 文 50 字、1 段落 3 文を目安にする。比べるものは表、流れと状態は図、手順は番号付きの箇条にする。
- 「このページは〜」の前置き、つなぎの文、本文の繰り返しになるまとめは書かない。
- 一般的な用語(MECE、CCN、EARS など)は解説しない。プロジェクト独自の語だけ、初出で 1 行添える。
- 同じ説明は 1 か所にだけ書き、ほかからリンクする。
- 書き終えたら yomiyasu スキル(ユーザーグローバル)で推敲する。

## 技術用語

- docs/ubiquitous/ の表記に従う。仕様が定める名前(フレーム名、メッセージ名、Object/Track など)と
  HTTP の method/scheme/authority/path/query/body は英語のままにする。
- 一覧にない語を使うときは、先に docs/ubiquitous/ に行を足す。表記を変えるときは用語集を先に直し、
  同じコミットで本文も直す。決めきれない語は英語のまま書く。

## 図

- mermaid で描き、ラベルは英語にする。日本語に訳さない。
- 1 つの図に 1 つのこと(依存、流れ、状態、判定)だけを描く。図の後の補足は 3 行までにする。

## 機械が読むもの

次のパスと書式は、スクリプトとスキルが読む。変えない。

- パス: `docs/features/`、`docs/security/vuln-ledger.md`、`docs/syscalls.md`。
- 要件台帳の書式: カバレッジと合計の行、`- test:` 行、docs/features/README.md の表、
  数えない見出し(未実装・対象外・実験的・参考情報)。正本は
  [docs/features/FORMAT.md](../../docs/features/FORMAT.md) で、`scripts/check_features.py` が検査する。
- 脆弱性台帳の `| V-` 行と列の並び。`scripts/vulnaudit/` が読む。
- docs/syscalls.md の表の 5 列。syscall-docs スキルが更新する。

## リンク

文書を移す・分けるときは、元のパスに移転先の表だけのページを残す。古い見出しのアンカー
(英語版のころのものも含む)は `<a id="…"></a>` で残し、外部からのリンクを切らない。

## 変更後の確認

```sh
just features-check                        # 要件台帳の書式とテストのリンク
python3 scripts/check_features.py --fix    # チェックボックスからカバレッジ・README の表・合計の行を書き直す
just vuln-check                            # 脆弱性台帳の書式
```
