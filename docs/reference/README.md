# 参照資料

[ドキュメント](../README.md) › 参照資料

| 項目 | 内容 |
|---|---|
| 目的 | `wired.h` から呼べる API の区分と、SDK が発行するシステムコールの所在を示す |
| 読む人 | API の互換性を判断するコントリビューター |
| 前提文書 | [ユビキタス言語](../ubiquitous/README.md) |
| 関連文書 | [コーディング規約](../standards/coding.md)、[API リファレンス](https://hakkadaikon.github.io/wired/) |

## 1. 文書の一覧

| 文書 | 中身 |
|---|---|
| [Stable API](api-stable.md) | アプリケーション向けで、互換性を壊す変更を避ける関数 |
| [Low-level / internal API](api-lowlevel.md) | 呼び出し順か寿命の前提条件を持つ関数 |
| [MoQT(experimental)](api-moqt.md) | ドラフトに従って変わる MoQT の公開面 |
| [バージョニングの方針](api-versioning.md) | 区分ごとの変更の扱いと、名前の接頭辞 |
| [システムコール](../syscalls.md) | SDK が発行する Linux のシステムコールのすべて |

関数の完全なシグネチャは [API リファレンス](https://hakkadaikon.github.io/wired/)(ヘッダーのコメントから doxygen で生成)にある。使い方は [wired ガイド](https://hakkadaikon.github.io/wired/guide/ja/) にある。

## 2. 区分

| 区分 | 条件 | 変更の扱い |
|---|---|---|
| Stable API | 最上位の単一の操作(run と driver の関数)か、複数の呼び出しにまたがるルールを持たない純粋関数(コーデック、ファイル I/O、ログ) | 互換性を壊す変更を避ける |
| Low-level / internal API | 呼び出し順か寿命の前提条件を持つ。`wired_server_run` とドライバーがこれらを組み合わせて使う | マイナーバージョンで変わりうる |
| experimental | MoQT の公開面。IETF のドラフトに従う | どのコミットでも変わりうる |

区分ごとの変更の扱いは [バージョニングの方針](api-versioning.md) にある。

## 3. 公開ヘッダー

`src/wired.h` は、アプリケーション向けのヘッダーをすべて取り込む単一のインクルードである。各文書で括弧に入れたヘッダー名は宣言のある場所を示し、インクルードは要らない。例外は `run/moqtswitch.h` で、[MoQT](api-moqt.md) の該当行に書いてある。

名前の接頭辞は想定する利用者を表す。`wired_*` はアプリケーション向けで、モジュールのトークンだけの名前(`sdrv_*`、`moqctl_*`、`bytes_*`)は SDK の内部向けである。`wired_*` の中で入口と低レベルのステップを分けるのは接頭辞ではなく、この区分である。

各文書に出てくる `wired_span` はビューで、ほかの誰かが所有するメモリを指すポインターと長さの組である。何もコピーしないので、ビューを使う間はそのメモリが生きていなければならない。
