closed: いいえ(進行中)。次のセッションはこのファイルから読んで再開すること。
進捗の正は `tasks/moqt-multidraft-ledger.md`。このファイルは台帳を読む前の状況説明・引き継ぎメモ。

# 再開メモ — 2026-10-05 15:00 UTC 時点(クラウドセッション2本目の終了時)

**最新(15:00)**: S10(13-9)と S11(13-10)は取り込み済み(d9feaf0、main にも push)。ghcr の relay イメージ更新済み。
moq-interop-runner fork の `interop-wired.yml` を起動済み: run 37329222499
(https://github.com/Hakkadaikon/moq-interop-runner/actions/runs/37329222499)。WebTransport(`wired`)→ raw QUIC
(`wired-quic`)の順に回り、両方の結果は artifact `interop-results`、Vercel レポートは後に走る wired-quic 分のみ。
**結果: WebTransport 9/14 PASS(前回 3/14)、raw QUIC 3/14 PASS**(内訳は台帳 12-10)。次のセッションはこの run の artifact `interop-results` の解析から始める(raw 専用クライアント全滅の原因と moqx/moxygen が最優先)(下の「次にやること」1・2 は完了、3 から)。

## ゴール(ユーザー指示、/goal)

「台帳の全てのチェックが通り、CI が通り、guide や feature などドキュメントも全て修正し、テストが全て通り、
moq-interop-runner のクライアント対向結果が全て成功する(クライアント起因の失敗を除く)まで」。
追加指示: raw QUIC 上の MoQT を計画して実装(台帳13章)、全部終わったら printf 互換関数(14章)。
運用指示: worktree の成果は実装が終わったら無条件で取り込み、作業ブランチ `claude/adoring-rubin-v4nl8o`
と `main` の両方へ push する(main は fast-forward)。

## 現在の状態

- 作業ブランチと main は同じコミットまで push 済み(このファイルのコミットが最新)。CI は確認できた範囲で全 green。
- **このサンドボックス(IPv6 無効)でも `just test` が失敗 0 件**になった(12-24 の IPv4 フォールバック)。
- 台帳: 完了 約125 / 部分(実ピア確認待ち)3 / 未着手 約8。未完了は台帳の `- [ ]` / `- [~]` を grep。
- 中断した作業: printf(14-1)のエージェントと interop 再試験のエージェントは予算の都合で停止(成果なし)。

## 次にやること(優先度順)

1. **S10(13-9)の取り込み**: hub の `wired_moqt_on_session_raw`、`moqraw_setup_verdict` 委譲、12-29/12-30。
   クラウドセッション終了時点でエージェントが作業中だった。成果が無ければやり直し(指示内容は台帳 13-9 と
   `tasks/loopeng/moqt/RawQuic/S9-notes.md` の S10 節)。
2. **S11(13-10)の取り込み**: 差分は `tasks/loopeng/moqt/RawQuic/pending/S11-example-interop.patch`
   (`git apply` で当てる)。S10 の `wired_moqt_on_session_raw` が無いとリンクしないので S10 の後。
   runner fork 側は branch `wired-raw-quic`(commit 90c5e9e、push 済み)に `wired-quic`(moqt://relay:4443)登録済み。
   main への merge は未実施(fork の main へ merge するか PR を作る)。
3. **interop 再試験(12-10、13-11)**: 手順は `tasks/loopeng/moqt/interop/baseline-2026-10-05.md`。
   - relay イメージは main への push で ghcr に再発行される(interop-image.yml)。ローカルなら
     `CONNTABLE_CAP=64 just gen-ninja && ninja examples/moqt_interop/wired_server` → `docker build -f interop/Dockerfile.moqt`。
   - IPv4 フォールバックが入ったので relay 側の ptrace シムは不要のはず(クライアント側は一部まだ必要)。
   - 最終判定は fork の GitHub Actions `interop-wired.yml`(IPv6 あり)。wired-quic 用の実行ステップ追加が必要。
   - 実装済みで実ピア確認待ち: 12-1 rendezvous、12-3 上流 SUBSCRIBE、12-20 GREASE、12-21 CONNECT FIN。
4. **13-12**: 文書(api-stability の raw 系 API、features の transport 行、moqtrun.h の WT 前提コメント)、valgrind 1 回。
5. **14章 printf**: 14-1 本体 → 14-2 置き換え。未着手(設計メモも無し)。

## 運用上の注意(このセッションで学んだこと)

- **並列化**: `moqtrun.c` も別 worktree なら並列編集できた(関数単位で局所化させ、`git apply --3way` で統合、
  衝突は `tests/run.c` の include/call 行がほとんど → 両側を残すだけ)。worktree を使うエージェントには
  「最初に `git merge claude/adoring-rubin-v4nl8o` して base を確認」させる。
- worktree 内のエージェントは main tree の `tasks/` に書けないことがある(サンドボックス)。成果物は worktree の
  `tasks/` に書かせ、統合時にコピーする。
- `tasks/` は gitignore。成果物を残すときは `git add -f`(`.bin` の TLC トレースは除外)。
- コスト: 4〜6 並列で約 $125/時 だった。
- ゲート: `nix develop -c sh -c 'just test; just ninja; lizard src --CCN 3 -w; just fmt-check; just docs; just fuzz-smoke'`。
  `just test` は "all tests passed" を確認(このサンドボックスでも 0 failure になった)。
- dockerd はコンテナで手動起動が必要(`dockerd &`)。TLC は tla2tools.jar を GitHub releases から取得。

## 参照

- 台帳: `tasks/moqt-multidraft-ledger.md`
- TLA+ / 設計: `tasks/loopeng/moqt/{MoqtVerCtl,MoqtFillLife,MoqtXRelay,Rendezvous,UpstreamSub,MoqtRawConn}/`
- raw QUIC: `tasks/loopeng/moqt/RawQuic/{plan.md,INTERFACES.md,S9-notes.md,pending/}`
- interop: `tasks/loopeng/moqt/interop/baseline-2026-10-05.md`
- EARS 台帳: `docs/features/draft-moq-transport{,-18,-22}.md`
