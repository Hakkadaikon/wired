closed: いいえ(進行中)。次のセッションはこのファイルから読んで再開すること。
進捗の正は `tasks/moqt-multidraft-ledger.md`(gitignore対象)。このファイルは
その台帳を読む前の状況説明・引き継ぎメモ。

# 再開メモ — 2026-10-05 MoQT マルチドラフト対応(draft-18/19/22)

## ゴール

wired の MoQT(当初 draft-19 専用)を draft-18/19/22 の3版を交渉できる実装
へ改める。計画全文は `/home/hakkadaikon/.claude/plans/steady-splashing-riddle.md`。
ユーザー指示は「全部終わるまで」(自律的に最後まで進める)だったが、週間
利用上限が96%に達したため、ユーザーの指示で4-15の取り込みまでで一旦停止。

## 現在の状態(2026-10-05 停止時点)

**作業ツリーはクリーン、origin/main と完全一致(`38f3e287`まで push済み、
全CIグリーン確認済み)。** 未コミットの差分は無い。

台帳の進捗: 83件完了 / 6件未着手 / 1件部分完了(詳細は台帳本体)。

## 今回のセッションで完了した主な作業

1. **SETUP交渉の重大バグ発見・修正**(1-3の実機バグ、commit `fcb70d72`等)
   — uniストリームのStream Type varintとSETUP Message自身のTypeを別々に
   2回書いていた誤り。moq-interop-runner実機対向で発見、修正後
   moq-dev-rs 2/6→6/6。
2. **E-2: hub発PUBLISH/PUBLISH_SKIPPED**(10-2/10-8、commit `26c0c138`/
   `816511eb`)— TLA+設計検証済み、外部レビュー合格。SUBSCRIBE_TRACKSを
   受けてhubが自発的にPUBLISHまたはPUBLISH_SKIPPEDを送る経路。
3. **6-8/6-9/6-10: WTフロー制御無効時の挙動**(commit `6c3d569f`)—
   draft-16 §5.1準拠。
4. **4-15: subgroup配信のEnd Object境界ゲート**(commit `38f3e287`)—
   draft-22 LOCATION_FILTER type 0x04のEnd Objectを、relay転送が
   Object単位で尊重するよう修正。
5. **8-1: EARS台帳draft-18/22新設**(commit `c7fbe1ef`)—
   `docs/features/draft-moq-transport-{18,22}.md`、stem `MQ18`/`MQ22`。
6. **7-3: golden vectorの版対応**(commit `e4be35ab`)。
7. **3-1〜3-4, 3-11, 3-12, 1-5, 1-6, 7-2**: 台帳の見落とし修正(実装済み
   なのに`[ ]`のままだったものを確認・`[x]`化)。1-5/1-6はブラウザの
   WebTransport APIがJSからWTサブプロトコルを選べないという技術的制約
   により、今回の計画ではスコープ外とする裁定を下した(台帳55-58行に
   理由を詳述)。
8. **外部interop結果の更新**: moq-interop-runner forkで対向試験実行
   (4/14 PASS、残りはE-2未実装由来と特定し、E-2実装後に再検証が要る
   — 下記「次にやること」参照)。quic-interop-runner forkでも対向試験
   実行(QUIC/WebTransport、`connectionmigration`失敗を新規発見、別件)。
9. **ドキュメント更新**: README/api-stability.md/guide hub.mdx(en/ja)/
   interop READMEのdraft-19固定記述を多版対応に修正。既存ドキュメントの
   ドリフト2件を発見・修正(MOQT-070の古いテスト参照、FETCH End Location
   のノート誤記)。

## 次にやること(優先度順)

### すぐ着手できる(ブロッカー無し)

- **4-4の残り**: `moqtrun_ctl_open`(`moqtrun.c`)が送信するSETUPが、
  ピアの版を見ずに常にMAX_FILTER_RANGES/MAX_REQUEST_UPDATESという
  Setup Option(draft-19/22専用)をdraft-18ピアにも送ってしまっている。
  draft-18は未知のSetup OptionsをMUST ignoreと規定しているため相互運用
  性への実害は無いが、版ゲートの抜け漏れとして直すべき。台帳139行目に
  詳細。小さい修正(1箇所の条件分岐追加、`p->ver`のcapビットを見て
  draft-18では省略する)。
- **5-2/5-3**: 台帳の「ブロッカーは2-1/2-2と同じ(版を保存する場所が無
  い)」という記述は古く、2-1/2-2は既に完了済み(`wired_moqtrun_peer.ver`)
  なのでブロッカーは解消済み。5-2は着手可能と確認(台帳193-195行)。5-3
  は「本当に版ごとの差し替えが必要か」自体を再調査してから着手すること
  (台帳196行、`moqfetch_obj_put`はデータプレーンで版不変の可能性が高く、
  対象外(N/A)として閉じる可能性もある)。
- **5-4**: 版をまたぐrelayのテスト(pub18/sub22等)。5-2/5-3の実装後に
  着手するのが自然(先行実装が無いので一から書く)。

### 外部検証の再実行(重要、忘れずに)

- **moq-interop-runner forkでの再対向試験**: E-2(10-2/10-8)実装前は
  14クライアント中4 PASSで、残り10件のFAILは全てE-2未実装起因と特定
  済み(台帳236-245行に詳細な原因分析あり)。**E-2が実装された今、
  同じ14クライアントで再実行し、PASS数の向上を確認すること。**
  実行方法: `cd ../moq-interop-runner && gh workflow run interop-wired.yml
  -R Hakkadaikon/moq-interop-runner`(または`make interop-relay
  RELAY=wired`でローカル実行)。

### まだ手を付けていない大きめの項目

- **7-1**: TLA+で3件モデル検査(版交渉と制御ストリームの組、22のfill
  fetchライフサイクル、版をまたぐrelayの購読とFETCHの対応)。
- **7-4**: 既存のmoqtテスト(542関数)のうち、セッションのシナリオ系を
  全版でループして回す。
- **7-5**: fuzz_moqtに版の選択バイトを足し、版ごとのcodecを通す。

## 運用上の注意(このセッションで学んだこと、次回も当てはまる)

- **複数エージェントの並行作業は`moqtrun.c`で必ず競合する**。このセッ
  ションで2回、メインツリーが他エージェントの`git reset --hard`/
  `git checkout --`で破壊される事故が起きた(1回は専用worktreeへの
  退避で復旧、1回はコミット前にメインツリーの状態を自分で検証して
  発見・修復)。`moqtrun.c`/`moqtrun.h`/`moqns.c`/`moqns.h`を触る作業は
  同時に1本のエージェントだけに限定し、他の作業(ドキュメント、
  `moqctl.c`限定の作業、golden vector等)はファイル領域が重ならないこと
  を確認してから並行させること。
- **`tests/app/srvinbox_test.c`はフレーキー**(今回4回中1回失敗、
  再実行で解消)。MoQT本線とは無関係な既存の共有メモリIPCテストなので、
  単発の失敗で焦って調査しない。再実行して再現するかどうかを先に見る。
- **台帳の「ブロッカー」「未着手」の記述は、他の章の完了によって古くなる
  ことがある**。着手前に、記述が依存する前提(「版を保存する場所が無い」
  等)が現在も真かどうかを一度確認する癖をつけること(今回5-2/5-3で
  これが起きていた)。
- **worktree退避パターン**: `moqtrun.c`の並行競合を避けるため、サブ
  エージェントに「メインツリーに他の未コミット変更が無いか確認し、
  あれば専用`git worktree add`で退避してから作業する」ことを明示的に
  指示するのが有効だった(4-15で機能した)。完了後はパッチを
  `git diff`で抽出し、メインツリーに`git apply`で適用→三点ゲート再検証
  →コミット→`git worktree remove --force`で後片付け、という手順が
  安全だった。

## 参照

- 台帳: `tasks/moqt-multidraft-ledger.md`(gitignore対象、進捗の正)
- EARS正式台帳: `docs/features/draft-moq-transport{,-18,-22}.md`
- 計画全文: `/home/hakkadaikon/.claude/plans/steady-splashing-riddle.md`
- E-2設計検証: `tasks/loopeng/moqt/MoqtHubPublish/`(TLA+、gitignore対象)
- draft-18/19差分カタログ: `tasks/loopeng/moqt/draft18-vs-19-diff.md`
- draft-19/22差分カタログ: `tasks/loopeng/moqt/draft19-vs-22-diff.md`
