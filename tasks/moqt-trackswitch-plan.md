closed (2026-10-09), successor: none (commits 29c57c3, a85f561, 7371b4c + the hub/server/docs commits of this date)

# moqtail 型トラック切り替え(SWITCH_FROM + SSTS backpressure)— 計画 (2026-10-09)

ユーザー指示: moqtail と同様のトラック切り替えアルゴリズムを SDK に入れ、moqt_chat に反映。計画 → TDD 実装 →
テスト。可能な限り subagent 並列。既に実装済みなら不要(→ 未実装を確認済み)。
参考: gist(Begen "The Art of The Switch" 登壇メモ)、moqtail ee9753c(scratchpad/moqtail/repo)。

## 0. 確定事項(調査結果)

- wired に切り替え機構は無い(SDK も moqt_chat も)。
- moqtail の実体:
  - SWITCH_FROM(message param 0x24、SUBSCRIBE / REQUEST_UPDATE): 「この購読を有効化し、RequestID の購読を停止」。
    Hard(新トラック初配信で旧をリセット)/ Soft(旧を境界の前のグループまで流し切る)。flags bit7 = Publish Done。
    moqtail 自身はストリーム経路の完了処理がコメントアウトされた未完成。
  - SSTS(sender-side track switching): SETUP option 0x09 SSTS_ALGORITHMS(varint 列)で交渉、
    SUBSCRIBE param 0x41 SWITCHING_SET_ASSIGNMENT で購読をセットに入れ、リレーがグループ境界ごとに
    1 メンバーだけ転送(決定はグループ単位で確定・不変)。
  - アルゴリズム: 0 = default(帯域を重み配分して閾値以下の最高メンバー)、0xff01 = backpressure
    (active stream depth: 購読者あたり開いている subgroup ストリーム数。depth<=1 が 5 回続けば 1 段上、
    depth>=2 で即 1 段下 + cooldown、cooldown 中は timeout か depth 上昇 2 回で更に下)。
  - 講演の switch prompt / GOP 長拡張 / latency budget はコードに無い → 対象外(既知の制限に記録)。
- draft-22 で 0x24, 0x41(param)、0x09(setup option)、REQUEST_ERROR 0x32、PUBLISH_DONE 0x3 は未割当
  (0x33 UNSUPPORTED_EXTENSION は d18/19/22 共通の標準コードで、moqtail も同名で使う)。
  moqtail と同じ値を使う(相互運用)。いずれも **実験的拡張、draft-22 セッションのみ**、hub の opt-in フラグで有効化
  (0 = 従来どおり、未知 param は PROTOCOL_VIOLATION のまま)。決定(W1 レビュー後): hub の拡張 OFF で 0x24/0x41 を受けたら PROTOCOL_VIOLATION、ON で不正・未交渉は 0x32/0x33。PUBLISH_DONE 0x3 は publish_done_for のマッピングを通さない専用経路で送る。SSA の PUBLISH_OK/REQUEST_OK 文脈(moqtail は許可)は対象外。wired では 0x32 が d18/19 の
  INVALID_JOINING_REQUEST_ID なので d22 限定が必須。
- hub の土台: Location Filter の end_group / start.group でグループ境界の正確な切断が既にできる
  (`moqtrun_sub_wants_group`)。lossy 経路の FORWARD=0 は開いたストリームを放置する既知リークがあるので、
  旧購読の終了は end_group + `moqtrun_sub_done` で行う。
- moqt_chat: 映像は画面共有のみ(VP8、2 s キーフレーム、キーフレーム毎に 1 グループ、`<id>/screen`)。
  受信側は keyframe で再構成するので解像度の違う変種への切替はデコーダ的に安全。
  `WIRED_MOQTRUN_MAX_TRACKS_PER_PEER` = 3 → 変種追加で 4 に。

## 1. ワイヤ契約(全ワーカー共通、draft-22 のみ)

- SWITCH_FROM 0x24: value = Length(vi) + { RequestID(vi), Mode(vi: 0 Hard, 1 Soft), Flags(u8: 0x80 Publish Done,
  他ビット 0 必須) }。余りバイトは違反。許可: SUBSCRIBE、REQUEST_UPDATE(subscription)。
  FORWARD と同居は REQUEST_ERROR INVALID_SWITCH(0x32)。自分自身・存在しない購読・同一トラックも 0x32。
  例: rid 7 Hard publish_done → `24 03 07 00 80`。
- SWITCHING_SET_ASSIGNMENT 0x41: value = Length(vi) + { SetID(vi), AlgorithmID(vi), ThresholdKbps(vi),
  Weight(vi 1..10), Activate(vi), [Rank(u8)] }。許可: SUBSCRIBE、REQUEST_UPDATE(subscription)。
  未交渉アルゴリズム / 別セット所属トラック → REQUEST_ERROR UNSUPPORTED_EXTENSION(0x33)。
- SSTS_ALGORITHMS setup option 0x09(奇数 = Length + bytes): varint の連結(件数なし)。hub は有効時のみ送る。
  交渉結果 = 双方の積集合。0 は default、0xff01 は backpressure。
- 旧購読の終了: Soft = 境界前グループの最後のストリーム完了後、Publish Done 指定なら PUBLISH_DONE 0x3
  ("switched"、d22 では未割当コードを moqtail 互換で使用)+ FIN。Publish Done 無しは moqtail 同様 A を suspend
  (ストリーム RESET・FORWARD 0・要求ストリームは開いたまま・PUBLISH_DONE 無し、REQUEST_UPDATE+SWITCH_FROM で戻せる)。Hard = 新トラックの境界グループが購読者へ
  開いた時点で旧の残ストリームを RESET(CANCELLED 0x1)し、Publish Done 指定なら同様に PUBLISH_DONE。
- 境界 G(SWITCH_FROM): G = max(旧トラック Largest.group, 新トラック Largest.group) + 1(どちらも無ければ
  新の start)。旧: end_group = G−1。新: start = {G,0}。変種トラックはグループ番号を揃える前提。

## 2. 作業単位

| ID | 内容 | ファイル | 依存 |
|---|---|---|---|
| W1 | codec: 0x24 / 0x41 / opt 0x09 / エラー定数(TDD) | src/app/moqt/ctl/moqctl.{h,c}, tests/app/moqctl_switch_test.c | なし |
| W2 | SSTS アルゴリズム純モジュール(default + backpressure、moqtail のテスト移植、TDD) | src/app/moqt/ssts/moqssts.{h,c}(新、prefix moqssts_), tests/app/moqssts_test.c | なし |
| W3 | TLA+: SWITCH_FROM(Hard/Soft、境界、NoGap/NoDup/DoneAfterLastStream/NoLeak)+ SSTS(グループ決定不変・1 メンバー転送) | tasks/loopeng/moqt/TrackSwitch/ | なし |
| W5 | moqt_chat フロント: 画面共有の hi/lo 変種(グループ番号共有)、0x24/0x41/0x09 の TS codec、SSTS で両変種購読、受信は両 alias を同一タイルへ、(任意)手動 auto/hi/lo を SWITCH_FROM で | examples/moqt_chat/frontend/** | ワイヤ契約のみ |
| W4a | hub: SWITCH_FROM(Soft/Hard、境界、旧の完了、re-attach 保持、エラー)TDD | src/app/moqt/run/(新 moqtswitch.c 推奨、moqtrun.c はフックのみ), tests/app/moqtrun_switch_test.c | W1 |
| W4b | hub: SSTS(交渉、セット管理、グループ毎決定、depth 計測、backpressure/default)TDD | src/app/moqt/run/(新 moqtssts の run 側), tests/app/moqtrun_ssts_test.c | W1, W2 |
| W6 | moqt_chat サーバー有効化 + MAX_TRACKS_PER_PEER 4 + 実ブラウザ確認 | examples/moqt_chat/wired_server.c, moqtrun.h | W4, W5 |
| W7 | ドキュメント(api-stability、feature ledger、known-limitations、README、guide は任意) | docs/**, examples/moqt_chat/README.md | 全体 |

並列: 第 1 波 W1, W2, W3, W5 同時(ファイル非重複)。W1 完了・コミット後に W4a と W4b を別 worktree で並列
(moqtrun.c のフック衝突はコーディネーターがマージ)。tests/run.c・gen_shards.py・git はコーディネーターのみ。
レビュー: 各ストリーム完了ごとに別 subagent で最大 3 回。

## 3. 完了条件
just test / test-fast / ninja / lizard / fmt-check / docs / golden-check / fuzz-smoke / examples build、
TLC 合格(MC_main + MC_bug が期待通り失敗)、frontend vitest + lint + tsc + build、実ブラウザで画面共有の
自動切替(混雑時に lo、回復で hi)が少なくとも 1 回観測できること(不可能なら理由を記録)、レビュー合格、push。

## 4. 実ブラウザ確認 W6(2026-10-09)

Chromium + 実験フラグ、moqt_chat サーバー(switch_track=1, ssts_algs={0xff01,0})、2 ユーザー。証跡 scratchpad/w6/。
- d22 交渉 + hub SETUP に 0x09 [0xff01, 0](`af 00 … 06 04 c0 ff 01 00`)、クライアントの SUBSCRIBE に 0x41。PASS。
- Auto: 初フレーム LO(640x360、g0-3 lo)→ g4 で HI(1280x720)、約 8 s。PASS。
- 手動 Low→High: SUBSCRIBE に `24 03 10 01 80`、旧 lo に PUBLISH_DONE 0x3 + FIN(グループ境界)、1.87 s で HI、フレーム継続。PASS。
- 混雑: CDP の帯域制限は WebTransport に効かず、CPU スロットルでも深さは変わらない。UDP 帯域制限プロキシ(700 kbps、hub→B のみ)で
  HI→LO(4 s)、制限中は LO 維持、解除後 約 11 s(5 グループ)で HI。PASS。
- フラグ無し(d19 フォールバック): チャット・画面共有 OK、バッジ・セレクタ無し、screen-lo を PUBLISH しない。PASS。
- 所見: High→Auto で約 2 s 停止(fill がゲートを lo に固定)→ フロント修正。1080p ループバックで busy-shed による無混雑の
  ダウンシフト → known-limitations に記録。

## 5. 結果(2026-10-09)

- W1 codec(0x24/0x41/opt 0x09、moqtail-rs ベクタ)、W4a hub SWITCH_FROM、W4b hub SSTS はレビュー各 2〜3 回で PASS。
  W2 アルゴリズム(29c57c3)。W5 フロント(a85f561、レビュー 3 回 PASS)、実ブラウザ所見の修正(7371b4c)。
- W3 TLA+ 合格。実装差分(Publish Done 無しは suspend、Hard は B の Largest ≥ G で切断)は design.md/RESULT.md に追記。
- W6: moqt_chat サーバーで有効化、要求ストリーム上限 64→96(ns_seen を複数語ビットマップ化)、実ブラウザ 5 ステップ PASS(§4)。
- W7: docs/features/moqt-track-switching.md 新設、draft-22 台帳 MQ22-X01..X13、known-limitations、api-stability、README。
- ゲート: test / test-fast / ninja / lizard / fmt-check / lint / docs / count 569=569 / fuzz-smoke / golden-check /
  examples 3 本 / guide-verify / frontend vitest 708 + lint + tsc + build。
- 未実施: 第三者実装(moqtail)との相互接続(台帳 MQ22-X13 [ ])。
