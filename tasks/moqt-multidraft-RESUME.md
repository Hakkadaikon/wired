closed (2026-10-05), successor: なし(台帳の全項目が完了)。次に手を付ける場合は下の「残っている改善余地」から。

# 再開メモ — 2026-10-05 17:20 UTC(クラウドセッション2本目の終了時)

## 結果

- 台帳 `tasks/moqt-multidraft-ledger.md`: **全項目 `[x]`**(未着手・部分完了なし)。
- moq-interop-runner(fork Hakkadaikon/moq-interop-runner、workflow `interop-wired.yml`、run 37338133133):
  WebTransport relay `wired` 12/14、raw-QUIC relay `wired-quic` 13/14。残る 3 件はクライアントが対応しない
  トランスポートの組合せのみ(xquic-draft-18/moqtopus は raw 専用、moq-dev-js は WT 専用)で、
  **全クライアントが対応トランスポートで PASS、wired 起因の失敗は 0**。ベースラインは 3/14 だった。
- CI: wired の CI / Examples / Docs / Guide が main で green(Guide は h3-stats golden 修正 c46731d で復帰)。
  このサンドボックス(IPv6 無効)でも `just test` は失敗 0。
- 追加で実施: raw QUIC 上の MoQT(13 章)、printf 互換 API(14 章、`src/common/fmt/`)、
  BoringSSL FileTest ベクタによる暗号の第三者オラクル(5fa543f、`docs/security/boringssl-vectors.md`、失敗 0)。

## 残っている改善余地(台帳外、任意)

- 仕様からの意図的逸脱 2 件: moxygen の Filter Type 250 を Largest Object として受理(b217989)、
  rendezvous 保留上限 1.5 s(03e69af、imquic が μs を送るため。1.5 s を超える正当な待機は TIMEOUT)。
- HMAC-SHA512 / SHA-1 / P-521 は未実装(TLS 1.3 ハンドシェイクには不要、証明書チェーン検証でのみ影響)。
- valgrind: BPF attr struct の 7 件(カーネルが size 以降をゼロ埋めするため偽陽性の見込み)、
  srvworkers_test の 5 件は valgrind 下のタイミング依存。`srvthreads_datagram_test.c:1095` が稀にフレーク。
- interop-runner fork の変更(wired-quic 登録、ワークフロー統合)は fork の main にのみ入っている(本家未提案)。

## 参照

- 台帳: `tasks/moqt-multidraft-ledger.md`
- TLA+ / 設計: `tasks/loopeng/moqt/{MoqtVerCtl,MoqtFillLife,MoqtXRelay,Rendezvous,UpstreamSub,MoqtRawConn}/`
- raw QUIC: `tasks/loopeng/moqt/RawQuic/`
- interop: `tasks/loopeng/moqt/interop/baseline-2026-10-05.md`
- BoringSSL ベクタ: `tests/vectors/boringssl/README.md`
