# 既知の制限: テストと検証

[ドキュメント](../../README.md) › [セキュリティ設計](../README.md) › [既知の制限](README.md) › テストと検証

| 項目 | 内容 |
|---|---|
| 目的 | テストと検証の抜けと、出荷するサーバーから呼ばれないライブラリコードを示す |
| 読む人 | テスト結果や台帳を読むコントリビューター |
| 前提文書 | [既知の制限](README.md) |
| 関連文書 | [要件台帳](../../features/README.md)、[相互運用性の検証結果](../../verification/interop.md)、[BoringSSL のベクター](../boringssl-vectors.md) |

## 1. テストと検証の抜け

| 抜け | 影響を受ける人 | 内容 |
|---|---|---|
| 自分同士のループバックは相互運用性の確認ではない | テストが通ったという結果を読む人 | wired が自分自身と通信すると、両端が同じコードなので共通のバグは打ち消し合う。このプロジェクトの決まりでは、送信路に関わる機能は、テストが RFC のベクターか実際の相手のトレースに固定するまで、台帳で `[~]`(間接)のままにする。ループバックのテストだけで完了にはしない |
| MoQT の相互運用性はこのプロジェクト自身の実行による | 相互運用性のダッシュボードを読む人 | MoQT のリレーの結果は、wired を加えた MoQT interop runner をこのプロジェクトが実行したもので、<https://moq-interop-runner-wired.vercel.app> で公開している。runner の公式の公開結果には含まれない。QUIC と WebTransport の状況は [相互運用性の検証結果](../../verification/interop.md) にある |
| ペーシングに従うデータグラムの送り出しは相互運用性テストを待っている | 損失のあるパスでデータグラムをまとめて送るアプリケーション | リングの送り出しは、interop のシミュレーターでの損失をもとに調整した 16 データグラム / 3000 バイトの固定の区切りではなく、今は接続のペーサーに従う。確かめているのは単体テストだけで、データグラムの相互運用性テストではまだ確認していない。参照: `srvrun_dgring_drain` |
| Valgrind | valgrind の出力を読む人 | BPF の attr 構造体についての 7 件の報告は、想定どおりの誤検出である(カーネルが渡した大きさより後ろをゼロで埋めるため)。`srvworkers_test` の 5 件の報告は valgrind のもとでのタイミングに左右される |
| 不安定なテスト | CI の再実行 | `sdt_run_wt_stages`(`tests/app/srvthreads_datagram_test.c` の中)の段階ごとの CHECK はまれに失敗する。ハンドシェイクの CHECK(`hs_ok`)も負荷がかかると失敗する。5 秒の Initial の期限がワーカースレッドのソケットの bind より前に始まり、サーバーには期限の起点にできる準備完了の合図がないためである。参照: `sdt_retry_initial` |
| テストのビルドが異なる | コントリビューター | `just test-fast` の分割した翻訳単位は、単一の翻訳単位の `just test` だけが見つける `static`/`typedef` の名前の衝突を見逃すことがある([ビルド](../../standards/build.md#3-test-と-test-fast)) |
| ファジングの範囲 | ハブのループの頑健さ | `fuzz_moqt` はコーデック、`moqdg`、`moqcache` を対象にする。ハブの実行ループ(`moqtrun`)はコーデックではないので、ファジングしていない |
| 台帳の件数 | 網羅率の合計 | まだテストしていない要件がある。件数は [要件台帳](../../features/README.md) にあり、残りは各台帳の `[ ]` の項目である。実験的な Track 切り替えの節(MQ22-X13 を含む)は数えない |
| BoringSSL による照合 | なし | 失敗はない。スキップは ECDSA の P-224/secp224k1 が 91 件、HMAC の MD5/SHA1/SHA224 が 12 件、96 ビットでない nonce の AES-GCM が 7 件、1,000,000 回反復する X25519 のケースである。参照: [BoringSSL のベクター](../boringssl-vectors.md) |

## 2. 出荷するサーバーから呼ばれないライブラリコード

Issue #24 では、何からも呼ばれないコードを削除し、ファズハーネス、guide のスニペット、例、出荷する経路の動作テストが使うものだけを残すと決めた。

以下の 47 個のソースファイルはライブラリにコンパイルされるが、`examples/` のどのサーバーからも関数が 1 つも到達しない。呼び出し元は、サーバーを相手にするテストのピア(TLS と HTTP/3 のクライアント側)、ファズハーネス、`examples/` が使わない公開 API、単体テストである。

これらのどれか 1 つだけを根拠に挙げている台帳の行は、出荷するサーバーの裏付けにならない。

影響: 単体テストが通ったことを、サーバーがそう動く証拠と受け取る読み手。

参照: `examples/` の 4 つのサーバーを `-ffunction-sections` と `--gc-sections` でリンクし、関数が 1 つも残らなかったファイル。

- `app/http3/core/h3conn/`: `request.c`
- `app/http3/core/h3run/`: `settings_seq.c`
- `app/http3/request/h3req/`: `reqbuild.c`, `respparse.c`
- `app/http3/request/h3reqenc/`: `header_encode.c`, `pseudo_encode.c`, `request_headers.c`
- `app/http3/server/srvrun/`: `httpx.c`, `srvrun_wt_export.c`
- `app/media/mp4frag/`: `mp4frag.c`
- `app/moqt/ctl/`: `moqctl_rngf_put.c`
- `app/moqt/data/`: `moqdata_blob.c`
- `app/moqt/dgram/`: `moqdg_put2.c`
- `app/webtransport/exporter/`: `exporter.c`
- `crypto/asymmetric/ecc/p256/`: `p256_field_fe.c`
- `crypto/asymmetric/ecc/p256fixed/`: `p256fixed_table.c`
- `crypto/kdf/keys/`: `discard_driver.c`
- `crypto/symmetric/aead/chacha/`: `poly1305_poly.c`
- `crypto/symmetric/aead/gcm/`: `gcm.c`
- `tls/ext/tparam/`: `tpblob_pa.c`
- `tls/ext/tpverify/`: `iscid.c`, `odcid.c`, `rscid.c`
- `tls/handshake/core/fullhs/`: `fullhs.c`, `fullhs_chain.c`, `fullhs_confirmed.c`
- `tls/handshake/core/hrr/`: `hrr_detect.c`
- `tls/handshake/core/tls/`: `alpn.c`, `clienthello.c`, `hs_message.c`, `hsdriver.c`, `msgassembly.c`, `serverhello.c`
- `tls/handshake/core/tlsdriver/`: `tlsdriver.c`, `tlsdriver_ch.c`, `tlsdriver_derive.c`
- `tls/handshake/roles/client/`: `clientwire.c`
- `tls/handshake/roles/server/`: `serverio.c`
- `tls/keys/keyupdate/`: `kuderive.c`
- `transport/conn/lifecycle/conn/`: `pnspace.c`
- `transport/conn/pnspace/crypto_stream/`: `crypto_rx.c`
- `transport/io/socket/poll/`: `nonblock.c`
- `transport/packet/build/initpkt/`: `initpkt.c`
- `transport/recovery/detect/recovery/`: `largestacked.c`, `probe.c`
- `transport/stream/data/appdata/`: `app_send.c`
- `transport/stream/flow/flow/`: `reassemble.c`
