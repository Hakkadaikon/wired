# 実 UDP QUIC サーバサンプル

`quic_server.c` は、実際の UDP ソケットで QUIC の Initial パケットを受信し、
リポジトリ本体の部品で TLS 1.3 のサーバフライトを組み立てて応答を返す最小サーバである。
libc 非依存・x86_64-linux・直接 syscall で動く（自前の `_start` を持つ静的バイナリ）。

何をするか。

- `0.0.0.0:4433` に bind する。
- datagram を受信し、簡易ロングヘッダから DCID を取り出す。
- 取り出した DCID から Initial 鍵を導出して Initial を復号し（RFC 9001 5.2）、
  CRYPTO フレームから ClientHello を取り出す。
- ALPN `h3` のオファーを確認し、実行時に自己署名 Ed25519 証明書を組み立てる。
- サーバドライバ（`sdrv`）で、**本物の TLS バイト列**のサーバフライトを生成する。
  ServerHello、EncryptedExtensions、Certificate、CertificateVerify、Finished
  （RFC 8446 4.4）である。
- ServerHello をサーバ Initial パケットに封入し（RFC 9000 17.2.2）、
  残りを Handshake パケットに封入して（RFC 9000 17.2.4、導出した handshake 鍵で保護）、
  両方を送信元へ返す。
- 各ステップを stderr に出力する。

## ビルドと起動

```sh
cd examples
nix develop          # clang / just / tcpdump が入る
just run             # ビルドして 0.0.0.0:4433 で起動
```

`just build` だけでも `examples/quic_server` バイナリが生成される。

## 実地検証で確認できたこと

別プロセスのクライアントから実 UDP（ループバック）で 1 往復させ、サーバの
受信・応答経路をワイヤ越しに通した。観測できた事実は次のとおり。

クライアントは、本物の ClientHello を載せた AEAD + ヘッダ保護つきの client Initial
（1200 バイト）を `127.0.0.1:4433` へ送る。

サーバは Initial を受信・復号し（`Initial received and opened`）、ALPN `h3` を選択し
（`ALPN: h3 selected`）、自己署名証明書を組み立て（`certificate built`）、サーバフライトを
生成し（`server flight built`）、ServerHello（Initial、128 バイト）とフライト
（Handshake、385 バイト）の 2 つの datagram を送り返す。

クライアントは応答を受け取り、サーバ Initial 鍵で 1 つ目の応答を復号して、本物の
ServerHello（handshake 型 `0x02`）を取り出せることを確認する。2 つ目の応答が
サーバフライトを載せた Handshake パケットとして届くことも確認する。

つまり「実 UDP ソケットで QUIC Initial を受信し、本物のサーバフライトを生成して返す」
ところまでを、ワイヤ越しに確認している。

ワイヤを介さないインプロセスの検査では、ここからさらに踏み込み、サーバが封入した
ServerHello とフライトを鍵で開き直してバイト列が一致すること、すなわち応答が
正しく保護された開封可能なパケットであることまで確かめている。署名（CertificateVerify）
と Finished の MAC をクライアントが検証して同じ ECDHE 共有秘密に到達する完全な
ハンドシェイクは、本体の `sdrv` テストとドライバテストがメモリ上で実証している。

## 正直な制約

- このサーバは**完全な HTTP/3 を返さない**。リクエストへのレスポンス生成は含まない。
  1-RTT 鍵の設置やクライアント Finished の受理も、このサンプルの範囲外である。
- 本体のパケットコーデックは簡易ロングヘッダ（SCID、token、length フィールドを持たない）
  を使う。このため `curl --http3` とはワイヤ互換でなく、curl では完走しない。
  この環境の curl は 8.5.0 で、そもそも HTTP/3 を含まないビルドだった
  （`curl --version` の Protocols/Features に http3 が無い）。
  検証は、同じコーデックを使うクライアントで行った。
- `tcpdump` でのパケットキャプチャは、この環境では権限（CAP_NET_RAW）が無く実行できなかった。
  代わりに、実ソケットでサーバの応答を受け取り、サーバ Initial 鍵で ServerHello を
  復号して取り出せること、Handshake パケットが届くことを確認している。
- 鍵は再現性のため固定シードである（`ponytail:` コメント参照）。本番では per-run 鍵にする。

本体のドライバテストは、同じハンドシェイクが 1-RTT 鍵設置まで完走することをメモリ上で実証している。

```sh
cd ..
just test
```
