# 実 UDP QUIC サーバサンプル

`quic_server.c` は、実際の UDP ソケットで QUIC の Initial パケットを受信し、
リポジトリ本体の `quic_driver` で handshake を駆動して応答を返す最小サーバである。
libc 非依存・x86_64-linux・直接 syscall で動く（自前の `_start` を持つ静的バイナリ）。

何をするか。

- `0.0.0.0:4433` に bind する。
- datagram を受信し、最初の Initial long header から DCID を取り出す（RFC 9000 17.2）。
- `quic_driver_init(.., is_server=1, dcid, dcid_len)` でサーバ側ドライバを起こす。
- 受信 datagram を `feed` し、`step`/`take` で handshake フライトを進め、
  生成された datagram を送信元へ `send` で返す。
- handshake 完了で `handshake complete` を stderr に出す。

## ビルドと起動

```sh
cd examples
nix develop          # clang / just / tcpdump が入る
just run             # ビルドして 0.0.0.0:4433 で起動
```

`just build` だけでも `examples/quic_server` バイナリが生成される。

## 外から繋ぐ

別端末で疎通を観測する。

```sh
# Initial の往復を観測
sudo tcpdump -i lo -n udp port 4433

# 生バイトを送って受信経路を叩く
nc -u 127.0.0.1 4433
```

curl の HTTP/3 で叩く。

```sh
curl --http3 https://127.0.0.1:4433/
```

このとき Initial 交換までは進み、`tcpdump` で Initial の往復が観測できる。
ただし**本物の証明書チェーン（PKI）が未実装のため、TLS の証明書検証で完走しない**。
後述の制約を参照のこと。

## 最も確実な確認

handshake が完了まで通ることは、リポジトリ本体のドライバテストがメモリ上で実証している。
クライアントとサーバの 2 つのドライバをリンクし、実際の connio による seal/open 往復、
hsdriver の順序機械、keyschedule の鍵導出を通して 1-RTT 鍵設置まで到達する。

```sh
cd ..
just test            # tests/driver_test.c が handshake 完了を検証
```

## 正直な制約

- このサーバは**完全な HTTP/3 を返さない**。リクエストへのレスポンス生成は含まない。
- `curl --http3` は Initial 交換までは進むが、**証明書チェーン（PKI）が未実装のため
  TLS 証明書検証で止まる**。完走はしない。
- これは「実 UDP ソケットで QUIC Initial を受信し、handshake をドライバで駆動して
  応答パケットを返す」ことと、パケット保護（RFC 9001 A.1 の鍵テストベクタ一致）を
  実証するサンプルである。本番の QUIC サーバではない。
