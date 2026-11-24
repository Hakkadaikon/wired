# nip05d

[wired](../../../README.md) › [moqt_chat](../README.md) › nip05d

| 項目 | 内容 |
|---|---|
| 目的 | NIP-05 の照合を wired_server の代わりに行う補助プロセスの、プロトコルと制限を示す |
| 読む人 | moqt_chat のサーバーと補助プロセスを動かす・変更するコントリビューター |
| 前提文書 | [moqt_chat](../README.md) |
| 関連文書 | tasks/moqt-chat-rooms.md の OD1 と P4 |

libc を使わない wired_server は、外向きの HTTPS クライアントを持たない。
そこで Go の標準ライブラリだけで書いたこのプロセスが、`name@domain` と公開鍵の対応を照合する。

## 1. 起動

```sh
CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o nip05d .
./nip05d -tcp 127.0.0.1:4480        # ループバックの TCP
./nip05d -unix /run/nip05d.sock     # Unix ソケット(モード 0600 で作る)
```

| フラグ | 意味 |
|---|---|
| `-tcp` | ループバックの `ip:port` だけを受け付ける。wired_server は AF_UNIX をまだ扱えないため、当面はこちらを使う |
| `-unix` | Unix ソケットのパス。同じパスに古いソケットが残っていれば消してから作る。ソケット以外のファイルは消さない |
| `-allow-private` | アドレスの制限を外す。e2e のフィクスチャ専用で、既定は無効 |

`-tcp` と `-unix` は同時に指定できない。
ループバックの TCP は同じホストのどのプロセスからも届く。nip05d が止まっている間は、別のプロセスが同じポートで待ち受けて偽の `ok` を返せる。AF_UNIX が使えるようになれば `-unix` に移す。

root では起動しない。照合 1 件ごとに、名前・ドメイン・公開鍵・結果を 1 行ログに出す。どれも公開情報である。

## 2. プロトコル

1 行に 1 リクエストを書く。パイプライン化してよく、応答はリクエストの順に返る。
同時に受け付ける接続は 16 本までで、超えた接続は前の接続が閉じるまで待たされる。
応答の書き込みが 5 秒で終わらない接続は閉じる。

```
check <name@domain> <pubkey-hex>\n
```

応答は `ok\n`、`fail <reason>\n`、`unknown <reason>\n` のどれかである。
`fail` は照合の失敗で、結果は確定している。`unknown` は判定できなかったことを表し、一時的なのでキャッシュしない。

| 応答 | 原因 |
|---|---|
| `ok` | `names[<name>]` が公開鍵と一致した |
| `fail bad-request` | `check <id> <pubkey>` の形でないか、0x80 以上のバイトを含む |
| `fail bad-name` / `bad-domain` / `bad-pubkey` | 3 章の入力規則に反する |
| `fail forbidden-address` | 名前解決したアドレスが公開アドレスでない |
| `fail http-<code>` | ステータスが 200、429、5xx のどれでもない。3xx も含む(リダイレクトを追わない) |
| `fail too-large` | body が 64 KiB を超えた |
| `fail bad-json` | `{"names":{...}}` の形でないか、`names[<name>]` が文字列でない。ほかの名前の値の型は見ない |
| `fail no-name` / `fail mismatch` | 名前がない / 値が公開鍵と違う |
| `fail line-too-long` | 行が `\n` を含めて 512 バイトを超えた。接続を閉じる |
| `unknown http-<code>` | ステータスが 429 か 5xx |
| `unknown timeout` | 全体の制限時間 2.5 秒を使い切った |
| `unknown network` | 名前解決・接続・TLS・読み込みのエラー |
| `unknown busy` | 同時に 8 件を照合中で、さらに 32 件が待っている。または空きを待つ間に 2.5 秒を使い切った |

## 3. 規則

| 対象 | 規則 |
|---|---|
| ローカル部 | 小文字にしてから `[a-z0-9-_.]` で 1 文字以上。`_` はルートの名前で、`name=_` で引く |
| ドメイン | 小文字にしてから ASCII の LDH ラベル(1〜63 文字、先頭と末尾はハイフン不可)を 2 個以上、全体で 253 文字以下、TLD の先頭は数字でない。これで IP リテラル、`0x7f.1` のような数値の形、ポートを拒む |
| IDNA | Go の標準ライブラリに IDNA がないため、非 ASCII のドメイン(U-label)は拒む。クライアントは punycode の A-label を送る。小文字にする前に行全体の非 ASCII を拒むので、U+212A(KELVIN SIGN)が `k` に化けることもない |
| 公開鍵 | 小文字の 16 進数 64 文字。JSON の値は完全一致が必要で、大文字の 16 進数は一致しない |
| URL | 常に `https://<domain>/.well-known/nostr.json?name=<local>`(ポート 443)。プロキシは使わない |
| アドレス | `net.Dialer.Control` で、名前解決の後に実際に接続するアドレスを判定する(DNS リバインディング対策)。IPv6 は 2000::/3 の中だけを許し、そこから 2002::/16(6to4)、2001::/32(Teredo)、2001:db8::/32 を除く。これで NAT64 64:ff9b::/96、IPv4 射影と IPv4 互換、ULA fc00::/7、サイトローカル、リンクローカルを拒む。IPv4 はループバック、RFC 1918、リンクローカル(169.254.169.254 を含む)、マルチキャスト、未指定、0.0.0.0/8、CGNAT 100.64/10、192.0.0.0/24、198.18.0.0/15、240.0.0.0/4(ブロードキャストを含む)を拒む |
| HTTP | リダイレクトを追わない。制限時間は空きの待ちを含めて全体で 2.5 秒で、wired_server の 3 秒より短い。body は 64 KiB、ヘッダーは 16 KiB まで。Content-Type は見ない |
| キャッシュ | キーは `(name@domain, pubkey)`。`ok` は 1 時間、`fail` は 5 分保持し、`unknown`(429 と 5xx を含む)は保持しない。4096 件に達したら全件を消す |

## 4. scratch イメージへの同梱

`CGO_ENABLED=0` の静的バイナリなので、scratch イメージにも wired_server のイメージにも置ける。
scratch にない次の 2 つが要る。

1. TLS のルート CA: バンドルを `/etc/ssl/certs/ca-certificates.crt`(Go の既定の探索先)へコピーする。`golang` か `alpine` のビルドステージから取る。
2. `/etc/resolv.conf`: 実行時に Docker が用意する。

非 root のユーザー(`USER 65534:65534`)で動かす。
wired_server と同じ `network_mode: host` なら `-tcp 127.0.0.1:<port>` で待ち受ける。

## 5. テスト

```sh
go vet ./... && go test -race ./...
```

すべての接続を `httptest.NewTLSServer` へ向け替えるので、ネットワークなしで動く。
