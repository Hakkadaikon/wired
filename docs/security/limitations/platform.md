# 既知の制限: プラットフォームと I/O

[ドキュメント](../../README.md) › [セキュリティ設計](../README.md) › [既知の制限](README.md) › プラットフォームと I/O

| 項目 | 内容 |
|---|---|
| 目的 | 動作環境、ソケット、AF_XDP、`printf` 互換関数の制限を示す |
| 読む人 | `src/common/` と I/O ドライバーを変更するコントリビューター、サーバーを本番に入れる人 |
| 前提文書 | [既知の制限](README.md) |
| 関連文書 | [システムコール](../../syscalls.md)、[容量の上限](capacity.md) |

## 1. 動作環境

### 1.1 Linux の x86-64 と aarch64 だけ

影響: ほかのすべての OS と CPU。

ISA に依存するコードは `src/common/arch/` の `x8664/` と `aarch64/` にあり、`common/arch/raw.h` がビルドする ISA のものを選ぶ([システムコール](../../syscalls.md) 2 章)。

| ISA | 確かめていること |
|---|---|
| x86-64 | ここに挙げるすべての検査 |
| aarch64 | CI の `aarch64` ジョブ(`ubuntu-24.04-arm`)でのフリースタンディングのビルド、単体テスト、`word_list` への HTTP/3 の POST。`guide.yml` の `snippets` ジョブの arm64 側での、guide のすべてのスニペット(HTTP/3、WebTransport、MoQT)を実際の UDP で通した出力と golden の一致 |

### 1.2 aarch64 はページの大きさが 4 KiB のカーネルだけ

影響: 16 KiB や 64 KiB のページで動く aarch64 の Linux。

スレッドのスタックのガードページ(`THREAD_GUARD_LEN`)と `madvise` の単位(`WIRED_ARCH_PAGE`)は 4 KiB である。ページがもっと大きいカーネルでは、`mprotect` と `madvise` が失敗する。

参照: `WIRED_ARCH_PAGE`(`common/arch/sysops.h`)、`THREAD_GUARD_LEN`(`common/platform/thread/thread.c`)

## 2. ソケット

### 2.1 `recvmmsg` のまとめ数の上限

影響: もっと大きなまとめ数を使う UDP 層の呼び出し側。

`WIRED_RECVMMSG_MAX` は 64 で、スタックに置く。

参照: `WIRED_RECVMMSG_MAX`(ponytail)

### 2.2 SO_REUSEPORT はできる範囲で設定する

影響: 複数ワーカー(`--cores N`)の運用。

`wired_server_run` は、自分のソケットで `SO_REUSEPORT` をできる範囲で有効にする(`srvrun_listen` の中の `wired_udp_reuseport_enable`)。カーネルがこれを拒むとエラーは無視され、2 つ目のワーカーの bind が失敗する。そのため `--cores N` には、`SO_REUSEPORT` を許すカーネルが必要である。

参照: `srvrun_listen`

## 3. AF_XDP

### 3.1 AF_XDP の経路は拡張ヘッダーのない IPv4 と IPv6 だけ

影響: カーネルを迂回するドライバーを使う運用。

送るときは、オプションのない 20 バイトの IPv4 ヘッダーか、拡張ヘッダーのない 40 バイトの IPv6 ヘッダーを使う。受けるときは、IPv4 のオプションを読み飛ばす。IPv6 の拡張ヘッダーの付いたパケット(Next Header が UDP でないもの)は BPF フィルターがカーネルへ渡すので、AF_XDP のソケットには届かない。

返信の送信元のアドレスは、そのピアから受けたフレームの宛先のアドレスである(`xdpmac`)。ピアから一度も受けていないアドレスへは送らない。

参照: [rfc791.md](../../features/rfc791.md)、`xdpframe_parse6`、`bpf_prog_ipv6`

### 3.2 AF_XDP の接続 ID によるルーティングは難読化で、暗号化ではない

影響: パス上に意図を持った観測者がいる、AF_XDP のマルチキュー(`--ifindex` と `--cores`)の運用。

各接続 ID の中のコア ID は接続 ID の続く 4 バイトを鍵付きの乗算 / xorshift で撹拌した値でマスクする。鍵はプロセスごとに取り、BPF の振り分けプログラムとだけ共有する(RFC 9312 §2.6)。BPF の側ではブロック暗号を動かせないので、QUIC-LB の AES を使う方式より弱い。

参照: [rfc9312.md](../../features/rfc9312.md) 9312-005、`ncid_route_key`

## 4. `printf` 互換関数

### 4.1 `wired_snprintf` の仲間の違い

影響: これらの関数でログを出すアプリケーション。

| 書式・関数 | 動作 |
|---|---|
| `%p` に NULL | `0x0` |
| `%f` | 整数部を 2^64 で頭打ち、精度の上限は 40 |
| `wired_dprintf` | 511 バイトを超えた出力を切り捨てる |

参照: `fmt.h`

## 5. ハブとソケットの調整

[容量の上限](capacity.md) にある。
