# ベンチマークの実行結果

[ドキュメント](../README.md) › [性能](./) › [比較](comparison.md) › 実行結果

[実装の比較](comparison.md)の元になった生データです。誰でも計算し直せるように載せています。2026-11-02 時点のスナップショットで、wired は `efd61452e` です。

## ループバックの計測

各サーバーについて続けて実行した `bench/run-lane.sh` の出力です。集計には `node bench/report.mjs speed|usage <file>` を使います。RSS の単位は KiB、`dticks` は `hz=100` での値です。クライアントが出す UDP バッファーの警告(`rmem_max` が 208 KiB だった)は、これらの行から取り除いています。これは 2 回行った計測の 2 回目です。1 回目は quiche のビルドでまだマシンが忙しいときに走ったので使っていません。

```text
wired-p2 r0 usage kind=idle reqs=0 dticks=0 wall_ms=0 hz=100 vmhwm_kb=512 vmrss_kb=512
wired-p2 r1 mode=ttfb n=100 fails=0 reqps=292.0 p50=2.99 p99=6.09 cpu%=75
wired-p2 r1 mode=load n=10000 fails=0 reqps=22165.7 p50=0.77 p99=3.05 cpu%=128
wired-p2 r1 usage kind=load reqs=10000 dticks=38 wall_ms=472 hz=100 vmhwm_kb=1896 vmrss_kb=1412
wired-p2 r2 mode=ttfb n=100 fails=0 reqps=330.8 p50=2.73 p99=4.58 cpu%=71
wired-p2 r2 mode=load n=10000 fails=0 reqps=23651.9 p50=0.70 p99=3.36 cpu%=124
wired-p2 r2 usage kind=load reqs=10000 dticks=34 wall_ms=443 hz=100 vmhwm_kb=1932 vmrss_kb=1412
wired-p2 r3 mode=ttfb n=100 fails=0 reqps=334.6 p50=2.68 p99=4.26 cpu%=72
wired-p2 r3 mode=load n=10000 fails=0 reqps=25011.1 p50=0.69 p99=2.67 cpu%=127
wired-p2 r3 usage kind=load reqs=10000 dticks=35 wall_ms=418 hz=100 vmhwm_kb=1932 vmrss_kb=1412
wired-p2 r4 mode=ttfb n=100 fails=0 reqps=336.6 p50=2.61 p99=5.67 cpu%=67
wired-p2 r4 mode=load n=10000 fails=0 reqps=23803.5 p50=0.69 p99=3.07 cpu%=130
wired-p2 r4 usage kind=load reqs=10000 dticks=35 wall_ms=439 hz=100 vmhwm_kb=1932 vmrss_kb=1412
wired-p2 r5 mode=ttfb n=100 fails=0 reqps=342.2 p50=2.64 p99=4.85 cpu%=70
wired-p2 r5 mode=load n=10000 fails=0 reqps=24490.5 p50=0.71 p99=3.12 cpu%=124
wired-p2 r5 usage kind=load reqs=10000 dticks=35 wall_ms=427 hz=100 vmhwm_kb=1932 vmrss_kb=1412
quic-go-p2 r0 usage kind=idle reqs=0 dticks=0 wall_ms=0 hz=100 vmhwm_kb=8424 vmrss_kb=8424
quic-go-p2 r1 mode=ttfb n=100 fails=0 reqps=288.1 p50=2.88 p99=9.54 cpu%=73
quic-go-p2 r1 mode=load n=10000 fails=0 reqps=12634.8 p50=1.36 p99=3.53 cpu%=89
quic-go-p2 r1 usage kind=load reqs=10000 dticks=76 wall_ms=810 hz=100 vmhwm_kb=15292 vmrss_kb=15292
quic-go-p2 r2 mode=ttfb n=100 fails=0 reqps=358.3 p50=2.39 p99=5.50 cpu%=77
quic-go-p2 r2 mode=load n=10000 fails=0 reqps=12000.7 p50=1.46 p99=3.93 cpu%=86
quic-go-p2 r2 usage kind=load reqs=10000 dticks=79 wall_ms=856 hz=100 vmhwm_kb=15304 vmrss_kb=15304
quic-go-p2 r3 mode=ttfb n=100 fails=0 reqps=363.9 p50=2.47 p99=3.92 cpu%=78
quic-go-p2 r3 mode=load n=10000 fails=0 reqps=12542.3 p50=1.37 p99=3.57 cpu%=82
quic-go-p2 r3 usage kind=load reqs=10000 dticks=77 wall_ms=819 hz=100 vmhwm_kb=15320 vmrss_kb=15320
quic-go-p2 r4 mode=ttfb n=100 fails=0 reqps=342.8 p50=2.65 p99=4.49 cpu%=78
quic-go-p2 r4 mode=load n=10000 fails=0 reqps=12050.4 p50=1.48 p99=3.38 cpu%=87
quic-go-p2 r4 usage kind=load reqs=10000 dticks=80 wall_ms=849 hz=100 vmhwm_kb=15328 vmrss_kb=15328
quic-go-p2 r5 mode=ttfb n=100 fails=0 reqps=315.6 p50=2.79 p99=5.68 cpu%=77
quic-go-p2 r5 mode=load n=10000 fails=0 reqps=10982.5 p50=1.59 p99=3.98 cpu%=87
quic-go-p2 r5 usage kind=load reqs=10000 dticks=86 wall_ms=932 hz=100 vmhwm_kb=15340 vmrss_kb=15340
quiche-p2 r0 usage kind=idle reqs=0 dticks=0 wall_ms=0 hz=100 vmhwm_kb=7804 vmrss_kb=7804
quiche-p2 r1 mode=ttfb n=100 fails=0 reqps=401.4 p50=2.16 p99=4.99 cpu%=92
quiche-p2 r1 mode=load n=10000 fails=0 reqps=19680.8 p50=0.89 p99=2.84 cpu%=108
quiche-p2 r1 usage kind=load reqs=10000 dticks=45 wall_ms=526 hz=100 vmhwm_kb=8444 vmrss_kb=8444
quiche-p2 r2 mode=ttfb n=100 fails=0 reqps=457.1 p50=1.81 p99=4.21 cpu%=97
quiche-p2 r2 mode=load n=10000 fails=0 reqps=22684.3 p50=0.80 p99=2.40 cpu%=118
quiche-p2 r2 usage kind=load reqs=10000 dticks=35 wall_ms=457 hz=100 vmhwm_kb=8464 vmrss_kb=8464
quiche-p2 r3 mode=ttfb n=100 fails=0 reqps=469.1 p50=1.79 p99=4.51 cpu%=92
quiche-p2 r3 mode=load n=10000 fails=0 reqps=23497.0 p50=0.77 p99=2.10 cpu%=122
quiche-p2 r3 usage kind=load reqs=10000 dticks=34 wall_ms=446 hz=100 vmhwm_kb=8464 vmrss_kb=8464
quiche-p2 r4 mode=ttfb n=100 fails=0 reqps=429.8 p50=2.14 p99=3.45 cpu%=84
quiche-p2 r4 mode=load n=10000 fails=0 reqps=22653.4 p50=0.79 p99=2.94 cpu%=120
quiche-p2 r4 usage kind=load reqs=10000 dticks=36 wall_ms=458 hz=100 vmhwm_kb=8464 vmrss_kb=8464
quiche-p2 r5 mode=ttfb n=100 fails=0 reqps=440.4 p50=1.97 p99=4.06 cpu%=96
quiche-p2 r5 mode=load n=10000 fails=0 reqps=22359.8 p50=0.79 p99=2.56 cpu%=118
quiche-p2 r5 usage kind=load reqs=10000 dticks=36 wall_ms=471 hz=100 vmhwm_kb=8468 vmrss_kb=8468
```

## グッドプットの計測

quic-interop-runner は `045b88d`、クライアントは `martenseemann/quic-go-interop`、`-t goodput` で、サーバーごとに 5 回繰り返しました。

| サーバー | 各回の kbps | イメージ |
|---|---|---|
| wired `efd61452e` | 9433 9419 9445 9453 9419 | ローカルでビルド(`CONNTABLE_CAP=64`) |
| quic-go | 9526 9562 9531 9529 9529 | `martenseemann/quic-go-interop@sha256:15040012e5cf` |
| quiche | 9438 9426 9433 9437 9435 | `cloudflare/quiche-qns@sha256:b67c084e211e` |
| ngtcp2 | 9316 9392 9297 9385 9371 | `ghcr.io/ngtcp2/ngtcp2-interop@sha256:ffb4689908dc` |
| picoquic | 9099 9106 9151 9105 9130 | `privateoctopus/picoquic@sha256:4d1da8e8557c` |

## バイナリのセクション

Berkeley 形式の `size(1)` で測りました。strip 後のサイズは、`strip` をかけた後のファイルの大きさです。

| バイナリ | text | data | bss | strip 後 |
|---|---|---|---|---|
| wired_server `efd61452e` | 510,144 | 7,994 | 29,427,736 | 525,040 |
| qgserver (quic-go v0.61.0) | 6,944,189 | 353,891 | 267,888 | 7,311,104 |
| quiche-server 0.29.3 | 5,857,037 | 375,456 | 7,648 | 6,237,840 |
