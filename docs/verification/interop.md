# 相互運用性テストの結果

[ドキュメント](../README.md) › [試験と品質](README.md) › 相互運用性テストの結果

| 項目 | 内容 |
|---|---|
| 目的 | 独立したクライアント実装を相手にした wired サーバーの最新の合否と、その証拠を示す |
| 読む人 | ある機能のワイヤー互換を主張する前に確かめるコントリビューター |
| 前提文書 | [テストの範囲](coverage.md)(相互運用性テストが要る理由) |
| 関連文書 | [相互運用性テストの経緯](interop-history.md)、[要件台帳](../features/README.md) |

## 1. 実行の方法

[quic-interop-runner](https://github.com/quic-interop/quic-interop-runner) は、サーバーとクライアントを 1 つずつ Docker コンテナに入れ、模擬ネットワークリンクの両側に置く。
テストケース(`handshake`、`retry`、`zerortt` など)ごとにクライアントを動かし、トラフィックのキャプチャとダウンロードしたファイルを調べて合否を判定する。

MoQT は [moq-interop-runner](https://github.com/englishm/moq-interop-runner) で実行する(5 章)。

### 1.1 ランナーの結果の記号

ランナーの結果の表はセルごとに記号を 1 つと、括弧に入れたテストケースの略号を表示する。

| 記号 | 意味 |
|---|---|
| `✓` | 合格 |
| `✕` | 不合格 |
| `?` | 未対応。片方がそのテストケースを実装していないと宣言し、ランナーは判定を出していない |

| 略号 | テストケース |
|---|---|
| `(E)` | `ecn` |
| `(V2)` | `v2` |
| `(CM)` | `connectionmigration` |

`✓(E)` は `ecn` の合格で、`?(E)` は未対応である。

この文書が合格として記録するのは、セルが `✓` で、かつその実行のログディレクトリが存在するものだけである。

### 1.2 この文書の表の結果

| 結果 | 意味 |
|---|---|
| 合格 | 合格 |
| 不合格 | このスナップショットで不合格 |
| 判定なし | 実装済みだが、ピアやツールの制約、またはプロトコル以外の未達で判定できない |
| 未実証 | まだ実証していない |

## 2. スナップショット

| 項目 | 内容 |
|---|---|
| 実行 | 2026-10-27 の CI 実行 |
| wired | `d32fccff5` |
| QUIC と WebTransport | [Hakkadaikon/quic-interop-runner の実行](https://github.com/Hakkadaikon/quic-interop-runner/actions/runs/40475049893) |
| MoQT | [Hakkadaikon/moq-interop-runner の実行](https://github.com/Hakkadaikon/moq-interop-runner/actions/runs/40475054806) |

| 対象 | クライアント | 結果 |
|---|---|---|
| QUIC | 15 種 | 合格 249、不合格 28、未対応 53(テストケースのセルだけ。計測 2 つは別に数える) |
| QUIC のうち quic-go | 1 種 | 22 テストケースのうち 19 が合格。計測 2 つも合格。`ecn` と `v2` は quic-go クライアントが未対応、`connectionmigration` は不合格 |
| WebTransport | 5 種 | 合格 26、不合格 9 |
| MoQT リレー | 14 種 | WebTransport 経由で 11、raw QUIC 経由で 13 が合格 |

### 2.1 損失と破損のテストケースの揺れ

`handshakeloss`(L1)、`transferloss`(L2)、`handshakecorruption`(C1)は、実行ごとに不合格になるクライアントが変わる。シミュレーターのランダムな損失パターンで結果が変わるので、1 回の実行の `✕` は合否どちらの根拠としても弱い。2026-10-27 の 2 回の CI 実行の不合格は次のとおりである。

| テストケース | [先の実行](https://github.com/Hakkadaikon/quic-interop-runner/actions/runs/40448020712) | 後の実行 |
|---|---|---|
| `handshakeloss` | ngtcp2、mvfst、quiche、picoquic、msquic、xquic、quinn | ngtcp2、mvfst、quiche、kwik、msquic、quinn |
| `handshakecorruption` | ngtcp2、mvfst、quiche、xquic、quinn | ngtcp2、mvfst、quinn、s2n-quic |
| `transferloss` | なし | xquic |
| `transfercorruption` | xquic | xquic |

`transfercorruption` は 2 回とも xquic で不合格なので、再現する不合格として扱う。

## 3. QUIC のテストケース(サーバー: wired、クライアント: quic-go)

ほかのクライアントで結果が違う場合は備考に書く。過去の失敗と修正は [相互運用性テストの経緯](interop-history.md) にある。

| テストケース | 結果 | 備考 |
|---|---|---|
| `handshake` | 合格 | 接続の確立 |
| `transfer` | 合格 | ストリーム上のファイルダウンロード。2026-08 にリグレッションが起き、再修正した |
| `http3` | 合格 | 並列の HTTP/3 GET(3 ストリーム、500 KB の body) |
| `longrtt` | 合格 | 高遅延のリンク |
| `chacha20` | 合格 | TLS_CHACHA20_POLY1305_SHA256 のエンドツーエンドのネゴシエーション。そのスイートでの転送途中の Key Update を含む |
| `keyupdate` | 合格 | RFC 9001 §6 の鍵更新、両方向 |
| `transferloss` | 合格 | パケット損失のもとでのファイル転送 |
| `transfercorruption` | 合格 | パケット破損のもとでのファイル転送 |
| `amplificationlimit` | 合格 | 証明書 9 枚で大きくしたサーバーフライトに、RFC 9000 §8.1 の増幅攻撃対策の上限を適用する。2026-10-27 に msquic で不合格([#178](https://github.com/Hakkadaikon/wired/issues/178))。サーバー側で修正済み。ローカルで 5 回中 5 回合格、次の CI 実行待ち |
| `goodput`(計測) | 合格 | ランナーの模擬 10 Mbps リンクで 10 MB、9418±14 kbps(2026-10-27)。これを実行するクライアント 14 種で 9169〜9418 kbps |
| `blackhole` | 合格 | 2 秒間の模擬リンク断のあと再開する |
| `multiplexing` | 合格 | 2026-08-05 から合格 |
| `handshakeloss` | 合格 | 30% のバースト損失のもとで 50 回のハンドシェイクがすべて完了 |
| `handshakecorruption` | 合格 | 同じシナリオを破損のもとで実行。`handshakeloss` と同じ修正で合格 |
| `retry` | 合格 | `--force-retry` による RFC 9000 §8.1.2 の強制アドレス検証 |
| `resumption` | 合格 | 実際の 2 回目のハンドシェイクでの PSK によるセッション再開 |
| `zerortt` | 合格 | 0-RTT データを受け取って処理する。msquic では不合格([#177](https://github.com/Hakkadaikon/wired/issues/177))。mvfst と quiche は未調査 |
| `ecn` | 判定なし | quic-go クライアントが `unsupported test case: ecn` を宣言。ngtcp2、picoquic、neqo、lsquic、quinn、s2n-quic では合格(2026-10-27) |
| `ipv6` | 合格 | ネイティブ IPv6 での転送 |
| `v2` | 判定なし | quic-go クライアントが `unsupported test case: v2` を宣言。ngtcp2、kwik、picoquic、aioquic、neqo、lsquic では合格、msquic と quinn では不合格(2026-10-27) |
| `rebind-port` / `rebind-addr` | 合格 | これらを実行するクライアント 14 種すべてで合格(2026-10-27) |
| `connectionmigration` | 不合格 | quic-go とほか 8 種のクライアントで不合格。ngtcp2、picoquic、aioquic、neqo、lsquic では合格(2026-10-27) |
| `crosstraffic`(計測) | 合格 | 競合する TCP cubic フローと並べて 25 MB。quic-go に対して 1453(± 111)kbps(2026-10-27)。msquic と xquic では不合格 |

## 4. WebTransport のテストケース(サーバー: wired、クライアント: webtransport-go)

セッションは Extended CONNECT リクエストで始まる(guide の [WebTransport のセッション](https://hakkadaikon.github.io/wired/guide/ja/wt/session/))。

| テストケース | 結果 | 備考 |
|---|---|---|
| `handshake` | 合格 | Extended CONNECT によるセッション確立 |
| `transfer-unidirectional-receive` | 合格 | サーバーが単方向ストリームでファイルを送る |
| `transfer-bidirectional-receive` | 合格 | サーバーが双方向ストリームで応答する |
| `transfer-datagram-receive` | 合格 | サーバーが DATAGRAM で送る |
| `transfer-unidirectional-send` | 合格 | 2xx とストリームの順序を 2026-08-23 に修正(`ee13cc7`)。ngtcp2 と webtransport-go で合格 |
| `transfer-bidirectional-send` | 不合格 | 2026-10-27 に webtransport-go でファイルが途中で切れて不合格([#180](https://github.com/Hakkadaikon/wired/issues/180))。根本原因は修正済み。ローカルで 5 回中 5 回合格、次の CI 実行待ち |
| `transfer-datagram-send` | 合格 | `transfer-unidirectional-send` と同じ修正。2026-08-23 のローカルでの逐次再実行で webtransport-go に合格 |

2026-10-27 の CI 実行のクライアント 5 種の結果は次のとおりである。

| クライアント | 合格 | 不合格 |
|---|---|---|
| flupke-webtransport | 7 | 0 |
| ngtcp2 | 7 | 0 |
| webtransport-go | 6 | 1(`transfer-bidirectional-send`) |
| Firefox | 6 | 1(`handshake`) |
| Chrome | 0 | 7 |

Chrome と Firefox の不合格は調査していない。

## 5. MoQT リレー(サーバー: wired、クライアント 14 種)

moq-interop-runner は、各クライアントのテストスイートを、リレーとして動かした `examples/moqt_interop` に対して WebTransport 経由と raw QUIC 経由で 1 回ずつ実行する。

下の表は [2026-10-27 の実行](https://github.com/Hakkadaikon/moq-interop-runner/actions/runs/40475054806) の結果である。

| トランスポート | 合格 | 不合格のクライアント |
|---|---|---|
| WebTransport | 14 中 11 | moq-dev-js、xquic-draft-18、moqtopus |
| raw QUIC | 14 中 13 | moq-dev-js |

| クライアント | トランスポート | 不合格の理由 |
|---|---|---|
| moq-dev-js | WebTransport | `subscribe-namespace-lifecycle` に不合格([#179](https://github.com/Hakkadaikon/wired/issues/179))。このクライアントの @moq/net 0.4.4 は PUBLISH_NAMESPACE を FIN だけで取り下げる。draft-ietf-moq-transport-22 §6.4.2.2 はこれをキャンセルとしないので、リレーが名前空間を保持し NAMESPACE_DONE を送らないのは仕様どおりである。@moq/net 0.4.7 はリクエストをキャンセルし、ローカルの実行で同じリレーに対して 8 テストすべてに合格する |
| moq-dev-js | raw QUIC | `setup-only` を含むすべてのテストで不合格。このクライアントは raw QUIC のトランスポートを持たず、URL スキームにかかわらず WebTransport のセッションを開く |
| xquic-draft-18、moqtopus | WebTransport | raw QUIC のリレー URL にだけ対応する(それぞれのログに記載)。raw QUIC 経由では合格 |

合格したクライアントのうち、moq-dev-rs と stitcher-moq はそれぞれ 2 テストをスキップする(`ok # SKIP`)。

## 6. 未解決の失敗

2026-10-27 の実行の失敗と、それを追う issue である。

| 失敗 | issue | 状態 |
|---|---|---|
| msquic での `zerortt`("client sent too much data in 1-RTT") | [#177](https://github.com/Hakkadaikon/wired/issues/177) | 作り直した msquic のイメージは最初の 0-RTT パケット(約 600 バイト)だけを送り、残りを 1-RTT で送る。quic-go のサーバーに対しても同じである。2026-10-04 に合格した wired のコミット(`4f38861a7`)も、ローカルの実行で同じように不合格になる。wired は PSK と early data を受け入れている |
| msquic での `amplificationlimit`(ファイルの欠落) | [#178](https://github.com/Hakkadaikon/wired/issues/178) | サーバー側の停止。修正済み。ローカルで 5 回中 5 回合格、次の CI 実行待ち([経緯](interop-history.md#14-amplificationlimit)) |
| webtransport-go での WebTransport の `transfer-bidirectional-send` | [#180](https://github.com/Hakkadaikon/wired/issues/180) | 修正済み(受信したバイトをビットマップで記録)、次の CI 実行待ち([経緯](interop-history.md#21-transfer-bidirectional-send)) |
| moq-dev-js での MoQT の `subscribe-namespace-lifecycle` | [#179](https://github.com/Hakkadaikon/wired/issues/179) | クライアントの動作。@moq/net 0.4.7 で修正されている |

issue のない未調査の失敗は次のとおりである。

- mvfst と quiche での `zerortt`
- 9 種のクライアントでの `connectionmigration`
- xquic での `multiplexing` と `transfercorruption`(2 回とも)
- msquic と quinn での `v2`
- msquic と xquic での `crosstraffic`
- WebTransport 経由の Chrome(7 つすべて)と Firefox(`handshake`)

シミュレーターの損失で結果が変わる失敗(2.1)は次のとおりである。

- ngtcp2、mvfst、quiche、kwik、msquic、quinn での `handshakeloss`
- ngtcp2、mvfst、quinn、s2n-quic での `handshakecorruption`
- xquic での `transferloss`

## 7. 未達の点

- QUIC の 22 テストケースのうち 3 つは、quic-go に対する合格がない。`ecn` と `v2` は quic-go クライアントが拒否し、どちらも ngtcp2 などほかのクライアントでは合格する。`connectionmigration` はほかのクライアント 5 種で合格する。計測のテストケースは 2 つとも合格している。
- Ed25519 と RSA の証明書の経路、HTTP/3 のリクエストの優先度([RFC 9218](../features/rfc9218.md))、QUIC ビットのグリース([RFC 9287](../features/rfc9287.md))は、単体テストで網羅し、実際のピアに対しては試していない。
- AF_XDP の経路(wired が IPv4/UDP ヘッダーを自分で組み立てる、オプションのカーネルバイパスの経路)は、相互運用性テストを実行していない。
