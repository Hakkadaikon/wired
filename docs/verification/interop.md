# 相互運用性テストの結果

[ドキュメント](../README.md) › [試験と品質](README.md) › 相互運用性テストの結果

| 項目 | 内容 |
|---|---|
| 目的 | 独立したクライアント実装を相手にした wired サーバーの最新の合否と、その証拠を示す |
| 読む人 | ある機能のワイヤー互換を主張する前に確かめるコントリビューター |
| 前提文書 | [テストの範囲](coverage.md)(相互運用性テストが要る理由) |
| 関連文書 | [要件台帳](../features/README.md) |

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
| 実行 | 2026-11-17 の CI 実行 |
| wired | `ed23f1470` |
| QUIC と WebTransport | [Hakkadaikon/quic-interop-runner の実行](https://github.com/Hakkadaikon/quic-interop-runner/actions/runs/44030242030) |
| MoQT | [Hakkadaikon/moq-interop-runner の実行](https://github.com/Hakkadaikon/moq-interop-runner/actions/runs/44030247172) |

| 対象 | クライアント | 結果 |
|---|---|---|
| QUIC | 14 種 | 合格 239、不合格 22、未対応 47(テストケースのセルだけ。計測 2 つは別に数える)。mvfst はクライアントのイメージを取得できず、実行していない |
| QUIC のうち quic-go | 1 種 | 22 テストケースのうち 19 が合格。計測 2 つも合格。`ecn` と `v2` は quic-go クライアントが未対応、`connectionmigration` は不合格 |
| WebTransport | 5 種 | 合格 27、不合格 8 |
| MoQT リレー | 14 種 | WebTransport 経由で 12、raw QUIC 経由で 13 が合格 |

CI の実行のあとに入れた修正は、同じ日にローカルのランナーで確かめた(2.2)。

### 2.1 損失と破損のテストケースの揺れ

`handshakeloss`(L1)と `handshakecorruption`(C1)は、実行ごとに不合格になるクライアントが変わる。シミュレーターのランダムな損失パターンで結果が変わるので、1 回の実行の `✕` は合否どちらの根拠としても弱い。3 回の CI 実行で不合格になったクライアントは次のとおりである。

| テストケース | [2026-10-27 の先の実行](https://github.com/Hakkadaikon/quic-interop-runner/actions/runs/40448020712) | [2026-10-27 の後の実行](https://github.com/Hakkadaikon/quic-interop-runner/actions/runs/40475049893) | 2026-11-17 の実行 |
|---|---|---|---|
| `handshakeloss` | ngtcp2、mvfst、quiche、picoquic、msquic、xquic、quinn | ngtcp2、mvfst、quiche、kwik、msquic、quinn | ngtcp2、quiche、picoquic、msquic、xquic |
| `handshakecorruption` | ngtcp2、mvfst、quiche、xquic、quinn | ngtcp2、mvfst、quinn、s2n-quic | ngtcp2、kwik、msquic、s2n-quic |
| `transferloss` | なし | xquic | なし |

### 2.2 CI の実行のあとにローカルで確かめたもの

2026-11-17 に、作業ツリーから作ったイメージでローカルの quic-interop-runner を実行した。ログは `~/.cache/wired-interop/quic-interop-runner/` の下にある。

| テストケース | クライアント | CI の結果 | ローカルの結果 | ログ |
|---|---|---|---|---|
| `v2` | msquic | 不合格 | 合格。サーバーが自分の優先順(v2、v1)で版を選ぶようにした(`d8f61b688`) | `logs_2026-11-17T07:33:02` |
| `v2` | ngtcp2 | 合格 | 合格 | `logs_2026-11-17T07:33:15` |
| `transfercorruption` | xquic | 不合格 | 合格。CUBIC に Reno と同等の成長を下限にする領域(RFC 9438 4.3)を足した | `logs_2026-11-17T07:45:10` |
| `transferloss` | xquic | 合格 | 合格 | `logs_2026-11-17T07:45:29` |
| `transfercorruption` | quic-go | 合格 | 合格 | `logs_2026-11-17T07:45:46` |
| `zerortt` | quinn | 不合格 | 合格 | `logs_2026-11-17T07:23:52` |

## 3. QUIC のテストケース(サーバー: wired、クライアント: quic-go)

ほかのクライアントで結果が違う場合は備考に書く。

| テストケース | 結果 | 備考 |
|---|---|---|
| `handshake` | 合格 | 接続の確立 |
| `transfer` | 合格 | ストリーム上のファイルダウンロード |
| `http3` | 合格 | 並列の HTTP/3 GET(3 ストリーム、500 KB の body) |
| `longrtt` | 合格 | 高遅延のリンク |
| `chacha20` | 合格 | TLS_CHACHA20_POLY1305_SHA256 のエンドツーエンドのネゴシエーション。そのスイートでの転送途中の Key Update を含む |
| `keyupdate` | 合格 | RFC 9001 §6 の鍵更新、両方向 |
| `transferloss` | 合格 | パケット損失のもとでのファイル転送 |
| `transfercorruption` | 合格 | パケット破損のもとでのファイル転送。xquic は CI の実行で不合格、ローカルの再実行で合格(2.2) |
| `amplificationlimit` | 合格 | 証明書 9 枚で大きくしたサーバーフライトに、RFC 9000 §8.1 の増幅攻撃対策の上限を適用する。これを実行するクライアント 13 種すべてで合格(2026-11-17) |
| `goodput`(計測) | 合格 | ランナーの模擬 10 Mbps リンクで 10 MB、9417±13 kbps(2026-11-17)。これを実行するクライアント 13 種で 8917〜9448 kbps |
| `blackhole` | 合格 | 2 秒間の模擬リンク断のあと再開する |
| `multiplexing` | 合格 | 1 つの接続で多数のストリームを並行して転送する。xquic では不合格(6 章) |
| `handshakeloss` | 合格 | 30% のバースト損失のもとで 50 回のハンドシェイクがすべて完了 |
| `handshakecorruption` | 合格 | 同じシナリオを破損のもとで実行 |
| `retry` | 合格 | `--force-retry` による RFC 9000 §8.1.2 の強制アドレス検証 |
| `resumption` | 合格 | 実際の 2 回目のハンドシェイクでの PSK によるセッション再開 |
| `zerortt` | 合格 | 0-RTT データを受け取って処理する。quinn は CI の実行で不合格、ローカルの再実行で合格(2.2)。mvfst は実行していない |
| `ecn` | 判定なし | quic-go クライアントが `unsupported test case: ecn` を宣言。ngtcp2、picoquic、neqo、lsquic、quinn、s2n-quic では合格(2026-11-17) |
| `ipv6` | 合格 | ネイティブ IPv6 での転送 |
| `v2` | 判定なし | quic-go クライアントが `unsupported test case: v2` を宣言。ngtcp2、kwik、picoquic、aioquic、neqo、lsquic では合格(2026-11-17)。msquic はローカルの再実行で合格(2.2)。quinn では不合格(6 章) |
| `rebind-port` / `rebind-addr` | 合格 | これらを実行するクライアント 13 種すべてで合格(2026-11-17) |
| `connectionmigration` | 不合格 | quic-go とほか 7 種のクライアントで不合格(6 章)。ngtcp2、picoquic、aioquic、neqo、lsquic では合格(2026-11-17) |
| `crosstraffic`(計測) | 合格 | 競合する TCP cubic フローと並べて 25 MB。quic-go に対して、CI の実行で 1633(± 108)kbps、輻輳制御と送信の修正(`ae2474b47`、`e83e35035`、`52f772d7e`)のあとのローカルの実行で 4870(± 373)kbps、ACK の同乗の修正(`4a0d5542c`)も入れた最終の状態で 4370〜4676 kbps(4 回)。go-x-net に対しては修正後に 3661(± 41)kbps で合格。msquic と xquic では不合格(6 章) |

## 4. WebTransport のテストケース(サーバー: wired、クライアント: webtransport-go)

セッションは Extended CONNECT リクエストで始まる(guide の [WebTransport のセッション](https://hakkadaikon.github.io/wired/guide/ja/wt/session/))。

| テストケース | 結果 | 備考 |
|---|---|---|
| `handshake` | 合格 | Extended CONNECT によるセッション確立 |
| `transfer-unidirectional-receive` | 合格 | サーバーが単方向ストリームでファイルを送る |
| `transfer-bidirectional-receive` | 合格 | サーバーが双方向ストリームで応答する |
| `transfer-datagram-receive` | 合格 | サーバーが DATAGRAM で送る |
| `transfer-unidirectional-send` | 合格 | ngtcp2 と webtransport-go で合格 |
| `transfer-bidirectional-send` | 合格 | 受信したバイトをビットマップで記録する |
| `transfer-datagram-send` | 合格 | `transfer-unidirectional-send` と同じ修正。2026-08-23 のローカルでの逐次再実行で webtransport-go に合格 |

2026-11-17 の CI 実行のクライアント 5 種の結果は次のとおりである。

| クライアント | 合格 | 不合格 |
|---|---|---|
| flupke-webtransport | 7 | 0 |
| ngtcp2 | 7 | 0 |
| webtransport-go | 7 | 0 |
| Firefox | 6 | 1(`handshake`) |
| Chrome | 0 | 7 |

Chrome と Firefox の不合格は、ローカルの再実行で次のように確かめた。

| クライアント | 観測したこと | ログ |
|---|---|---|
| Chrome | クライアントのイメージの中で ChromeDriver(Chrome 146 向け)と Chrome(151.0.7922.47)の版が合わず、ブラウザーが起動しない。サーバーへの接続は始まらない | `logs_2026-11-17T08:31:12` |
| Firefox | セッションは確立する。クライアントは選ばれたプロトコルを返さない(`session established, negotiated protocol: None`)。サーバーが `WT-Available-Protocols` を受け取ったかは確かめていない | `logs_2026-11-17T08:31:34` |

## 5. MoQT リレー(サーバー: wired、クライアント 14 種)

moq-interop-runner は、各クライアントのテストスイートを、リレーとして動かした `examples/moqt_interop` に対して WebTransport 経由と raw QUIC 経由で 1 回ずつ実行する。

下の表は [2026-11-17 の実行](https://github.com/Hakkadaikon/moq-interop-runner/actions/runs/44030247172) の結果である。

| トランスポート | 合格 | 不合格のクライアント |
|---|---|---|
| WebTransport | 14 中 12 | xquic-draft-18、moqtopus |
| raw QUIC | 14 中 13 | moq-dev-js |

| クライアント | トランスポート | 不合格の理由 |
|---|---|---|
| moq-dev-js | raw QUIC | `setup-only` を含むすべてのテストで不合格。このクライアントは raw QUIC のトランスポートを持たず、URL スキームにかかわらず WebTransport のセッションを開く |
| xquic-draft-18、moqtopus | WebTransport | raw QUIC のリレー URL にだけ対応する(それぞれのログに記載)。raw QUIC 経由では合格 |

合格したクライアントのうち、moq-dev-rs と stitcher-moq はそれぞれ 2 テストをスキップする(`ok # SKIP`)。

## 6. 未解決の失敗

2026-11-17 の実行で残った不合格と、ローカルの再実行で分かった原因である。

| 不合格 | クライアント | 原因 | 追跡 |
|---|---|---|---|
| `connectionmigration` | quic-go、go-x-net、kwik、msquic、quiche、quinn、s2n-quic、xquic | クライアントが、サーバーの知らせた推奨アドレスへ移行しない。転送は元のパスだけで完了し、ランナーは `Server saw only a single path in use` と記録する | なし(クライアントの動作) |
| `multiplexing` | xquic | クライアントが、サーバーの知らせた上限(`initial_max_streams_bidi` 40)を超えて 128 本のストリームを開く。サーバーは STREAM_LIMIT_ERROR で接続を閉じる | なし(クライアントの動作) |
| `v2` | quinn | クライアントが version_information を送らないので、サーバーは版を切り替えられない(RFC 9368 §2.3) | なし(クライアントの動作) |
| `crosstraffic`(計測) | msquic | クライアントが 50 秒で打ち切る。25 MB を送り終えるには 4.2 Mbps が要り、TCP 1 本と分け合う公平な取り分(約 5 Mbps)の 84% に当たる。修正後のサーバーは 4.0〜4.3 Mbps で、反復ごとに完了と打ち切りが分かれる(完了は 48.9 秒、打ち切りは 95〜98%) | なし |
| `crosstraffic`(計測) | xquic | クライアントが接続を 30 秒で閉じる(受信は 13.6 MB)。25 MB を送り終えるには 7 Mbps が要り、公平な取り分を超える | なし(クライアントの制限時間) |
| WebTransport の全 7 ケース | Chrome | クライアントのイメージでブラウザーが起動しない(4 章) | なし(クライアントのイメージ) |
| WebTransport の `handshake` | Firefox | クライアントが、選ばれたプロトコルを返さない(4 章) | なし |

`connectionmigration`、`multiplexing`、`v2` の原因は、ローカルの再実行のログとキャプチャで確かめた。

| テストケース | クライアント | ログ |
|---|---|---|
| `connectionmigration` | quiche、msquic、xquic、quinn、go-x-net、s2n-quic、kwik | `logs_2026-11-17T07:19:54`、`07:20:17`、`07:21:22`、`07:23:03`、`07:24:07`、`07:24:34`、`07:25:12` |
| `multiplexing` | xquic | `logs_2026-11-17T07:22:08` |
| `v2` | quinn | `logs_2026-11-17T07:23:39` |
| `crosstraffic` | msquic | `logs_2026-11-17T18:15:58`、`18:32:14`、`19:16:30` |
| `crosstraffic` | go-x-net(合格) | `logs_2026-11-17T18:58:10` |
| `crosstraffic` | xquic | `logs_2026-11-17T18:47:50` |

シミュレーターの損失で結果が変わる不合格(2.1)は次のとおりである。

- ngtcp2、quiche、picoquic、msquic、xquic での `handshakeloss`
- ngtcp2、kwik、msquic、s2n-quic での `handshakecorruption`

mvfst は、クライアントのイメージを取得できず、2026-11-17 の実行に含まれていない。

## 7. ランナーの外で実際のピアに対して確かめたもの

2026-11-18 から 11-19 に確かめた。AF_XDP の行は CI で毎回実行している。ランナーのテストケースにない機能で、相手はほかの実装である。

| 機能 | 相手 | 結果 | 証拠 |
|---|---|---|---|
| クライアント証明書(RSA、ECDSA P-256、Ed25519) | quic-go v0.62.0(Go の crypto/tls) | 3 種とも検証して 200。信頼しない CA の Ed25519 は `bad_certificate`、証明書なしは `certificate_required` | ハーネスと出力は `tasks/f06-peer-checks/`(`client-final.log`) |
| QUIC ビットのグリース([RFC 9287](../features/rfc9287.md)) | quinn(grease_quic_bit を広告する) | `handshake`、`transfer` とも ✓。`transfer` で wired が送ったショートヘッダー 7,657 個のうち 3,828 個が QUIC ビット 0 | `logs_2026-11-18T13:31:03`(pcap の先頭バイトを数えた) |
| リクエストの優先度([RFC 9218](../features/rfc9218.md)) | quic-go v0.62.0。`priority: u=7` の GET 3 本のあと、300 ms 遅れて `u=0` の GET 1 本。20 Mbps のユーザー空間の中継を挟む | u=0 は u=7 の 1 本を追い越す。全部 u=3 の対照では最後に終わる | `tasks/f06-peer-checks/prio/prio-shaped-after.log` |
| MoQT の Track 切り替え(SWITCH_FROM の Hard) | moqtail `7412a2f` の `apps/client`(WebTransport、draft-22) | 切り替えのあとも新しい Track の Object を欠けずに受け取った。Soft と SSTS は動かしていない([MoQT の Track 切り替えの既知の制限](../security/limitations/moqt-switching.md) 2.1) | `tasks/f07-moqtail/` |
| AF_XDP の経路(wired が IP/UDP ヘッダーを自分で組み立てるカーネルバイパスの経路) | quic-go(ランナーのイメージ)。サーバーは `SERVER_PARAMS=af_xdp` で eth0 の AF_XDP(汎用モード)に切り替え、クライアントのパケットは模擬ネットワークを通る | `handshake`、`transfer`、`http3` とも ✓。CI の `AF_XDP` ワークフローの `interop` ジョブで毎回実行する | 実行 44375728547 のアーティファクト `interop-af-xdp` |

- Ed25519 で署名した証明書のチェーンは、この確認で検証できないと分かり、`f26e88fc2` で直した。
- この確認で、優先度の欠落が 2 つ分かった。ヘッダーの値がスケジューラーに届いていなかった(`ebd6191be`)。送信の周回が urgency にかかわらず全スロットに 1 スライスずつ配っていた(`e0e8b3153`)。
- AF_XDP の経路は、この確認で接続のおよそ 4 つに 1 つが成り立たないと分かり、`c3f2b2622` で直した。1 つの AF_XDP ソケットで動くサーバーが接続 ID にルーティングバイトを埋めず、BPF フィルターがその接続のパケットを空の XSKMAP スロットからカーネルへ渡していた。
- u=0 が u=7 の全部を追い越さないのは、大きいレスポンス用のバッファーが先着 2 本に割り当たるためである([HTTP/3 の既知の制限](../security/limitations/http3.md) 2.16)。

## 8. 未達の点

- QUIC の 22 テストケースのうち 3 つは、quic-go に対する合格がない。`ecn` と `v2` は quic-go クライアントが拒否し、どちらも ngtcp2 などほかのクライアントでは合格する。`connectionmigration` はほかのクライアント 5 種で合格する。計測のテストケースは 2 つとも合格している。
- RSA-PSS と ECDSA P-384/P-521 の証明書は、実際のピアに対して試していない。PRIORITY_UPDATE フレームは、送るクライアントが手元になく、単体テストだけである。
