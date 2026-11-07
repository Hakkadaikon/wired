# レイヤー構成(移転しました)

| 旧ページの節 | 移転先 |
|---|---|
| <a id="the-layers"></a><a id="レイヤー構成"></a>レイヤー構成 | [詳細設計](../design/README.md) |
| <a id="common-share-the-byte-level-primitives"></a><a id="common-バイト単位の基本部品を共有する"></a>common: バイト単位の基本部品を共有する | [common](../design/common.md) |
| <a id="the-variable-length-integer-varint"></a><a id="可変長整数varint"></a>可変長整数(varint) | [可変長整数](../design/common.md#1-可変長整数) |
| <a id="byte-cursors-and-shared-helpers"></a><a id="バイトカーソルと共有ヘルパー"></a>バイトカーソルと共有ヘルパー | [バイトカーソルと共有ヘルパー](../design/common.md#2-バイトカーソルと共有ヘルパー) |
| <a id="the-kernel-boundary"></a><a id="カーネルとの境界"></a>カーネルとの境界 | [カーネルとの境界](../design/common.md#3-カーネルとの境界) |
| <a id="crypto-protect-the-packets-prove-the-peer"></a><a id="crypto-パケットの保護と相手の証明"></a>crypto: パケットの保護と相手の証明 | [crypto](../design/crypto.md) |
| <a id="why-it-is-a-separate-layer"></a><a id="独立したレイヤーにしている理由"></a>独立したレイヤーにしている理由 | [独立した層にする理由](../design/crypto.md#1-独立した層にする理由) |
| <a id="where-crypto-meets-tls"></a><a id="crypto-と-tls-の接点"></a>crypto と tls の接点 | [tls との接点](../design/crypto.md#2-tls-との接点) |
| <a id="crypto-domains"></a><a id="crypto-のドメイン"></a>crypto のドメイン | [ドメイン](../design/crypto.md#3-ドメイン) |
| <a id="transport-lay-reliable-multiplexed-streams-over-udp"></a><a id="transport-udp-の上に信頼性のある多重化ストリームを敷く"></a>transport: UDP の上に信頼性のある多重化ストリームを敷く | [transport](../design/transport.md) |
| <a id="why-udp-and-not-tcp"></a><a id="なぜ-tcp-でなく-udp-なのか"></a>なぜ TCP でなく UDP なのか | [UDP を使う理由](../design/transport.md#1-udp-を使う理由) |
| <a id="head-of-line-blocking"></a><a id="ヘッドオブラインブロッキング"></a>ヘッドオブラインブロッキング | [ヘッドオブラインブロッキング](../design/transport.md#2-ヘッドオブラインブロッキング) |
| <a id="two-level-flow-control"></a><a id="2-段階のフロー制御"></a>2 段階のフロー制御 | [2 段階のフロー制御](../design/transport.md#3-2-段階のフロー制御) |
| <a id="loss-detection-and-the-probe-timeout"></a><a id="損失検出とプローブタイムアウト"></a>損失検出とプローブタイムアウト | [損失検出とプローブタイムアウト](../design/transport.md#4-損失検出とプローブタイムアウト) |
| <a id="congestion-control"></a><a id="輻輳制御"></a>輻輳制御 | [輻輳制御](../design/transport.md#5-輻輳制御) |
| <a id="path-mtu-discovery-dplpmtud"></a><a id="パス-mtu-探索dplpmtud"></a>パス MTU 探索(DPLPMTUD) | [パス MTU 探索(DPLPMTUD)](../design/transport.md#6-パス-mtu-探索dplpmtud) |
| <a id="transport-domains"></a><a id="transport-のドメイン"></a>transport のドメイン | [ドメイン](../design/transport.md#7-ドメイン) |
| <a id="tls-make-the-keys-authenticate-the-peer"></a><a id="tls-鍵の生成と相手の認証"></a>tls: 鍵の生成と相手の認証 | [tls](../design/tls.md) |
| <a id="how-quic-carries-tls"></a><a id="quic-が-tls-を運ぶ仕組み"></a>QUIC が TLS を運ぶ仕組み | [QUIC が TLS を運ぶ仕組み](../design/tls.md#1-quic-が-tls-を運ぶ仕組み) |
| <a id="transport-parameters"></a><a id="トランスポートパラメーター"></a>トランスポートパラメーター | [トランスポートパラメーター](../design/tls.md#2-トランスポートパラメーター) |
| <a id="key-update"></a><a id="鍵更新"></a>鍵更新 | [鍵更新](../design/tls.md#3-鍵更新) |
| <a id="tls-domains"></a><a id="tls-のドメイン"></a>tls のドメイン | [ドメイン](../design/tls.md#4-ドメイン) |
| <a id="app-speak-http-and-media-over-quic"></a><a id="app-quic-の上で-http-とメディアを扱う"></a>app: QUIC の上で HTTP とメディアを扱う | [app](../design/app.md) |
| <a id="http3"></a>HTTP/3 | [HTTP/3](../design/app.md#2-http3) |
| <a id="why-qpack-and-not-hpack"></a><a id="なぜ-hpack-でなく-qpack-なのか"></a>なぜ HPACK でなく QPACK なのか | [QPACK を使う理由](../design/app.md#3-qpack-を使う理由) |
| <a id="datagram"></a>DATAGRAM | [DATAGRAM](../design/app.md#4-datagram) |
| <a id="webtransport"></a>WebTransport | [WebTransport](../design/app.md#5-webtransport) |
| <a id="moqt"></a>MoQT | [MoQT](../design/app.md#6-moqt) |
| <a id="rawquic-telling-the-two-bindings-apart"></a><a id="rawquic-2-つのバインディングの見分け"></a>rawquic: 2 つのバインディングの見分け | [rawquic: 2 つのバインディングの見分け](../design/app.md#7-rawquic-2-つのバインディングの見分け) |
| <a id="media-cutting-mp4-files-into-objects"></a><a id="media-mp4-ファイルを-object-に切り分ける"></a>media: MP4 ファイルを Object に切り分ける | [media: MP4 ファイルを Object に分ける](../design/app.md#8-media-mp4-ファイルを-object-に分ける) |
| <a id="app-domains"></a><a id="app-のドメイン"></a>app のドメイン | [ドメイン](../design/app.md#9-ドメイン) |
