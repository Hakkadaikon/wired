# 既知の制限: 対象外と予定なし

[ドキュメント](../../README.md) › [セキュリティ設計](../README.md) › [既知の制限](README.md) › 対象外と予定なし

| 項目 | 内容 |
|---|---|
| 目的 | 設計上の対象外と、実装しないと決めた機能を示す |
| 読む人 | 機能を追加しようとするコントリビューター |
| 前提文書 | [既知の制限](README.md) |
| 関連文書 | [機能のない部分](../feature-gaps.md)、[要件台帳](../../features/README.md) |

## 1. 対象外(設計上)

台帳はこれらを SDK のコードではなく、運用者、アプリケーション、クライアント、仲介者の関心事として扱い、網羅率の集計から外す。

| 項目 | 影響を受ける人 | 内容 | 参照 |
|---|---|---|---|
| クライアント役 | クライアントが必要なアプリケーション | クライアント側の TLS/QUIC/HTTP/3/WebTransport/MoQT の動作は出荷していない。クライアントのパケット処理、ClientHello の組み立て、Version Negotiation への反応、0-RTT のクライアントの規則、リダイレクトの追跡、WT-Available-Protocols の組み立てである。サーバーは受け取った Version Negotiation パケットを無視する | [rfc9000.md](../../features/rfc9000.md)、[rfc9368.md](../../features/rfc9368.md)、[rfc9369.md](../../features/rfc9369.md)、[rfc8999.md](../../features/rfc8999.md)、[draft-webtrans-http3.md](../../features/draft-webtrans-http3.md) の対象外 |
| 仲介者とプロキシの動作 | プロキシが必要な運用 | HTTP のキャッシュ、Via/Forwarded、TCP への CONNECT、カプセルの表し直し、QPACK の再符号化、リレー同士の連携、Session Migration | 各台帳 |
| 運用者向けの指針 | 運用者 | ロードバランサーの接続 ID によるルーティング、Alt-Svc、DSCP/QoS、NAT のタイムアウト、鍵のライフサイクル、プロトコルをまたぐ考慮事項とプライバシーの考慮事項(RFC 9312、RFC 9308、MoQT のセキュリティの節) | 各台帳 |
| 従来の制御ストリームでの PUBLISH_DONE | 共有の制御ストリームで購読する購読者 | そうした購読は PUBLISH_DONE を受け取らない。このメッセージは draft-18/19/22 では Request ID を持たず(載っているリクエストストリームで購読を指す)、複数の購読が共有するストリームではどの購読が終わったかを示せない。ハブは代わりにその購読を残し、パブリッシャーが戻ったときに通知なしでつなぎ直す(`moqtrun_reattach_subs`) | `moqctl_publish_done` |
| MoQT の URI と名前の表示 | クライアント | `moqt://` の URI を解析して参照先を引くことや、SVCB/HTTPS の DNS レコードでの名前解決はクライアントの関心事で、実装していない。名前は生のバイト列として比べ、人が読む形に表示しない | MoQT の台帳 |
| Object のエンドツーエンド暗号化(SFRAME / Secure Objects) | エンドツーエンドの暗号化が必要なアプリケーション | 外部の仕組みである | [draft-moq-transport-22.md](../../features/draft-moq-transport-22.md) |
| 失効と PKI の運用 | 証明書を管理する運用者 | CRL、OCSP、CA の発行規則、ピン留め、参照識別子の組み立ては呼び出し側の方針である | [rfc5280.md](../../features/rfc5280.md)、[rfc6125.md](../../features/rfc6125.md) |
| 古い TLS | TLS 1.3 を使えないクライアント | TLS 1.2 以前、レコード層、KeyUpdate メッセージ、EndOfEarlyData、ミドルボックス互換モード。QUIC がこれらを置き換える | [rfc8446.md](../../features/rfc8446.md) |

MoQT について記録した、対象に戻す条件は次のとおりである。どれかが生じると、対応する対象外の項目が対象に戻る。

- draft-17 以前しか話さない相手(ドラフト 14 から 17 について)
- raw QUIC での 0-RTT を求める相手
- トランスポートごとに GOAWAY の URI が必要な運用
- wired 側に raw の MoQT のクライアント役が必要になること

## 2. 予定なし

これらは運用者やクライアントの関心事ではなく、SDK のプロトコルの機能である。実装しないと決めており、下の理由が成り立つ間は実装しない。各層の文書と、挙げた台帳の対象外の節でも扱っている。

| 機能 | 理由 | 参照 |
|---|---|---|
| RFC 9002 の MAY の経験則 | MAY の項目で、必須ではない | [rfc9002.md](../../features/rfc9002.md) |
| OCSP stapling | ブラウザーは stapling を求めず、must-staple の証明書もまれである。実装には ClientHello の拡張の解析、CertificateEntry の拡張、更新の仕組みが必要で、得られるものよりコストが大きい | [rfc8446.md](../../features/rfc8446.md)、[rfc6066.md](../../features/rfc6066.md) |
| `certificate_authorities` による証明書の選択 | 複数の証明書チェーンを前提としているが、サーバーが出すチェーンは 1 つである | [rfc8446.md](../../features/rfc8446.md) |
| HTTP/3 のサーバープッシュ | ブラウザーがプッシュを削除した | [rfc9114.md](../../features/rfc9114.md) |
| デコーダー側の QPACK のブロックされたストリーム | リクエストストリームを待たせる状態機械が必要になるのに、得られるのはリクエストヘッダーの数バイトである。セクションを失敗させれば足りる | [rfc9204.md](../../features/rfc9204.md) |
| MoQT のエイリアスによる認可トークンのキャッシュ | セッションごとのメモリの上限と、認可の考え方を決める必要がある。使うクライアントが現れるまで先送りする | MoQT の台帳 |
| MoQT の Padding Datagram | 送るのはオリジンの役割で、リレー(ハブ)の役割ではない | MoQT の台帳 |
| MoQT の EXPIRES | リレーがこれに従って動いても得るものはわずかである | MoQT の台帳 |
| カプセルだけで送る HTTP Datagram への代替 | WebTransport は QUIC DATAGRAM を前提にしているので、これを使う経路がない | [rfc9297.md](../../features/rfc9297.md) |
