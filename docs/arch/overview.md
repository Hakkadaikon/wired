# アーキテクチャとデータの流れ(移転しました)

| 旧ページの節 | 移転先 |
|---|---|
| <a id="architecture-and-data-flow"></a><a id="アーキテクチャとデータの流れ"></a>アーキテクチャとデータの流れ | [基本設計](../architecture/README.md) |
| <a id="the-boundary-between-user-space-and-the-kernel"></a><a id="ユーザー空間とカーネルの境界"></a>ユーザー空間とカーネルの境界 | [基本設計](../architecture/README.md#2-カーネルとの境界) |
| <a id="how-the-sdk-reaches-the-kernel"></a><a id="sdk-からカーネルを呼ぶ仕組み"></a>SDK からカーネルを呼ぶ仕組み | [基本設計](../architecture/README.md#21-システムコールの経路) |
| <a id="the-five-layers"></a><a id="5-つのレイヤー"></a>5 つのレイヤー | [基本設計](../architecture/README.md#3-5-つの層) |
| <a id="data-flow"></a><a id="データの流れ"></a>データの流れ | [データの流れ](../architecture/dataflow.md)、[暗号化レベルと鍵](../architecture/keys.md) |
| <a id="the-handshake-making-the-keys-while-connecting"></a><a id="ハンドシェイクで接続しながら鍵を作る"></a>ハンドシェイクで接続しながら鍵を作る | [暗号化レベルと鍵](../architecture/keys.md#1-ハンドシェイク) |
| <a id="encryption-levels-and-when-keys-are-dropped"></a><a id="暗号化レベルと鍵を捨てるタイミング"></a>暗号化レベルと鍵を捨てるタイミング | [暗号化レベルと鍵](../architecture/keys.md#2-暗号化レベル) |
| <a id="one-http3-get-through-the-layers"></a><a id="http3-の-get-1-件がレイヤーを通る流れ"></a>HTTP/3 の GET 1 件がレイヤーを通る流れ | [データの流れ](../architecture/dataflow.md#1-http3-の-get-1-件) |
| <a id="how-a-packet-reaches-the-application-io-drivers"></a><a id="io-ドライバーとパケットの届き方"></a>I/O ドライバーとパケットの届き方 | [I/O ドライバー](../architecture/io-drivers.md) |
| <a id="two-ways-to-get-a-datagram-out-of-the-kernel"></a><a id="カーネルからデータグラムを取り出す-2-つの方法"></a>カーネルからデータグラムを取り出す 2 つの方法 | [I/O ドライバー](../architecture/io-drivers.md#1-受信の経路) |
| <a id="how-the-driver-is-chosen"></a><a id="ドライバーの選び方"></a>ドライバーの選び方 | [I/O ドライバー](../architecture/io-drivers.md#2-ドライバーの選択) |
| <a id="waiting-for-the-next-packet-block-or-spin"></a><a id="次のパケットの待ち方-ブロックかスピンか"></a>次のパケットの待ち方: ブロックかスピンか | [I/O ドライバー](../architecture/io-drivers.md#3-次のパケットの待ち方) |
