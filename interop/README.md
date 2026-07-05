# quic-interop-runner endpoint

`wired` を [quic-interop-runner](https://github.com/quic-interop/quic-interop-runner)
のサーバーエンドポイントとして走らせるための最小構成。

## 使い方(runner ホスト側)

```sh
just ninja examples/word_list/wired_server
docker build -t wired-interop -f interop/Dockerfile .
# quic-interop-runner の implementations.json に追記:
#   "wired": { "image": "wired-interop", "url": "...", "role": "server" }
python3 run.py -s wired -c quic-go -t handshake,transfer,http3
```

## 対応テストケース

`handshake` / `transfer` / `http3`(それ以外は exit 127 で未対応を宣言)。
クライアントロールは未提供(サーバー専用 SDK のため exit 127)。

## 制約

- 応答ボディはスロットあたり 16KB まで(それ超過のファイルは 404)。
- Retry・アドレス検証は未実装のため `retry` テストは未対応。
