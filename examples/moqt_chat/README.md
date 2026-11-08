# moqt_chat

[wired](../../README.md) › moqt_chat

| 項目 | 内容 |
|---|---|
| 目的 | MoQT で作ったチャットと音声通話のルームの構成を示す |
| 読む人 | moqt_chat のサーバーとフロントエンドを動かす・変更するコントリビューター |
| 前提文書 | [MoQT draft-23 の要件台帳](../../docs/features/draft-moq-transport-23.md) |
| 関連文書 | [MoQT Track 切り替え](../../docs/features/moqt-track-switching.md)、[moqt_chat のリソース監視](../../docs/performance/monitoring.md) |

## 1. 文書の構成

| 文書 | 中身 |
|---|---|
| この文書 | 全体の構成、Track の一覧、ディレクトリ |
| [MoQT の使い方](wire.md) | セッション、名前空間の発見、履歴、Object の形、Track 切り替え |
| [サーバー](server.md) | ビルドと起動、設定、ハブの上限、GOAWAY による再起動 |
| [フロントエンド](frontend.md) | 開発サーバー、GitHub Pages、Biome、カメラと動画 |
| [e2e テスト](e2e.md) | 負荷テスト、安定性のシナリオ、そのほかの確認 |

## 2. 全体の構成

サーバーは libc を使わない WebTransport サーバーである。`src/app/moqt/run`(`moqtrun.h`)のハブを UDP につなぐ。参加者が送るチャットのメッセージと Opus の音声フレームを、ほかの参加者全員に中継する。

```mermaid
graph LR
    a["browser (user1)"] -- "WebTransport / moqt-23" --> hub["wired_server<br/>(moqtrun hub)"]
    b["browser (user2)"] -- "WebTransport / moqt-23" --> hub
    hub -- "Objects of user1's tracks" --> b
    hub -- "Objects of user2's tracks" --> a
```

| 項目 | 値 |
|---|---|
| MoQT のドラフト | draft-ietf-moq-transport-23。クライアントは `moqt-23` だけを提示する |
| ルーム | 固定で 1 つ |
| 参加者 ID | `user1`〜`user4` の 4 つ(`CANDIDATE_PARTICIPANT_IDS`、`moqtClient.ts`) |
| 名前空間 | `wired/moqt_chat` |
| フロントエンド | Next.js と React の静的エクスポート。GitHub Pages にだけデプロイする |

## 3. Track

参加者は名前空間 `wired/moqt_chat` の下に、次の Track を配信する。Track Alias は参加者 ID の添字(`user1` が 0)に表のオフセットを足した値である。

| Track 名 | 中身 | Track Alias | 配信する条件 |
|---|---|---|---|
| `<id>` | チャット | 0〜3 | 常に |
| `<id>/audio` | 音声(Opus) | 4〜7 | 常に |
| `<id>/screen` | 画面共有(VP8、高レート) | 10〜13 | 画面共有の間 |
| `<id>/screen-lo` | 画面共有(VP8、低レート) | 14〜17 | 画面共有の間で、ハブが Track 切り替えを提示したとき |
| `<id>/camera` | カメラか動画ファイル(VP8) | 18〜21 | カメラか動画ファイルを送る間 |

ハブは Track Alias 0〜3(`CHAT_ALIAS_LIMIT`、`wired_server.c`)を確実に中継し、それ以外の Track は送れないときに捨てる。各 Track の Object の形は [MoQT の使い方](wire.md) に書く。

## 4. ディレクトリ

| パス | 中身 |
|---|---|
| `server/wired_server.c` | ハブの初期化、WebTransport のコールバックの接続、証明書、CLI |
| `server/access.c` | 名前空間の認可と Origin の許可リスト |
| `server/live.c` | `wired_moqt_io` の `send_uni2`。セッションごとのリングに送信を溜める |
| `server/relay.c` | セッションの数え上げ、GOAWAY、10 秒ごとの中継の統計のログ |
| `server/moqt_chat.h` | サーバーの各ファイルが共有する宣言 |
| `server/Dockerfile`、`server/docker-compose.yml` | `just up` が作って動かす `scratch` イメージ |
| `frontend/src/lib/moqtWire.ts`、`moqtClient.ts` | ワイヤーのコーデック。セッション、リクエストストリーム、名前空間の発見、履歴、GOAWAY |
| `frontend/src/lib/moqtScreenWire.ts`、`moqtScreenClient.ts` | 画面共有とカメラの Track、別版、Track 切り替え |
| `frontend/src/lib/moqtVoiceWire.ts`、`moqtVoiceClient.ts` | 音声の Object の形と、音声の Track の配信と購読 |
| `frontend/src/lib/*Pipeline.ts`、`jitterBuffer.ts`、`playbackSink.ts`、`audioContextGate.ts` | マイクの取り込みから Opus のエンコード、Object までと、受信側のジッター吸収、デコード、再生 |
| `frontend/src/app/page.tsx`、`src/stores/moqtChatStore.ts`、`src/hooks/useMoqtChat.ts` | UI |
| `e2e/` | ヘッドレスの Chrome を使う e2e テストのハーネス |
| `testvectors/moqt_golden.json` | C と TypeScript が共有するゴールデンベクター |
| `justfile` | ビルド、起動、フロントエンド、e2e のレシピ |

ワイヤーのコーデックは C(`src/app/moqt/vi`、`kvp`、`ctl`、`data`)と TypeScript(`moqtWire.ts`)で別々に実装している。両方を `testvectors/moqt_golden.json`(draft-19 のフレーミング)で固定する。フロントエンドは draft-23 の vi64 の Length で制御メッセージを組み直し、draft-23 との差分はドラフトの本文から導いたベクターで固定する。
