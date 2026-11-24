[ドキュメント](../README.md) › [機能](README.md) › NIP-98

# NIP-98: HTTP Auth

仕様の本文(<https://github.com/nostr-protocol/nips/blob/master/98.md>)から抽出した EARS 形式の要件台帳です。各要件には、それを確かめるテストを付けています。チェックがなくテスト行もない項目は、未解決のギャップです。

wired の検査は `nip98_check`(`src/app/nostr/nip98/`)です。サーバーの本番の経路からはまだ呼ばれないので、項目は `[~]` にしています。

凡例:

- `[x]`: 挙げたテストで確認済み
- `[~]`: 間接的に確認(専用のテストはなく、evidence 行で確かめ方を説明)
- `[ ]`: まだどのテストでも確認していない

**カバレッジ: テスト済み 0/10、間接 10、未テスト 0。**

## Nostr event

- [~] N98-001 (Nostr event) kind が 27235 でないとき、サーバーはトークンを拒否しなければならない。
  - evidence: `tests/app/nip98_test.c` の `test_nip98_fields` が kind 1 のイベントを確かめる。サーバーからはまだ呼ばれない。
- [~] N98-002 (Nostr event) created_at が今の時刻から時間の窓(既定は 60 秒)より離れているとき、サーバーはトークンを拒否しなければならない。
  - evidence: `tests/app/nip98_test.c` の `test_nip98_window` が ±60 秒、±61 秒、窓 5 秒のキャッシュでの境界を確かめる。サーバーからはまだ呼ばれない。
- [~] N98-003 (Nostr event) u タグが要求の絶対 URL(クエリを含む)とバイト単位で一致しないとき、サーバーはトークンを拒否しなければならない。
  - evidence: `tests/app/nip98_test.c` の `test_nip98_fields` が末尾の `/` と大文字のホストを確かめる。サーバーからはまだ呼ばれない。
- [~] N98-004 (Nostr event) method タグが要求の HTTP method と一致しないとき、サーバーはトークンを拒否しなければならない。
  - evidence: `tests/app/nip98_test.c` の `test_nip98_fields` と `test_nip98_spec_example` が確かめる。サーバーからはまだ呼ばれない。
- [~] N98-005 (Nostr event) 要求の body のハッシュを照合する構成では、payload タグが body の SHA-256 の 16 進と一致しないとき、サーバーはトークンを拒否しなければならない。
  - evidence: `tests/app/nip98_test.c` の `test_nip98_fields` が、payload タグがないトークン、一致するトークン、1 ビット違うハッシュを確かめる。ハッシュを渡さないときは payload タグを見ない。サーバーからはまだ呼ばれない。
- [~] N98-006 (Nostr event) イベントの id または署名が正しくないとき、サーバーはトークンを拒否しなければならない。
  - evidence: `tests/app/nip98_test.c` の `test_nip98_malformed` が id と sig を 1 文字変えたトークンを、`test_nip98_spec_example` が仕様の例(id がイベントのハッシュと合わない)を確かめる。サーバーからはまだ呼ばれない。

## Request Flow

- [~] N98-007 (Request Flow) サーバーは、`Nostr` の認可スキームと base64 でエンコードしたイベントのトークンを受け付けなければならない。
  - evidence: `tests/app/nip98_test.c` の `test_nip98_ok_forms` が nostr-tools の `getToken` の出力(パディングあり、スキームの大文字小文字の違い)を、`test_nip98_spec_example` が仕様の例(パディングなし)を確かめる。ファズハーネス `fuzz/fuzz_nip98.c` も検査を動かす。サーバーからはまだ呼ばれない。

## wired の追加の検査

仕様の「Servers MAY perform additional implementation-specific validation checks」にあたる規則です。

- [~] N98-008 (wired) u タグか method タグが 2 つ以上あるか、値(2 つ目の文字列)がないとき、サーバーはトークンを拒否しなければならない。
  - evidence: `tests/app/nip98_test.c` の `test_nip98_tag_shape` が確かめる。サーバーからはまだ呼ばれない。
- [~] N98-009 (wired) 署名を確かめ、公開鍵を認可したトークンの id がリプレイキャッシュの有効な項目にあるとき、サーバーはトークンを拒否しなければならない。`nip98_check` は id を登録せず、呼び出し側が認可の後で `nip98_replay_admit` を呼ぶ。
  - evidence: `tests/app/nip98_test.c` の `test_nip98_replay_check` が、検査だけでは登録されないこと、2 回目の登録が `NIP98_REPLAY_SEEN` になること、署名が正しくないトークンを登録しないことを確かめる。サーバーからはまだ呼ばれない。
- [~] N98-010 (wired) リプレイキャッシュのすべての項目が有効なとき、サーバーは有効な項目を追い出さずに新しいトークンを拒否しなければならない。
  - evidence: `tests/app/nip98_test.c` の `test_nip98_replay_cache` が満杯のときの拒否と期限の切れた項目の再利用を、`test_nip98_replay_saturate` が期限の計算の飽和を確かめる。時間の窓はキャッシュの初期化で決まり、`nip98_check` もその窓を使う。サーバーからはまだ呼ばれない。

## 対象外

- (Nostr event) content を空にすること: クライアントへの SHOULD。サーバーは content を検査しない。
- (Nostr event) 検査に失敗したときの 401 Unauthorized の応答: 応答はトークンを運ぶ層が決める。
- (Request Flow) `Authorization` ヘッダーでトークンを運ぶこと: 逸脱。ブラウザーは WebTransport の CONNECT にヘッダーを付けられないので、moqt_chat は MoQT の CLIENT_SETUP の AUTHORIZATION_TOKEN でトークンを運ぶ予定である。この逸脱はまだ実装していない。
