[ドキュメント](../README.md) › [機能](README.md) › NIP-01

# NIP-01: Nostr の基本プロトコル(イベントと署名)

仕様の本文(<https://github.com/nostr-protocol/nips/blob/master/01.md>)から抽出した EARS 形式の要件台帳です。各要件には、それを確かめるテストを付けています。チェックがなくテスト行もない項目は、未解決のギャップです。

wired が実装するのは、1 件のイベントの解析、id を計算するための直列化、id と署名の検証です。今は NIP-98 の検査(`nip98_check`)だけが呼び、サーバーの本番の経路からはまだ呼ばれません。そのため項目は `[~]` にしています。

凡例:

- `[x]`: 挙げたテストで確認済み
- `[~]`: 間接的に確認(専用のテストはなく、evidence 行で確かめ方を説明)
- `[ ]`: まだどのテストでも確認していない

**カバレッジ: テスト済み 0/16、間接 16、未テスト 0。**

## Events and signatures

- [~] N01-001 (Events and signatures) 実装は、id、pubkey、created_at、kind、tags、content、sig をそれぞれ 1 回ずつ持つ JSON オブジェクトだけをイベントとして受け付け、キーの重複と欠けを拒否しなければならない。
  - evidence: `tests/app/nostrev_test.c` の `test_nostrev_keys` が重複、欠け、エスケープで綴ったキーの重複を確かめる。サーバーからはまだ呼ばれない。
- [~] N01-002 (Events and signatures) 実装は、キーの順序によらずイベントを受け付けなければならない。
  - evidence: `tests/app/nostrev_test.c` の `test_nostrev_parse_fixture` が、nostr-tools の出力するキーの順序のイベントを確かめる。サーバーからはまだ呼ばれない。
- [~] N01-003 (Events and signatures) 実装は、id と pubkey を 64 文字、sig を 128 文字の小文字の 16 進としてだけ受け付けなければならない。
  - evidence: `tests/app/nostrev_test.c` の `test_nostrev_hex` が 63 文字、65 文字、大文字、16 進でない文字、文字列でない値を確かめる。サーバーからはまだ呼ばれない。
- [~] N01-004 (Events and signatures) 実装は、kind を 0 以上 65535 以下の整数としてだけ受け付けなければならない。
  - evidence: `tests/app/nostrev_test.c` の `test_nostrev_integers` が 65535 と 65536 を確かめる。サーバーからはまだ呼ばれない。
- [~] N01-005 (Tags) 実装は、tags を 1 つ以上の文字列からなる配列の配列としてだけ受け付けなければならない。
  - evidence: `tests/app/nostrev_test.c` の `test_nostrev_tags` が空のタグ、文字列でない要素、配列でない tags を確かめる。サーバーからはまだ呼ばれない。
- [~] N01-006 (Events and signatures) 実装は、[0,pubkey,created_at,kind,tags,content] を空白も改行も入れずに UTF-8 で直列化しなければならない。
  - evidence: `tests/app/nostrev_test.c` の `test_nostrev_serialize` が nostr-tools の `serializeEvent` の出力とバイト単位で一致することを、`test_nostrev_serialize_c0` が空のイベントの直列化を確かめる。サーバーからはまだ呼ばれない。
- [~] N01-007 (Events and signatures) 直列化では、実装は 0x0A、0x22、0x5C、0x0D、0x09、0x08、0x0C をそれぞれ \n、\"、\\、\r、\t、\b、\f と書き、ほかの文字はそのまま書かなければならない。
  - evidence: `tests/app/nostrev_test.c` の `test_nostrev_serialize` が 7 つのエスケープ、`/`、非 ASCII、0x7F を含む content を確かめる。サーバーからはまだ呼ばれない。
- [~] N01-008 (Events and signatures) id が直列化の SHA-256 と一致しないとき、実装はイベントを拒否しなければならない。
  - evidence: `tests/app/nostrev_test.c` の `test_nostrev_verify` が content を 1 文字変えたイベントを確かめる。サーバーからはまだ呼ばれない。
- [~] N01-009 (Events and signatures) sig が id に対する pubkey の BIP-340 署名でないとき、実装はイベントを拒否しなければならない。
  - evidence: `tests/app/nostrev_test.c` の `test_nostrev_verify` が sig の 1 バイトを変えたイベントを確かめる。サーバーからはまだ呼ばれない。

## wired の受け付け範囲

仕様にない、wired が決めた規則です。

- [~] N01-010 (wired) 実装は、文字列の \" \\ \/ \b \f \n \r \t と \uXXXX をデコードし、サロゲートペアを 1 文字にまとめ、対のないサロゲートを拒否しなければならない。
  - evidence: `tests/app/nostrev_test.c` の `test_nostrev_escapes` と `test_nostrev_bad_strings` が確かめる。サーバーからはまだ呼ばれない。
- [~] N01-011 (wired) 実装は、不正な UTF-8(冗長な符号化、サロゲート、U+10FFFF を超える値、途中で切れた列)と、文字列の中の 0x20 未満の生のバイトを拒否しなければならない。
  - evidence: `tests/app/nostrev_test.c` の `test_nostrev_bad_strings` が確かめる。サーバーからはまだ呼ばれない。
- [~] N01-012 (wired) デコードした文字列が直列化でエスケープしない 0x20 未満のバイトを含むとき、実装は id を計算せずにイベントを拒否しなければならない。
  - evidence: `tests/app/nostrev_test.c` の `test_nostrev_serialize_c0` が content とタグの \u0000、\u000b、\u001f、\u0001 を、`test_nostrev_verify` が検証の結果を確かめる。実装によって直列化の形が変わる文字なので、受け付けない。サーバーからはまだ呼ばれない。
- [~] N01-013 (wired) 実装は、7 つのキーのほかのキーを、値を検査してから読み飛ばし、その数を数えなければならない(id に含まれないキー)。
  - evidence: `tests/app/nostrev_test.c` の `test_nostrev_keys` が入れ子の値、深さ 8 と 9、不正な値を確かめる。サーバーからはまだ呼ばれない。
- [~] N01-014 (wired) 実装は、符号、小数、指数、先頭の 0 を含む数と、20 桁以上の数を拒否しなければならない。
  - evidence: `tests/app/nostrev_test.c` の `test_nostrev_integers` が確かめる。サーバーからはまだ呼ばれない。
- [~] N01-015 (wired) 実装は、64 KiB を超えるイベント、64 を超えるタグ、16 を超える要素を持つタグ、全タグで合計 256 を超える文字列、4096 バイトを超えるタグの文字列を拒否しなければならない。
  - evidence: `tests/app/nostrev_test.c` の `test_nostrev_tags`、`test_nostrev_max_elems`(16 x 16 = 256 と 257 個目)、`test_nostrev_framing` が上限とその 1 つ先を確かめる。サーバーからはまだ呼ばれない。
- [~] N01-016 (wired) 実装は、オブジェクトの後ろに空白でない文字が続く入力を拒否しなければならない。
  - evidence: `tests/app/nostrev_test.c` の `test_nostrev_framing` が確かめる。ファズハーネス `fuzz/fuzz_nostrev.c` も解析器を動かす。サーバーからはまだ呼ばれない。

## 対象外

- (Communication between clients and relays) EVENT、REQ、CLOSE などのリレーのメッセージとフィルター: wired はリレーではなく、イベントを 1 件ずつ検証するだけ。
- (Kinds) 置き換え可能なイベントなど kind ごとの意味: イベントを使うアプリケーションが決める。
- (Events and signatures) イベントの作成と署名: 署名はクライアント(NIP-07)が行う。
