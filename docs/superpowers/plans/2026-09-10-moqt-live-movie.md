# MoQT ライブ動画 実装計画

> **エージェントで作業する人へ:** 必須のサブスキル: この計画をタスクごとに実装するには superpowers:subagent-driven-development(推奨)か superpowers:executing-plans を使う。各ステップは進捗管理のためにチェックボックス(`- [ ]`)の記法で書いている。

**目的:** `examples/moqt_chat` のサーバーから `assets/movie.mp4` を、実時間の速さで進む MoQT のライブ Track(Group ごとにキーフレームでそろえた fMP4 フラグメントを 1 つ)として配信し、ブラウザーが MSE で再生できるようにする。途中から参加した人は現在の Group から再生を始める。

**構成:** 新しい `mp4frag` ドメインがコミット済みの fMP4 を init とフラグメントに分ける。ハブ(`moqtrun`)には時計で進むライブ Track を足し、各 Group を購読者ごとに `send_uni2` を 1 回ずつ呼んで配る。`srvrun` にはステップごとに呼ばれる `on_step` フックと `inflight` の問い合わせを足し、サンプルがセッションごとのステージング領域を使い回せるようにする。フロントエンドはフラグメントを sequence モードの `SourceBuffer` に追記する。

**使う技術:** libc-free の C(この SDK の制約に従う)、TypeScript/Next.js と vitest、puppeteer の e2e、一度だけのアセット変換に nix 経由の ffmpeg。

**仕様:** `docs/superpowers/specs/2026-09-10-moqt-live-movie-design.md`

## 全体の制約

- `src/` は libc-free: 使えるのは `common/platform/sys/syscall.h` の型と `src/common/bytes/util/*.h` のヘルパー(`bytes_memcpy`, `be_get_be32`, `ct_diffn`, `u64_min`)だけ。標準ヘッダーは使わない。
- `src/` のすべての関数は循環的複雑度 3 以下(`lizard src --CCN 3 -w` が 0 で終わる)。`&&`, `||`, `?:`, `if`, `for`, `while` はそれぞれ +1 と数える。
- `tests/run.c` は、すべての `src/**/*.c` とすべての `tests/**/*_test.c` を取り込む 1 つの翻訳単位。新しく足す名前は static でも非 static でも全体で一意にする(足す前に `grep -rn '<name>' src/ tests/` で確かめる)。
- 公開ヘッダーに足すメンバー、マクロ、関数には `/** */` のドキュメントコメントを付ける(doxygen は WARN_AS_ERROR で動く)。
- 内部 API はモジュール名を接頭辞にする(`mp4frag_*`, `moqtrun_*`)。アプリケーション向けの API は `wired_*` にする。
- コミットゲート(毎回): `just test-fast` が "all tests passed" を出し、かつ `just ninja` が 0 で終わり、かつ `lizard src --CCN 3 -w` が 0 で終わること。`if A && B && C; then git commit; fi` の形で実行する(`| tail && commit` は使わない)。push の前には `just test`, `just fmt-check`, `just docs`, `just lint`, `just fuzz-smoke` を実行する(どれも `nix develop` 経由。`just` が自分で通す)。
- 並列で動くワーカーは自分の新しいファイルだけを編集する。`git add`/`commit`/`push` はしない。`tests/run.c` と `justfile` も編集しない。配線とコミットは 1 人の統合担当が行う(タスク 8)。
- コミットのトレーラー(毎回):
  ```
  Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>
  Claude-Session: https://claude.ai/code/session_01MUGHRYWD7RZSxw8p3C7GP1
  ```
- Track Alias: チャット 0..3、音声 4..7、`movie` 8、`movie/init` 9。Group の間隔は 2000 ms。MIME は `video/mp4; codecs="avc1.64001e, mp4a.40.2"`(生成したファイルの `avcC` 64 00 1e と AAC-LC の DSI から決めた値)。

## 並列化

第 1 波(互いに独立。同時に実行する): タスク 1(アセット)、タスク 2(mp4frag)、タスク 3(srvrun のフック)、タスク 4(ハブのライブ Track)、タスク 5(フロントエンドのライブクライアント)。タスク 4 の状態モデル(タスク 4a)は タスク 4 と並行して進め、見つかった反例は タスク 8 がコミットする前に タスク 4 のテストへ取り込む。
第 2 波: タスク 6(サンプルサーバー)は 2、3、4 のあと。タスク 7(e2e とドキュメント)は 5、6 のあと。
タスク 8(統合担当: 配線、ゲート、マイクロコミット)で各波を締める。

---

### タスク 1: 断片化したアセットを生成してコミットする

**ファイル:**
- 作成: `assets/movie-live.mp4`
- 変更: `examples/moqt_chat/README.md`(変換コマンドのブロックだけ。README のほかの部分は タスク 7)

**インターフェース:**
- 生成するもの: `assets/movie-live.mp4`。fMP4、init 1,260 バイト、`moof`+`mdat` のフラグメント 16 個、`avcC` の profile/compat/level = 64 00 1e。

- [ ] **ステップ 1: ファイルを生成する**

```sh
nix shell nixpkgs#ffmpeg-headless -c ffmpeg -v error -y -i assets/movie.mp4 \
  -c:v libx264 -preset medium -profile:v high -g 48 -keyint_min 48 \
  -sc_threshold 0 -b:v 1200k -c:a aac -b:a 128k \
  -movflags +frag_keyframe+empty_moov+default_base_moof \
  -f mp4 assets/movie-live.mp4
```

- [ ] **ステップ 2: レイアウトを確かめる(これがアセットの受け入れテスト)**

```sh
python3 - <<'EOF'
import struct
d=open('assets/movie-live.mp4','rb').read(); off=0; frags=0; init=0
while off<len(d):
    sz,=struct.unpack('>I',d[off:off+4]); t=d[off+4:off+8]
    assert 8<=sz<=len(d)-off, (off,sz)
    if t in (b'ftyp',b'moov'): init=off+sz
    if t==b'moof': frags+=1; assert d[off+sz+4:off+sz+8]==b'mdat'
    off+=sz
i=d.find(b'avcC'); print('init',init,'frags',frags,'avcC',d[i+5:i+8].hex())
assert init==1260 and frags==16 and d[i+5:i+8].hex()=='64001e'
EOF
```
期待する結果: `init 1260 frags 16 avcC 64001e` が出て、アサーションが失敗しないこと。

- [ ] **ステップ 3: README にコマンドを記録する**

"## What this demonstrates" の下("The server is a publisher too" で始まる段落のあと)に、ステップ 1 のコマンドだけを入れたフェンス付きブロックを足す。前置きは "`assets/movie-live.mp4` is generated from `assets/movie.mp4` once with:" の 1 文にする。

- [ ] **ステップ 4: コミットする**

```sh
git add assets/movie-live.mp4 examples/moqt_chat/README.md
git commit -m "chore(assets): add fragmented 2-second-GOP copy of the sample movie"
```

---

### タスク 2: `mp4frag` ドメイン(fMP4 の最上位ボックスの走査)

**ファイル:**
- 作成: `src/app/media/mp4frag/mp4frag.h`, `src/app/media/mp4frag/mp4frag.c`
- テスト: `tests/app/mp4frag_test.c`
- (両方を `tests/run.c` に配線するのは タスク 8。)

**インターフェース:**
- 使うもの: `be_get_be32`(`common/bytes/util/be.h`)、`wired_span`/`wired_span_of`(`common/bytes/span/span.h`)。
- 生成するもの:
  ```c
  #define MP4FRAG_MAX_FRAGS 64
  typedef struct { wired_span init; wired_span frags[MP4FRAG_MAX_FRAGS]; usz n_frags; } mp4frag_layout;
  int mp4frag_scan(wired_span file, mp4frag_layout* out);   /* 1 ok, 0 malformed */
  ```

- [ ] **ステップ 1: 失敗するテストを書く**

`tests/app/mp4frag_test.c`:

```c
#include "app/media/mp4frag/mp4frag.h"

#include "common/bytes/util/be.h"
#include "test.h"

/* Appends one box (size + type + n filler bytes) at *off, returns its
 * start. */
static usz mp4frag_test_box(u8* buf, usz* off, const char* type, usz n) {
  usz at = *off;
  be_put_be32(buf + at, (u32)(8 + n));
  for (usz i = 0; i < 4; i++) buf[at + 4 + i] = (u8)type[i];
  for (usz i = 0; i < n; i++) buf[at + 8 + i] = (u8)(0xA0 + i);
  *off = at + 8 + n;
  return at;
}

/* ftyp(12) moov(20) moof(16) mdat(40) moof(8) mdat(24): init = first
 * 2 boxes, two fragments spanning each moof+mdat pair exactly. */
static void test_mp4frag_scan_two_fragments(void) {
  u8  buf[256];
  usz off = 0;
  mp4frag_test_box(buf, &off, "ftyp", 12);
  mp4frag_test_box(buf, &off, "moov", 20);
  usz f0 = mp4frag_test_box(buf, &off, "moof", 16);
  mp4frag_test_box(buf, &off, "mdat", 40);
  usz f1 = mp4frag_test_box(buf, &off, "moof", 8);
  mp4frag_test_box(buf, &off, "mdat", 24);
  mp4frag_layout l;
  CHECK(mp4frag_scan(wired_span_of(buf, off), &l) == 1);
  CHECK(l.init.p == buf && l.init.n == 8 + 12 + 8 + 20);
  CHECK(l.n_frags == 2);
  CHECK(l.frags[0].p == buf + f0 && l.frags[0].n == (8 + 16) + (8 + 40));
  CHECK(l.frags[1].p == buf + f1 && l.frags[1].n == (8 + 8) + (8 + 24));
}

/* A free box between fragments (and one before moov) is skipped, not
 * counted and not folded into a fragment. */
static void test_mp4frag_scan_skips_free_boxes(void) {
  u8  buf[256];
  usz off = 0;
  mp4frag_test_box(buf, &off, "ftyp", 4);
  mp4frag_test_box(buf, &off, "free", 4);
  mp4frag_test_box(buf, &off, "moov", 4);
  usz f0 = mp4frag_test_box(buf, &off, "moof", 4);
  mp4frag_test_box(buf, &off, "mdat", 4);
  mp4frag_test_box(buf, &off, "free", 4);
  usz f1 = mp4frag_test_box(buf, &off, "moof", 4);
  mp4frag_test_box(buf, &off, "mdat", 4);
  mp4frag_layout l;
  CHECK(mp4frag_scan(wired_span_of(buf, off), &l) == 1);
  CHECK(l.init.n == 3 * 12);
  CHECK(l.n_frags == 2);
  CHECK(l.frags[0].p == buf + f0 && l.frags[0].n == 24);
  CHECK(l.frags[1].p == buf + f1 && l.frags[1].n == 24);
}

static usz mp4frag_test_valid(u8* buf) {
  usz off = 0;
  mp4frag_test_box(buf, &off, "ftyp", 4);
  mp4frag_test_box(buf, &off, "moov", 4);
  mp4frag_test_box(buf, &off, "moof", 4);
  mp4frag_test_box(buf, &off, "mdat", 4);
  return off;
}

/* Malformed shapes all return 0: a moof not followed by mdat, a box
 * whose size runs past the end, a size below 8, size 1 (largesize) and
 * size 0 (to-end), no fragment at all, no moov at all. */
static void test_mp4frag_scan_rejects_malformed(void) {
  u8             buf[128];
  mp4frag_layout l;
  usz            n = mp4frag_test_valid(buf);

  buf[24 + 4] = 'f'; /* second fragment's... no: rename moof->foof */
  CHECK(mp4frag_scan(wired_span_of(buf, n), &l) == 0 || l.n_frags == 0);

  n = mp4frag_test_valid(buf);
  buf[36 + 4] = 'x'; /* mdat -> xdat: moof without mdat */
  CHECK(mp4frag_scan(wired_span_of(buf, n), &l) == 0);

  n = mp4frag_test_valid(buf);
  be_put_be32(buf + 36, 100); /* mdat size past the end */
  CHECK(mp4frag_scan(wired_span_of(buf, n), &l) == 0);

  n = mp4frag_test_valid(buf);
  be_put_be32(buf + 24, 7); /* size below the 8-byte header */
  CHECK(mp4frag_scan(wired_span_of(buf, n), &l) == 0);

  n = mp4frag_test_valid(buf);
  be_put_be32(buf + 24, 1); /* largesize */
  CHECK(mp4frag_scan(wired_span_of(buf, n), &l) == 0);

  n = mp4frag_test_valid(buf);
  be_put_be32(buf + 36, 0); /* to-end-of-file */
  CHECK(mp4frag_scan(wired_span_of(buf, n), &l) == 0);

  usz off = 0; /* init only, no fragment */
  mp4frag_test_box(buf, &off, "ftyp", 4);
  mp4frag_test_box(buf, &off, "moov", 4);
  CHECK(mp4frag_scan(wired_span_of(buf, off), &l) == 0);

  off = 0; /* no moov */
  mp4frag_test_box(buf, &off, "ftyp", 4);
  mp4frag_test_box(buf, &off, "moof", 4);
  mp4frag_test_box(buf, &off, "mdat", 4);
  CHECK(mp4frag_scan(wired_span_of(buf, off), &l) == 0);

  CHECK(mp4frag_scan(wired_span_of(buf, 0), &l) == 0);
}

/* One more fragment than MP4FRAG_MAX_FRAGS is refused. */
static void test_mp4frag_scan_rejects_too_many(void) {
  static u8      buf[8 + 8 + (MP4FRAG_MAX_FRAGS + 1) * 16];
  usz            off = 0;
  mp4frag_layout l;
  mp4frag_test_box(buf, &off, "ftyp", 0);
  mp4frag_test_box(buf, &off, "moov", 0);
  for (usz i = 0; i < MP4FRAG_MAX_FRAGS; i++) {
    mp4frag_test_box(buf, &off, "moof", 0);
    mp4frag_test_box(buf, &off, "mdat", 0);
  }
  CHECK(mp4frag_scan(wired_span_of(buf, off), &l) == 1);
  CHECK(l.n_frags == MP4FRAG_MAX_FRAGS);
  mp4frag_test_box(buf, &off, "moof", 0);
  mp4frag_test_box(buf, &off, "mdat", 0);
  CHECK(mp4frag_scan(wired_span_of(buf, off), &l) == 0);
}

void test_mp4frag(void) {
  test_mp4frag_scan_two_fragments();
  test_mp4frag_scan_skips_free_boxes();
  test_mp4frag_scan_rejects_malformed();
  test_mp4frag_scan_rejects_too_many();
}
```

最初の不正ケースに注意: `moof` を `foof` に改名すると、フラグメントが 0 個の正しい形のファイルになるので、そこでも `scan` は 0 を返す(フラグメントが 1 つもないのは失敗扱い)。その `CHECK` を `CHECK(mp4frag_scan(...) == 0);` に置き換え、紛れ込んだコメントを消す。

- [ ] **ステップ 2: 失敗することを確かめる($TMPDIR でスタブに対してコンパイルする)**

```sh
mkdir -p $TMPDIR/mp4frag && cat > $TMPDIR/mp4frag/main.c <<'EOF'
#include <stdio.h>
int wired_test_fails;
#include "app/media/mp4frag/mp4frag.c"
#include "mp4frag_test.c"
int main(void){ test_mp4frag(); printf("fails=%d\n", wired_test_fails); return wired_test_fails!=0; }
EOF
clang -Wall -Wextra -Werror -O2 -Isrc -Itests -Itests/app $TMPDIR/mp4frag/main.c -o $TMPDIR/mp4frag/t && $TMPDIR/mp4frag/t
```
期待する結果: コンパイルエラー(ヘッダーがない)。これが Red。`tests/test.h` で `CHECK`/`wired_test_fails` がどう宣言されているかを確かめ、同じ形にする(unity ビルドでは `tests/run.c` が `wired_test_fails` を定義する。ここではスタブの main が定義する)。

- [ ] **ステップ 3: ヘッダーを書く**

`src/app/media/mp4frag/mp4frag.h`:

```c
#ifndef MP4FRAG_H
#define MP4FRAG_H

#include "common/bytes/span/span.h"
#include "common/platform/sys/syscall.h"

/** @file
 * Fragmented-MP4 top-level layout (ISO/IEC 14496-12 box structure): the
 * init segment (`ftyp` through `moov`) and each `moof`+`mdat` media
 * fragment as views into the caller's file bytes. No sample-table
 * parsing -- a publisher only needs the fragment boundaries. */

/** Fixed capacity: media fragments one file may hold. 64 covers a
 * 2-minute loop at the sample's 2-second fragments (16 today). */
#define MP4FRAG_MAX_FRAGS 64

/** Result of mp4frag_scan: init is `ftyp` up to and including `moov`;
 * frags[i] spans the i-th `moof` and the `mdat` that immediately follows
 * it. All views point into the scanned file. */
typedef struct {
  wired_span init;                     /**< ftyp..moov inclusive */
  wired_span frags[MP4FRAG_MAX_FRAGS]; /**< each moof+mdat pair */
  usz        n_frags;                  /**< fragments found */
} mp4frag_layout;

/** Scan file's top-level boxes into *out.
 * @param file the whole fMP4
 * @param out receives the layout (valid only when 1 is returned)
 * @return 1 on success; 0 when a box header is truncated, a box size is
 *   below 8, 1 (64-bit largesize) or 0 (to end of file), a size runs past
 *   the file, a `moof` is not immediately followed by `mdat`, no `moov`
 *   precedes the first fragment, no fragment exists, or more than
 *   MP4FRAG_MAX_FRAGS fragments exist */
int mp4frag_scan(wired_span file, mp4frag_layout* out);

#endif
```

- [ ] **ステップ 4: 実装を書く(どの関数も CCN 3 以下)**

`src/app/media/mp4frag/mp4frag.c`:

```c
#include "app/media/mp4frag/mp4frag.h"

#include "common/bytes/util/be.h"

/* ISO/IEC 14496-12 4.2: size(4, big-endian) + type(4). Sizes 0 and 1 are
 * legal in the standard but never produced by the sample's encoder; they
 * are refused so a fragment view can never be open-ended. */

typedef struct {
  usz start;
  usz end; /* start + size */
  u32 type;
} mp4frag_box;

static u32 mp4frag_fourcc(const char* s) {
  return ((u32)(u8)s[0] << 24) | ((u32)(u8)s[1] << 16) |
         ((u32)(u8)s[2] << 8) | (u32)(u8)s[3];
}

static int mp4frag_size_ok(u32 size, usz remaining) {
  return size >= 8 && size <= remaining;
}

/* Reads the box at *off; 0 when the header is truncated or the size is
 * unusable. On 1, *off advances past the box. */
static int mp4frag_box_take(wired_span file, usz* off, mp4frag_box* b) {
  if (file.n - *off < 8) return 0;
  u32 size = be_get_be32(file.p + *off);
  if (!mp4frag_size_ok(size, file.n - *off)) return 0;
  b->start = *off;
  b->end   = *off + size;
  b->type  = be_get_be32(file.p + *off + 4);
  *off     = b->end;
  return 1;
}

/* Boxes up to and including moov form the init segment. 0 when the file
 * ends (or breaks) before a moov. */
static int mp4frag_scan_init(wired_span file, usz* off, mp4frag_layout* out) {
  mp4frag_box b;
  while (mp4frag_box_take(file, off, &b)) {
    if (b.type != mp4frag_fourcc("moov")) continue;
    out->init = wired_span_of(file.p, b.end);
    return 1;
  }
  return 0;
}

/* The box after a moof must be its mdat; records the pair as one
 * fragment. 0 on a missing/malformed mdat or a full table. */
static int mp4frag_take_mdat(
    wired_span file, usz* off, const mp4frag_box* moof, mp4frag_layout* out) {
  mp4frag_box mdat;
  if (!mp4frag_box_take(file, off, &mdat)) return 0;
  if (mdat.type != mp4frag_fourcc("mdat")) return 0;
  if (out->n_frags == MP4FRAG_MAX_FRAGS) return 0;
  out->frags[out->n_frags++] =
      wired_span_of(file.p + moof->start, mdat.end - moof->start);
  return 1;
}

/* Every moof+mdat pair after the init segment; other boxes are skipped.
 * 0 on any malformed box or pair. */
static int mp4frag_scan_frags(wired_span file, usz* off, mp4frag_layout* out) {
  mp4frag_box b;
  while (*off < file.n) {
    if (!mp4frag_box_take(file, off, &b)) return 0;
    if (b.type == mp4frag_fourcc("moof") &&
        !mp4frag_take_mdat(file, off, &b, out))
      return 0;
  }
  return 1;
}

int mp4frag_scan(wired_span file, mp4frag_layout* out) {
  usz off      = 0;
  out->n_frags = 0;
  if (!mp4frag_scan_init(file, &off, out)) return 0;
  if (!mp4frag_scan_frags(file, &off, out)) return 0;
  return out->n_frags != 0;
}
```

`mp4frag_scan_frags` は `while` + `if` + `if(&&)` で CCN 4 になる。`&&` を述語関数 `static int mp4frag_moof_bad(wired_span file, usz* off, const mp4frag_box* b, mp4frag_layout* out) { return b->type == mp4frag_fourcc("moof") && !mp4frag_take_mdat(file, off, b, out); }` に切り出し、`if (mp4frag_moof_bad(...)) return 0;` で呼ぶ。`lizard src/app/media/mp4frag/mp4frag.c --CCN 3 -w` で確かめる。

- [ ] **ステップ 5: $TMPDIR のハーネスを実行して `fails=0` を確かめる。このファイルに lizard をかけ、0 で終わることを確かめる。**

- [ ] **ステップ 6: コミットも配線もしない。2 つのファイルのパスとハーネスの出力を統合担当(タスク 8)に報告する。**

---

### タスク 3: srvrun のステップごとのフックと送信中の問い合わせ

**ファイル:**
- 変更: `src/app/http3/server/srvrun/srvrun.h`(`wired_srvrun_opt` の `wt_session_close_ctx` のあとにメンバーを足し、`wired_server_wt_stream_reset` のあとに問い合わせ関数の宣言を足す)
- 変更: `src/app/http3/server/srvrun/srvrun.c`(`srvrun_cfg` の末尾、`srvrun_build_cfg`、`srvrun_step`、新しい問い合わせ関数)
- テスト: `tests/app/srvrun_test.c`(テストを 2 つ追記し、`test_srvrun` に登録する)

**インターフェース:**
- 生成するもの:
  ```c
  typedef void (*wired_srvrun_on_step)(void* ctx, u64 now_ms);
  /* in wired_srvrun_opt: */ wired_srvrun_on_step on_step; void* on_step_ctx;
  int wired_server_wt_stream_inflight(wired_wt_session* s, u64 stream_id);
  ```

- [ ] **ステップ 1: 既存のテストの書き方を読む**

`tests/app/srvrun_test.c` の 4500〜4560 行あたり(`srvrun_step(&cfg, &st, bufs, 2)` をループで呼ぶテスト)と 4561 行あたり("WRAPPER EQUIVALENCE")を開き、テストの中で `srvrun_cfg`/`srvrun_state` をじかに組み立てる方法を確かめる。組み立て用のヘルパーは同じ名前のものを使い回す(いちばん近いテストから準備の行をそのまま写す。新しいフィクスチャーは作らない)。

- [ ] **ステップ 2: 失敗するテストを書く**

`void test_srvrun(void)` の前に追記する:

```c
/* on_step fires once per srvrun_step with a non-decreasing monotonic
 * clock, and not at all when left at 0. */
static u64 g_sr_step_calls;
static u64 g_sr_step_last_ms;
static void sr_test_on_step(void* ctx, u64 now_ms) {
  (void)ctx;
  CHECK(now_ms >= g_sr_step_last_ms);
  g_sr_step_last_ms = now_ms;
  g_sr_step_calls++;
}

static void test_srvrun_on_step_fires_per_step(void) {
  /* build cfg/st/bufs exactly like the neighboring srvrun_step test */
  ...
  cfg.on_step     = sr_test_on_step;
  cfg.on_step_ctx = 0;
  g_sr_step_calls = 0;
  g_sr_step_last_ms = 0;
  for (int i = 0; i < 3; i++) srvrun_step(&cfg, &st, bufs, 2);
  CHECK(g_sr_step_calls == 3);
  cfg.on_step = 0;
  for (int i = 0; i < 3; i++) srvrun_step(&cfg, &st, bufs, 2);
  CHECK(g_sr_step_calls == 3);
}

/* A session that resolves to no live connection is never in flight, and
 * a stream id no send slot holds is not in flight. */
static void test_srvrun_wt_stream_inflight_unknown_is_zero(void) {
  CHECK(wired_server_wt_stream_inflight(0, 3) == 0);
}
```

`...` は写したフィクスチャーの行に置き換える(ファイルを開かずに正確な形は計画に書けない。4500 行あたりの隣のテストを雛形にする)。そのテストの `srvrun_step` はブロックしてはならない。そこのフィクスチャーはブロックしない設定を使っているので、そのまま同じにする。

- [ ] **ステップ 3: `just test-fast` を実行し、`on_step` を名指しするコンパイルエラーになることを確かめる(Red)。**

- [ ] **ステップ 4: 実装する**

`srvrun.h` の、`wired_srvrun_opt` の `wt_session_close_ctx` メンバーのあと:

```c
  /** Per-step application hook, 0 to disable (the default): called once
   * per event-loop step after that step's receive/serve work, with the
   * loop's own monotonic clock (ms). Runs inside the loop, so every
   * wired_server_wt_* send API may be called from it. The loop polls with
   * a bounded timeout whenever a connection is live, so the hook fires at
   * least every SRVRUN_PTO_MS (25 ms) while anyone is connected; with no
   * connection it may not fire at all. */
  wired_srvrun_on_step on_step;
  void*                on_step_ctx; /**< opaque ctx passed to on_step */
```

`wired_srvrun_opt` の typedef の上(ほかのコールバックの typedef の隣):

```c
/** Per-step application hook (wired_srvrun_opt.on_step).
 * @param ctx opaque context registered alongside this callback
 * @param now_ms the loop's monotonic clock at this step */
typedef void (*wired_srvrun_on_step)(void* ctx, u64 now_ms);
```

`wired_server_wt_stream_reset` の宣言のあと:

```c
/** 1 while a send slot on s's connection still holds stream_id -- its
 * bytes not yet fully acknowledged, or the stream still open for
 * appends -- and 0 once the slot was reaped or stream_id never named a
 * server-sent stream on this session. A payload handed to
 * wired_server_wt_open_uni above the slot's staging capacity is held as a
 * VIEW (see its doc); this is the signal that the view may be reused.
 * @param s the session whose connection carries the stream
 * @param stream_id a stream id returned by one of the open_* calls
 * @return 1 in flight, 0 otherwise */
int wired_server_wt_stream_inflight(wired_wt_session* s, u64 stream_id);
```

`srvrun.c`: `srvrun_cfg` の末尾(`wt_session_close_ctx` のあと)に足す:

```c
  /** Per-step app hook, 0 to disable, see wired_srvrun_opt. */
  wired_srvrun_on_step on_step;
  void*                on_step_ctx; /**< opaque ctx for on_step */
```

`srvrun_build_cfg` の複合リテラルの末尾にも足す: `opt->on_step, opt->on_step_ctx`。

`srvrun_step` の、`if (srvrun_wait_input(cfg, st)) srvrun_recv_serve(...)` の行の直後:

```c
  srvrun_app_step(cfg);
```

あわせて `srvrun_step` の上に:

```c
/* wired_srvrun_opt.on_step: the app's own per-step work (e.g. a clock-
 * paced publisher), given the same monotonic clock the loop's timers use. */
static void srvrun_app_step(const srvrun_cfg* cfg) {
  if (cfg->on_step) cfg->on_step(cfg->on_step_ctx, clock_mono_ms());
}
```

問い合わせ関数は `wired_server_wt_stream_reset` の隣に:

```c
int wired_server_wt_stream_inflight(wired_wt_session* s, u64 stream_id) {
  srvrun_conn* c = srvrun_session_conn(s);
  if (!c) return 0;
  return srvrun_wtsend_find(c, stream_id) != 0;
}
```

`srvrun_session_conn(0)` が null のセッションに 0 を返すことを確かめる(中身を読む。参照外しをしているなら、先頭に `if (!s) return 0;` のガードを置く)。`srvrun_wtsend_find` が `in_use` のスロットだけに一致することも確かめる(本体を読む。3752 行あたりで前方宣言されている)。

- [ ] **ステップ 5: `just test-fast` が "all tests passed" を出し、`lizard src/app/http3/server/srvrun/srvrun.c --CCN 3 -w` が 0 で終わり、`just docs` が 0 で終わる(ヘッダーにメンバーを足したため)。**

- [ ] **ステップ 6: コミットしない。統合担当に報告する。**

---

### タスク 4: ハブのライブ Track(`moqtrun`)

**ファイル:**
- 変更: `src/app/moqt/run/moqtrun.h`(io テーブルに `send_uni2`。新しい `wired_moqtrun_live` 型とハブのメンバー。新しい関数 2 つ。カウンター 2 つ)
- 変更: `src/app/moqt/run/moqtrun.c`
- テスト: `tests/app/moqtrun_test.c`(`send_uni2` のスタブと、新しい第 13 節)

**インターフェース:**
- 使うもの: `moqdata_subhdr_put`, `moqdata_obj_put`(data/moqdata.h)、`MOQDATA_MSG_OVERHEAD`。既存の `moqtrun_track_claim`, `moqtrun_sub_slot`, `moqtrun_track_sub_of_peer`, `moqtrun_queue_subscribe_ok`, `moqtrun_send_request_error`, `moqtrun_track_drop_sub`。
- 生成するもの:
  ```c
  /* io table, after stream_reset: */
  i64 (*send_uni2)(wired_wt_session* s, wired_span head, wired_span body);
  int  wired_moqt_publish_live(wired_moqt_hub*, wired_span name, u64 track_alias,
                               const wired_span* frags, usz n_frags, u64 group_ms, u64 now_ms);
  void wired_moqt_tick(wired_moqt_hub*, u64 now_ms);
  /* hub counters: */ u64 stat_live_sent; u64 stat_live_drop;
  ```

- [ ] **ステップ 1: テスト用スタブを拡張する**(`tests/app/moqtrun_test.c` の先頭)

呼び出しの種類 8 = `send_uni2` を足す。`head||body` を `payload` に記録し(`MOQTRUN_TEST_MAX_PAYLOAD` で切り詰める)、`payload_len` には切り詰める前の `head.n + body.n` を入れる(記録側が切り詰めても、テストが本当の長さを確かめられるようにするため)。`g_send_uni2_fail_n > 0` のあいだと、`g_send_uni2_reject_sess == s` のときは拒否する(-1 を返す)。この 2 つは `moqtrun_test_reset` で戻す。`moqtrun_test_io` で `io.send_uni2 = moqtrun_test_send_uni2` を設定する。

```c
static int               g_send_uni2_fail_n;
static wired_wt_session* g_send_uni2_reject_sess;

static i64 moqtrun_test_send_uni2(
    wired_wt_session* s, wired_span head, wired_span body) {
  i64 sid = g_next_stream_id++;
  moqtrun_test_record(8, s, (u64)sid, 1, head);
  moqtrun_test_call* c = &g_calls[g_n_calls - 1];
  usz room = MOQTRUN_TEST_MAX_PAYLOAD - c->payload_len;
  usz take = body.n < room ? body.n : room;
  for (usz i = 0; i < take; i++) c->payload[c->payload_len + i] = body.p[i];
  c->payload_len = head.n + body.n; /* true length, buffer may be shorter */
  if (g_send_uni2_fail_n > 0) {
    g_send_uni2_fail_n--;
    return -1;
  }
  if (g_send_uni2_reject_sess && s == g_send_uni2_reject_sess) return -1;
  return sid;
}
```

`payload_len` はバッファーより大きくなりうる点に注意する。`payload_len` を読む既存の箇所はどれも、その値で `payload` を添字参照している。ライブのテストのフラグメントは 200 バイト以下にして head+body が必ず収まるようにし、`MOQTRUN_TEST_MAX_PAYLOAD` より先は読まない。

- [ ] **ステップ 2: 失敗するテストを書く**(`void test_moqtrun(void)` の前に新しい第 13 節として)

```c
/* ===================== 13. hub-owned live track ===================== */

static const u8 LIVE_NAME[5] = {'m', 'o', 'v', 'i', 'e'};
static u8       g_live_frag[3][64];
static wired_span g_live_frags[3];

/* Three distinct 40/50/60-byte fragments, cadence 2000 ms from t0=1000. */
static void moqtrun_test_publish_live(wired_moqt_hub* hub) {
  for (usz f = 0; f < 3; f++) {
    for (usz i = 0; i < 40 + 10 * f; i++) g_live_frag[f][i] = (u8)(f * 50 + i);
    g_live_frags[f] = wired_span_of(g_live_frag[f], 40 + 10 * f);
  }
  CHECK(
      wired_moqt_publish_live(
          hub, wired_span_of(LIVE_NAME, 5), 8, g_live_frags, 3, 2000, 1000) ==
      1);
}

/* Same shape as moqtrun_test_subscribe_movie (name "movie"). */
static void moqtrun_test_subscribe_live(wired_moqt_hub* hub, wired_wt_session* s) {
  moqtrun_test_subscribe_movie(hub, s);
}

/* Decodes a recorded send_uni2 call as SUBGROUP_HEADER + one Object;
 * returns the Group ID and copies the payload to out (n bytes). */
static u64 moqtrun_test_live_group(
    const moqtrun_test_call* c, u8* out, usz* n) {
  usz            off = 0;
  moqdata_subhdr hdr;
  CHECK(moqdata_subhdr_take(wired_span_of(c->payload, c->payload_len), &off, &hdr) == MOQDATA_OK);
  CHECK(hdr.track_alias == 8);
  moqdata_objseq seq = moqdata_objseq_of(hdr.type);
  moqdata_obj    obj;
  CHECK(moqdata_obj_take(wired_span_of(c->payload, c->payload_len), &off, &seq, &obj) == MOQDATA_OK);
  CHECK(obj.object_id == 0);
  CHECK(off == c->payload_len);
  bytes_memcpy(out, obj.payload.p, obj.payload.n);
  *n = obj.payload.n;
  return hdr.group_id;
}

static void test_moqtrun_live_publish_rejects_bad_args(void) {
  wired_moqt_hub hub;
  wired_moqt_init(&hub, moqtrun_test_io());
  g_live_frags[0] = wired_span_of(g_live_frag[0], 4);
  CHECK(wired_moqt_publish_live(&hub, wired_span_of(LIVE_NAME, 5), 8, g_live_frags, 0, 2000, 0) == 0);
  CHECK(wired_moqt_publish_live(&hub, wired_span_of(LIVE_NAME, 5), 8, g_live_frags, 1, 0, 0) == 0);
}

/* SUBSCRIBE at t=1000+2500 (Group 1): SUBSCRIBE_OK alias 8 and one
 * immediate send of Group 1 = fragment 1. */
static void test_moqtrun_live_subscribe_sends_current_group(void) {
  moqtrun_test_reset();
  wired_moqt_hub hub;
  wired_moqt_init(&hub, moqtrun_test_io());
  moqtrun_test_publish_live(&hub);
  wired_moqt_tick(&hub, 3500);
  moqtrun_test_subscribe_live(&hub, SESS_A);

  wired_span body;
  CHECK(moqtrun_test_last_reply(&body) == MOQCTL_T_SUBSCRIBE_OK);
  moqctl_subscribe_ok ok;
  usz                 boff = 0;
  CHECK(moqctl_subscribe_ok_take(body, &boff, &ok) == MOQCTL_OK);
  CHECK(ok.track_alias == 8);
  CHECK(moqtrun_test_count_kind(8) == 1);
  u8  got[64];
  usz n;
  CHECK(moqtrun_test_live_group(moqtrun_test_last_kind(8), got, &n) == 1);
  CHECK(n == 50 && ct_diffn(got, g_live_frag[1], 50) == 0);
  CHECK(hub.stat_live_sent == 1);
}

/* Ticks inside the same Group send nothing; the tick that enters the
 * next Group sends the next fragment; fragments wrap at n_frags. */
static void test_moqtrun_live_tick_advances_groups(void) {
  moqtrun_test_reset();
  wired_moqt_hub hub;
  wired_moqt_init(&hub, moqtrun_test_io());
  moqtrun_test_publish_live(&hub);
  wired_moqt_tick(&hub, 1000);
  moqtrun_test_subscribe_live(&hub, SESS_A); /* Group 0 */
  wired_moqt_tick(&hub, 1500);
  wired_moqt_tick(&hub, 2999);
  CHECK(moqtrun_test_count_kind(8) == 1);
  wired_moqt_tick(&hub, 3000); /* Group 1 */
  wired_moqt_tick(&hub, 5000); /* Group 2 */
  wired_moqt_tick(&hub, 7000); /* Group 3 -> fragment 0 again */
  CHECK(moqtrun_test_count_kind(8) == 4);
  u8  got[64];
  usz n;
  CHECK(moqtrun_test_live_group(moqtrun_test_last_kind(8), got, &n) == 3);
  CHECK(n == 40 && ct_diffn(got, g_live_frag[0], 40) == 0);
}

/* A refused send is retried on the next tick of the SAME Group and
 * abandoned (counted) once the Group advances -- never sent late. */
static void test_moqtrun_live_refused_send_retries_then_drops(void) {
  moqtrun_test_reset();
  wired_moqt_hub hub;
  wired_moqt_init(&hub, moqtrun_test_io());
  moqtrun_test_publish_live(&hub);
  wired_moqt_tick(&hub, 1000);
  moqtrun_test_subscribe_live(&hub, SESS_A);
  CHECK(moqtrun_test_count_kind(8) == 1);

  g_send_uni2_fail_n = 1;
  wired_moqt_tick(&hub, 3000); /* Group 1: refused */
  CHECK(hub.stat_live_sent == 1);
  wired_moqt_tick(&hub, 3100); /* still Group 1: retried, accepted */
  CHECK(hub.stat_live_sent == 2);
  u8  got[64];
  usz n;
  CHECK(moqtrun_test_live_group(moqtrun_test_last_kind(8), got, &n) == 1);

  g_send_uni2_fail_n = 1;
  wired_moqt_tick(&hub, 5000); /* Group 2: refused */
  wired_moqt_tick(&hub, 7000); /* Group 3: Group 2 abandoned, 3 sent */
  CHECK(hub.stat_live_drop == 1);
  CHECK(moqtrun_test_live_group(moqtrun_test_last_kind(8), got, &n) == 3);
  usz sent = 0;
  for (usz i = 0; i < g_n_calls; i++) {
    if (g_calls[i].kind != 8) continue;
    u8  p[64];
    usz pn;
    CHECK(moqtrun_test_live_group(&g_calls[i], p, &pn) != 2); /* never late */
    sent++;
  }
  (void)sent;
}

/* Two subscribers are independent: one refused, the other still served. */
static void test_moqtrun_live_two_subscribers_independent(void) {
  moqtrun_test_reset();
  wired_moqt_hub hub;
  wired_moqt_init(&hub, moqtrun_test_io());
  moqtrun_test_publish_live(&hub);
  wired_moqt_tick(&hub, 1000);
  moqtrun_test_subscribe_live(&hub, SESS_A);
  moqtrun_test_subscribe_live(&hub, SESS_B);
  CHECK(moqtrun_test_count_kind(8) == 2);
  g_send_uni2_reject_sess = SESS_A;
  wired_moqt_tick(&hub, 3000);
  CHECK(moqtrun_test_last_kind(8)->s == SESS_B);
  usz to_b = 0;
  for (usz i = 0; i < g_n_calls; i++)
    if (g_calls[i].kind == 8 && g_calls[i].s == SESS_B) to_b++;
  CHECK(to_b == 2);
  CHECK(hub.stat_live_sent == 3);
}

/* Repeat SUBSCRIBE: SUBSCRIBE_OK again, nothing sent. */
static void test_moqtrun_live_resubscribe_no_resend(void) {
  moqtrun_test_reset();
  wired_moqt_hub hub;
  wired_moqt_init(&hub, moqtrun_test_io());
  moqtrun_test_publish_live(&hub);
  wired_moqt_tick(&hub, 1000);
  moqtrun_test_subscribe_live(&hub, SESS_A);
  moqtrun_test_subscribe_live(&hub, SESS_A);
  CHECK(moqtrun_test_last_reply_type() == MOQCTL_T_SUBSCRIBE_OK);
  CHECK(moqtrun_test_count_kind(8) == 1);
}

/* Close stops sends; a reconnect in the same slot starts at the current
 * Group. */
static void test_moqtrun_live_close_then_reconnect(void) {
  moqtrun_test_reset();
  wired_moqt_hub hub;
  wired_moqt_init(&hub, moqtrun_test_io());
  moqtrun_test_publish_live(&hub);
  wired_moqt_tick(&hub, 1000);
  moqtrun_test_subscribe_live(&hub, SESS_A);
  wired_moqt_on_session_close(&hub, SESS_A);
  wired_moqt_tick(&hub, 3000);
  CHECK(moqtrun_test_count_kind(8) == 1);
  wired_moqt_tick(&hub, 5000);
  moqtrun_test_subscribe_live(&hub, SESS_B);
  u8  got[64];
  usz n;
  CHECK(moqtrun_test_live_group(moqtrun_test_last_kind(8), got, &n) == 2);
}

/* Blob and live tracks coexist and route by name. */
static void test_moqtrun_live_and_blob_coexist(void) {
  moqtrun_test_reset();
  wired_moqt_hub hub;
  wired_moqt_init(&hub, moqtrun_test_io());
  moqtrun_test_publish_live(&hub);
  static const u8 INIT_NAME[10] = {'m','o','v','i','e','/','i','n','i','t'};
  for (usz i = 0; i < 100; i++) g_test_blob[i] = (u8)i;
  CHECK(wired_moqt_publish_blob(&hub, wired_span_of(INIT_NAME, 10), 9,
        wired_span_of(g_test_blob, 100), wired_mspan_of(g_test_wire, sizeof g_test_wire)) > 0);
  wired_moqt_tick(&hub, 1000);
  /* SUBSCRIBE "movie/init": golden SUBSCRIBE renamed (11-byte name needs
   * the same Length backpatch moqtrun_test_rename_track_to_audio does --
   * write a sibling helper for a 10-byte name, or reuse that function's
   * layout note). */
  ...
  CHECK(moqtrun_test_count_kind(4) == 1); /* blob: send_uni */
  moqtrun_test_subscribe_live(&hub, SESS_A);
  CHECK(moqtrun_test_count_kind(8) == 1); /* live: send_uni2 */
}
```

最後のテストの `...` について: `moqtrun_test_rename_track_to_audio` を写して汎用の `moqtrun_test_rename_track(const u8* src, usz src_len, const u8* name, usz name_len, u8* dst)` を作り、16 ビットの Length を `name_len - 5` だけ後から書き換えるようにする。それを `"movie/init"` に使う。8 つのテストをすべて `test_moqtrun` に登録する。

- [ ] **ステップ 3: `just test-fast` を実行し、`wired_moqt_publish_live` でコンパイルエラーになることを確かめる(Red)。**

- [ ] **ステップ 4: 実装する**

`moqtrun.h` の io テーブルの、`stream_reset` のあと:

```c
  /** wired_server_wt_open_uni-shaped for a two-part payload: head (a
   * short framing prefix) immediately followed by body (a large media
   * fragment the hub holds only as a view into caller storage). The
   * adapter concatenates them (with its own signal prefix) into
   * session-owned staging; -1 when it has none free. Returns the stream
   * id or negative. */
  i64 (*send_uni2)(wired_wt_session* s, wired_span head, wired_span body);
```

`wired_moqt_hub` の前に新しい型:

```c
/** The hub's own clock-paced live track (wired_moqt_publish_live): Group
 * g carries fragment g mod n_frags as its only Object, Groups advancing
 * every group_ms from t0_ms. sent_group[i]/sent_any[i] record, per sub
 * slot of track.subs[], the last Group actually accepted for that
 * subscriber -- a refused send leaves them untouched so the next tick
 * retries while the clock is still in that Group. */
typedef struct {
  wired_moqtrun_track track;   /**< name, own_alias, subs[] */
  const wired_span*   frags;   /**< caller-owned fragment views */
  usz                 n_frags; /**< entries at frags */
  u64                 t0_ms;   /**< clock at publish: Group 0's start */
  u64                 group_ms; /**< Group duration */
  u64 sent_group[WIRED_MOQTRUN_MAX_SUBS]; /**< last Group sent per sub */
  int sent_any[WIRED_MOQTRUN_MAX_SUBS];   /**< 0 until the first send */
} wired_moqtrun_live;
```

`blob_wire` のあとにハブのメンバー:

```c
  /** The hub's live track (wired_moqt_publish_live); track.in_use once
   * published. */
  wired_moqtrun_live live;
  /** Live Groups accepted by io.send_uni2 / abandoned because the clock
   * left the Group before a refused send could be retried. */
  u64 stat_live_sent;
  u64 stat_live_drop;
```

関数:

```c
/** Publish a hub-owned live track ... (spec section 3 text) ...
 * @return 1, or 0 when n_frags or group_ms is 0 (hub state unchanged) */
int wired_moqt_publish_live(wired_moqt_hub* hub, wired_span name, u64 track_alias,
    const wired_span* frags, usz n_frags, u64 group_ms, u64 now_ms);

/** Clock tick (wire to wired_srvrun_opt.on_step): the current Group is
 * (now_ms - t0_ms) / group_ms; every live subscriber whose last accepted
 * Group is older is sent it via io.send_uni2. No live track: no-op. */
void wired_moqt_tick(wired_moqt_hub* hub, u64 now_ms);
```

`moqtrun.c` の `wired_moqt_init` に: `hub->live.track.in_use = 0; hub->stat_live_sent = 0; hub->stat_live_drop = 0;`。

ライブの節(blob の節のあと):

```c
/* ===================== hub-owned live track ===================== */

int wired_moqt_publish_live(
    wired_moqt_hub*   hub,
    wired_span        name,
    u64               track_alias,
    const wired_span* frags,
    usz               n_frags,
    u64               group_ms,
    u64               now_ms) {
  if (n_frags == 0 || group_ms == 0) return 0;
  hub->live.track.in_use = 0;
  moqtrun_track_claim(&hub->live.track, name, track_alias);
  hub->live.frags    = frags;
  hub->live.n_frags  = n_frags;
  hub->live.t0_ms    = now_ms;
  hub->live.group_ms = group_ms;
  return 1;
}

static u64 moqtrun_live_group_at(const wired_moqtrun_live* live, u64 now_ms) {
  return now_ms < live->t0_ms ? 0 : (now_ms - live->t0_ms) / live->group_ms;
}

/* SUBGROUP_HEADER (Type 0x70 shape, live alias, Group g) + the Object's
 * ID Delta 0 and Payload Length -- the framing that precedes the fragment
 * bytes on the wire. Returns the head length (<= MOQDATA_MSG_OVERHEAD). */
static usz moqtrun_live_head(
    const wired_moqtrun_live* live, u64 group, usz frag_len, u8* head) {
  usz            off = 0;
  moqdata_subhdr h   = {0};
  h.type             = 0x70;
  h.track_alias      = live->track.own_alias;
  h.group_id         = group;
  wired_mspan buf    = wired_mspan_of(head, MOQDATA_MSG_OVERHEAD);
  if (moqdata_subhdr_put(buf, &off, &h) != MOQDATA_OK) return 0;
  if (!moqvi_put(buf, &off, 0)) return 0;
  if (!moqvi_put(buf, &off, frag_len)) return 0;
  return off;
}
```

(`moqdata_obj_put` は delta + length + payload を一度に書く。head にはペイロード抜きの delta + length が要るので、`moqvi_put` を 2 回呼ぶ。`moqdata.c` の `moqdata_obj_put` の本体を読み、空でないペイロードのときに出す varint の並び(delta、length、バイト列の順)を確かめて、`head||body` が `moqdata_obj_put` の出力とバイト単位で一致するようにする。共存テストの `moqtrun_test_live_group` がそれを `moqdata_obj_take` でデコードすることが、その証明になる。)

```c
/* 1 iff sub slot i still owes Group g (never sent, or last sent older). */
static int moqtrun_live_owes(const wired_moqtrun_live* live, usz i, u64 g) {
  return !live->sent_any[i] || live->sent_group[i] < g;
}

/* Sends Group g to sub slot i; on acceptance records it. A refused send
 * records nothing (retried next tick while the clock is still in g). */
static void moqtrun_live_send_one(wired_moqt_hub* hub, usz i, u64 g) {
  wired_moqtrun_live* live = &hub->live;
  wired_moqtrun_peer* dst  = &hub->peers[live->track.subs[i].session_idx];
  wired_span          frag = live->frags[g % live->n_frags];
  u8                  head[MOQDATA_MSG_OVERHEAD];
  usz                 hn = moqtrun_live_head(live, g, frag.n, head);
  if (!dst->in_use) return;
  if (hub->io.send_uni2(dst->wt, wired_span_of(head, hn), frag) < 0) return;
  live->sent_group[i] = g;
  live->sent_any[i]   = 1;
  hub->stat_live_sent++;
}

/* A Group the clock has left while sub slot i's send was still refused is
 * abandoned: count it and skip ahead so the subscriber is never sent a
 * stale Group. */
static void moqtrun_live_skip_stale(wired_moqt_hub* hub, usz i, u64 g) {
  wired_moqtrun_live* live = &hub->live;
  if (!live->sent_any[i]) return;
  if (live->sent_group[i] + 1 < g) hub->stat_live_drop += g - live->sent_group[i] - 1;
}
```

注意: `moqtrun_live_skip_stale` は飛ばした Group ごとに 1 回ずつ取りこぼしを数える。しかし k Group 遅れた購読者は、飛ばした Group ごとにちょうど 1 回ずつ数えたうえで、次に受け付けられた送信で `sent_group = g` によって追いつかせなければならない。いちばん単純で正しい形は次のとおり。`moqtrun_live_send_one` で送信が受け付けられたとき、`sent_group = g` を設定する前に `if (live->sent_any[i] && live->sent_group[i] + 1 < g) hub->stat_live_drop += g - live->sent_group[i] - 1;` を実行し、`moqtrun_live_skip_stale` は消す。2 条件の判定を、飛ばした Group の数(なければ 0)を返すヘルパー `static u64 moqtrun_live_gap(const wired_moqtrun_live*, usz i, u64 g)` に移せば、CCN 3 以下を保てる。

```c
static void moqtrun_live_serve_sub(wired_moqt_hub* hub, usz i, u64 g) {
  if (!hub->live.track.subs[i].active) return;
  if (!moqtrun_live_owes(&hub->live, i, g)) return;
  moqtrun_live_send_one(hub, i, g);
}

void wired_moqt_tick(wired_moqt_hub* hub, u64 now_ms) {
  if (!hub->live.track.in_use) return;
  u64 g = moqtrun_live_group_at(&hub->live, now_ms);
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_SUBS; i++)
    moqtrun_live_serve_sub(hub, i, g);
}
```

SUBSCRIBE を受けた時点でも現在の時刻が要る(仕様: 現在の Group をすぐに送る)。ハブは自前の時計を持たないので、最後の tick の `now_ms` を `hub->live.last_now_ms` に保存し(構造体に足し、ドキュメントコメントは "clock of the most recent wired_moqt_tick; a SUBSCRIBE between ticks is served the Group current at that tick" にする)、SUBSCRIBE の経路でそれを使う:

```c
/* SUBSCRIBE for the live track: record the peer and send it the current
 * Group at once (its fragment starts with a keyframe). */
static void moqtrun_subscribe_live(wired_moqt_hub* hub, wired_moqtrun_peer* p, usz peer_idx) {
  wired_moqtrun_track* t    = &hub->live.track;
  wired_moqtrun_sub*   held = moqtrun_track_sub_of_peer(t, peer_idx);
  if (held) {
    moqtrun_queue_subscribe_ok(p, held->track_alias);
    return;
  }
  wired_moqtrun_sub* slot = moqtrun_sub_slot(t);
  if (!slot) {
    moqtrun_send_request_error(p, MOQCTL_ERR_INTERNAL_ERROR);
    return;
  }
  moqtrun_live_attach(hub, p, slot, peer_idx);
}

static void moqtrun_live_attach(wired_moqt_hub* hub, wired_moqtrun_peer* p, wired_moqtrun_sub* slot, usz peer_idx) {
  usz i             = (usz)(slot - hub->live.track.subs);
  slot->session_idx = peer_idx;
  slot->track_alias = hub->live.track.own_alias;
  slot->active      = 1;
  hub->live.sent_any[i] = 0;
  moqtrun_queue_subscribe_ok(p, slot->track_alias);
  moqtrun_live_send_one(hub, i, moqtrun_live_group_at(&hub->live, hub->live.last_now_ms));
}
```

`moqtrun_subscribe_live` は `if` + `if` で CCN 3(`held`/`slot` の if)。これで問題ない。`moqtrun_route_subscribe` の振り分けでは、blob の判定のあとに `if (moqtrun_track_name_matches(&hub->live.track, m->name.name)) { moqtrun_subscribe_live(hub, p, peer_idx); return; }` を足す。これで `moqtrun_route_subscribe` は CCN 3 になる。セッションを閉じるときは、`moqtrun_blob_drop_sub` に同じやり方でライブ Track を足す(名前を `moqtrun_hub_tracks_drop_sub` に変える。CCN はガード付きの if 2 つで 3)。

また、`moqtrun_track_claim` が `subs[].active` をクリアするのはスロットが in_use でなかったときだけだが、`sent_any` は購読者を付けるたびにリセットされるので、追加のゼロ埋めは要らない。

- [ ] **ステップ 5: `just test-fast` が "all tests passed" を出し、`lizard src/app/moqt/run/moqtrun.c --CCN 3 -w` が 0 で終わり、`just docs` が 0 で終わる。**

- [ ] **ステップ 6: コミットしない。統合担当に報告する。直す必要があったテストがあれば、それと理由も含める。**

---

### タスク 4a: ライブ送信部の状態モデル(タスク 4 と並行して進める)

**ファイル:** `tasks/loopeng/moqtlive/` の下のすべて(コミットしない)。

ハブのライブ送信部を modeler エージェントでモデル化する。変数は `clock_group`、購読者ごとの `sent_group`/`sent_any`/`active`、セッションごとのステージングスロット `free|inflight`。アクションは `Tick`(clock_group' = clock_group + 1 のあと、配信を 1 巡)、`Subscribe`、`Close`、`SendAccepted`(空きスロットが要る。そのスロットを inflight にし、Group を記録する)、`SendRefused`(空きスロットがない。何も記録しない)、`SlotReleased`。不変条件は次の 4 つ。(1) どの購読者も、履歴の中で同じ Group を 2 回記録しない。(2) 購読者ごとに、記録した Group は狭義単調に増える。(3) inflight のスロットを取り直さない。(4) 記録した Group は、送信した時点の時計の Group に等しい(遅れない)。活性: `SlotReleased` の弱公平性のもとで、アクティブな購読者の `sent_group` は、どの Group にもいずれ届く。モデルの範囲: 購読者 2、スロット 2、時計は 4 まで。

反例が出たら、1 つごとに タスク 4 の第 13 節へテストを 1 つ足す(同じ書き方で、テスト名にモデルの用語や ID を入れない)。モデルが反例を見つけなければ、タスク 4 のテストはそのままにする。

---

### タスク 5: フロントエンドのライブクライアント

**ファイル:**
- 作成: `examples/moqt_chat/frontend/src/lib/moqtLiveClient.ts`, `examples/moqt_chat/frontend/src/lib/__tests__/moqtLiveClient.test.ts`
- 変更: `examples/moqt_chat/frontend/src/lib/moqtMovieClient.ts`(init 用に使っていた `MOVIE_TRACK_NAME` を改める: `MOVIE_INIT_TRACK_NAME = "movie/init"` と `MOVIE_INIT_TRACK_ALIAS = 9n` を足す。`subscribeMovieInit(chat)` を足す。`readMovie` は init の読み取りに残す)、`useMoqtChat.ts`、`moqtChatStore.ts`(とそのテスト)、`page.tsx`

**インターフェース:**
- 使うもの: `MoqtChatClient.subscribeTrack`, `readToEof`, `decodeBlobObjects`, `MOVIE_TRACK_ALIAS = 8n`。
- 生成するもの:
  ```ts
  export const MOVIE_MIME = 'video/mp4; codecs="avc1.64001e, mp4a.40.2"';
  export interface SourceBufferLike { updating: boolean; mode: string; appendBuffer(b: BufferSource): void; remove(s: number, e: number): void; addEventListener(t: "updateend" | "error", h: () => void): void; buffered: { length: number; start(i: number): number; end(i: number): number } }
  export class AppendQueue { constructor(sb: SourceBufferLike, onError: (msg: string) => void); push(bytes: Uint8Array): void; trim(currentTime: number): void; }
  export class LiveMovie { constructor(chat: MoqtChatClient, video: HTMLVideoElement, onError: (msg: string) => void); start(): Promise<void>; handleInit(bytes: Uint8Array): void; handleFragment(firstChunkTail: Uint8Array, reader, hasProperties: boolean, groupId: bigint): Promise<void>; stop(): void; firstGroup: bigint | undefined }
  ```

- [ ] **ステップ 1: 失敗するテストを書く**(`moqtLiveClient.test.ts`、vitest、`moqtMovieClient.test.ts` と同じ書き方)

```ts
import { describe, expect, it, vi } from "vitest";
import { AppendQueue, LiveMovie, MOVIE_MIME } from "../moqtLiveClient";
import { encodeVarint, concatBytes } from "../moqtWire";
import { readFileSync } from "node:fs";
import path from "node:path";

function fakeSourceBuffer() {
  const listeners: Record<string, (() => void)[]> = { updateend: [], error: [] };
  const appended: Uint8Array[] = [];
  const removed: [number, number][] = [];
  const sb = {
    updating: false,
    mode: "segments",
    buffered: { length: 0, start: () => 0, end: () => 0 },
    appendBuffer(b: BufferSource) { if (sb.updating) throw new Error("busy"); sb.updating = true; appended.push(new Uint8Array(b as ArrayBuffer)); },
    remove(s: number, e: number) { if (sb.updating) throw new Error("busy"); sb.updating = true; removed.push([s, e]); },
    addEventListener(t: "updateend" | "error", h: () => void) { listeners[t].push(h); },
    finish() { sb.updating = false; for (const h of listeners.updateend) h(); },
  };
  return { sb, appended, removed };
}

describe("AppendQueue", () => {
  it("appends one buffer at a time, in order, waiting for updateend", () => {
    const { sb, appended } = fakeSourceBuffer();
    const q = new AppendQueue(sb, vi.fn());
    q.push(new Uint8Array([1])); q.push(new Uint8Array([2])); q.push(new Uint8Array([3]));
    expect(appended.length).toBe(1);
    sb.finish(); expect(appended.length).toBe(2);
    sb.finish(); expect(appended.length).toBe(3);
    expect([...appended[2]]).toEqual([3]);
  });
  it("queues a trim like an append and only when more than 60 s sit behind currentTime", () => {
    const { sb, removed } = fakeSourceBuffer();
    sb.buffered = { length: 1, start: () => 0, end: () => 100 };
    const q = new AppendQueue(sb, vi.fn());
    q.trim(30); expect(removed.length).toBe(0);
    q.trim(70); expect(removed).toEqual([[0, 40]]);
  });
  it("reports a SourceBuffer error once and stops appending", () => { /* fire the error listener, expect onError called with a string, further push() ignored */ });
});

describe("MOVIE_MIME", () => {
  it("matches the committed asset's avcC profile/compat/level", () => {
    const f = readFileSync(path.resolve(__dirname, "../../../../../../assets/movie-live.mp4"));
    const i = f.indexOf("avcC");
    const hex = [f[i + 5], f[i + 6], f[i + 7]].map((b) => b.toString(16).padStart(2, "0")).join("");
    expect(MOVIE_MIME).toContain(`avc1.${hex}`);
  });
});

describe("LiveMovie", () => {
  it("appends init before any fragment and buffers fragments that arrive first", async () => { /* fake chat + fake video with a fake MediaSource; handleFragment before handleInit -> nothing appended; handleInit -> init then fragment appended in that order */ });
  it("records the first Group id it received", async () => { /* firstGroup === 7n after handleFragment(..., 7n) */ });
  it("drops a malformed fragment without touching the queue", async () => {});
});
```

実行する前に、3 つの `/* */` の本体を実際のコードで埋める(これはテストそのもので、仮置きではない)。フラグメントのストリームは `concatBytes([encodeVarint(0n), encodeVarint(BigInt(payload.length)), payload])` で組み立てる(ヘッダーは呼び出し側が読み終えている)。偽の reader は `moqtMovieClient.test.ts` のヘルパーから作る。偽の `MediaSource` をグローバルに置き、その `addSourceBuffer` が偽の SourceBuffer を返し、`start()` の中から `sourceopen` を同期的に発火させる(`vi.stubGlobal("MediaSource", ...)`、`URL.createObjectURL` もスタブにする)。

- [ ] **ステップ 2: `pnpm test src/lib/__tests__/moqtLiveClient.test.ts` が失敗する(モジュールがない)。**

- [ ] **ステップ 3: `moqtLiveClient.ts` を実装する**

```ts
// MOQT live movie playback: the hub paces keyframe-aligned fMP4 fragments
// as MoQT Groups on the "movie" track (Track Alias 8) and serves the init
// segment once on "movie/init" (alias 9, moqtMovieClient.ts's blob reader).
// Each Group's stream is SUBGROUP_HEADER + one Object whose payload is a
// moof+mdat pair; appended to a SourceBuffer in "sequence" mode so the
// asset's 30-second loop (timestamps restart at 0) plays through.
import type { MoqtChatClient } from "./moqtClient";
import { decodeBlobObjects, MOVIE_INIT_TRACK_NAME, MOVIE_TRACK_NAME, subscribeMovieInit } from "./moqtMovieClient";
import { readToEof, utf8ToBytes } from "./moqtWire";

export const MOVIE_MIME = 'video/mp4; codecs="avc1.64001e, mp4a.40.2"';
const KEEP_BEHIND_S = 30;
const TRIM_WHEN_BEHIND_S = 60;

export interface SourceBufferLike { /* as in Interfaces */ }

export class AppendQueue {
  #sb: SourceBufferLike; #queue: (() => void)[] = []; #dead = false; #onError: (m: string) => void;
  constructor(sb: SourceBufferLike, onError: (msg: string) => void) {
    this.#sb = sb; this.#onError = onError;
    sb.addEventListener("updateend", () => this.#next());
    sb.addEventListener("error", () => { this.#dead = true; onError("video buffer error"); });
  }
  push(bytes: Uint8Array) { this.#enqueue(() => this.#sb.appendBuffer(bytes as BufferSource)); }
  trim(currentTime: number) {
    const b = this.#sb.buffered;
    if (b.length === 0 || currentTime - b.start(0) <= TRIM_WHEN_BEHIND_S) return;
    this.#enqueue(() => this.#sb.remove(0, currentTime - KEEP_BEHIND_S));
  }
  #enqueue(op: () => void) { if (this.#dead) return; this.#queue.push(op); if (!this.#sb.updating) this.#next(); }
  #next() { if (this.#sb.updating || this.#dead) return; const op = this.#queue.shift(); if (!op) return; try { op(); } catch { this.#dead = true; this.#onError("video buffer append failed"); } }
}
```

`LiveMovie`: `chat`、`video`、`AppendQueue | undefined`、`#init?: Uint8Array`、`#pending: Uint8Array[]`、`firstGroup?: bigint` を持つ。`start()`: `const ms = new MediaSource(); video.src = URL.createObjectURL(ms); await new Promise(r => ms.addEventListener("sourceopen", r, { once: true })); const sb = ms.addSourceBuffer(MOVIE_MIME); sb.mode = "sequence"; this.#q = new AppendQueue(sb, onError); await subscribeMovieInit(chat);`。あわせて `video.addEventListener("timeupdate", () => this.#q?.trim(video.currentTime))`。`handleInit(bytes)`: 保存して `q.push(bytes)` し、続いて `#pending` を順に流し込み、最後に `chat.subscribeTrack(utf8ToBytes(MOVIE_TRACK_NAME), MOVIE_TRACK_NAME)`。`handleFragment(tail, reader, props, groupId)`: try/catch の中で `const bytes = decodeBlobObjects(await readToEof(tail, reader), props)`(失敗したら return)。`firstGroup ??= groupId`。init がまだなければ `#pending` に積み(上限 8、あふれたらいちばん古いものを捨てる)、あれば `q.push`。`stop()`: `video.removeAttribute("src"); video.load();`。

- [ ] **ステップ 4: フック、ストア、ページを配線する**

`moqtChatStore.ts`: `movieUrl`/`setMovieUrl` を `liveError: string | null` / `setLiveError` に置き換え、そのテストの初期状態のアサーションを更新する。`useMoqtChat.ts`: フックから `videoRef`(`useRef<HTMLVideoElement>(null)`)を返す。`connect()` の中で、チャットがつながったあとに `const live = new LiveMovie(client, videoRef.current!, (m) => store.setLiveError(m)); liveRef.current = live; live.start().catch(() => {});`。`onUnknownUniStream`: alias 9 なら `readMovie(...).then((b) => b && liveRef.current?.handleInit(b))`、alias 8 なら `liveRef.current?.handleFragment(tail, reader, header.flags.properties, header.groupId)`、それ以外は音声。`leave()`: `liveRef.current?.stop()`。`page.tsx`: 接続中はメッセージ一覧の上に `<video ref={videoRef} data-testid="live" autoplay muted playsInline controls data-first-group={...}>` を描く(`data-first-group` には、ストアの小さなフィールド `liveFirstGroup: string | null` の値を入れる。このフィールドは `handleFragment` が `onFirstGroup` コールバックで更新する。コールバックは `LiveMovie` のコンストラクターのオプションに足す。e2e がこの属性を読む)。`liveError` が設定されていれば動画の下に表示する。

- [ ] **ステップ 5: `pnpm test && pnpm lint && pnpm build` がすべて通る。コミットせず、報告する。**

---

### タスク 6: サンプルサーバー(fMP4 での起動、ライブ配信、ステージングのリング)

**ファイル:**
- 変更: `examples/moqt_chat/wired_server.c`

**インターフェース:**
- 使うもの: `mp4frag_scan`, `wired_moqt_publish_live`, `wired_moqt_tick`, `wired_srvrun_opt.on_step`, `wired_server_wt_stream_inflight`, `wired_moqt_publish_blob`。

- [ ] **ステップ 1: 動画のブロックを置き換える**

```c
/* --- Movie track (--movie PATH, a fragmented MP4) ----------------------
 * Read once at boot into g_movie; mp4frag_scan splits it into the init
 * segment (published as the "movie/init" blob track, alias 9) and its
 * moof+mdat fragments (published as the clock-paced "movie" live track,
 * alias 8, one fragment per 2-second Group -- the encode's GOP, see the
 * README's ffmpeg command). 8 MiB: assets/movie-live.mp4 is 5.1 MB. */
#define MOVIE_MAX (8u << 20)
#define MOVIE_GROUP_MS 2000
#define MOVIE_TRACK_ALIAS 8
#define MOVIE_INIT_TRACK_ALIAS 9
#define MOVIE_TRACK_NAME "movie"
#define MOVIE_INIT_TRACK_NAME "movie/init"
static u8             g_movie[MOVIE_MAX];
static mp4frag_layout g_movie_layout;
static u8             g_movie_init_wire[MOQDATA_BLOB_WIRE_CAP(4096)];

/* Per-session staging ring for live fragments: ... (spec section 4 text:
 * LIVE_RING = 3 slots x LIVE_FRAG_MAX = 1 MiB; a slot is free when
 * wired_server_wt_stream_inflight says its stream is done; session close
 * frees all) */
#define LIVE_RING 3
#define LIVE_FRAG_MAX (1u << 20)
#define BIG_SIG_MAX 9
#define BIG_SLOTS (...same min macro as today...)
typedef struct { u64 stream_id; int used; u8 buf[BIG_SIG_MAX + MOQDATA_MSG_OVERHEAD + LIVE_FRAG_MAX]; } live_slot;
typedef struct { wired_wt_session* s; live_slot ring[LIVE_RING]; } live_session;
static live_session g_live[BIG_SLOTS];
```

関数(どれも小さく): `live_session_for(s)`(セッションのポインターで探すか確保する)、`live_slot_free(session, slot)`(`!used || !wired_server_wt_stream_inflight(s, stream_id)`)、`live_slot_claim(...)`、`moqt_io_send_uni2(s, head, body)`(スロットを確保し、シグナルの接頭部 + head + body を `bytes_memcpy` で写し、`wired_server_wt_open_uni` を呼ぶ。成功したら `stream_id` を記録し、`used = 1` にする)、`on_session_close` の中の `live_session_release(s)`。`g_big`/`big_slot_*`/`send_uni_big` は消す(blob の init は 1.2 KB でスタックの経路を通る。`moqt_io_send_uni` はスタックのステージングを超える大きさで、これまでどおり -1 を返す)。`g_moqt_io` に `send_uni2` を足す。`publish_movie`: 読み込み、`mp4frag_scan`(0 なら終了する)、blob(init)を配信してからライブを配信し(`clock_mono_ms()`。`common/platform/clock/mono.h` を取り込む。`wired.h` 経由で届くかを確かめ、届かなければ include を足す)、`movie: <n> fragments, init <b> bytes, group <ms> ms` をログに出す。`on_step`: `static void on_step(void* ctx, u64 now_ms) { wired_moqt_tick((wired_moqt_hub*)ctx, now_ms); }` と `opt.run.on_step = on_step; opt.run.on_step_ctx = &g_hub;`。`log_relay_stats` に `live_sent=`/`live_dropped=` を足す。

- [ ] **ステップ 2: `ninja examples/moqt_chat/wired_server` でビルドできる。起動の確認: `./examples/moqt_chat/wired_server --movie assets/movie-live.mp4 --port 14433` が動画の行を出し、2 秒間動き続ける。`--movie` なしでも起動する(CI の examples ワークフローは引数なしで動かす)。**

- [ ] **ステップ 3: コミットせず、報告する。**

---

### タスク 7: 実ブラウザーでの確認、ドキュメント、Docker

**ファイル:**
- 作成: `examples/moqt_chat/e2e/run-live-check.mjs`
- 変更: `examples/moqt_chat/justfile`(`e2e-movie` の隣に `e2e-live` レシピを置く。`e2e-movie` は `run-movie-check.mjs` と一緒に消す。blob の動画 Track はもう利用者向けの機能ではないため)、`examples/moqt_chat/Dockerfile`(`COPY assets/movie-live.mp4 /movie.mp4`)、`examples/moqt_chat/README.md`(動画の段落を置き換える: ライブ Track のモデル、alias 8/9、`--movie` に fMP4 を渡すこと、`just e2e-live`)

- [ ] **ステップ 1: `run-live-check.mjs` を書く**(骨組みは `run-movie-check.mjs` と同じ: `lib/args.mjs` の `arg`、`startServer`、静的なフロントエンド、`args: ["--no-sandbox", "--autoplay-policy=no-user-gesture-required"]` 付きの puppeteer):

user1 で参加する。`waitForFunction(() => { const v = document.querySelector('[data-testid="live"]'); return v && v.readyState >= 3 && v.currentTime > 4; }, { timeout: 30000 })`。`data-first-group` を読む。`await sleep(5000)`。user2 も同じように参加させる。`BigInt(user2.firstGroup) > BigInt(user1.firstGroup)` を求める。両方について `currentTime` を 3 秒あけて 2 回取り、2 秒以上進んでいることを求める。閉じる。`await server.stop()`。サーバーのログから `live_sent=` を grep し、値が 0 より大きいことを求める。JSON の要約を出力し、どれか 1 つでも失敗したら 0 以外で終わる。

- [ ] **ステップ 2: 実行する: `cd examples/moqt_chat && just e2e-live`(タスク 8 がサーバーをビルドし、`pnpm build` を実行したあと)。期待する結果: 両クライアントが ok の JSON が出て、0 で終わる。先に、残っている古い `wired_server` を止める(`pgrep -a wired_server`)。残ったプロセスは SO_REUSEPORT で 4433 番ポートを共有し、ハンドシェイクを横取りする。**

- [ ] **ステップ 3: 上に挙げたドキュメントと Docker の編集。コミットせず、報告する。**

---

### タスク 8: 統合、ゲート、マイクロコミット(直列、ワーカー 1 人)

- [ ] **ステップ 1: `mp4frag` を `tests/run.c` に配線する:** 本番コードのブロックに `#include "app/media/mp4frag/mp4frag.c"`(アルファベット順で `app/http3/server/staticfile/staticfile.c` の近くでよい)、テストのブロックに `#include "app/mp4frag_test.c"`、`main()` に `test_mp4frag();`。そのあと、配線の前後で `grep -c include tests/run.c` を比べ(+2)、`just ninja` のあとに数の確認 `[ "$(find src -name '*.c' | wc -l)" = "$(find build/src -name '*.o' | wc -l)" ]` を実行する。

- [ ] **ステップ 2: ゲート:** `just fmt`(nix)、続いて `if just test-fast 2>&1 | grep -q "all tests passed" && just ninja >/dev/null 2>&1 && lizard src --CCN 3 -w; then echo GATE-OK; fi`、続いて `just test`, `just fmt-check`, `just docs`, `just lint`, `just fuzz-smoke`、続いて `cd examples/moqt_chat/frontend && pnpm test && pnpm lint && pnpm build`、最後に `just e2e-live`。

- [ ] **ステップ 3: 次の順でマイクロコミットする(どれも、同じ作業ツリーで上のゲートが通ったあとに):**
  1. `feat(mp4frag): scan a fragmented MP4 into init segment and moof+mdat fragments` -- mp4frag.[ch], mp4frag_test.c, tests/run.c
  2. `feat(srvrun): per-step app hook and WT send in-flight query` -- srvrun.[ch], srvrun_test.c
  3. `feat(moqtrun): clock-paced live track with one fragment per Group` -- moqtrun.[ch], moqtrun_test.c
  4. `feat(moqt_chat): publish the movie as a live track with a per-session staging ring` -- wired_server.c
  5. `feat(moqt_chat/frontend): play the live movie track through MSE` -- frontend files
  6. `test(moqt_chat/e2e): real-browser live movie check (just e2e-live)` -- run-live-check.mjs, justfile, deleted run-movie-check.mjs
  7. `build(moqt_chat): ship the fragmented movie in the scratch image` -- Dockerfile
  8. `docs(moqt_chat): describe the live movie track` -- README

- [ ] **ステップ 4: `git status` がクリーンであることを確かめ、`git log --oneline -9` を実行し、ハッシュと e2e の JSON を報告する。**
