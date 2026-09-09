# MoQT Live Movie Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deliver `assets/movie.mp4` from `examples/moqt_chat`'s server as a wall-clock-paced MoQT live track (one keyframe-aligned fMP4 fragment per Group) that browsers play through MSE, with late joiners starting at the current Group.

**Architecture:** A new `mp4frag` domain splits the committed fMP4 into init + fragments; the hub (`moqtrun`) gains a clock-driven live track that fans each Group out with one `send_uni2` per subscriber; `srvrun` gains a per-step `on_step` hook and an `inflight` query so the example can recycle per-session staging; the frontend appends fragments to a `SourceBuffer` in sequence mode.

**Tech Stack:** libc-free C (this SDK's constraints), TypeScript/Next.js + vitest, puppeteer e2e, ffmpeg via nix for the one-time asset conversion.

**Spec:** `docs/superpowers/specs/2026-09-10-moqt-live-movie-design.md`

## Global Constraints

- `src/` is libc-free: only `common/platform/sys/syscall.h` types and `src/common/bytes/util/*.h` helpers (`bytes_memcpy`, `be_get_be32`, `ct_diffn`, `u64_min`). No standard headers.
- Every function in `src/` has cyclomatic complexity <= 3 (`lizard src --CCN 3 -w` exits 0). `&&`, `||`, `?:`, `if`, `for`, `while` each count +1.
- `tests/run.c` is one translation unit including every `src/**/*.c` and every `tests/**/*_test.c`: every new non-static AND static name must be globally unique (`grep -rn '<name>' src/ tests/` before adding).
- New public header members/macros/functions carry `/** */` doc comments (doxygen runs with WARN_AS_ERROR).
- Internal API uses the module token as prefix (`mp4frag_*`, `moqtrun_*`); application-facing API uses `wired_*`.
- Commit gate (every commit): `just test-fast` prints "all tests passed" AND `just ninja` exits 0 AND `lizard src --CCN 3 -w` exits 0, run as `if A && B && C; then git commit; fi` (never `| tail && commit`). Before pushing: `just test`, `just fmt-check`, `just docs`, `just lint`, `just fuzz-smoke` (all through `nix develop`, which `just` does itself).
- Parallel workers edit only their own new files; never `git add`/`commit`/`push`; never edit `tests/run.c` or `justfile`. One integrator wires and commits (Task 8).
- Commit trailer (every commit):
  ```
  Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>
  Claude-Session: https://claude.ai/code/session_01MUGHRYWD7RZSxw8p3C7GP1
  ```
- Track aliases: chat 0..3, audio 4..7, `movie` 8, `movie/init` 9. Group cadence 2000 ms. MIME `video/mp4; codecs="avc1.64001e, mp4a.40.2"` (from the generated file's `avcC` 64 00 1e and AAC-LC DSI).

## Parallelism

Wave 1 (independent, run concurrently): Task 1 (asset), Task 2 (mp4frag), Task 3 (srvrun hooks), Task 4 (hub live track), Task 5 (frontend live client). Task 4's state model (Task 4a) runs alongside Task 4 and its counterexamples are folded into Task 4's tests before Task 8 commits.
Wave 2: Task 6 (example server) after 2, 3, 4. Task 7 (e2e + docs) after 5, 6.
Task 8 (integrator: wiring, gate, micro-commits) closes each wave.

---

### Task 1: Generate and commit the fragmented asset

**Files:**
- Create: `assets/movie-live.mp4`
- Modify: `examples/moqt_chat/README.md` (only the conversion command block; the rest of the README is Task 7)

**Interfaces:**
- Produces: `assets/movie-live.mp4` — fMP4, init 1,260 bytes, 16 `moof`+`mdat` fragments, `avcC` profile/compat/level = 64 00 1e.

- [ ] **Step 1: Generate the file**

```sh
nix shell nixpkgs#ffmpeg-headless -c ffmpeg -v error -y -i assets/movie.mp4 \
  -c:v libx264 -preset medium -profile:v high -g 48 -keyint_min 48 \
  -sc_threshold 0 -b:v 1200k -c:a aac -b:a 128k \
  -movflags +frag_keyframe+empty_moov+default_base_moof \
  -f mp4 assets/movie-live.mp4
```

- [ ] **Step 2: Verify the layout (this is the acceptance test of the asset)**

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
Expected: `init 1260 frags 16 avcC 64001e` and no assertion.

- [ ] **Step 3: Record the command in the README**

Add under "## What this demonstrates" (after the paragraph that starts "The server is a publisher too") a fenced block containing exactly the Step 1 command, introduced by one sentence: "`assets/movie-live.mp4` is generated from `assets/movie.mp4` once with:".

- [ ] **Step 4: Commit**

```sh
git add assets/movie-live.mp4 examples/moqt_chat/README.md
git commit -m "chore(assets): add fragmented 2-second-GOP copy of the sample movie"
```

---

### Task 2: `mp4frag` domain — fMP4 top-level box scan

**Files:**
- Create: `src/app/media/mp4frag/mp4frag.h`, `src/app/media/mp4frag/mp4frag.c`
- Test: `tests/app/mp4frag_test.c`
- (Task 8 wires both into `tests/run.c`.)

**Interfaces:**
- Consumes: `be_get_be32` (`common/bytes/util/be.h`), `wired_span`/`wired_span_of` (`common/bytes/span/span.h`).
- Produces:
  ```c
  #define MP4FRAG_MAX_FRAGS 64
  typedef struct { wired_span init; wired_span frags[MP4FRAG_MAX_FRAGS]; usz n_frags; } mp4frag_layout;
  int mp4frag_scan(wired_span file, mp4frag_layout* out);   /* 1 ok, 0 malformed */
  ```

- [ ] **Step 1: Write the failing tests**

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

Note the first malformed case: renaming `moof` to `foof` leaves a valid file with zero fragments, so `scan` returns 0 there too (no fragment at all is a failure). Replace that `CHECK` with `CHECK(mp4frag_scan(...) == 0);` and drop the stray comment.

- [ ] **Step 2: Verify it fails (compile against a stub in $TMPDIR)**

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
Expected: compile error (header missing) — that is the Red. Check `tests/test.h` for how `CHECK`/`wired_test_fails` are declared and mirror it (the unity `tests/run.c` defines `wired_test_fails`; here the stub main does).

- [ ] **Step 3: Write the header**

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

- [ ] **Step 4: Write the implementation (every function CCN <= 3)**

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

`mp4frag_scan_frags` has `while` + `if` + `if(&&)` = CCN 4: split the `&&` into a predicate `static int mp4frag_moof_bad(wired_span file, usz* off, const mp4frag_box* b, mp4frag_layout* out) { return b->type == mp4frag_fourcc("moof") && !mp4frag_take_mdat(file, off, b, out); }` and call `if (mp4frag_moof_bad(...)) return 0;`. Confirm with `lizard src/app/media/mp4frag/mp4frag.c --CCN 3 -w`.

- [ ] **Step 5: Run the $TMPDIR harness — expect `fails=0`; run lizard on the file — expect exit 0.**

- [ ] **Step 6: Do NOT commit or wire. Report the two file paths and the harness output to the integrator (Task 8).**

---

### Task 3: srvrun per-step hook and in-flight query

**Files:**
- Modify: `src/app/http3/server/srvrun/srvrun.h` (add to `wired_srvrun_opt` after `wt_session_close_ctx`; add the query declaration after `wired_server_wt_stream_reset`)
- Modify: `src/app/http3/server/srvrun/srvrun.c` (`srvrun_cfg` tail, `srvrun_build_cfg`, `srvrun_step`, new query function)
- Test: `tests/app/srvrun_test.c` (append two tests; register them in `test_srvrun`)

**Interfaces:**
- Produces:
  ```c
  typedef void (*wired_srvrun_on_step)(void* ctx, u64 now_ms);
  /* in wired_srvrun_opt: */ wired_srvrun_on_step on_step; void* on_step_ctx;
  int wired_server_wt_stream_inflight(wired_wt_session* s, u64 stream_id);
  ```

- [ ] **Step 1: Read the existing test style**

Open `tests/app/srvrun_test.c` around line 4500-4560 (the test that calls `srvrun_step(&cfg, &st, bufs, 2)` in a loop) and around line 4561 ("WRAPPER EQUIVALENCE") to see how a `srvrun_cfg`/`srvrun_state` is built directly in a test. Reuse the same construction helpers by name (copy the exact setup lines from the nearest test; do not invent new fixtures).

- [ ] **Step 2: Write the failing tests**

Append before `void test_srvrun(void)`:

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

Replace the `...` with the copied fixture lines (the plan cannot know their exact shape without the file open; the neighboring test at ~line 4500 is the template). The `srvrun_step` in that test must not block: the fixture there uses a non-blocking configuration — keep it identical.

- [ ] **Step 3: Run `just test-fast` — expect a compile error naming `on_step` (Red).**

- [ ] **Step 4: Implement**

`srvrun.h`, after the `wt_session_close_ctx` member of `wired_srvrun_opt`:

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

and above the `wired_srvrun_opt` typedef (next to the other callback typedefs):

```c
/** Per-step application hook (wired_srvrun_opt.on_step).
 * @param ctx opaque context registered alongside this callback
 * @param now_ms the loop's monotonic clock at this step */
typedef void (*wired_srvrun_on_step)(void* ctx, u64 now_ms);
```

and after `wired_server_wt_stream_reset`'s declaration:

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

`srvrun.c`: add to the END of `srvrun_cfg` (after `wt_session_close_ctx`):

```c
  /** Per-step app hook, 0 to disable, see wired_srvrun_opt. */
  wired_srvrun_on_step on_step;
  void*                on_step_ctx; /**< opaque ctx for on_step */
```

and to the END of the compound literal in `srvrun_build_cfg`: `opt->on_step, opt->on_step_ctx`.

In `srvrun_step`, right after the `if (srvrun_wait_input(cfg, st)) srvrun_recv_serve(...)` line:

```c
  srvrun_app_step(cfg);
```

with, above `srvrun_step`:

```c
/* wired_srvrun_opt.on_step: the app's own per-step work (e.g. a clock-
 * paced publisher), given the same monotonic clock the loop's timers use. */
static void srvrun_app_step(const srvrun_cfg* cfg) {
  if (cfg->on_step) cfg->on_step(cfg->on_step_ctx, clock_mono_ms());
}
```

The query, next to `wired_server_wt_stream_reset`:

```c
int wired_server_wt_stream_inflight(wired_wt_session* s, u64 stream_id) {
  srvrun_conn* c = srvrun_session_conn(s);
  if (!c) return 0;
  return srvrun_wtsend_find(c, stream_id) != 0;
}
```

Check `srvrun_session_conn(0)` returns 0 for a null session (read it; if it dereferences, guard `if (!s) return 0;` first) and that `srvrun_wtsend_find` only matches `in_use` slots (read its body; it is forward-declared near line 3752).

- [ ] **Step 5: `just test-fast` prints "all tests passed"; `lizard src/app/http3/server/srvrun/srvrun.c --CCN 3 -w` exits 0; `just docs` exits 0 (new header members).**

- [ ] **Step 6: Do NOT commit. Report to the integrator.**

---

### Task 4: Hub live track (`moqtrun`)

**Files:**
- Modify: `src/app/moqt/run/moqtrun.h` (io table: `send_uni2`; new `wired_moqtrun_live` type + hub member; two new functions; two counters)
- Modify: `src/app/moqt/run/moqtrun.c`
- Test: `tests/app/moqtrun_test.c` (stub `send_uni2` + new section 13)

**Interfaces:**
- Consumes: `moqdata_subhdr_put`, `moqdata_obj_put` (data/moqdata.h), `MOQDATA_MSG_OVERHEAD`; existing `moqtrun_track_claim`, `moqtrun_sub_slot`, `moqtrun_track_sub_of_peer`, `moqtrun_queue_subscribe_ok`, `moqtrun_send_request_error`, `moqtrun_track_drop_sub`.
- Produces:
  ```c
  /* io table, after stream_reset: */
  i64 (*send_uni2)(wired_wt_session* s, wired_span head, wired_span body);
  int  wired_moqt_publish_live(wired_moqt_hub*, wired_span name, u64 track_alias,
                               const wired_span* frags, usz n_frags, u64 group_ms, u64 now_ms);
  void wired_moqt_tick(wired_moqt_hub*, u64 now_ms);
  /* hub counters: */ u64 stat_live_sent; u64 stat_live_drop;
  ```

- [ ] **Step 1: Extend the test stub** (top of `tests/app/moqtrun_test.c`)

Add call kind 8 = `send_uni2`; record `head||body` into `payload` (truncated to `MOQTRUN_TEST_MAX_PAYLOAD`), `payload_len` = full `head.n + body.n` (so a test can check the real length even when the recorder truncates); refuse (return -1) while `g_send_uni2_fail_n > 0` or when `g_send_uni2_reject_sess == s`; reset both in `moqtrun_test_reset`; set `io.send_uni2 = moqtrun_test_send_uni2` in `moqtrun_test_io`.

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

Note `payload_len` may exceed the buffer: every existing reader of `payload_len` indexes `payload` — keep the live tests' fragments <= 200 bytes so head+body always fits, and never read past `MOQTRUN_TEST_MAX_PAYLOAD`.

- [ ] **Step 2: Write the failing tests** (new section 13 before `void test_moqtrun(void)`)

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

For the `...` in the last test: copy `moqtrun_test_rename_track_to_audio` into a generic `moqtrun_test_rename_track(const u8* src, usz src_len, const u8* name, usz name_len, u8* dst)` that backpatches the 16-bit Length by `name_len - 5`, then use it for `"movie/init"`. Register all eight tests in `test_moqtrun`.

- [ ] **Step 3: Run `just test-fast` — compile error on `wired_moqt_publish_live` (Red).**

- [ ] **Step 4: Implement**

`moqtrun.h` — io table, after `stream_reset`:

```c
  /** wired_server_wt_open_uni-shaped for a two-part payload: head (a
   * short framing prefix) immediately followed by body (a large media
   * fragment the hub holds only as a view into caller storage). The
   * adapter concatenates them (with its own signal prefix) into
   * session-owned staging; -1 when it has none free. Returns the stream
   * id or negative. */
  i64 (*send_uni2)(wired_wt_session* s, wired_span head, wired_span body);
```

new type before `wired_moqt_hub`:

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

hub members after `blob_wire`:

```c
  /** The hub's live track (wired_moqt_publish_live); track.in_use once
   * published. */
  wired_moqtrun_live live;
  /** Live Groups accepted by io.send_uni2 / abandoned because the clock
   * left the Group before a refused send could be retried. */
  u64 stat_live_sent;
  u64 stat_live_drop;
```

functions:

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

`moqtrun.c` — in `wired_moqt_init`: `hub->live.track.in_use = 0; hub->stat_live_sent = 0; hub->stat_live_drop = 0;`.

Live section (after the blob section):

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

(`moqdata_obj_put` writes delta + length + payload in one go; the head needs delta + length WITHOUT the payload, hence the two `moqvi_put` calls. Check `moqdata_obj_put`'s body in `moqdata.c` to confirm the exact varint sequence it emits for a non-empty payload -- delta, then length, then bytes -- so `head||body` is byte-identical to `moqdata_obj_put`; the coexist test's `moqtrun_test_live_group` decodes it with `moqdata_obj_take`, which is the proof.)

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

Careful: `moqtrun_live_skip_stale` counts drops once per Group skipped, but a subscriber that fell behind by k Groups must be counted exactly once per skipped Group and then caught up by `sent_group = g` on the next accepted send. Simplest correct shape: in `moqtrun_live_send_one`, on acceptance, `if (live->sent_any[i] && live->sent_group[i] + 1 < g) hub->stat_live_drop += g - live->sent_group[i] - 1;` BEFORE setting `sent_group = g`, and delete `moqtrun_live_skip_stale`. That keeps CCN <= 3 by moving the two-condition check into a helper `static u64 moqtrun_live_gap(const wired_moqtrun_live*, usz i, u64 g)` returning the number of skipped Groups (0 when none).

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

The tick needs the current clock at SUBSCRIBE time too (spec: send the current Group at once). The hub has no clock of its own: store the last tick's `now_ms` in `hub->live.last_now_ms` (add to the struct with a doc comment: "clock of the most recent wired_moqt_tick; a SUBSCRIBE between ticks is served the Group current at that tick") and use it in the SUBSCRIBE path:

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

`moqtrun_subscribe_live` has `if` + `if` = CCN 3 (the `held`/`slot` ifs); fine. Routing in `moqtrun_route_subscribe`: after the blob check add `if (moqtrun_track_name_matches(&hub->live.track, m->name.name)) { moqtrun_subscribe_live(hub, p, peer_idx); return; }` -- that makes `moqtrun_route_subscribe` CCN 3. Session close: in `moqtrun_blob_drop_sub` add the live track the same way (rename it `moqtrun_hub_tracks_drop_sub`; CCN: two guarded ifs = 3).

Also `moqtrun_track_claim` clears `subs[].active` only when the slot was not in_use; `sent_any` is reset per attach, so no extra zeroing is needed.

- [ ] **Step 5: `just test-fast` prints "all tests passed"; `lizard src/app/moqt/run/moqtrun.c --CCN 3 -w` exits 0; `just docs` exits 0.**

- [ ] **Step 6: Do NOT commit. Report to the integrator, including any test you had to adjust and why.**

---

### Task 4a: State model of the live sender (runs alongside Task 4)

**Files:** everything under `tasks/loopeng/moqtlive/` (never committed).

Model the hub's live sender with the modeler agent: variables `clock_group`, per-subscriber `sent_group`/`sent_any`/`active`, per-session staging slots `free|inflight`; actions `Tick` (clock_group' = clock_group + 1, then a serve pass), `Subscribe`, `Close`, `SendAccepted` (requires a free slot; marks it inflight; records the Group), `SendRefused` (no free slot; records nothing), `SlotReleased`. Invariants: (1) no subscriber has the same Group recorded twice across its history, (2) recorded Groups per subscriber strictly increase, (3) an inflight slot is never re-claimed, (4) a recorded Group equals the clock Group at the time of the send (never late). Liveness: under weak fairness of `SlotReleased`, every active subscriber's `sent_group` eventually reaches any given Group. Model bound: 2 subscribers, 2 slots, clock up to 4.

Every counterexample becomes one more test in Task 4's section 13 (written in the same style, no model vocabulary or ids in the test names). If the model finds no counterexample, Task 4's tests stand.

---

### Task 5: Frontend live client

**Files:**
- Create: `examples/moqt_chat/frontend/src/lib/moqtLiveClient.ts`, `examples/moqt_chat/frontend/src/lib/__tests__/moqtLiveClient.test.ts`
- Modify: `examples/moqt_chat/frontend/src/lib/moqtMovieClient.ts` (rename `MOVIE_TRACK_NAME` use for init: add `MOVIE_INIT_TRACK_NAME = "movie/init"`, `MOVIE_INIT_TRACK_ALIAS = 9n`; `subscribeMovieInit(chat)`; keep `readMovie` as the init reader), `useMoqtChat.ts`, `moqtChatStore.ts` (+ its test), `page.tsx`

**Interfaces:**
- Consumes: `MoqtChatClient.subscribeTrack`, `readToEof`, `decodeBlobObjects`, `MOVIE_TRACK_ALIAS = 8n`.
- Produces:
  ```ts
  export const MOVIE_MIME = 'video/mp4; codecs="avc1.64001e, mp4a.40.2"';
  export interface SourceBufferLike { updating: boolean; mode: string; appendBuffer(b: BufferSource): void; remove(s: number, e: number): void; addEventListener(t: "updateend" | "error", h: () => void): void; buffered: { length: number; start(i: number): number; end(i: number): number } }
  export class AppendQueue { constructor(sb: SourceBufferLike, onError: (msg: string) => void); push(bytes: Uint8Array): void; trim(currentTime: number): void; }
  export class LiveMovie { constructor(chat: MoqtChatClient, video: HTMLVideoElement, onError: (msg: string) => void); start(): Promise<void>; handleInit(bytes: Uint8Array): void; handleFragment(firstChunkTail: Uint8Array, reader, hasProperties: boolean, groupId: bigint): Promise<void>; stop(): void; firstGroup: bigint | undefined }
  ```

- [ ] **Step 1: Write the failing tests** (`moqtLiveClient.test.ts`, vitest, style of `moqtMovieClient.test.ts`)

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

Fill the three `/* */` bodies with real code before running (they are the test, not placeholders): build a fragment stream as `concatBytes([encodeVarint(0n), encodeVarint(BigInt(payload.length)), payload])` (header already consumed by the caller), a fake reader from `moqtMovieClient.test.ts`'s helper, and a fake `MediaSource` global with `addSourceBuffer` returning the fake SourceBuffer and dispatching `sourceopen` synchronously from `start()` (`vi.stubGlobal("MediaSource", ...)`, `URL.createObjectURL` stubbed).

- [ ] **Step 2: `pnpm test src/lib/__tests__/moqtLiveClient.test.ts` fails (module missing).**

- [ ] **Step 3: Implement `moqtLiveClient.ts`**

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

`LiveMovie`: holds `chat`, `video`, `AppendQueue | undefined`, `#init?: Uint8Array`, `#pending: Uint8Array[]`, `firstGroup?: bigint`. `start()`: `const ms = new MediaSource(); video.src = URL.createObjectURL(ms); await new Promise(r => ms.addEventListener("sourceopen", r, { once: true })); const sb = ms.addSourceBuffer(MOVIE_MIME); sb.mode = "sequence"; this.#q = new AppendQueue(sb, onError); await subscribeMovieInit(chat);` -- and `video.addEventListener("timeupdate", () => this.#q?.trim(video.currentTime))`. `handleInit(bytes)`: store, `q.push(bytes)`, then flush `#pending` in order, then `chat.subscribeTrack(utf8ToBytes(MOVIE_TRACK_NAME), MOVIE_TRACK_NAME)`. `handleFragment(tail, reader, props, groupId)`: `const bytes = decodeBlobObjects(await readToEof(tail, reader), props)` in try/catch (return on failure); `firstGroup ??= groupId`; if no init yet push to `#pending` (cap 8, drop oldest) else `q.push`. `stop()`: `video.removeAttribute("src"); video.load();`.

- [ ] **Step 4: Wire the hook/store/page**

`moqtChatStore.ts`: replace `movieUrl`/`setMovieUrl` with `liveError: string | null` / `setLiveError`; update its test's initial-state assertion. `useMoqtChat.ts`: a `videoRef` (`useRef<HTMLVideoElement>(null)`) returned from the hook; in `connect()`, after chat connects, `const live = new LiveMovie(client, videoRef.current!, (m) => store.setLiveError(m)); liveRef.current = live; live.start().catch(() => {});`; `onUnknownUniStream`: alias 9 -> `readMovie(...).then((b) => b && liveRef.current?.handleInit(b))`; alias 8 -> `liveRef.current?.handleFragment(tail, reader, header.flags.properties, header.groupId)`; else voice. `leave()`: `liveRef.current?.stop()`. `page.tsx`: render `<video ref={videoRef} data-testid="live" autoplay muted playsInline controls data-first-group={...}>` above the message list whenever connected (`data-first-group` is set from a small store field `liveFirstGroup: string | null` that `handleFragment` updates through an `onFirstGroup` callback -- add it to `LiveMovie`'s constructor options; the e2e reads it). Show `liveError` under the video when set.

- [ ] **Step 5: `pnpm test && pnpm lint && pnpm build` all pass. Do NOT commit; report.**

---

### Task 6: Example server: fMP4 boot, live publish, staging ring

**Files:**
- Modify: `examples/moqt_chat/wired_server.c`

**Interfaces:**
- Consumes: `mp4frag_scan`, `wired_moqt_publish_live`, `wired_moqt_tick`, `wired_srvrun_opt.on_step`, `wired_server_wt_stream_inflight`, `wired_moqt_publish_blob`.

- [ ] **Step 1: Replace the movie block**

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

Functions (each small): `live_session_for(s)` (find or claim by session pointer), `live_slot_free(session, slot)` (`!used || !wired_server_wt_stream_inflight(s, stream_id)`), `live_slot_claim(...)`, `moqt_io_send_uni2(s, head, body)` (claim a slot; signal prefix + head + body via `bytes_memcpy`; `wired_server_wt_open_uni`; on success record `stream_id`, `used = 1`), `live_session_release(s)` in `on_session_close`. Remove `g_big`/`big_slot_*`/`send_uni_big` (the blob's init is 1.2 KB and takes the stack path; `moqt_io_send_uni` returns -1 above the stack staging as before). Add `send_uni2` to `g_moqt_io`. `publish_movie`: read, `mp4frag_scan` (die on 0), publish blob (init) then live (`clock_mono_ms()` -- include `common/platform/clock/mono.h`, check it is reachable through `wired.h`; if not, add the include), log `movie: <n> fragments, init <b> bytes, group <ms> ms`. `on_step`: `static void on_step(void* ctx, u64 now_ms) { wired_moqt_tick((wired_moqt_hub*)ctx, now_ms); }` and `opt.run.on_step = on_step; opt.run.on_step_ctx = &g_hub;`. Extend `log_relay_stats` with `live_sent=`/`live_dropped=`.

- [ ] **Step 2: `ninja examples/moqt_chat/wired_server` builds; boot smoke: `./examples/moqt_chat/wired_server --movie assets/movie-live.mp4 --port 14433` prints the movie line and stays up 2 s; without `--movie` it boots too (CI's examples workflow runs it bare).**

- [ ] **Step 3: Do NOT commit; report.**

---

### Task 7: Real-browser check, docs, Docker

**Files:**
- Create: `examples/moqt_chat/e2e/run-live-check.mjs`
- Modify: `examples/moqt_chat/justfile` (`e2e-live` recipe next to `e2e-movie`; `e2e-movie` is deleted along with `run-movie-check.mjs` -- the blob movie track no longer exists as a user feature), `examples/moqt_chat/Dockerfile` (`COPY assets/movie-live.mp4 /movie.mp4`), `examples/moqt_chat/README.md` (replace the movie paragraphs: live track model, aliases 8/9, `--movie` takes the fMP4, `just e2e-live`)

- [ ] **Step 1: Write `run-live-check.mjs`** (same skeleton as `run-movie-check.mjs`: `arg` from `lib/args.mjs`, `startServer`, static frontend, puppeteer with `args: ["--no-sandbox", "--autoplay-policy=no-user-gesture-required"]`):

join user1; `waitForFunction(() => { const v = document.querySelector('[data-testid="live"]'); return v && v.readyState >= 3 && v.currentTime > 4; }, { timeout: 30000 })`; read `data-first-group`; `await sleep(5000)`; join user2 the same way; require `BigInt(user2.firstGroup) > BigInt(user1.firstGroup)`; for both, sample `currentTime` twice 3 s apart and require it advanced by >= 2 s; close; `await server.stop()`; grep the server log for `live_sent=` and require a value > 0. Print a JSON summary; exit non-zero on any failure.

- [ ] **Step 2: Run it: `cd examples/moqt_chat && just e2e-live` (after Task 8 has built the server and `pnpm build` ran). Expected: JSON with both clients ok, exit 0. Kill any stale `wired_server` first (`pgrep -a wired_server`): a leftover one shares port 4433 via SO_REUSEPORT and steals the handshake.**

- [ ] **Step 3: Docs + Docker edits as listed. Do NOT commit; report.**

---

### Task 8: Integration, gate, micro-commits (serial, one worker)

- [ ] **Step 1: Wire `mp4frag` into `tests/run.c`:** `#include "app/media/mp4frag/mp4frag.c"` in the production block (alphabetically near `app/http3/server/staticfile/staticfile.c` is fine), `#include "app/mp4frag_test.c"` in the test block, `test_mp4frag();` in `main()`. Then `grep -c include tests/run.c` before/after (+2) and the count check `[ "$(find src -name '*.c' | wc -l)" = "$(find build/src -name '*.o' | wc -l)" ]` after `just ninja`.

- [ ] **Step 2: Gate:** `just fmt` (nix), then `if just test-fast 2>&1 | grep -q "all tests passed" && just ninja >/dev/null 2>&1 && lizard src --CCN 3 -w; then echo GATE-OK; fi`; then `just test`, `just fmt-check`, `just docs`, `just lint`, `just fuzz-smoke`; then `cd examples/moqt_chat/frontend && pnpm test && pnpm lint && pnpm build`; then `just e2e-live`.

- [ ] **Step 3: Micro-commits in this order (each after the gate above is green in the same tree):**
  1. `feat(mp4frag): scan a fragmented MP4 into init segment and moof+mdat fragments` -- mp4frag.[ch], mp4frag_test.c, tests/run.c
  2. `feat(srvrun): per-step app hook and WT send in-flight query` -- srvrun.[ch], srvrun_test.c
  3. `feat(moqtrun): clock-paced live track with one fragment per Group` -- moqtrun.[ch], moqtrun_test.c
  4. `feat(moqt_chat): publish the movie as a live track with a per-session staging ring` -- wired_server.c
  5. `feat(moqt_chat/frontend): play the live movie track through MSE` -- frontend files
  6. `test(moqt_chat/e2e): real-browser live movie check (just e2e-live)` -- run-live-check.mjs, justfile, deleted run-movie-check.mjs
  7. `build(moqt_chat): ship the fragmented movie in the scratch image` -- Dockerfile
  8. `docs(moqt_chat): describe the live movie track` -- README

- [ ] **Step 4: `git status` clean; `git log --oneline -9`; report the hashes and the e2e JSON.**
