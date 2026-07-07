#include "test.h"

#define WTERRMAP_FIRST 0x52e4a40fa8dbULL
#define WTERRMAP_LAST 0x52e5ac983162ULL

/* Small deterministic LCG so the random sample is reproducible without any
 * libc random function. */
static u32 wterrmap_test_lcg(u32* state) {
  *state = *state * 1664525u + 1013904223u;
  return *state;
}

static const u32 wterrmap_boundary_vals[] = {
    0,          1,          29,         30,         31,        32,
    60,         61,         929,        930,        931,       0x7fffffff,
    0xfffffffe, 0xffffffff,
};
#define WTERRMAP_NBOUNDARY \
  (sizeof(wterrmap_boundary_vals) / sizeof(wterrmap_boundary_vals[0]))

static void wterrmap_check_roundtrip(u32 n) {
  u64 h = quic_wterrmap_to_http3(n);
  CHECK(h >= WTERRMAP_FIRST && h <= WTERRMAP_LAST);
  u32 back = 0;
  CHECK(quic_wterrmap_from_http3(h, &back) == 1);
  CHECK(back == n);
}

void test_wterrmap(void) {
  usz i;

  /* 1+2+5: round-trip and range over the boundary/spot-check set. */
  for (i = 0; i < WTERRMAP_NBOUNDARY; i++) {
    wterrmap_check_roundtrip(wterrmap_boundary_vals[i]);
  }

  /* Tight-bound equalities. */
  CHECK(quic_wterrmap_to_http3(0) == WTERRMAP_FIRST);
  CHECK(quic_wterrmap_to_http3(0xffffffff) == WTERRMAP_LAST);

  /* 1: modest random sample via a fixed-seed LCG (deterministic). */
  u32 seed = 0xC0FFEEu;
  for (i = 0; i < 5000; i++) {
    u32 n = wterrmap_test_lcg(&seed);
    wterrmap_check_roundtrip(n);
  }

  /* 3: reserved codepoint within [first, last] must be rejected. shifted=30
   * => h = first + 30 = 0x52e4a40fa8f9, which is of reserved form on h
   * itself: (h - 0x21) % 0x1f == 0. */
  u64 reserved_h  = WTERRMAP_FIRST + 30;
  u32 reserved_out = 0;
  CHECK((reserved_h - 0x21) % 0x1f == 0);
  CHECK(quic_wterrmap_from_http3(reserved_h, &reserved_out) == 0);

  /* 4: out-of-range rejection on both sides. */
  u32 oor_out = 0;
  CHECK(quic_wterrmap_from_http3(WTERRMAP_FIRST - 1, &oor_out) == 0);
  CHECK(quic_wterrmap_from_http3(WTERRMAP_LAST + 1, &oor_out) == 0);

  /* 6: regression for the "checked on shifted instead of h" bug class.
   * At shifted=30, (h-0x21)%0x1f == 0 (reserved on h, must reject) but
   * (shifted-0x21)%0x1f == 28 != 0 (would wrongly accept if checked on
   * shifted). This is a genuine divergence, not an unconstructable case. */
  CHECK((30 - 0x21) % 0x1f != 0);
  CHECK(quic_wterrmap_from_http3(reserved_h, &reserved_out) == 0);

  /* 7: named WT application error codes (webtransport-plan.md Section G)
   * carry the exact hex values from the draft. Most are not wired to a
   * live trigger site yet (see errmap.h doc comment) but a wrong constant
   * is a real bug independent of that, and each round-trips through the
   * same mapping arithmetic checked above. */
  CHECK(QUIC_WTERR_BUFFERED_STREAM_REJECTED == 0x3994bd84u);
  CHECK(QUIC_WTERR_SESSION_GONE == 0x170d7b68u);
  CHECK(QUIC_WTERR_FLOW_CONTROL_ERROR == 0x045d4487u);
  CHECK(QUIC_WTERR_ALPN_ERROR == 0x0817b3ddu);
  CHECK(QUIC_WTERR_REQUIREMENTS_NOT_MET == 0x212c0d48u);
  wterrmap_check_roundtrip(QUIC_WTERR_BUFFERED_STREAM_REJECTED);
  wterrmap_check_roundtrip(QUIC_WTERR_SESSION_GONE);
  wterrmap_check_roundtrip(QUIC_WTERR_FLOW_CONTROL_ERROR);
  wterrmap_check_roundtrip(QUIC_WTERR_ALPN_ERROR);
  wterrmap_check_roundtrip(QUIC_WTERR_REQUIREMENTS_NOT_MET);
}
