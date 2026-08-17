#include "test.h"

/* Build a 0x31 frame, then extract its payload as a view round-trips. */
void test_dg_recv_with_length(void) {
  const u8       data[] = {0xDE, 0xAD, 0xBE, 0xEF};
  u8             frame[16];
  wired_obuf     fb = obuf_of(frame, sizeof(frame));
  dgdeliver_opts o  = {1, 64};
  dgdeliver_frame(wired_span_of(data, 4), &o, &fb);

  wired_span p  = {0, 0};
  int        ok = dgdeliver_extract(wired_span_of(frame, fb.len), &p);
  CHECK(ok == 1 && p.n == 4 && p.p == frame + 2); /* type + len byte */
  CHECK(p.p[0] == 0xDE && p.p[3] == 0xEF);
}

/* A 0x30 frame's payload is everything after the type byte. */
void test_dg_recv_no_length(void) {
  const u8       data[] = {7, 8, 9};
  u8             frame[16];
  wired_obuf     fb = obuf_of(frame, sizeof(frame));
  dgdeliver_opts o  = {0, 64};
  dgdeliver_frame(wired_span_of(data, 3), &o, &fb);

  wired_span p  = {0, 0};
  int        ok = dgdeliver_extract(wired_span_of(frame, fb.len), &p);
  CHECK(ok == 1 && p.n == 3 && p.p == frame + 1);
  CHECK(p.p[0] == 7 && p.p[2] == 9);
}

/* A truncated 0x31 frame (length claims more than is present) is rejected. */
void test_dg_recv_truncated(void) {
  const u8       data[] = {1, 2, 3, 4, 5};
  u8             frame[16];
  wired_obuf     fb = obuf_of(frame, sizeof(frame));
  dgdeliver_opts o  = {1, 64};
  dgdeliver_frame(wired_span_of(data, 5), &o, &fb);

  wired_span p = {0, 0};
  CHECK(dgdeliver_extract(wired_span_of(frame, fb.len - 1), &p) == 0);
}
