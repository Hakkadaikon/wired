#include "transport/recovery/congestion/cc/cubic.h"

#include "test.h"

/* Hand-checkable window values (RFC 9438 4.1/4.2, C=0.4, beta=0.7):
 * W_max=100 segments -> K = cbrt(0.75*100 s^3) = 4.21716... s = 4217 ms.
 * W(K) = W_max; W(0) = W_max - 0.4*K^3 = beta*W_max = 70;
 * W(K+10s) = W_max + 0.4*10^3 = 500. */
static void test_cubic_window_vectors(void) {
  u64 k = quic_cubic_k_ms(100);
  CHECK(k == 4217);
  CHECK(quic_cubic_w(k, k, 100) == 100);
  CHECK(quic_cubic_w(0, k, 100) == 70);
  CHECK(quic_cubic_w(k + 10000, k, 100) == 500);
}

/* The concave region climbs monotonically toward W_max and never overshoots
 * it before K; the convex region grows past it after K. */
static void test_cubic_window_shape(void) {
  u64 k    = quic_cubic_k_ms(100);
  u64 prev = 0;
  for (u64 t = 0; t <= k; t += 400) {
    u64 w = quic_cubic_w(t, k, 100);
    CHECK(w >= prev && w <= 100);
    prev = w;
  }
  CHECK(quic_cubic_w(k + 2000, k, 100) > 100);
}

/* K for a tiny flow floors sanely; a zero W_max window floors at 0. */
static void test_cubic_edges(void) {
  CHECK(quic_cubic_k_ms(0) == 0);
  CHECK(quic_cubic_w(0, 0, 0) == 0);
  /* far before K on a small W_max: the cubic term dominates, floor at 0 */
  CHECK(quic_cubic_w(0, quic_cubic_k_ms(1), 1) <= 1);
}

/* Fast convergence (RFC 9438 4.6): a loss below the previous W_max remembers
 * a further-reduced W_max (x0.85); at or above it, W_max is just W. */
static void test_cubic_fast_convergence(void) {
  CHECK(quic_cubic_wmax_fastconv(100, 200) == 85);
  CHECK(quic_cubic_wmax_fastconv(200, 200) == 200);
  CHECK(quic_cubic_wmax_fastconv(300, 200) == 300);
}

void test_cubic(void) {
  test_cubic_window_vectors();
  test_cubic_window_shape();
  test_cubic_edges();
  test_cubic_fast_convergence();
}
