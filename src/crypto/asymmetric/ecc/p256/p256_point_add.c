#include "crypto/asymmetric/ecc/p256/p256_point_impl.h"

static void slope_add(p256_fe lam, const ec_point* p, const ec_point* q);
static void slope_double(p256_fe lam, const ec_point* p);
static void from_slope(ec_point* r, const p256_slope* sl);
static void add_distinct(ec_point* r, const ec_point* p, const ec_point* q);
static int  is_inverse_pair(const ec_point* p, const ec_point* q);
static void add_same_x(ec_point* r, const ec_point* p, const ec_point* q);
static int  add_infinity(ec_point* r, const ec_point* p, const ec_point* q);

/* lambda = (y2 - y1) / (x2 - x1); caller guarantees x1 != x2. */
static void slope_add(p256_fe lam, const ec_point* p, const ec_point* q) {
  p256_fe num, den, inv;
  p256_fp_sub(num, (fpab){q->y, p->y}, p256_p);
  p256_fp_sub(den, (fpab){q->x, p->x}, p256_p);
  p256_fp_inv_p(inv, den);
  p256_fp_mul_p(lam, num, inv);
}

/* lambda = (3x^2 - 3) / (2y). */
static void slope_double(p256_fe lam, const ec_point* p) {
  p256_fe x2, num, den, inv, three = {3, 0, 0, 0};
  p256_fp_sqr_p(x2, p->x);
  p256_fp_mul_p(num, three, x2);
  p256_fp_sub(num, (fpab){num, three}, p256_p); /* 3x^2 - 3 (a=-3) */
  p256_fp_add(den, (fpab){p->y, p->y}, p256_p);
  p256_fp_inv_p(inv, den);
  p256_fp_mul_p(lam, num, inv);
}

/* From the slope and source x-coords, produce r = (x3,y3). */
static void from_slope(ec_point* r, const p256_slope* sl) {
  p256_fe x3, t;
  p256_fp_sqr_p(x3, sl->lam);
  p256_fp_sub(x3, (fpab){x3, sl->x1}, p256_p);
  p256_fp_sub(x3, (fpab){x3, sl->x2}, p256_p); /* lam^2 - x1 - x2 */
  p256_fp_sub(t, (fpab){sl->x1, x3}, p256_p);
  p256_fp_mul_p(t, sl->lam, t);
  p256_fp_sub(r->y, (fpab){t, sl->y1}, p256_p); /* lam(x1-x3) - y1 */
  p256_fp_set(r->x, x3);
  r->inf = 0;
}

void ec_double(ec_point* r, const ec_point* p) {
  p256_slope sl;
  if (p->inf || p256_fp_is_zero(p->y)) {
    r->inf = 1;
    return;
  }
  p256_fp_set(sl.x1, p->x);
  p256_fp_set(sl.y1, p->y);
  p256_fp_set(sl.x2, p->x);
  slope_double(sl.lam, p);
  from_slope(r, &sl);
}

/* p and q are not infinity and not mutually inverse: distinct addition. */
static void add_distinct(ec_point* r, const ec_point* p, const ec_point* q) {
  p256_slope sl;
  p256_fp_set(sl.x1, p->x);
  p256_fp_set(sl.y1, p->y);
  p256_fp_set(sl.x2, q->x);
  slope_add(sl.lam, p, q);
  from_slope(r, &sl);
}

/* 1 if p and q have equal x but are not equal points (sum is infinity). */
static int is_inverse_pair(const ec_point* p, const ec_point* q) {
  return p256_fp_eq(p->x, q->x) && !p256_fp_eq(p->y, q->y);
}

/* Same x: result is either infinity (inverse pair) or 2p (p == q). */
static void add_same_x(ec_point* r, const ec_point* p, const ec_point* q) {
  if (is_inverse_pair(p, q)) {
    r->inf = 1;
  } else {
    ec_double(r, p);
  }
}

/* Handle an infinity operand. Returns 1 if r was set, 0 if both are finite. */
static int add_infinity(ec_point* r, const ec_point* p, const ec_point* q) {
  if (p->inf) {
    ec_set(r, q);
  } else if (q->inf) {
    ec_set(r, p);
  } else {
    return 0;
  }
  return 1;
}

void ec_add(ec_point* r, const ec_point* p, const ec_point* q) {
  if (add_infinity(r, p, q)) {
    return;
  }
  if (p256_fp_eq(p->x, q->x)) {
    add_same_x(r, p, q);
  } else {
    add_distinct(r, p, q);
  }
}
