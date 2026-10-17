#include "crypto/pki/encoding/x509/dirstring_impl.h"

static int atv_parts(wired_span atv, wired_span* oid, wired_span* val);
static int atv_pair_parts(
    wired_span  a,
    wired_span  b,
    wired_span* oid_a,
    wired_span* val_a,
    wired_span* oid_b,
    wired_span* val_b);
static int atv_ci_equal(wired_span a, wired_span b);
static int parallel_step(
    derseq* ca, derseq* cb, dirstring_elem_eq elem_eq, int* done);
static int parallel_seq_equal(
    wired_span a, wired_span b, dirstring_elem_eq elem_eq);
static int prefix_pair(derseq* ca, derseq* cb, dirstring_elem_eq elem_eq);
static int prefix_step(
    derseq* ca, derseq* cb, dirstring_elem_eq elem_eq, int* done);
static int prefix_seq_equal(
    wired_span a, wired_span b, dirstring_elem_eq elem_eq);
static int rdn_ci_equal(wired_span a, wired_span b);
static int name_pair_content(
    wired_span a, wired_span b, wired_span* seq_a, wired_span* seq_b);

/* AttributeTypeAndValue ::= SEQUENCE { type OID, value ANY }. View the type
 * OID and the value TLV's content octets. */
static int atv_parts(wired_span atv, wired_span* oid, wired_span* val) {
  derseq c;
  u8     tag;
  derseq_init(&c, atv);
  if (!derseq_next_tagged(&c, DER_OID, oid)) {
    return 0;
  }
  return derseq_next(&c, &tag, val);
}

/* View both elements' parts; 0 if either is malformed. */
static int atv_pair_parts(
    wired_span  a,
    wired_span  b,
    wired_span* oid_a,
    wired_span* val_a,
    wired_span* oid_b,
    wired_span* val_b) {
  if (!atv_parts(a, oid_a, val_a)) {
    return 0;
  }
  return atv_parts(b, oid_b, val_b);
}

/* Two AttributeTypeAndValue elements: same type OID, dirstring-ci-equal
 * value. */
static int atv_ci_equal(wired_span a, wired_span b) {
  wired_span oid_a, val_a, oid_b, val_b;
  if (!atv_pair_parts(a, b, &oid_a, &val_a, &oid_b, &val_b)) {
    return 0;
  }
  if (!der_oid_equal(oid_a, oid_b)) {
    return 0;
  }
  return x509_dirstring_ci_equal(val_a, val_b);
}

static int parallel_step(
    derseq* ca, derseq* cb, dirstring_elem_eq elem_eq, int* done) {
  u8         ta, tb;
  wired_span va, vb;
  int        ok_a = derseq_next(ca, &ta, &va);
  int        ok_b = derseq_next(cb, &tb, &vb);
  if (ok_a != ok_b) {
    return 0;
  }
  *done = !ok_a;
  return *done || elem_eq(va, vb);
}

/* Walk two SEQUENCE-OF-shaped content spans in lockstep, requiring the same
 * element count and elem_eq to hold on every pair (in encoded order). */
static int parallel_seq_equal(
    wired_span a, wired_span b, dirstring_elem_eq elem_eq) {
  derseq ca, cb;
  int    done = 0;
  derseq_init(&ca, a);
  derseq_init(&cb, b);
  while (!done) {
    if (!parallel_step(&ca, &cb, elem_eq, &done)) {
      return 0;
    }
  }
  return 1;
}

/* One pair of a prefix walk: both cursors must yield an element and the pair
 * must satisfy elem_eq; a short b (or a malformed element) rejects. */
static int prefix_pair(derseq* ca, derseq* cb, dirstring_elem_eq elem_eq) {
  u8         ta, tb;
  wired_span va, vb;
  if (!derseq_next(ca, &ta, &va)) {
    return 0;
  }
  if (!derseq_next(cb, &tb, &vb)) {
    return 0;
  }
  return elem_eq(va, vb);
}

/* One step of a prefix walk: a exhausted means the prefix is satisfied
 * (*done); otherwise compare the next pair. */
static int prefix_step(
    derseq* ca, derseq* cb, dirstring_elem_eq elem_eq, int* done) {
  if (ca->off >= ca->len) {
    *done = 1;
    return 1;
  }
  return prefix_pair(ca, cb, elem_eq);
}

/* Walk two SEQUENCE-OF-shaped content spans in lockstep until a runs out,
 * requiring elem_eq on every pair up to there (b may be longer). */
static int prefix_seq_equal(
    wired_span a, wired_span b, dirstring_elem_eq elem_eq) {
  derseq ca, cb;
  int    done = 0;
  derseq_init(&ca, a);
  derseq_init(&cb, b);
  while (!done) {
    if (!prefix_step(&ca, &cb, elem_eq, &done)) {
      return 0;
    }
  }
  return 1;
}

/* Two RDNs (SET OF AttributeTypeAndValue): same element count, each pair
 * (in encoded order) atv-ci-equal. See dirstring.h on why encoded order is
 * required rather than unordered SET matching. */
static int rdn_ci_equal(wired_span a, wired_span b) {
  return parallel_seq_equal(a, b, atv_ci_equal);
}

/* View both Names' content octets (SEQUENCE OF RDN); 0 if either is
 * malformed. */
static int name_pair_content(
    wired_span a, wired_span b, wired_span* seq_a, wired_span* seq_b) {
  if (!der_seq(a, seq_a)) {
    return 0;
  }
  return der_seq(b, seq_b);
}

int x509_dn_equal_ci(wired_span a, wired_span b) {
  wired_span seq_a, seq_b;
  if (!name_pair_content(a, b, &seq_a, &seq_b)) {
    return 0;
  }
  return parallel_seq_equal(seq_a, seq_b, rdn_ci_equal);
}

int x509_dn_prefix_ci(wired_span base, wired_span name) {
  wired_span seq_b, seq_n;
  if (!name_pair_content(base, name, &seq_b, &seq_n)) {
    return 0;
  }
  return prefix_seq_equal(seq_b, seq_n, rdn_ci_equal);
}
