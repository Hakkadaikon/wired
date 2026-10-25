#include "crypto/pki/encoding/x509/nameconstraints_impl.h"

static int nc_min_zero(u8 tag, wired_span v);
static int fields_bounded(derseq* c);
static int subtree_bounded(wired_span sub);
static int subtrees_bounded(wired_span subtrees);
static int half_bounded(wired_span seq, u8 half);

/* An explicit minimum of 0 is the DEFAULT, i.e. no constraint. */
static int nc_min_zero(u8 tag, wired_span v) {
  return tag == NC_MINIMUM_TAG && v.n == 1 && v.p[0] == 0;
}

/* Any GeneralSubtree field after base other than minimum 0. */
static int fields_bounded(derseq* c) {
  u8         tag;
  wired_span v;
  while (derseq_next(c, &tag, &v)) {
    if (!nc_min_zero(tag, v)) {
      return 1;
    }
  }
  return 0;
}

/* GeneralSubtree ::= SEQUENCE { base, minimum [0] DEFAULT 0, maximum [1]
 * OPTIONAL }: 1 if minimum != 0 or maximum is present. */
static int subtree_bounded(wired_span sub) {
  derseq c;
  derseq_init(&c, sub);
  if (!derseq_skip(&c, 1)) {
    return 0;
  }
  return fields_bounded(&c);
}

/* Some GeneralSubtree of a GeneralSubtrees SEQUENCE is bounded. */
static int subtrees_bounded(wired_span subtrees) {
  derseq     c;
  u8         tag;
  wired_span e;
  derseq_init(&c, subtrees);
  while (derseq_next(&c, &tag, &e)) {
    if (subtree_bounded(e)) {
      return 1;
    }
  }
  return 0;
}

/* One half (permitted/excluded) carries a bounded subtree. */
static int half_bounded(wired_span seq, u8 half) {
  wired_span subtrees;
  if (!x509_nc_half(seq, half, &subtrees)) {
    return 0;
  }
  return subtrees_bounded(subtrees);
}

/* RFC 5280 4.2.1.10: either half carries a minimum/maximum. */
int x509_nc_bounded(wired_span seq) {
  return half_bounded(seq, NC_PERMITTED_TAG) ||
         half_bounded(seq, NC_EXCLUDED_TAG);
}
