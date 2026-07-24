#include "crypto/pki/encoding/x509/dirstring.h"

#include "common/bytes/util/bytes.h"
#include "crypto/pki/encoding/asn1/der.h"
#include "crypto/pki/encoding/asn1/derseq.h"
#include "crypto/pki/encoding/asn1/derval.h"

/* RFC 4518 2.6.1 (ASCII scope, see dirstring.h). Only the plain space
 * (0x20) is treated as insignificant whitespace; tab/newline are not
 * FOLDed by this SDK's simplified preparation. */
static int is_space(u8 c) { return c == 0x20; }

/* 1 if any octet in s is outside the ASCII range this SDK case-folds
 * (>= 0x80): a multi-byte DirectoryString encoding (UTF-8 non-ASCII,
 * BMPString, UniversalString, TeletexString 8-bit) this SDK does not
 * decode. */
static int has_non_ascii(quic_span s) {
  for (usz i = 0; i < s.n; i++)
    if (s.p[i] & 0x80) return 1;
  return 0;
}

/* A cursor over one DirectoryString value that yields its RFC 4518
 * Insignificant-Space-Handling-normalized characters one at a time:
 * leading/trailing space runs yield nothing, an internal space run yields
 * exactly one space, everything else yields its case-folded octet.
 * `emitted` distinguishes a leading run (nothing produced yet, so this run
 * is insignificant even though non-space content follows) from an internal
 * run (something was already produced, so this run is significant). */
typedef struct {
  quic_span s;
  usz       i;
  int       emitted;
} dirstring_cursor;

static void cursor_init(dirstring_cursor* c, quic_span s) {
  c->s       = s;
  c->i       = 0;
  c->emitted = 0;
}

/* Advance past a run of one or more spaces starting at c->i (caller has
 * already confirmed c->i is a space). */
static void cursor_skip_space_run(dirstring_cursor* c) {
  while (c->i < c->s.n && is_space(c->s.p[c->i])) c->i++;
}

static int cursor_next(dirstring_cursor* c, u8* out);

/* c->i is a space: consume the run. A leading run (nothing emitted yet)
 * produces no character of its own -- instead, go on to whatever the run's
 * end actually is (more content, or the true end of the string), since a
 * single cursor_next call must always resolve to either a real character or
 * genuine exhaustion, never a silent "skipped, call me again". An internal
 * run (something already emitted, more content follows) produces one
 * normalized space; a trailing run (nothing follows) produces nothing. */
static int cursor_next_space(dirstring_cursor* c, u8* out) {
  int was_emitted = c->emitted;
  cursor_skip_space_run(c);
  if (!was_emitted) return cursor_next(c, out);
  if (c->i >= c->s.n) return 0;
  *out = 0x20;
  return 1;
}

/* Pull the next normalized character out of *c into *out. Returns 1 if a
 * character was produced, 0 at end of input. */
static int cursor_next(dirstring_cursor* c, u8* out) {
  if (c->i >= c->s.n) return 0;
  if (is_space(c->s.p[c->i])) return cursor_next_space(c, out);
  *out = quic_ascii_lower(c->s.p[c->i]);
  c->i++;
  c->emitted = 1;
  return 1;
}

/* Both cursors produce the same next normalized character (or both are
 * exhausted). */
static int step_equal(dirstring_cursor* a, dirstring_cursor* b, int* more) {
  u8  ca, cb;
  int ha = cursor_next(a, &ca);
  int hb = cursor_next(b, &cb);
  if (ha != hb) return 0;
  *more = ha;
  return !ha || ca == cb;
}

/* Byte-exact comparison (RFC 4518 preparation skipped). */
static int dirstring_bytes_eq(quic_span a, quic_span b) {
  usz diff = 0;
  if (a.n != b.n) return 0;
  for (usz i = 0; i < a.n; i++) diff |= (usz)(a.p[i] ^ b.p[i]);
  return diff == 0;
}

/* Either operand carries a byte this SDK does not case-fold (see dirstring.h
 * on why that falls back to byte-exact comparison). */
static int either_non_ascii(quic_span a, quic_span b) {
  return has_non_ascii(a) || has_non_ascii(b);
}

/* Drain both cursors in lockstep; 1 if every step matched through to EOF. */
static int cursors_equal(dirstring_cursor* a, dirstring_cursor* b) {
  int more = 1;
  while (more)
    if (!step_equal(a, b, &more)) return 0;
  return 1;
}

int quic_x509_dirstring_ci_equal(quic_span a, quic_span b) {
  dirstring_cursor ca, cb;
  if (either_non_ascii(a, b)) return dirstring_bytes_eq(a, b);
  cursor_init(&ca, a);
  cursor_init(&cb, b);
  return cursors_equal(&ca, &cb);
}

/* AttributeTypeAndValue ::= SEQUENCE { type OID, value ANY }. View the type
 * OID and the value TLV's content octets. */
static int atv_parts(quic_span atv, quic_span* oid, quic_span* val) {
  quic_derseq c;
  u8          tag;
  quic_derseq_init(&c, atv);
  if (!quic_derseq_next_tagged(&c, QUIC_DER_OID, oid)) return 0;
  return quic_derseq_next(&c, &tag, val);
}

/* View both elements' parts; 0 if either is malformed. */
static int atv_pair_parts(
    quic_span  a,
    quic_span  b,
    quic_span* oid_a,
    quic_span* val_a,
    quic_span* oid_b,
    quic_span* val_b) {
  if (!atv_parts(a, oid_a, val_a)) return 0;
  return atv_parts(b, oid_b, val_b);
}

/* Two AttributeTypeAndValue elements: same type OID, dirstring-ci-equal
 * value. */
static int atv_ci_equal(quic_span a, quic_span b) {
  quic_span oid_a, val_a, oid_b, val_b;
  if (!atv_pair_parts(a, b, &oid_a, &val_a, &oid_b, &val_b)) return 0;
  if (!quic_der_oid_equal(oid_a, oid_b)) return 0;
  return quic_x509_dirstring_ci_equal(val_a, val_b);
}

/* One step of a parallel derseq walk: advance both cursors, comparing
 * element presence and, when both present, applying elem_eq to their
 * values. *done is set once either cursor runs out. Returns 0 to signal
 * "the two sequences differ, stop and reject". */
typedef int (*dirstring_elem_eq)(quic_span, quic_span);

static int parallel_step(
    quic_derseq* ca, quic_derseq* cb, dirstring_elem_eq elem_eq, int* done) {
  u8        ta, tb;
  quic_span va, vb;
  int       ok_a = quic_derseq_next(ca, &ta, &va);
  int       ok_b = quic_derseq_next(cb, &tb, &vb);
  if (ok_a != ok_b) return 0;
  *done = !ok_a;
  return *done || elem_eq(va, vb);
}

/* Walk two SEQUENCE-OF-shaped content spans in lockstep, requiring the same
 * element count and elem_eq to hold on every pair (in encoded order). */
static int parallel_seq_equal(
    quic_span a, quic_span b, dirstring_elem_eq elem_eq) {
  quic_derseq ca, cb;
  int         done = 0;
  quic_derseq_init(&ca, a);
  quic_derseq_init(&cb, b);
  while (!done)
    if (!parallel_step(&ca, &cb, elem_eq, &done)) return 0;
  return 1;
}

/* Two RDNs (SET OF AttributeTypeAndValue): same element count, each pair
 * (in encoded order) atv-ci-equal. See dirstring.h on why encoded order is
 * required rather than unordered SET matching. */
static int rdn_ci_equal(quic_span a, quic_span b) {
  return parallel_seq_equal(a, b, atv_ci_equal);
}

/* View both Names' content octets (SEQUENCE OF RDN); 0 if either is
 * malformed. */
static int name_pair_content(
    quic_span a, quic_span b, quic_span* seq_a, quic_span* seq_b) {
  if (!quic_der_seq(a, seq_a)) return 0;
  return quic_der_seq(b, seq_b);
}

int quic_x509_dn_equal_ci(quic_span a, quic_span b) {
  quic_span seq_a, seq_b;
  if (!name_pair_content(a, b, &seq_a, &seq_b)) return 0;
  return parallel_seq_equal(seq_a, seq_b, rdn_ci_equal);
}
