#include "crypto/pki/cert/tbscert/fields.h"

#include "crypto/pki/encoding/asn1/der.h"
#include "crypto/pki/encoding/asn1/derseq.h"

/* RFC 5280 4.1.2.1. version is [0] EXPLICIT. */
#define TBS_VERSION_TAG 0xa0
/* RFC 5280 4.1.2.9. extensions is [3] EXPLICIT. */
#define TBS_EXTENSIONS_TAG 0xa3

/* A (ptr, len) member pair inside quic_tbscert, addressed for the loop below.
 */
typedef struct {
  const u8 **p;
  usz       *len;
} tbs_slot;

/* The tbs SEQUENCE value (after its own header). 0 if not a SEQUENCE. */
static int tbs_seq_value(const u8 *tbs, usz tbs_len, const u8 **v, usz *vlen) {
  u8  tag;
  usz used;
  if (!quic_der_read(tbs, tbs_len, &tag, v, vlen, &used)) return 0;
  return tag == QUIC_DER_SEQUENCE;
}

/* True if the next element at the cursor carries the explicit tag want. */
static int peek_is(quic_derseq *c, u8 want) {
  return c->off < c->len && c->p[c->off] == want;
}

/* Read [0] EXPLICIT version, descending to its inner INTEGER value. */
static int tbs_take_version(quic_derseq *c, quic_tbscert *o) {
  u8        tag;
  const u8 *outer;
  usz       olen, used;
  if (!quic_derseq_next(c, &tag, &outer, &olen)) return 0;
  return quic_der_read(outer, olen, &tag, &o->version, &o->version_len, &used);
}

/* RFC 5280 4.1.2.1. Optional version: present only with the [0] tag. */
static int opt_version(quic_derseq *c, quic_tbscert *o) {
  if (peek_is(c, TBS_VERSION_TAG)) return tbs_take_version(c, o);
  return 1;
}

/* Fill one slot from the next cursor element value. */
static int take_slot(quic_derseq *c, tbs_slot s) {
  u8 tag;
  return quic_derseq_next(c, &tag, s.p, s.len);
}

/* RFC 5280 4.1.2.2-4.1.2.7. serial, signature, issuer, validity, subject, spki
 * in order; each is one mandatory element. */
static int take_body(quic_derseq *c, quic_tbscert *o) {
  tbs_slot slots[6] = {
      {&o->serial, &o->serial_len},   {&o->sig_alg, &o->sig_alg_len},
      {&o->issuer, &o->issuer_len},   {&o->validity, &o->validity_len},
      {&o->subject, &o->subject_len}, {&o->spki, &o->spki_len},
  };
  for (usz i = 0; i < 6; i++)
    if (!take_slot(c, slots[i])) return 0;
  return 1;
}

/* Read [3] EXPLICIT extensions, descending to its inner SEQUENCE value. */
static int take_extensions(quic_derseq *c, quic_tbscert *o) {
  u8        tag;
  const u8 *outer;
  usz       olen, used;
  if (!quic_derseq_next(c, &tag, &outer, &olen)) return 0;
  return quic_der_read(
      outer, olen, &tag, &o->extensions, &o->extensions_len, &used);
}

/* RFC 5280 4.1.2.9. Optional extensions: present only with the [3] tag. */
static int opt_extensions(quic_derseq *c, quic_tbscert *o) {
  if (peek_is(c, TBS_EXTENSIONS_TAG)) return take_extensions(c, o);
  return 1;
}

/* version, mandatory body, then optional extensions, in DER order. */
static int tbs_walk(quic_derseq *c, quic_tbscert *o) {
  return opt_version(c, o) && take_body(c, o) && opt_extensions(c, o);
}

int quic_tbscert_parse(const u8 *tbs, usz tbs_len, quic_tbscert *out) {
  const u8   *v;
  usz         vlen;
  quic_derseq c;
  out->version        = 0;
  out->version_len    = 0;
  out->extensions     = 0;
  out->extensions_len = 0;
  if (!tbs_seq_value(tbs, tbs_len, &v, &vlen)) return 0;
  quic_derseq_init(&c, v, vlen);
  return tbs_walk(&c, out);
}
