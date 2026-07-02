#include "crypto/pki/cert/tbscert/fields.h"

#include "crypto/pki/encoding/asn1/der.h"
#include "crypto/pki/encoding/asn1/derseq.h"

/* RFC 5280 4.1.2.1. version is [0] EXPLICIT. */
#define TBS_VERSION_TAG 0xa0
/* RFC 5280 4.1.2.9. extensions is [3] EXPLICIT. */
#define TBS_EXTENSIONS_TAG 0xa3

/* True if the next element at the cursor carries the explicit tag want. */
static int peek_is(quic_derseq *c, u8 want) {
  return c->off < c->len && c->p[c->off] == want;
}

/* Read an EXPLICIT wrapper, descending to its inner element value. */
static int take_wrapped(quic_derseq *c, quic_span *inner) {
  u8           tag;
  quic_span    outer;
  quic_der_tlv t;
  if (!quic_derseq_next(c, &tag, &outer)) return 0;
  if (!quic_der_read(outer, &t)) return 0;
  *inner = t.val;
  return 1;
}

/* RFC 5280 4.1.2.1. Optional version: present only with the [0] tag. */
static int opt_version(quic_derseq *c, quic_tbscert *o) {
  if (peek_is(c, TBS_VERSION_TAG)) return take_wrapped(c, &o->version);
  return 1;
}

/* Fill one field from the next cursor element value. */
static int take_slot(quic_derseq *c, quic_span *s) {
  u8 tag;
  return quic_derseq_next(c, &tag, s);
}

/* RFC 5280 4.1.2.2-4.1.2.7. serial, signature, issuer, validity, subject, spki
 * in order; each is one mandatory element. */
static int take_body(quic_derseq *c, quic_tbscert *o) {
  quic_span *slots[6] = {&o->serial,   &o->sig_alg, &o->issuer,
                         &o->validity, &o->subject, &o->spki};
  for (usz i = 0; i < 6; i++)
    if (!take_slot(c, slots[i])) return 0;
  return 1;
}

/* RFC 5280 4.1.2.9. Optional extensions: present only with the [3] tag. */
static int opt_extensions(quic_derseq *c, quic_tbscert *o) {
  if (peek_is(c, TBS_EXTENSIONS_TAG)) return take_wrapped(c, &o->extensions);
  return 1;
}

/* version, mandatory body, then optional extensions, in DER order. */
static int tbs_walk(quic_derseq *c, quic_tbscert *o) {
  return opt_version(c, o) && take_body(c, o) && opt_extensions(c, o);
}

int quic_tbscert_parse(quic_span tbs, quic_tbscert *out) {
  quic_span   v;
  quic_derseq c;
  out->version    = quic_span_of(0, 0);
  out->extensions = quic_span_of(0, 0);
  if (!quic_der_seq(tbs, &v)) return 0;
  quic_derseq_init(&c, v);
  return tbs_walk(&c, out);
}
