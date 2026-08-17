#ifndef QUIC_P256CERT_ENC_H
#define QUIC_P256CERT_ENC_H

#include "common/bytes/span/span.h"
#include "common/bytes/util/bytes.h"
#include "crypto/pki/cert/selfcert/derenc.h"

/** X.690 append cursor shared by the P-256 cert encoders. Inline so spki.c and
 * tbs.c share one definition under the unity build (no duplicate static). */
typedef struct {
  u8* buf;
  usz cap;
  usz off;
  int ok;
} p256cert_enc;

/* Append one TLV at the cursor, advancing off. Latches ok=0 on overflow. */
static inline void p256cert_put(p256cert_enc* e, u8 tag, wired_span val) {
  wired_obuf o = obuf_of(e->buf + e->off, e->cap - e->off);
  if (e->ok && selfcert_der_tlv(tag, val, &o))
    e->off += o.len;
  else
    e->ok = 0;
}

/* Append pre-encoded TLV bytes verbatim onto the cursor. */
static inline void p256cert_put_pre(p256cert_enc* e, wired_span tlv) {
  if (e->ok &&
      bytes_put(
          wired_mspan_of(e->buf, e->cap), &e->off, wired_span_of(tlv.p, tlv.n)))
    return;
  e->ok = 0;
}

/* A cursor pre-loaded with n value bytes in buf, ok only when n is non-zero. */
static inline p256cert_enc p256cert_loaded(u8* buf, usz n) {
  p256cert_enc e = {buf, n, n, n != 0};
  return e;
}

/* Wrap the cursor's bytes in one TLV of tag into out. 0 length on failure. */
static inline usz p256cert_wrap(p256cert_enc* e, u8 tag, wired_obuf* out) {
  if (e->ok && selfcert_der_tlv(tag, wired_span_of(e->buf, e->off), out))
    return out->len;
  return 0;
}

#endif
