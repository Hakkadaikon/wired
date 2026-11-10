#include "crypto/pki/cert/certreq/certreq.h"

#include "common/bytes/util/be.h"
#include "tls/handshake/core/tls/handshake.h"

#define HS_CERTIFICATE_REQUEST 0x0d
#define EXT_SIGNATURE_ALGORITHMS 0x000d

/* RFC 8446 4.3.2: write the signature_algorithms extension (type, ext_data
 * length, scheme list length, schemes) at out. Returns bytes written. */
static usz put_sig_algs(u8* out, wired_span sa) {
  be_put_be16(out, EXT_SIGNATURE_ALGORITHMS);
  be_put_be16(out + 2, (u16)(sa.n + 2));
  be_put_be16(out + 4, (u16)sa.n);
  for (usz i = 0; i < sa.n; i++) {
    out[6 + i] = sa.p[i];
  }
  return 6 + sa.n;
}

int certreq_build(wired_span sig_algs, wired_obuf* out) {
  usz off = hs_begin(out->p, out->cap, HS_CERTIFICATE_REQUEST);
  usz ext = sig_algs.n + 6;
  if (off == 0 || off + 3 + ext > out->cap) {
    return 0;
  }
  out->p[off] = 0;                         /* empty context */
  be_put_be16(out->p + off + 1, (u16)ext); /* extensions length */
  put_sig_algs(out->p + off + 3, sig_algs);
  out->len = off + 3 + ext;
  hs_finish(out->p, out->len);
  return 1;
}
