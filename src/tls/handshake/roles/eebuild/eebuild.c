#include "tls/handshake/roles/eebuild/eebuild.h"

#include "common/bytes/util/be.h"
#include "tls/ext/salpn/negotiate.h"
#include "tls/ext/tlsext/earlydata.h"
#include "tls/handshake/core/tls/ext_algs.h"
#include "tls/handshake/core/tls/handshake.h"
#include "tls/handshake/core/tls/sni.h"
#include "tls/handshake/core/tls/tpext.h"

/* RFC 8446 4.2.10: the empty early_data extension. */
static usz eebuild_early_data(u8* p) {
  usz n;
  tlsext_early_data_ch(p, 4, &n);
  return n;
}

/* RFC 6066 3: the server_name extension with empty extension_data. */
static usz eebuild_server_name(u8* p) {
  be_put_be16(p, SNI_TYPE);
  be_put_be16(p + 2, 0);
  return 4;
}

/* RFC 8446 4.2.7: supported_groups listing every group this server
 * supports, most preferred first (x25519, then secp256r1). */
static usz eebuild_groups(u8* p) {
  be_put_be16(p, EXT_SUPPORTED_GROUPS);
  be_put_be16(p + 2, 6);
  be_put_be16(p + 4, 4);
  be_put_be16(p + 6, GROUP_X25519);
  be_put_be16(p + 8, GROUP_SECP256R1);
  return 10;
}

/* The optional extensions, in wire order: flag, encoded size, writer. */
static const struct {
  unsigned flag;
  usz      len;
  usz (*put)(u8* p);
} EEBUILD_OPT[] = {
    {EEBUILD_EARLY_DATA, 4, eebuild_early_data},
    {EEBUILD_SERVER_NAME, 4, eebuild_server_name},
    {EEBUILD_GROUPS, 10, eebuild_groups},
};

#define EEBUILD_OPT_N (sizeof EEBUILD_OPT / sizeof *EEBUILD_OPT)

/* Bytes the flagged optional extensions take. */
static usz eebuild_opt_len(unsigned flags) {
  usz n = 0;
  for (usz i = 0; i < EEBUILD_OPT_N; i++) {
    n += (flags & EEBUILD_OPT[i].flag) ? EEBUILD_OPT[i].len : 0;
  }
  return n;
}

/* Write the flagged optional extensions at p (room already checked). */
static usz eebuild_opt(u8* p, unsigned flags) {
  usz n = 0;
  for (usz i = 0; i < EEBUILD_OPT_N; i++) {
    n += (flags & EEBUILD_OPT[i].flag) ? EEBUILD_OPT[i].put(p + n) : 0;
  }
  return n;
}

/* Body = extensions<2> wrapping the ALPN extension (6-byte header +
 * name_len(1) + the alpn_len-byte name), the quic_transport_parameters
 * extension (4-byte header + tp_len) and the flagged optional extensions,
 * after the 4-byte message header. */
static int eebuild_fits(usz alpn_len, usz tp_len, unsigned flags, usz cap) {
  return tp_len <= 0xFFFF &&
         4 + 2 + 7 + alpn_len + 4 + tp_len + eebuild_opt_len(flags) <= cap;
}

/* quic_transport_parameters then the optional extensions, written at p.
 * Returns bytes. */
static usz eebuild_tail(u8* p, usz cap, wired_span tp, unsigned flags) {
  wired_obuf eob = obuf_of(p, cap);
  usz        ext = tpext_encode(&eob, tp);
  return ext + eebuild_opt(p + ext, flags);
}

int eebuild_encrypted_extensions(
    wired_span  alpn,
    wired_span  transport_params,
    unsigned    flags,
    wired_obuf* out) {
  usz        off, at, n;
  wired_obuf eob;
  if (!eebuild_fits(alpn.n, transport_params.n, flags, out->cap)) {
    return 0;
  }
  off = hs_begin(out->p, out->cap, HS_ENCRYPTED_EXT);
  eob = obuf_of(out->p + off + 2, out->cap - off - 2);
  if (!salpn_build_response_tok(alpn, &eob)) {
    return 0; /* nothing negotiated or too small -- nothing built */
  }
  at = off + 2 + eob.len;
  n  = eob.len +
       eebuild_tail(out->p + at, out->cap - at, transport_params, flags);
  be_put_be16(out->p + off, (u16)n); /* extensions block length */
  out->len = off + 2 + n;
  hs_finish(out->p, out->len);
  return 1;
}
