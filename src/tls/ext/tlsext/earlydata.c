#include "tls/ext/tlsext/earlydata.h"

#include "common/bytes/util/be.h"

#define QUIC_TLSEXT_T_EARLY_DATA 0x002a

/* RFC 8446 4.2.10: ClientHello form is type(2) + ext_data len(2) = 0. */
int quic_tlsext_early_data_ch(u8* out, usz cap, usz* out_len) {
  if (cap < 4) return 0;
  quic_put_be16(out, QUIC_TLSEXT_T_EARLY_DATA);
  quic_put_be16(out + 2, 0);
  *out_len = 4;
  return 1;
}

/* RFC 8446 4.2.10: NewSessionTicket form carries a 4-byte max_early_data_size.
 */
int quic_tlsext_early_data_nst(u32 max_size, quic_obuf* out) {
  if (out->cap < 8) return 0;
  quic_put_be16(out->p, QUIC_TLSEXT_T_EARLY_DATA);
  quic_put_be16(out->p + 2, 4);
  quic_put_be32(out->p + 4, max_size);
  out->len = 8;
  return 1;
}

/* The 4-byte header names early_data with a 4-byte body fully readable. */
static int nst_framed(const u8* out, usz n) {
  return n >= 8 && ((u16)out[0] << 8 | out[1]) == QUIC_TLSEXT_T_EARLY_DATA &&
         ((usz)out[2] << 8 | out[3]) == 4;
}

int quic_tlsext_early_data_nst_parse(const u8* out, usz n, u32* max_size) {
  if (!nst_framed(out, n)) return 0;
  *max_size = (u32)out[4] << 24 | (u32)out[5] << 16 | (u32)out[6] << 8 | out[7];
  return 1;
}
