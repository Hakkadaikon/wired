#include "tls/ext/tlsext/pskmodes.h"

#include "common/bytes/util/be.h"

#define QUIC_TLSEXT_T_PSK_MODES 0x002d

/* RFC 8446 4.2.9: type(2) + ext_data len(2) + list len(1) + 1 mode = 6. */
int quic_tlsext_psk_modes(u8 *out, usz cap, usz *out_len) {
  if (cap < 6) return 0;
  quic_put_be16(out, QUIC_TLSEXT_T_PSK_MODES);
  quic_put_be16(out + 2, 2);
  out[4]   = 1;
  out[5]   = QUIC_TLSEXT_PSK_DHE_KE;
  *out_len = 6;
  return 1;
}

/* The 4-byte header names psk_key_exchange_modes and the body fits in n. */
static int modes_framed(const u8 *out, usz n) {
  usz dlen = (usz)out[2] << 8 | out[3];
  return ((u16)out[0] << 8 | out[1]) == QUIC_TLSEXT_T_PSK_MODES &&
         4 + dlen <= n && dlen == (usz)out[4] + 1;
}

/* The ke_modes list holds psk_dhe_ke at some index. */
static int modes_has_dhe(const u8 *out, usz cnt) {
  for (usz i = 0; i < cnt; i++)
    if (out[5 + i] == QUIC_TLSEXT_PSK_DHE_KE) return 1;
  return 0;
}

int quic_tlsext_psk_modes_parse(const u8 *out, usz n) {
  if (n < 6 || !modes_framed(out, n)) return 0;
  return modes_has_dhe(out, out[4]);
}
