#include "tls/ext/salpn/idna.h"

/* RFC 5891 4.4 / RFC 3492: true if every byte of host is ASCII (<0x80), i.e.
 * host is already in A-label form and needs no Punycode conversion. */
static int idna_all_ascii(wired_span host) {
  for (usz i = 0; i < host.n; i++)
    if (host.p[i] >= 0x80) return 0;
  return 1;
}

/* host is already ASCII-only (needs no Punycode conversion) and fits cap. */
static int idna_passthrough_ok(wired_span host, usz cap) {
  return idna_all_ascii(host) && host.n <= cap;
}

usz salpn_idna_to_ascii(wired_span host, u8* out, usz cap) {
  if (!idna_passthrough_ok(host, cap)) return 0;
  for (usz i = 0; i < host.n; i++) out[i] = host.p[i];
  return host.n;
}
