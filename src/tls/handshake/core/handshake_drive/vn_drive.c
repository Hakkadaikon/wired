#include "tls/handshake/core/handshake_drive/vn_drive.h"

#include "transport/version/version/version.h"

/* Read the i-th offered version (4 big-endian bytes) from the VN list. */
static u32 vn_at(quic_span vn, usz i) {
  const u8* p = vn.p + i * 4;
  return ((u32)p[0] << 24) | ((u32)p[1] << 16) | ((u32)p[2] << 8) | (u32)p[3];
}

/* True if want appears verbatim in the VN list. */
static int vn_lists(quic_span vn, u32 want) {
  for (usz i = 0; i < vn.n / 4; i++)
    if (vn_at(vn, i) == want) return 1;
  return 0;
}

/* True if want is offered in the VN list and is not a reserved/GREASE value. */
static int vn_offers(quic_span vn, u32 want) {
  if (quic_version_is_reserved(want)) return 0;
  return vn_lists(vn, want);
}

int quic_vn_choose(quic_span vn, quic_verlist mine, u32* chosen) {
  for (usz i = 0; i < mine.n; i++) {
    if (!vn_offers(vn, mine.list[i])) continue;
    *chosen = mine.list[i];
    return 1;
  }
  return 0;
}

int quic_vn_acceptable(int handshake_started) { return handshake_started == 0; }
