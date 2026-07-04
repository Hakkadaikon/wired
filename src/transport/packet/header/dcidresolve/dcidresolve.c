#include "transport/packet/header/dcidresolve/dcidresolve.h"

static int dcidresolve_is_long(quic_mspan dg) {
  return dg.n >= 1 && (dg.p[0] & 0x80) != 0;
}

static int dcidresolve_short_len(quic_mspan dg, u8 short_hdr_len) {
  return dg.n >= 1 ? short_hdr_len : -1;
}

static int dcidresolve_long_len(quic_mspan dg) {
  return dg.n >= 6 ? dg.p[5] : -1;
}

int quic_dcidresolve_len(quic_mspan dg, u8 short_hdr_len) {
  if (dcidresolve_is_long(dg)) return dcidresolve_long_len(dg);
  return dcidresolve_short_len(dg, short_hdr_len);
}

static usz dcidresolve_offset(quic_mspan dg) {
  return dcidresolve_is_long(dg) ? 6 : 1;
}

quic_span quic_dcidresolve_dcid(quic_mspan dg, int dcid_len) {
  usz off = dcidresolve_offset(dg);
  if (dcid_len < 0 || off + (usz)dcid_len > dg.n) return quic_span_of(0, 0);
  return quic_span_of(dg.p + off, (usz)dcid_len);
}
