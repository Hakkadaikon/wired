#include "tls/handshake/core/tls/handshake.h"

usz hs_begin(u8* out, usz cap, u8 msg_type) {
  if (cap < 4) {
    return 0;
  }
  out[0] = msg_type;
  out[1] = out[2] = out[3] = 0; /* length patched later */
  return 4;
}

void hs_finish(u8* out, usz total) {
  usz body = total - 4;
  out[1]   = (u8)(body >> 16);
  out[2]   = (u8)(body >> 8);
  out[3]   = (u8)body;
}

usz hs_parse(wired_span buf, u8* type, usz* body_len) {
  usz len;
  if (buf.n < 4) {
    return 0;
  }
  len = ((usz)buf.p[1] << 16) | ((usz)buf.p[2] << 8) | buf.p[3];
  if (4 + len > buf.n) {
    return 0;
  }
  *type     = buf.p[0];
  *body_len = len;
  return 4;
}
