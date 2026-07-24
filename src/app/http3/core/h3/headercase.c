#include "app/http3/core/h3/headercase.h"

/* RFC 9114 4.3. 1 if c is an uppercase ASCII letter A-Z. */
static int upper(u8 c) { return c >= 'A' && c <= 'Z'; }

int quic_h3_header_name_ok(const u8* name, usz len) {
  for (usz i = 0; i < len; i++)
    if (upper(name[i])) return 0;
  return 1;
}

/* RFC 9114 10.3 / RFC 9110 5.5. 1 if c is CR, LF or NUL. */
static int forbidden(u8 c) { return c == 0x0d || c == 0x0a || c == 0x00; }

int quic_h3_header_bytes_ok(const u8* buf, usz len) {
  for (usz i = 0; i < len; i++)
    if (forbidden(buf[i])) return 0;
  return 1;
}
