#include "crypto/pki/cert/tbscert/version_serial.h"

#include "crypto/pki/encoding/asn1/derval.h"

/* RFC 5280 4.1.2.2. serialNumber MUST be at most 20 octets. */
#define TBS_SERIAL_MAX 20

int quic_tbscert_version(const quic_tbscert *t, u64 *out) {
  if (t->version_len == 0) {
    *out = 0;
    return 1;
  }
  return quic_der_uint(t->version, t->version_len, out);
}

/* True if the serial view is present and within the 20-octet ceiling. */
static int serial_ok(const quic_tbscert *t) {
  return t->serial_len > 0 && t->serial_len <= TBS_SERIAL_MAX;
}

int quic_tbscert_serial(const quic_tbscert *t, const u8 **serial, usz *len) {
  if (!serial_ok(t)) return 0;
  *serial = t->serial;
  *len    = t->serial_len;
  return 1;
}
