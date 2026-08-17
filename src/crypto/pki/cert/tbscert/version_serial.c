#include "crypto/pki/cert/tbscert/version_serial.h"

#include "crypto/pki/encoding/asn1/derval.h"

/* RFC 5280 4.1.2.2. serialNumber MUST be at most 20 octets. */
#define TBS_SERIAL_MAX 20

int tbscert_version(const tbscert* t, u64* out) {
  if (t->version.n == 0) {
    *out = 0;
    return 1;
  }
  return der_uint(t->version.p, t->version.n, out);
}

/* True if the serial view is present and within the 20-octet ceiling. */
static int serial_ok(const tbscert* t) {
  return t->serial.n > 0 && t->serial.n <= TBS_SERIAL_MAX;
}

int tbscert_serial(const tbscert* t, wired_span* serial) {
  if (!serial_ok(t)) return 0;
  *serial = t->serial;
  return 1;
}
