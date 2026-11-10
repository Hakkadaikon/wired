#include "crypto/pki/cert/selfcert/tbs.h"

#include "common/bytes/util/bytes.h"

/* RFC 5280 4.1 / RFC 8410 4. Every field of this tbsCertificate is fixed
 * except the 32-byte Ed25519 key that ends it, so the encoding is this
 * header followed by the key. */
static const u8 selfcert_tbs_head[] = {
    0x30, 0x81, 0x87,                         /* TBSCertificate (135) */
    0xa0, 0x03, 0x02, 0x01, 0x02,             /* [0] version v3 */
    0x02, 0x01, 0x01,                         /* serialNumber 1 */
    0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, /* signature id-Ed25519 */
    /* issuer Name { CN = UTF8String "localhost" } */
    0x30, 0x14, 0x31, 0x12, 0x30, 0x10, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c,
    0x09, 'l', 'o', 'c', 'a', 'l', 'h', 'o', 's', 't',
    /* validity UTCTime 200101000000Z .. 300101000000Z */
    0x30, 0x1e, 0x17, 0x0d, '2', '0', '0', '1', '0', '1', '0', '0', '0', '0',
    '0', '0', 'Z', 0x17, 0x0d, '3', '0', '0', '1', '0', '1', '0', '0', '0', '0',
    '0', '0', 'Z',
    /* subject Name, the same as issuer (self-issued) */
    0x30, 0x14, 0x31, 0x12, 0x30, 0x10, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c,
    0x09, 'l', 'o', 'c', 'a', 'l', 'h', 'o', 's', 't',
    /* SPKI { id-Ed25519, BIT STRING 0 unused bits || key } */
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00};
#define SELFCERT_TBS_LEN (sizeof(selfcert_tbs_head) + 32)

int selfcert_tbs(const u8 pub[32], wired_obuf* out) {
  wired_mspan m   = wired_mspan_of(out->p, out->cap);
  usz         off = 0;
  if (out->cap < SELFCERT_TBS_LEN) {
    out->len = 0;
    return 0;
  }
  bytes_put(
      m, &off, wired_span_of(selfcert_tbs_head, sizeof(selfcert_tbs_head)));
  bytes_put(m, &off, wired_span_of(pub, 32));
  out->len = off;
  return 1;
}
