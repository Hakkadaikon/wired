#include "test.h"

/* RFC 9000 5.1/17.2/17.3: extract a datagram's DCID without a full header
 * parse, for the fast slot-routing path a multi-connection server needs. */
void test_dcidresolve(void) {
  /* long header: byte0 high bit set, dcid_len at byte 5 */
  u8 lh[] = {0x80, 0, 0, 0, 0, 4, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE};
  /* short header: byte0 high bit clear, DCID starts at byte 1 */
  u8 sh[] = {0x40, 0x11, 0x22, 0x33};

  CHECK(quic_dcidresolve_len(quic_mspan_of(lh, sizeof lh), 3) == 4);
  CHECK(quic_dcidresolve_len(quic_mspan_of(sh, sizeof sh), 3) == 3);
  /* long header truncated before the length byte (need 6 bytes) */
  u8 lh_short[] = {0x80, 0, 0, 0, 0};
  CHECK(
      quic_dcidresolve_len(quic_mspan_of(lh_short, sizeof lh_short), 3) == -1);
  /* short header with nothing at all */
  CHECK(quic_dcidresolve_len(quic_mspan_of(0, 0), 3) == -1);

  /* dcid's offset within dg: 6 for long header, 1 for short (implicit in the
   * returned span's first byte below) */
  quic_span dcid = quic_dcidresolve_dcid(quic_mspan_of(lh, sizeof lh), 4);
  CHECK(dcid.n == 4);
  CHECK(dcid.p[0] == 0xAA && dcid.p[3] == 0xDD);

  quic_span dcid_sh = quic_dcidresolve_dcid(quic_mspan_of(sh, sizeof sh), 3);
  CHECK(dcid_sh.n == 3);
  CHECK(dcid_sh.p[0] == 0x11 && dcid_sh.p[2] == 0x33);

  /* claimed dcid_len does not fit in the remaining bytes: empty span */
  quic_span oob = quic_dcidresolve_dcid(quic_mspan_of(lh, sizeof lh), 10);
  CHECK(oob.n == 0);

  /* negative dcid_len (upstream already rejected it): empty span */
  quic_span neg = quic_dcidresolve_dcid(quic_mspan_of(lh, sizeof lh), -1);
  CHECK(neg.n == 0);
}
