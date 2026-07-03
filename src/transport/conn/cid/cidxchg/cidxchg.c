#include "transport/conn/cid/cidxchg/cidxchg.h"

#include "common/bytes/util/bytes.h"
#include "tls/ext/tpverify/odcid.h"

/* RFC 9000 7.2: a CID stored in cidxchg fits in 20 bytes. */
static int cidxchg_fits(u8 a, u8 b) { return a <= 20 && b <= 20; }

static void cidxchg_set(u8 *dst, u8 *dst_len, quic_span src) {
  usz off = 0;
  quic_put_bytes(quic_mspan_of(dst, 20), &off, quic_span_of(src.p, (u8)src.n));
  *dst_len = (u8)src.n;
}

/* RFC 9000 7.2/7.3 */
int quic_cidxchg_init(quic_cidxchg *x, quic_span init_dcid, quic_span own_scid) {
  if (!cidxchg_fits((u8)init_dcid.n, (u8)own_scid.n)) return 0;
  cidxchg_set(x->init_dcid, &x->init_dcid_len, init_dcid);
  cidxchg_set(x->own_scid, &x->own_scid_len, own_scid);
  cidxchg_set(x->dcid, &x->dcid_len, init_dcid);
  return 1;
}

/* RFC 9000 7.2 */
int quic_cidxchg_on_server_scid(
    quic_cidxchg *x, const u8 *server_scid, u8 scid_len) {
  if (scid_len > 20) return 0;
  cidxchg_set(x->dcid, &x->dcid_len, quic_span_of(server_scid, scid_len));
  return 1;
}

/* RFC 9000 7.3 */
int quic_cidxchg_remember_odcid(
    quic_cidxchg *x, const u8 *initial_dcid, u8 len) {
  if (len > 20) return 0;
  cidxchg_set(x->init_dcid, &x->init_dcid_len, quic_span_of(initial_dcid, len));
  return 1;
}

/* RFC 9000 7.3 */
int quic_cidxchg_verify_odcid(
    const quic_cidxchg *x, const u8 *odcid_tp, u8 len) {
  return quic_tpverify_odcid(
      quic_span_of(x->init_dcid, x->init_dcid_len),
      quic_span_of(odcid_tp, len));
}
