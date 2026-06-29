#include "cidxchg/cidxchg.h"
#include "tpverify/odcid.h"
#include "util/bytes.h"

/* RFC 9000 7.2: a CID stored in cidxchg fits in 20 bytes. */
static int cidxchg_fits(u8 a, u8 b)
{
    return a <= 20 && b <= 20;
}

static void cidxchg_set(u8 *dst, u8 *dst_len, const u8 *src, u8 len)
{
    usz off = 0;
    quic_put_bytes(dst, 20, &off, src, len);
    *dst_len = len;
}

/* RFC 9000 7.2/7.3 */
int quic_cidxchg_init(quic_cidxchg *x, const u8 *init_dcid, u8 dcid_len,
                      const u8 *own_scid, u8 scid_len)
{
    if (!cidxchg_fits(dcid_len, scid_len)) return 0;
    cidxchg_set(x->init_dcid, &x->init_dcid_len, init_dcid, dcid_len);
    cidxchg_set(x->own_scid, &x->own_scid_len, own_scid, scid_len);
    cidxchg_set(x->dcid, &x->dcid_len, init_dcid, dcid_len);
    return 1;
}

/* RFC 9000 7.2 */
int quic_cidxchg_on_server_scid(quic_cidxchg *x, const u8 *server_scid,
                                u8 scid_len)
{
    if (scid_len > 20) return 0;
    cidxchg_set(x->dcid, &x->dcid_len, server_scid, scid_len);
    return 1;
}

/* RFC 9000 7.3 */
int quic_cidxchg_remember_odcid(quic_cidxchg *x, const u8 *initial_dcid,
                                u8 len)
{
    if (len > 20) return 0;
    cidxchg_set(x->init_dcid, &x->init_dcid_len, initial_dcid, len);
    return 1;
}

/* RFC 9000 7.3 */
int quic_cidxchg_verify_odcid(const quic_cidxchg *x, const u8 *odcid_tp,
                              u8 len)
{
    return quic_tpverify_odcid(x->init_dcid, x->init_dcid_len, odcid_tp, len);
}
