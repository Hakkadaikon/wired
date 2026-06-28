#include "rtxbytes/collect.h"

#include "rtxbytes/rebuild.h"

/* RFC 9002 13.3: rebuild one held pn's frame into out+*off, advancing *off by
 * the retransmittable bytes. Returns 1 on success (including a skipped pn or a
 * non-retransmittable frame), 0 if out has no room. */
static int collect_one(const quic_rtxbytes *st, u64 pn, u8 *out, usz cap,
                       usz *off)
{
    const u8 *bytes;
    usz len, wrote;

    if (!quic_rtxbytes_get(st, pn, &bytes, &len)) return 1;
    if (!quic_rtxbytes_rebuild(bytes, len, out + *off, cap - *off, &wrote))
        return 0;
    *off += wrote;
    return 1;
}

int quic_rtxbytes_collect(const quic_rtxbytes *st, const u64 *lost_pns,
                          usz n, u8 *out, usz cap, usz *out_len)
{
    usz off = 0;
    for (usz i = 0; i < n; i++) {
        if (!collect_one(st, lost_pns[i], out, cap, &off)) return 0;
    }
    *out_len = off;
    return 1;
}
