#include "datagram/dgsize.h"
#include "varint/varint.h"

/* RFC 9221 5. Largest payload whose own length varint still fits in room.
 * The length varint widens with the payload, so each varint width caps a
 * different payload; take the largest payload across all four widths. */
static const u64 dg_varint_max[4] = { 0x3F, 0x3FFF, 0x3FFFFFFF,
                                      0x3FFFFFFFFFFFFFFFULL };

/* Largest payload that encodes in the varint width capping at cap, fitting
 * room = length-varint + payload. 0 if none fits. RFC 9221 5. */
static u64 dg_payload_in_width(u64 room, u64 cap)
{
    u64 vlen = quic_varint_len(cap);
    if (room <= vlen) return 0;
    return (room - vlen < cap) ? room - vlen : cap;
}

/* Best payload over all four varint widths for the given room. RFC 9221 5. */
static u64 dg_best_payload(u64 room)
{
    u64 best = 0, i, p;
    for (i = 0; i < 4; i++) {
        p = dg_payload_in_width(room, dg_varint_max[i]);
        best = (p > best) ? p : best;
    }
    return best;
}

u64 quic_datagram_max_payload(u64 max_frame_size, int with_len)
{
    u64 room;
    if (max_frame_size < 2) return 0; /* need at least type + 1 byte */
    room = max_frame_size - 1;        /* RFC 9221 5: minus the type byte */
    return with_len ? dg_best_payload(room) : room;
}
