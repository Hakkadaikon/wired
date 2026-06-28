#include "rtxbytes/rtxstore.h"

#include "util/bytes.h"

void quic_rtxbytes_init(quic_rtxbytes *st)
{
    st->next = 0;
    for (usz i = 0; i < QUIC_RTXBYTES_SLOTS; i++) st->s[i].used = 0;
}

int quic_rtxbytes_store(quic_rtxbytes *st, u64 pn, const u8 *frame_bytes,
                        usz len)
{
    quic_rtxbytes_slot *slot;
    usz off = 0;

    if (len > QUIC_RTXBYTES_FRAME) return 0;
    slot = &st->s[st->next];
    if (!quic_put_bytes(slot->data, QUIC_RTXBYTES_FRAME, &off, frame_bytes, len))
        return 0;
    slot->pn = pn;
    slot->len = len;
    slot->used = 1;
    st->next = (st->next + 1) % QUIC_RTXBYTES_SLOTS;
    return 1;
}

/* RFC 9002 13.3: a held slot matches when in use and its pn equals pn. */
static int slot_holds(const quic_rtxbytes_slot *slot, u64 pn)
{
    return slot->used && slot->pn == pn;
}

int quic_rtxbytes_get(const quic_rtxbytes *st, u64 pn, const u8 **bytes,
                      usz *len)
{
    for (usz i = 0; i < QUIC_RTXBYTES_SLOTS; i++) {
        if (!slot_holds(&st->s[i], pn)) continue;
        *bytes = st->s[i].data;
        *len = st->s[i].len;
        return 1;
    }
    return 0;
}
