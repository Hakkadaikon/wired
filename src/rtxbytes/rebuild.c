#include "rtxbytes/rebuild.h"

#include "transport/packet/frame/frame/frame.h"
#include "common/bytes/util/bytes.h"
#include "common/bytes/varint/varint.h"

/* RFC 9000 19.3: ACK frame type is 0x02 or 0x03. */
static int is_ack_or_padding(u64 type)
{
    return type == QUIC_FRAME_PADDING || type == 0x02 || type == 0x03;
}

int quic_rtxbytes_retransmittable(const u8 *buf, usz len)
{
    u64 type;
    if (quic_varint_decode(buf, len, &type) == 0) return -1;
    return is_ack_or_padding(type) ? 0 : 1;
}

/* Copy the retransmittable frame bytes out. Returns 1 on success. */
static int rebuild_copy(const u8 *lost_frame, usz len, u8 *out, usz cap,
                        usz *out_len)
{
    usz off = 0;
    if (!quic_put_bytes(out, cap, &off, lost_frame, len)) return 0;
    *out_len = len;
    return 1;
}

int quic_rtxbytes_rebuild(const u8 *lost_frame, usz len, u8 *out, usz cap,
                          usz *out_len)
{
    int rtx = quic_rtxbytes_retransmittable(lost_frame, len);

    if (rtx < 0) return 0;
    if (rtx == 0) return (*out_len = 0, 1);
    return rebuild_copy(lost_frame, len, out, cap, out_len);
}
