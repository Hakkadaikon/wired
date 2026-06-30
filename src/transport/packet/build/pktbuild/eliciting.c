#include "transport/packet/build/pktbuild/eliciting.h"
#include "transport/packet/frame/frame/frame.h"

/* RFC 9000 13.2.1: ACK (0x02/0x03), PADDING (0x00), CONNECTION_CLOSE
 * (0x1c/0x1d) are the only non-ack-eliciting frames. */
static const u8 eliciting_non_kinds[] = {
    QUIC_FRAME_PADDING, 0x02, 0x03,
    QUIC_FRAME_CONN_CLOSE_TPT, QUIC_FRAME_CONN_CLOSE_APP,
};

static int is_non_eliciting(u8 t)
{
    for (usz i = 0; i < sizeof(eliciting_non_kinds); i++) {
        if (eliciting_non_kinds[i] == t) return 1;
    }
    return 0;
}

int quic_pktbuild_is_eliciting(const u8 *frame_types, usz n)
{
    for (usz i = 0; i < n; i++) {
        if (!is_non_eliciting(frame_types[i])) return 1;
    }
    return 0;
}
