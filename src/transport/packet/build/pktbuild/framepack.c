#include "transport/packet/build/pktbuild/framepack.h"
#include "common/bytes/util/bytes.h"

/* RFC 9000 12.4: a packet payload is a sequence of complete frames. */
int quic_pktbuild_framepack(u8 *payload, usz cap, const u8 *const *frames,
                            const usz *frame_lens, usz n_frames, usz *out_len)
{
    usz off = 0;
    for (usz i = 0; i < n_frames; i++) {
        if (!quic_put_bytes(payload, cap, &off, frames[i], frame_lens[i])) return 0;
    }
    *out_len = off;
    return 1;
}
