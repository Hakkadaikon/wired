#ifndef QUIC_FLOW_REASSEMBLE_H
#define QUIC_FLOW_REASSEMBLE_H

#include "common/platform/sys/syscall.h"

/* RFC 9000 2.2: STREAM/CRYPTO data arrives out of order at byte offsets.
 * The reassembler delivers only the contiguous prefix from offset 0;
 * data past a gap is buffered but not delivered until the gap fills. */

#define QUIC_REASM_CAP 4096

typedef struct {
    u8 buf[QUIC_REASM_CAP];
    u8 have[QUIC_REASM_CAP]; /* 1 if that byte offset has been received */
    u64 delivered;           /* length of the contiguous prefix consumed */
    u64 final_size;          /* set once FIN is known */
    int have_final;
} quic_reasm;

void quic_reasm_init(quic_reasm *r);

/* Insert len bytes at offset. Returns 1 on success, 0 if it exceeds the
 * buffer capacity or a known final size. Idempotent on overlapping data. */
int quic_reasm_insert(quic_reasm *r, u64 offset, const u8 *data, usz len);

/* Record the stream's final size (from a FIN). Returns 1 on success, 0 if it
 * conflicts with data already received past it. */
int quic_reasm_set_final(quic_reasm *r, u64 final_size);

/* Advance over the contiguous received prefix; returns the new delivered
 * watermark (== length of data ready to hand to the application). */
u64 quic_reasm_deliver(quic_reasm *r);

#endif
