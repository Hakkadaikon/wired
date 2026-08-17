#ifndef RTXDRIVE_BATCH_H
#define RTXDRIVE_BATCH_H

#include "common/platform/sys/syscall.h"
#include "transport/recovery/rtx/rtxbytes/collect.h"
#include "transport/recovery/rtx/rtxbytes/rtxstore.h"

/* RFC 9002 13.3: frames from several lost packets may be repackaged into one
 * new packet. Concatenate the retransmittable frame bytes for each lost pn
 * into out, in order, stopping when the next frame would not fit (out is one
 * packet's worth of room). Non-retransmittable frames and pns not held are
 * skipped. out->len is the bytes written. Returns 1. */
int rtxdrive_batch(const rtxbytes* store, lost_pns lost, wired_obuf* out);

#endif
