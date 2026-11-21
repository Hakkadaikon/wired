#ifndef APP_HTTP3_SERVER_SRVXDP_SRVXDP_IMPL_H
#define APP_HTTP3_SERVER_SRVXDP_SRVXDP_IMPL_H

/* Internal to the srvxdp*.c pieces of this directory: shared types, macros
 * and the functions and tables more than one piece uses. Not public API. */

#include "app/http3/server/srvfwd/srvfwd.h"
#include "app/http3/server/srvxdp/srvxdp.h"
#include "common/bytes/util/be.h"
#include "common/bytes/util/bytes.h"
#include "common/platform/debug/debug.h"
#include "transport/io/xdp/xdpframe/xdpframe.h"

#define SRVXDP_TXPOOL_FRAMES (XSKSETUP_UMEM_FRAMES - XSKSETUP_RX_POOL_FRAMES)
#define SRVXDP_TXPOOL_BASE ((u64)XSKSETUP_RX_POOL_FRAMES * XSKSETUP_FRAME_SIZE)

i64 srvxdp_txpool_get(wired_srvxdp* x);
int srvxdp_rx_deliver(wired_srvxdp* x, const xdpframe_rx* rx, mmsg_buf* out);
/* RFC 9000 9 forwarding (srvxdp_fwd.c): 1 when rx belongs to another
 * worker and was queued for it (or dropped on a full ring), 0 to serve it
 * here; srvxdp_fwd_drain delivers up to max datagrams forwarded to x. */
int srvxdp_fwd_handoff(wired_srvxdp* x, const xdpframe_rx* rx);
u32 srvxdp_fwd_drain(wired_srvxdp* x, mmsg_buf* bufs, u32 max);

#endif
