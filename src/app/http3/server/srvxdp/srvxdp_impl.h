#ifndef APP_HTTP3_SERVER_SRVXDP_SRVXDP_IMPL_H
#define APP_HTTP3_SERVER_SRVXDP_SRVXDP_IMPL_H

/* Internal to the srvxdp*.c pieces of this directory: shared types, macros
 * and the functions and tables more than one piece uses. Not public API. */

#include "app/http3/server/srvxdp/srvxdp.h"
#include "common/bytes/util/be.h"
#include "common/bytes/util/bytes.h"
#include "common/platform/debug/debug.h"
#include "transport/io/xdp/xdpframe/xdpframe.h"

#define SRVXDP_TXPOOL_FRAMES (XSKSETUP_UMEM_FRAMES - XSKSETUP_RX_POOL_FRAMES)
#define SRVXDP_TXPOOL_BASE ((u64)XSKSETUP_RX_POOL_FRAMES * XSKSETUP_FRAME_SIZE)

i64 srvxdp_txpool_get(wired_srvxdp* x);

#endif
