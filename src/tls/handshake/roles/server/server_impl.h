#ifndef TLS_HANDSHAKE_ROLES_SERVER_SERVER_IMPL_H
#define TLS_HANDSHAKE_ROLES_SERVER_SERVER_IMPL_H

/* Internal to the server*.c pieces of this directory: shared types, macros
 * and the functions and tables more than one piece uses. Not public API. */

#include "common/bytes/util/bytes.h"
#include "common/diag/error/error.h"
#include "common/platform/keylog/keylog.h"
#include "tls/handshake/core/hrr/hrr_build.h"
#include "tls/handshake/core/tls/finished.h"
#include "tls/handshake/core/tls/handshake.h"
#include "tls/handshake/core/tls/hs_message.h"
#include "tls/handshake/core/tls/schedule.h"
#include "tls/handshake/core/tls/transcript.h"
#include "tls/handshake/core/tls/x25519.h"
#include "tls/handshake/roles/server/server.h"
#include "tls/handshake/roles/srvfin/hsdone.h"
#include "tls/handshake/roles/srvfin/verify.h"
#include "transport/conn/lifecycle/idledrive/idlenego.h"
#include "transport/conn/loop/crecv/message.h"

/* RFC 8446 4.1.2: legacy_version(2) precedes ClientHello.random, both after
 * the 4-byte handshake header (HS_HEADER) put_prefix wrote them at. */
#define SRV_CH_RANDOM_OFF (HS_HEADER + 2)

const tls_hash* server_srv_hash(const wired_server* s);
usz             server_srv_tr_add(wired_server* s, const u8* msg, usz len);
int             server_srv_verify_finished(
    wired_server* s, const u8* msg, usz len, u8* c_traffic);

#endif
