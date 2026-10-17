#ifndef TLS_HANDSHAKE_CORE_SDRV_SDRV_FLIGHT_IMPL_H
#define TLS_HANDSHAKE_CORE_SDRV_SDRV_FLIGHT_IMPL_H

/* Internal to the sdrv_flight*.c pieces of this directory: shared types, macros
 * and the functions and tables more than one piece uses. Not public API. */

#include "common/bytes/util/bytes.h"
#include "common/diag/error/error.h"
#include "crypto/asymmetric/ecc/cvecdsa/cvecdsa.h"
#include "tls/ext/stp/server_tp.h"
#include "tls/ext/tparam/tparam.h"
#include "tls/ext/tparam/tpblob.h"
#include "tls/handshake/core/sdrv/sdrv.h"
#include "tls/handshake/core/tls/ext_keyshare.h"
#include "tls/handshake/core/tls/handshake.h"
#include "tls/handshake/core/tls/schedule.h"
#include "tls/handshake/core/tls/x25519.h"
#include "tls/handshake/roles/eebuild/eebuild.h"
#include "tls/handshake/roles/sflight/certmsg.h"
#include "tls/handshake/roles/sflight/finished_build.h"
#include "tls/handshake/roles/shbuild/shbuild.h"
#include "transport/conn/pnspace/crypto_stream/ecdhe.h"
#include "transport/version/version/version.h"
#include "transport/version/versmgr/avail.h"

int        sdrv_flight_emit_msg(sdrv* s, wired_span msg, wired_obuf* flight);
int        sdrv_flight_derive_secret(sdrv* s);
wired_span sdrv_sreset_token_span(const sdrv* s);
int        sdrv_flight_emit_ee_version_info(const sdrv* s, wired_obuf* tob);
int        sdrv_flight_emit_ee_pref_addr(const sdrv* s, wired_obuf* tob);

#endif
