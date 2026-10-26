#ifndef TLS_HANDSHAKE_CORE_TLSDRIVER_TLSDRIVER_IMPL_H
#define TLS_HANDSHAKE_CORE_TLSDRIVER_TLSDRIVER_IMPL_H

/* Internal to the tlsdriver*.c pieces of this directory: shared types, macros
 * and the functions and tables more than one piece uses. Not public API. */

#include "common/bytes/util/bytes.h"
#include "common/diag/error/error.h"
#include "tls/ext/tparam/tparam.h"
#include "tls/ext/tparam/tpblob.h"
#include "tls/handshake/core/hrr/hrr_detect.h"
#include "tls/handshake/core/tls/clienthello.h"
#include "tls/handshake/core/tls/ext_keyshare.h"
#include "tls/handshake/core/tls/handshake.h"
#include "tls/handshake/core/tls/serverhello.h"
#include "tls/handshake/core/tlsdriver/tlsdriver.h"
#include "transport/conn/pnspace/crypto_stream/crypto_tx.h"
#include "transport/packet/frame/frame/frame.h"

/* The ClientHello extensions block being walked for the key_share. */
typedef struct {
  const u8* b;
  usz       end;
} ch_block;

int tlsdriver_peer_keyshare(tlsdriver* d, const u8* msg, usz n, u8 pub[65]);

#endif
