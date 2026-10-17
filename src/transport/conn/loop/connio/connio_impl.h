#ifndef TRANSPORT_CONN_LOOP_CONNIO_CONNIO_IMPL_H
#define TRANSPORT_CONN_LOOP_CONNIO_CONNIO_IMPL_H

/* Internal to the connio*.c pieces of this directory: shared types, macros
 * and the functions and tables more than one piece uses. Not public API. */

#include "common/diag/error/error.h"
#include "crypto/kdf/keys/keyset.h"
#include "crypto/symmetric/aead/aes/aes.h"
#include "transport/conn/loop/connio/connio.h"
#include "transport/packet/frame/frame/frame.h"
#include "transport/packet/frame/frame/stream_ctl.h"
#include "transport/packet/frame/pipeline/framewalk.h"
#include "transport/packet/frame/pipeline/rxpacket.h"
#include "transport/packet/frame/pipeline/txpacket.h"

/* The protection level and datagram connio_recv opens. */
typedef struct {
  int         level;
  wired_mspan datagram;
} connio_recv_in;

int connio_level_is_initial(int level);

#endif
