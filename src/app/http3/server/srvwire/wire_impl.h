#ifndef APP_HTTP3_SERVER_SRVWIRE_WIRE_IMPL_H
#define APP_HTTP3_SERVER_SRVWIRE_WIRE_IMPL_H

/* Internal to the wire*.c pieces of this directory: shared types, macros
 * and the functions and tables more than one piece uses. Not public API. */

#include "app/http3/server/srvwire/wire.h"
#include "common/bytes/util/bytes.h"
#include "crypto/symmetric/aead/aes/aes.h"
#include "transport/conn/pnspace/crypto_stream/crypto_tx.h"
#include "transport/packet/build/hspkt/hspkt_build.h"
#include "transport/packet/build/hspkt/hspkt_open.h"
#include "transport/packet/build/initpkt/initkeys.h"
#include "transport/packet/build/initpkt/initopen.h"
#include "transport/packet/frame/frame/ack.h"
#include "transport/packet/frame/frame/frame.h"
#include "transport/packet/frame/pipeline/rxpacket.h"
#include "transport/packet/frame/pipeline/txpacket.h"
#include "transport/version/version/v2types.h"

int srvwire_take_crypto(wired_span frames, wired_span* tls);
int srvwire_append_ack(wired_obuf* frames, const srvwire_seal_in* in);
int srvwire_emit_frames(const srvwire_seal_in* in, wired_obuf* out);
u32 srvwire_ver_or_v1(u32 v);
int srvwire_initial_tx_lean(
    const srvwire_seal_in* in, wired_obuf* fb, wired_obuf* out);
int srvwire_initial_tx_ver(
    u32 version, const srvwire_seal_in* in, wired_obuf* fb, wired_obuf* out);

#endif
