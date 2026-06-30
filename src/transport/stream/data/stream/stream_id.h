#ifndef QUIC_STREAM_STREAM_ID_H
#define QUIC_STREAM_STREAM_ID_H

#include "common/platform/sys/syscall.h"

/* RFC 9000 2.1: the two least-significant bits of a stream ID encode who
 * initiated it (bit 0: 0=client, 1=server) and its directionality (bit 1:
 * 0=bidirectional, 1=unidirectional). The remaining bits are a sequence
 * number within that of the four stream types. */

#define QUIC_STREAM_INITIATOR_BIT 0x1 /* 0 client, 1 server */
#define QUIC_STREAM_DIR_BIT       0x2 /* 0 bidi, 1 uni */

/* Whether the stream was initiated by the client (vs the server). */
int quic_stream_is_client_initiated(u64 id);

/* Whether the stream is unidirectional (vs bidirectional). */
int quic_stream_is_uni(u64 id);

/* The nth stream (sequence index) of a given type. is_server and is_uni
 * select one of the four types; index is the 0-based position. */
u64 quic_stream_id(int is_server, int is_uni, u64 index);

#endif
