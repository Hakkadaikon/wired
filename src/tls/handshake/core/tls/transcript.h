#ifndef QUIC_TLS_TRANSCRIPT_H
#define QUIC_TLS_TRANSCRIPT_H

#include "crypto/symmetric/hash/hash/sha256.h"

/* RFC 8446 4.4.1: cumulative Transcript-Hash over handshake messages. */

typedef struct {
    quic_sha256_ctx h;
} quic_transcript;

void quic_transcript_init(quic_transcript *t);
void quic_transcript_add(quic_transcript *t, const u8 *msg, usz len);
/* Running hash at the current point; t is left unchanged. */
void quic_transcript_hash(const quic_transcript *t, u8 out[QUIC_SHA256_DIGEST]);

#endif
