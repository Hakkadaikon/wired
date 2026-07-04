#ifndef QUIC_TLS_TRANSCRIPT_H
#define QUIC_TLS_TRANSCRIPT_H

#include "crypto/symmetric/hash/hash/sha256.h"

/** @file
 * RFC 8446 4.4.1: cumulative Transcript-Hash over handshake messages. */

/** Cumulative Transcript-Hash state. */
typedef struct {
  quic_sha256_ctx h; /**< running SHA-256 over the handshake messages */
} quic_transcript;

/** Start an empty transcript.
 * @param t transcript state to initialize */
void quic_transcript_init(quic_transcript* t);
/** Fold a handshake message into the transcript.
 * @param t transcript state
 * @param msg the handshake message bytes
 * @param len length of msg in bytes */
void quic_transcript_add(quic_transcript* t, const u8* msg, usz len);
/** Running hash at the current point; t is left unchanged.
 * @param t transcript state
 * @param out receives the transcript hash */
void quic_transcript_hash(const quic_transcript* t, u8 out[QUIC_SHA256_DIGEST]);

#endif
