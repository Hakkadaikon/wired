#ifndef TLS_TRANSCRIPT_H
#define TLS_TRANSCRIPT_H

#include "crypto/symmetric/hash/hash/sha256.h"
#include "crypto/symmetric/hash/hash/sha384.h"

/** @file
 * RFC 8446 4.4.1: cumulative Transcript-Hash over handshake messages. */

/** Cumulative Transcript-Hash state. */
typedef struct {
  sha256_ctx h;    /**< running SHA-256 over the handshake messages */
  sha512_ctx h384; /**< running SHA-384 over the same messages (the suite
                    * is not known until the ClientHello is parsed) */
} transcript;

/** Start an empty transcript.
 * @param t transcript state to initialize */
void transcript_init(transcript* t);
/** Fold a handshake message into the transcript.
 * @param t transcript state
 * @param msg the handshake message bytes
 * @param len length of msg in bytes */
void transcript_add(transcript* t, const u8* msg, usz len);
/** Running hash at the current point; t is left unchanged.
 * @param t transcript state
 * @param out receives the transcript hash */
void transcript_hash(const transcript* t, u8 out[SHA256_DIGEST]);
/** Running hash under suite's hash (SHA-384 for TLS_AES_256_GCM_SHA384,
 * else SHA-256); t is left unchanged.
 * @param t transcript state
 * @param suite RFC 8446 B.4 cipher suite
 * @param out receives Hash.length bytes */
void transcript_hash_suite(const transcript* t, u16 suite, u8* out);

#endif
