#ifndef CLIENT_CLIENT_H
#define CLIENT_CLIENT_H

#include "common/platform/sys/syscall.h"
#include "tls/handshake/core/fullhs/fullhs.h"
#include "tls/handshake/core/tlsdriver/tlsdriver.h"

/* RFC 9000 5/7: client-side handshake state the in-tree loopback tests drive
 * against the server (clientwire.h seals/opens its packets): tlsdriver
 * agrees the ECDHE secret over ClientHello/ServerHello; fullhs sequences
 * Certificate/CertificateVerify/Finished. */
typedef struct {
  tlsdriver tls;
  fullhs    hs;
  u8        sh_transcript[512]; /* ClientHello..ServerHello bytes for fullhs */
  usz       sh_len;
} client;

#endif
