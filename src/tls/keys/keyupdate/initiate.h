#ifndef KEYUPDATE_INITIATE_H
#define KEYUPDATE_INITIATE_H

#include "common/platform/sys/syscall.h"

/* RFC 9001 6.1: an endpoint must not start a key update until the handshake
 * is confirmed, and must not start a new one until at least three times the
 * PTO has passed since the prior update completed (preventing back-to-back
 * updates that would exhaust the peer's retained keys). */

/** Inputs to keyupdate_may_initiate: whether the handshake is confirmed,
 * the time of the last update, the current time, and the PTO. */
typedef struct {
  int handshake_confirmed;
  u64 last_update;
  u64 now;
  u64 pto;
} keyupdate_in;

/* 1 if a key update may begin now: handshake confirmed and 3*PTO elapsed
 * since last_update. */
int keyupdate_may_initiate(const keyupdate_in* in);

#endif
