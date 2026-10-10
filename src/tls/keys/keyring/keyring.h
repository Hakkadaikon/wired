#ifndef WIRED_KEYRING_KEYRING_H
#define WIRED_KEYRING_KEYRING_H

#include "common/platform/sys/syscall.h"

/** @file
 * Time-rotated server secret (session-ticket key, Retry-token key) with two
 * generations accepted. Wall-clock time is cut into KEYRING_PERIOD_SECS
 * epochs; epoch e's key is HMAC-SHA256(seed, be64(e)). The current epoch's
 * key seals; it and the previous epoch's key open. The keys are a pure
 * function of (seed, time), so every worker thread or forked process
 * rotates in lockstep with no shared mutable state. */

#define KEYRING_KEY 32

/** Rotation period. RFC 8446 4.6.1: every ticket this server issues has a
 * 7200 s lifetime (respond.c); a key that seals during epoch e still opens
 * through epoch e+1, so every ticket opens for at least its lifetime.
 * Retry tokens carry no timestamp; this bounds them to two epochs. */
#define KEYRING_PERIOD_SECS 7200

/** The key for the epoch containing now (back = 0: current, seals) or the
 * one before it (back = 1: previous, still opens).
 * @param seed the long-lived secret every key derives from
 * @param now wall-clock epoch seconds
 * @param back generations back from the current epoch
 * @param out KEYRING_KEY bytes */
void keyring_key(
    const u8 seed[KEYRING_KEY], u64 now, u64 back, u8 out[KEYRING_KEY]);

#endif
