#ifndef MOQRAW_H
#define MOQRAW_H

#include "app/moqt/ctl/moqctl.h"
#include "common/bytes/span/span.h"
#include "common/platform/sys/syscall.h"

/** @file
 * MoQT-over-raw-QUIC Setup Option policy. On native QUIC there is no
 * Extended CONNECT, so the client carries its URI's authority and
 * path-abempty [?query] in the AUTHORITY (0x05) and PATH (0x01) Setup
 * Options (draft-ietf-moq-transport-18 3.1.4/10.3.1.1-2, -19 3.1.5/
 * 10.3.1.1-2, -22 6.2.2/9.1.1-2). Both are client-only and native-QUIC-only:
 * over WebTransport their presence is itself a close. This module decides
 * the session-termination code (draft-ietf-moq-transport-19 3.5, -22 6.6 /
 * 12.2) one client SETUP calls for. */

/** -18/-19 10.3.1.2, -22 9.1.2: PATH over WebTransport or naming an
 * unsupported path. */
#define MOQRAW_CLOSE_INVALID_PATH 0x8
/** -18/-19 10.3.1.2, -22 9.1.2: PATH not RFC 3986 path-abempty [?query]. */
#define MOQRAW_CLOSE_MALFORMED_PATH 0x9
/** -18/-19 10.3.1.1, -22 9.1.1: AUTHORITY over WebTransport or naming an
 * unsupported authority. */
#define MOQRAW_CLOSE_INVALID_AUTHORITY 0x19
/** -18/-19 10.3.1.1, -22 9.1.1: AUTHORITY not an RFC 3986 authority with a
 * non-empty host. */
#define MOQRAW_CLOSE_MALFORMED_AUTHORITY 0x1A

/** The application's optional say over well-formed PATH/AUTHORITY values on
 * raw QUIC. Zero-initialized (or a 0 pointer to it) accepts every
 * well-formed value -- the default policy. A hook is only consulted for an
 * option that is present and passed its syntax check. */
typedef struct {
  /** 1 to accept path, 0 to close with MOQRAW_CLOSE_INVALID_PATH; 0 hook =
   * accept. path is a view valid only for the call. */
  int (*accept_path)(void* ctx, wired_span path);
  /** 1 to accept authority, 0 to close with MOQRAW_CLOSE_INVALID_AUTHORITY;
   * 0 hook = accept. authority is a view valid only for the call. */
  int (*accept_authority)(void* ctx, wired_span authority);
  /** opaque context passed to both hooks */
  void* ctx;
} moqraw_policy;

/** RFC 3986 3.3/3.4 subset for the PATH option: 1 when path is empty, or
 * starts with "/" and continues with pchar / "/" segments, optionally
 * followed by "?" and query characters; every "%" must be followed by two
 * hex digits. "#", space, control bytes and non-ASCII bytes are malformed.
 * @param path the PATH option value
 * @return 1 well-formed, 0 malformed */
int moqraw_path_ok(wired_span path);

/** RFC 3986 3.2 subset for the AUTHORITY option: [userinfo "@"] host
 * [":" port], where host is a non-empty reg-name, an IPv4 address, or a
 * bracketed IP literal ("[" ... "]"), and port is zero or more digits whose
 * value is at most 65535 (an empty port after ":" is allowed by RFC 3986
 * 3.2.3). An empty host is malformed (-22 6.1).
 * @param authority the AUTHORITY option value
 * @return 1 well-formed, 0 malformed */
int moqraw_authority_ok(wired_span authority);

/** The close code a decoded client SETUP calls for, 0 to accept. PATH is
 * judged before AUTHORITY, so a SETUP bad in both closes on the PATH code.
 * raw == 0 (WebTransport): PATH present -> MOQRAW_CLOSE_INVALID_PATH, else
 * AUTHORITY present -> MOQRAW_CLOSE_INVALID_AUTHORITY, exactly the hub's
 * pre-raw behavior. raw == 1: each present option must pass its syntax
 * check (else MALFORMED_PATH / MALFORMED_AUTHORITY), then the policy hook
 * (else INVALID_PATH / INVALID_AUTHORITY). Absent options and unknown
 * options (not surfaced by moqctl_setup_take) never close.
 * @param raw 1 for a raw-QUIC session, 0 for WebTransport
 * @param m the decoded client SETUP
 * @param pol the application policy, or 0 to accept every well-formed value
 * @return 0 accept, else the session termination code */
u32 moqraw_setup_verdict(
    int raw, const moqctl_setup* m, const moqraw_policy* pol);

#endif
