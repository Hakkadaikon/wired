#ifndef SALPN_RAW_H
#define SALPN_RAW_H

#include "common/bytes/span/span.h"
#include "common/platform/sys/syscall.h"
#include "tls/ext/salpn/negotiate.h"

/** @file
 * RFC 7301 3.1/3.2: server-side ALPN selection widened to a configured list
 * of "raw application" protocol ids next to h3/hq-interop -- the MoQT
 * native-QUIC versions moqt-22/moqt-19/moqt-18 (draft-ietf-moq-transport-18
 * 3.1, -19 3.1, -22 6.2: the version is negotiated by ALPN, "moqt-" + NN).
 * One UDP port serves both transports: a client lists any mix of MoQT ids
 * and h3 in preference order, and the first one this server speaks wins
 * (-18 3.1.2, -19 3.1.3, -22 6.1.2). */

/** 1 if the name_len bytes at name are exactly one entry of list, else 0.
 * list is a space-separated set of protocol ids (e.g. "moqt-22 moqt-19
 * moqt-18"); matching is an exact, case-sensitive byte compare (RFC 7301
 * 3.1: protocol ids are opaque octet strings), so "moqt-1", "moqt-190" and
 * "MOQT-19" are not members of a list holding "moqt-19". A 0 list, an empty
 * list, or an empty name is never a member. The list must not itself name
 * h3 or hq-interop: those are classified before the list is consulted.
 * @param list space-separated protocol ids, NUL-terminated, or 0
 * @param name the candidate protocol id bytes
 * @param name_len bytes at name
 * @return 1 member, 0 otherwise */
int salpn_raw_list_has(const char* list, const u8* name, usz name_len);

/** RFC 7301 3.1/3.2: walk the client's ProtocolNameList (alpn_ext_data, len
 * bytes) in the client's preference order and return the first entry this
 * server speaks: SALPN_H3 for "h3", SALPN_HQ for "hq-interop", SALPN_RAW for
 * a member of raw_list (salpn_raw_list_has). On SALPN_RAW, *tok is set to a
 * view into raw_list itself (not into the ClientHello), so it outlives the
 * handshake when raw_list is static configuration; on any other result *tok
 * is left untouched. With a 0 or empty raw_list the result equals
 * salpn_negotiate's. SALPN_NONE when nothing matches or the list is
 * malformed (list length overrun, zero-length entry, entry overrun); the
 * caller then fails the handshake with no_application_protocol (RFC 7301
 * 3.2, RFC 9001 8.1).
 * @param alpn_ext_data the ALPN extension_data (2-byte list length first)
 * @param len bytes at alpn_ext_data
 * @param raw_list space-separated raw protocol ids, or 0 for none
 * @param tok receives the chosen raw id on SALPN_RAW
 * @return the negotiated choice */
salpn_choice salpn_raw_pick(
    const u8* alpn_ext_data, usz len, const char* raw_list, wired_span* tok);

#endif
