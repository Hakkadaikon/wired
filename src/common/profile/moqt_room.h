#ifndef COMMON_PROFILE_MOQT_ROOM_H
#define COMMON_PROFILE_MOQT_ROOM_H

/** @file
 * Build profile for a moqt_chat hub of WIRED_MOQT_CHAT_MAX_ROOMS full
 * rooms (-DWIRED_PROFILE_MOQT_ROOM). Without it every limit below keeps
 * its SDK default (defined, each behind its own define guard, next to the
 * table it sizes); with it these values apply unless the constant is
 * itself given on the command line. Derived sizes and the _Static_asserts
 * here and beside each default are computed from these, so an override
 * stays consistent.
 *
 * A participant publishes 9 tracks: chat, audio, screen, screen-lo,
 * camera, nostr-presence (kind 10312), nostr-30312, nostr-30313 and
 * nostr-react (kinds 7 and 5). In a 4-person room one session holds
 * 9 PUBLISH + 4 namespace requests + 3 x 9 SUBSCRIBEs = 40 request
 * streams, and a joiner subscribing with history asks 3 x 9 = 27 fills at
 * once; every room may have one join in flight.
 * - Request streams: 3 rooms x 4 x 40 = 480 plus 3 joins x 27 fills,
 *   rounded up to a whole number of 64-slot words: 576. One session may
 *   hold 67, a joiner's 40 plus its 27 joining FETCHes: a fixed cap rather
 *   than a share of the pool, so one room cannot starve another (the
 *   WebTransport bidi limit, 47 open at once, paces a joiner before it).
 * - Fetches: 3 joins x 27 fills = 81 at once, half serving and half held
 *   (fetch_waits): 41 + 41. Gone ranges: two per upstream fetch leg.
 * - Rendezvous holds: 81, the same 3 x 27 at once; one session may own 27
 *   (one joiner's SUBSCRIBEs). It also sizes the upstream SUBSCRIBE table.
 * - The Object cache arena (wired_moqt_cache_attach) is one, shared by
 *   every room: a busy room can evict another room's history.
 * - WebTransport: 47 client bidi streams per session (40 + 7 spare; 17 +
 *   47 = 64 send slots, the pass mask's limit), 9 uni streams (one open
 *   Subgroup per track) in a 12-slot table (3 more for HTTP/3 plumbing),
 *   initial data 56 x 49152 = 2752512, and 49 request slots, so the QUIC
 *   bidi limit covers the CONNECT stream, 47 WT streams and one stream past
 *   the WT limit (refused with WT_FLOW_CONTROL_ERROR, not a connection
 *   STREAM_LIMIT_ERROR).
 * - Peers (WIRED_MOQTRUN_MAX_SESSIONS 32) and subscribers per track (31)
 *   keep their SDK defaults, above 3 x 4. The connection table is 16
 *   (3 x 4 plus 4 spare), set with the profile flag in
 *   scripts/just/flags.sh. */

#ifdef WIRED_PROFILE_MOQT_ROOM
/** Rooms one hub serves (moqt_chat D5). */
#ifndef WIRED_MOQT_CHAT_MAX_ROOMS
#define WIRED_MOQT_CHAT_MAX_ROOMS 3
#endif
/** Participants per room (moqt_chat D5). */
#define WIRED_MOQT_ROOM_PEOPLE 4
#ifndef WIRED_MOQTRUN_MAX_TRACKS_PER_PEER
#define WIRED_MOQTRUN_MAX_TRACKS_PER_PEER 9
#endif
/** Request streams one participant holds in a full room: its PUBLISHes,
 * 4 namespace requests and a SUBSCRIBE per other participant's track. */
#define WIRED_MOQT_ROOM_SESSION_REQS       \
  (WIRED_MOQTRUN_MAX_TRACKS_PER_PEER + 4 + \
   (WIRED_MOQT_ROOM_PEOPLE - 1) * WIRED_MOQTRUN_MAX_TRACKS_PER_PEER)
/** Fills one joiner asks at once: one per other participant's track. */
#define WIRED_MOQT_ROOM_JOIN_FILLS \
  ((WIRED_MOQT_ROOM_PEOPLE - 1) * WIRED_MOQTRUN_MAX_TRACKS_PER_PEER)
/** Fills of one join in flight per room, all rooms at once. */
#define WIRED_MOQT_ROOM_FILLS \
  (WIRED_MOQT_CHAT_MAX_ROOMS * WIRED_MOQT_ROOM_JOIN_FILLS)
#ifndef WIRED_MOQTRUN_MAX_REQS
#define WIRED_MOQTRUN_MAX_REQS                            \
  (((WIRED_MOQT_CHAT_MAX_ROOMS * WIRED_MOQT_ROOM_PEOPLE * \
         WIRED_MOQT_ROOM_SESSION_REQS +                   \
     WIRED_MOQT_ROOM_FILLS + 63) /                        \
    64) *                                                 \
   64)
#endif
#ifndef WIRED_MOQTRUN_MAX_REQS_PER_SESSION
#define WIRED_MOQTRUN_MAX_REQS_PER_SESSION \
  (WIRED_MOQT_ROOM_SESSION_REQS + WIRED_MOQT_ROOM_JOIN_FILLS)
#endif
#ifndef WIRED_MOQTRUN_MAX_FETCHES
#define WIRED_MOQTRUN_MAX_FETCHES ((WIRED_MOQT_ROOM_FILLS + 1) / 2)
#endif
#ifndef WIRED_MOQTRUN_MAX_RDV
#define WIRED_MOQTRUN_MAX_RDV WIRED_MOQT_ROOM_FILLS
#endif
#ifndef WIRED_MOQTRUN_RDV_PER_SESSION
#define WIRED_MOQTRUN_RDV_PER_SESSION WIRED_MOQT_ROOM_JOIN_FILLS
#endif
#ifndef MOQCACHE_GONE_MAX
#define MOQCACHE_GONE_MAX (2 * WIRED_MOQTRUN_MAX_FETCHES)
#endif
#ifndef H3SETTINGS_WT_INIT_STREAMS_BIDI_VALUE
#define H3SETTINGS_WT_INIT_STREAMS_BIDI_VALUE 47
#endif
#ifndef H3SETTINGS_WT_INIT_STREAMS_UNI_VALUE
#define H3SETTINGS_WT_INIT_STREAMS_UNI_VALUE 9
#endif
#ifndef WIRED_SRVLOOP_MAX_WT_STREAMS
#define WIRED_SRVLOOP_MAX_WT_STREAMS 47
#endif
#ifndef WIRED_SRVLOOP_MAX_WT_UNI_STREAMS
#define WIRED_SRVLOOP_MAX_WT_UNI_STREAMS 12
#endif
#ifndef WIRED_SRVLOOP_MAX_STREAMS
#define WIRED_SRVLOOP_MAX_STREAMS 49
#endif
_Static_assert(
    WIRED_MOQTRUN_MAX_REQS % 64 == 0 &&
        WIRED_MOQTRUN_MAX_REQS >= WIRED_MOQT_CHAT_MAX_ROOMS *
                                          WIRED_MOQT_ROOM_PEOPLE *
                                          WIRED_MOQT_ROOM_SESSION_REQS +
                                      WIRED_MOQT_ROOM_FILLS,
    "every room full plus one join per room fits whole request words");
_Static_assert(
    WIRED_MOQTRUN_MAX_REQS_PER_SESSION >=
        WIRED_MOQT_ROOM_SESSION_REQS + WIRED_MOQT_ROOM_JOIN_FILLS,
    "a joiner's requests and joining FETCHes fit its session cap");
_Static_assert(
    2 * WIRED_MOQTRUN_MAX_FETCHES >= WIRED_MOQT_ROOM_FILLS,
    "one join per room is served or held at once, never refused");
_Static_assert(
    WIRED_MOQTRUN_MAX_RDV >= WIRED_MOQT_ROOM_FILLS &&
        WIRED_MOQTRUN_RDV_PER_SESSION >= WIRED_MOQT_ROOM_JOIN_FILLS,
    "every joiner's SUBSCRIBEs may wait for their publishers at once");
#endif

#endif
