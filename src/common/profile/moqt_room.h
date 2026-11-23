#ifndef COMMON_PROFILE_MOQT_ROOM_H
#define COMMON_PROFILE_MOQT_ROOM_H

/** @file
 * Build profile for a full moqt_chat room (-DWIRED_PROFILE_MOQT_ROOM).
 * Without it every limit below keeps its SDK default (defined, each behind
 * its own define guard, next to the table it sizes); with it these values
 * apply unless the constant is itself given on the command line. Derived
 * sizes and the _Static_asserts beside each default are computed from
 * these, so an override stays consistent.
 *
 * A participant publishes 9 tracks: chat, audio, screen, screen-lo,
 * camera, nostr-presence (kind 10312), nostr-30312, nostr-30313 and
 * nostr-react (kinds 7 and 5). In a 4-person room one session holds
 * 9 PUBLISH + 4 namespace requests + 3 x 9 SUBSCRIBEs = 40 request
 * streams.
 * - Request streams: 192 hub-wide (a whole number of 64-slot words), so
 *   the per-session quarter is 48 = 40 + 8 spare for fills or a FETCH.
 * - Fetches: a joiner subscribing with history asks 3 x 9 = 27 fills at
 *   once; 16 serving + 16 held = 32.
 * - Rendezvous holds: 24, an eighth of the request pool; it also sizes the
 *   upstream SUBSCRIBE table, which must exceed two publishers' tracks.
 * - Gone ranges: 32, two per upstream fetch leg (16).
 * - WebTransport: 47 client bidi streams per session (40 + 7 spare; 17 +
 *   47 = 64 send slots, the pass mask's limit), 9 uni streams (one open
 *   Subgroup per track) in a 12-slot table (3 more for HTTP/3 plumbing),
 *   initial data 56 x 49152 = 2752512, and 49 request slots, so the QUIC
 *   bidi limit covers the CONNECT stream, 47 WT streams and one stream past
 *   the WT limit (refused with WT_FLOW_CONTROL_ERROR, not a connection
 *   STREAM_LIMIT_ERROR). */

#ifdef WIRED_PROFILE_MOQT_ROOM
#ifndef WIRED_MOQTRUN_MAX_TRACKS_PER_PEER
#define WIRED_MOQTRUN_MAX_TRACKS_PER_PEER 9
#endif
#ifndef WIRED_MOQTRUN_MAX_REQS
#define WIRED_MOQTRUN_MAX_REQS 192
#endif
#ifndef WIRED_MOQTRUN_MAX_FETCHES
#define WIRED_MOQTRUN_MAX_FETCHES 16
#endif
#ifndef WIRED_MOQTRUN_MAX_RDV
#define WIRED_MOQTRUN_MAX_RDV 24
#endif
#ifndef MOQCACHE_GONE_MAX
#define MOQCACHE_GONE_MAX 32
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
#endif

#endif
