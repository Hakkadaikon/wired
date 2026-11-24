#ifndef WIRED_MOQTRUN_HOOKS_H
#define WIRED_MOQTRUN_HOOKS_H

#include "app/moqt/run/moqtrun_types.h"

/** @file
 * The policy hooks a wired_moqt_hub calls (moqtrun.h): the authorizers,
 * session admission and the Object tap. Each gets the session it acts
 * for, so a policy can be per session (e.g. room membership). */

/** draft-ietf-moq-transport-19 SS13.3 authorization hook: as
 * authorize_subscribe the hub calls it once per SUBSCRIBE and per
 * TRACK_STATUS naming a known track, as authorize_publish once per
 * PUBLISH, each with the Full Track Name and the presented AUTHORIZATION
 * TOKEN (Alias Type USE_VALUE; 0 when the message carried none), and s,
 * the requesting session (the one wired_moqt_admit_fn admitted). Return
 * non-zero to grant, 0 to answer REQUEST_ERROR UNAUTHORIZED. The token scheme
 * (CAT / Privacy Pass) is the deployment's to verify -- this SDK carries the
 * bytes, not the policy. */
typedef int (*wired_moqt_authorize_fn)(
    void*               ctx,
    wired_wt_session*   s,
    const moqctl_ftn*   name,
    const moqctl_token* token);

/** draft-ietf-moq-transport-19 10.15 / 10.18 namespace authorization
 * hook: the hub calls it once per PUBLISH_NAMESPACE, SUBSCRIBE_NAMESPACE
 * or SUBSCRIBE_TRACKS (msg_type MOQNS_T_PUBLISH_NAMESPACE /
 * MOQNS_T_SUBSCRIBE_NAMESPACE / MOQCTL_T_SUBSCRIBE_TRACKS) with the
 * Track Namespace or Prefix, the presented AUTHORIZATION TOKEN
 * (Alias Type USE_VALUE; 0 when the message carried none) and s, the
 * requesting session. Return non-zero to grant, 0 to answer REQUEST_ERROR
 * UNAUTHORIZED. */
typedef int (*wired_moqt_authorize_ns_fn)(
    void*               ctx,
    wired_wt_session*   s,
    u64                 msg_type,
    const moqctl_ns*    ns,
    const moqctl_token* token);

/** Admission hook (draft-ietf-moq-transport-22 9.1.4): the hub calls it
 * once per session, synchronously, when the client's SETUP decoded, with
 * the first AUTHORIZATION TOKEN option carrying a value (0 when none;
 * token->value is a view valid during the call only). Until it admits,
 * no request of the session is handled (those sent before the SETUP wait
 * for it). Return 0 to admit; any other value is the session close code,
 * sent with *reason (a caller-owned view, empty by default; the transport
 * truncates it to WTCAPSULE_CLOSE_MESSAGE_MAX = 1024 bytes on
 * WebTransport and to 48 bytes on raw QUIC) -- nothing the session sent,
 * held requests included, is handled after it. The hook may instead close
 * s itself with wired_moqt_close (any return value then refuses). With a
 * hook set, a legacy WebTransport session (no moqt-NN subprotocol, which
 * need never send a SETUP) is closed UNAUTHORIZED at wired_moqt_on_session
 * instead. */
typedef u32 (*wired_moqt_admit_fn)(
    void*               ctx,
    wired_wt_session*   s,
    const moqctl_token* token,
    wired_span*         reason);

/** Object tap: the hub calls it, read-only, for every whole Normal Object
 * an open (not closing) session publishes on a Subgroup stream of a track
 * whose namespace starts with wired_moqt_hub.tap_prefix (an empty prefix
 * matches every namespace), when the payload is at most tap_max bytes
 * (0: only empty payloads). ns is the track's encoded Track Namespace
 * (count + Length-prefixed fields, moqctl_ns_take decodes it), name its
 * Track Name; every view is valid during the call only. The hook may
 * close the publisher with wired_moqt_close: that Object and everything
 * after it are then neither noted, cached, relayed nor tapped. The relay
 * cuts an Object through as it arrives, so the leading bytes of one that
 * spans deliveries may already have gone to subscribers before the whole
 * Object reaches the tap; a close cannot recall them. Datagrams are not
 * tapped. */
typedef void (*wired_moqt_tap_fn)(
    void*             ctx,
    wired_wt_session* s,
    wired_span        ns,
    wired_span        name,
    wired_span        payload);

#endif
