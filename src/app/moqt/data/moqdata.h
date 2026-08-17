#ifndef QUIC_MOQDATA_H
#define QUIC_MOQDATA_H

#include "common/bytes/span/span.h"
#include "common/platform/sys/syscall.h"

/** @file
 * draft-ietf-moq-transport-19 data-plane: unidirectional stream
 * classification (3.4), SUBGROUP_HEADER (11.4.2) and Object framing
 * (11.4.2 / 4237-4466). Fetch/control/padding streams are only classified
 * here; their bodies are decoded by moqctl (control) and other modules.
 */

#define QUIC_MOQDATA_OK 1
#define QUIC_MOQDATA_INSUFFICIENT 0
#define QUIC_MOQDATA_VIOLATION (-1)

/* Unidirectional stream types (3.4). */
#define QUIC_MOQDATA_STREAM_INSUFFICIENT 0
#define QUIC_MOQDATA_STREAM_CONTROL 1
#define QUIC_MOQDATA_STREAM_FETCH 2
#define QUIC_MOQDATA_STREAM_SUBGROUP 3
#define QUIC_MOQDATA_STREAM_PADDING 4
#define QUIC_MOQDATA_STREAM_UNKNOWN 5

#define QUIC_MOQDATA_TYPE_SETUP 0x2F00ULL
#define QUIC_MOQDATA_TYPE_FETCH_HEADER 0x05ULL
#define QUIC_MOQDATA_TYPE_PADDING 0x132B3E28ULL

/** Classify a unidirectional stream by its leading Stream Type varint
 * (3.4). Returns one of the QUIC_MOQDATA_STREAM_* values above; *off is
 * advanced past the Stream Type field on any outcome but INSUFFICIENT
 * (left at 0 there). SUBGROUP_HEADER's Type byte is left unconsumed so the
 * caller can pass it to moqdata_subhdr_take. */
int moqdata_classify(wired_span in, usz* off);

/** SUBGROUP_HEADER Type byte (11.4.2): 0b0XX1XXXX with bit4 required and
 * mode 0b11 reserved. */
int moqdata_type_valid(u64 type);
int moqdata_type_props(u64 type);
u64 moqdata_type_sgid_mode(u64 type);
int moqdata_type_end_of_group(u64 type);
int moqdata_type_default_priority(u64 type);
int moqdata_type_first_object(u64 type);

/** Decoded SUBGROUP_HEADER (11.4.2). subgroup_id_pending is set when mode
 * is 0b01 (Subgroup ID == first Object ID, resolved once that Object is
 * decoded); subgroup_id is 0 until then. priority is the raw 8-bit
 * Publisher Priority (0 when the header carries no explicit field, i.e.
 * type has the DEFAULT_PRIORITY bit set). */
typedef struct {
  u64 type;
  u64 track_alias;
  u64 group_id;
  u64 subgroup_id;
  int subgroup_id_pending;
  u64 priority;
} moqdata_subhdr;

/** Returns QUIC_MOQDATA_OK/INSUFFICIENT/VIOLATION. On any outcome but OK,
 * *off is left unchanged. */
int moqdata_subhdr_take(wired_span buf, usz* off, moqdata_subhdr* h);
int moqdata_subhdr_put(wired_mspan buf, usz* off, const moqdata_subhdr* h);

/** Resolves a mode-0b01 deferred Subgroup ID from the first Object ID.
 * No-op when h->subgroup_id_pending is already false. */
void moqdata_subhdr_resolve(moqdata_subhdr* h, u64 first_object_id);

/** Per-subgroup Object decode state, threaded across successive
 * moqdata_obj_take calls on the same SUBGROUP_HEADER. */
typedef struct {
  int has_props;
  int have_prev;
  u64 prev_id;
} moqdata_objseq;

/** Initializes an Object sequence from a SUBGROUP_HEADER Type byte. */
moqdata_objseq moqdata_objseq_of(u64 type);

/** Decoded Object (11.4.2 / 4237-4466). status is 0 (Normal) unless the
 * Payload Length was 0 and an explicit Status was read. payload is empty
 * when Payload Length is 0. */
typedef struct {
  u64        object_id;
  u64        status;
  wired_span payload;
} moqdata_obj;

#define QUIC_MOQDATA_STATUS_NORMAL 0x0ULL
#define QUIC_MOQDATA_STATUS_END_OF_GROUP 0x3ULL
#define QUIC_MOQDATA_STATUS_END_OF_TRACK 0x4ULL

/** Decodes one Object and advances *seq (Object ID chaining, 11.4.2).
 * Returns QUIC_MOQDATA_OK/INSUFFICIENT/VIOLATION; on anything but OK,
 * *off and *seq are left unchanged. VIOLATION covers: cumulative Object
 * ID overflow, an unknown Status value, and a non-empty Properties field
 * on a non-Normal (Payload Length 0 + explicit Status) Object. */
int moqdata_obj_take(
    wired_span buf, usz* off, moqdata_objseq* seq, moqdata_obj* out);

/** Encodes an Object ID Delta of id_delta followed by payload. Non-empty
 * payload: Payload Length + bytes (Status omitted, implicit Normal).
 * Empty payload: Payload Length 0 followed by an explicit Normal Status
 * (11.4.2: the Status field is required whenever Payload Length is 0). */
int moqdata_obj_put(
    wired_mspan buf, usz* off, u64 id_delta, wired_span payload);

/** Encodes an Object ID Delta of id_delta, Payload Length 0, and the
 * given explicit Status. */
int moqdata_obj_put_status(wired_mspan buf, usz* off, u64 id_delta, u64 status);

/** One-message builder: a single SUBGROUP_HEADER (Type 0x70: PROPERTIES
 * off, mode 0b00, no end-of-group, default priority, FIRST_OBJECT set)
 * carrying one Object (payload form, implicit Normal status). */
typedef struct {
  u64        track_alias;
  u64        group_id;
  wired_span payload;
} moqdata_msg;

/** Worst-case wire size of moqdata_msg_build's header + Object
 * framing (excludes payload bytes): Type(1) + Track Alias(9) +
 * Group ID(9) + Object ID Delta(9) + Payload Length(9) = 37. */
#define QUIC_MOQDATA_MSG_OVERHEAD 37

int moqdata_msg_build(wired_mspan buf, usz* off, const moqdata_msg* m);

#endif
