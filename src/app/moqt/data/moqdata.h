#ifndef MOQDATA_H
#define MOQDATA_H

#include "common/bytes/span/span.h"
#include "common/platform/sys/syscall.h"

/** @file
 * draft-ietf-moq-transport-18/19/22 data-plane (draft-19 sections; the
 * wire is byte-identical in all three, so nothing here takes a version):
 * unidirectional stream classification (3.4), SUBGROUP_HEADER (11.4.2,
 * draft-22 11.3.1) and Object framing (11.4.2 / 4237-4466).
 * Fetch/control/padding streams are only classified here; their bodies are
 * decoded by moqctl (control) and other modules.
 */

/** Take result: decoded, *off advanced. */
#define MOQDATA_OK 1
/** Take result: more stream bytes needed; nothing consumed. */
#define MOQDATA_INSUFFICIENT 0
/** Take result: malformed; the session closes with PROTOCOL_VIOLATION. */
#define MOQDATA_VIOLATION (-1)

/* Unidirectional stream types (3.4). */
/** Stream Type varint not complete yet. */
#define MOQDATA_STREAM_INSUFFICIENT 0
/** Stream starts with SETUP (MOQDATA_TYPE_SETUP). */
#define MOQDATA_STREAM_CONTROL 1
/** Fetch data stream (FETCH_HEADER, MOQDATA_TYPE_FETCH_HEADER). */
#define MOQDATA_STREAM_FETCH 2
/** Subgroup data stream (a valid SUBGROUP_HEADER Type). */
#define MOQDATA_STREAM_SUBGROUP 3
/** Padding stream (MOQDATA_TYPE_PADDING); its bytes are ignored. */
#define MOQDATA_STREAM_PADDING 4
/** Any other Stream Type. */
#define MOQDATA_STREAM_UNKNOWN 5

/** Stream Type of a SETUP control stream. */
#define MOQDATA_TYPE_SETUP 0x2F00ULL
/** Stream Type of FETCH_HEADER. */
#define MOQDATA_TYPE_FETCH_HEADER 0x05ULL
/** Stream Type of a padding stream. */
#define MOQDATA_TYPE_PADDING 0x132B3E28ULL
/** SUBGROUP_HEADER Type this SDK sends: PROPERTIES off, mode 0b00, no
 * end-of-group, default priority, FIRST_OBJECT set. */
#define MOQDATA_MSG_TYPE 0x70ULL

/** Classify a unidirectional stream by its leading Stream Type varint
 * (3.4). Returns one of the MOQDATA_STREAM_* values above; *off is
 * advanced past the Stream Type field on any outcome but INSUFFICIENT
 * (left at 0 there). SUBGROUP_HEADER's Type byte is left unconsumed so the
 * caller can pass it to moqdata_subhdr_take. */
int moqdata_classify(wired_span in, usz* off);

/** SUBGROUP_HEADER Type byte (11.4.2): 0b0XX1XXXX with bit4 required and
 * mode 0b11 reserved. */
int moqdata_type_valid(u64 type);
/** 1 iff type has PROPERTIES (bit 0x01): each Object carries a
 * Properties field. */
int moqdata_type_props(u64 type);
/** Subgroup ID mode, bits 0x06: 0 = Subgroup ID 0, 1 = first Object ID,
 * 2 = explicit field, 3 = reserved. */
u64 moqdata_type_sgid_mode(u64 type);
/** 1 iff type has END_OF_GROUP (bit 0x08). */
int moqdata_type_end_of_group(u64 type);
/** 1 iff type has DEFAULT_PRIORITY (bit 0x20): no Publisher Priority
 * field in the header. */
int moqdata_type_default_priority(u64 type);
/** 1 iff type has FIRST_OBJECT (bit 0x40). */
int moqdata_type_first_object(u64 type);

/** Decoded SUBGROUP_HEADER (11.4.2). subgroup_id_pending is set when mode
 * is 0b01 (Subgroup ID == first Object ID, resolved once that Object is
 * decoded); subgroup_id is 0 until then. priority is the raw 8-bit
 * Publisher Priority (0 when the header carries no explicit field, i.e.
 * type has the DEFAULT_PRIORITY bit set). */
typedef struct {
  /** SUBGROUP_HEADER Type (flag bits, see moqdata_type_*). */
  u64 type;
  /** Track Alias the subscription was given. */
  u64 track_alias;
  /** Group ID. */
  u64 group_id;
  /** Subgroup ID (0 for mode 0b00, wire field for 0b10, first Object ID
   * for 0b01 once resolved). */
  u64 subgroup_id;
  /** 1 while a mode-0b01 Subgroup ID awaits the first Object. */
  int subgroup_id_pending;
  /** Publisher Priority (0..255); 0 under DEFAULT_PRIORITY. */
  u64 priority;
} moqdata_subhdr;

/** Returns MOQDATA_OK/INSUFFICIENT/VIOLATION. On any outcome but OK,
 * *off is left unchanged. */
int moqdata_subhdr_take(wired_span buf, usz* off, moqdata_subhdr* h);
/** Writes h as a SUBGROUP_HEADER; the fields h->type selects are
 * emitted (Subgroup ID only in mode 0b10, priority only without
 * DEFAULT_PRIORITY).
 * @param buf output buffer
 * @param off write offset, advanced past the header
 * @param h header to encode
 * @return MOQDATA_OK, MOQDATA_INSUFFICIENT (buf too small) or
 *   MOQDATA_VIOLATION (invalid h->type); *off unchanged unless OK */
int moqdata_subhdr_put(wired_mspan buf, usz* off, const moqdata_subhdr* h);

/** Resolves a mode-0b01 deferred Subgroup ID from the first Object ID.
 * No-op when h->subgroup_id_pending is already false. */
void moqdata_subhdr_resolve(moqdata_subhdr* h, u64 first_object_id);

/** Per-subgroup Object decode state, threaded across successive
 * moqdata_obj_take calls on the same SUBGROUP_HEADER. */
typedef struct {
  /** 1 iff each Object carries a Properties field (from the Type). */
  int has_props;
  /** 1 once an Object was decoded; the next delta chains from prev_id. */
  int have_prev;
  /** Object ID of the previous Object; valid iff have_prev. */
  u64 prev_id;
} moqdata_objseq;

/** Initializes an Object sequence from a SUBGROUP_HEADER Type byte. */
moqdata_objseq moqdata_objseq_of(u64 type);

/** Decoded Object (11.4.2 / 4237-4466). status is 0 (Normal) unless the
 * Payload Length was 0 and an explicit Status was read. payload is empty
 * when Payload Length is 0. */
typedef struct {
  /** Absolute Object ID after delta chaining. */
  u64 object_id;
  /** Object Status, one of MOQDATA_STATUS_*. */
  u64 status;
  /** Object payload; view into the stream buffer. */
  wired_span payload;
} moqdata_obj;

/** Object Status: a normal Object. */
#define MOQDATA_STATUS_NORMAL 0x0ULL
/** Object Status: no Objects follow in this group. */
#define MOQDATA_STATUS_END_OF_GROUP 0x3ULL
/** Object Status: no Objects follow in this track. */
#define MOQDATA_STATUS_END_OF_TRACK 0x4ULL

/** Decodes one Object and advances *seq (Object ID chaining, 11.4.2).
 * Returns MOQDATA_OK/INSUFFICIENT/VIOLATION; on anything but OK,
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
  /** Track Alias carried by the header. */
  u64 track_alias;
  /** Group ID carried by the header. */
  u64 group_id;
  /** The one Object's payload (copied into buf). */
  wired_span payload;
} moqdata_msg;

/** Worst-case wire size of moqdata_msg_build's header + Object
 * framing (excludes payload bytes): Type(1) + Track Alias(9) +
 * Group ID(9) + Object ID Delta(9) + Payload Length(9) = 37. */
#define MOQDATA_MSG_OVERHEAD 37

/** Writes m as one SUBGROUP_HEADER + one Object (Object ID 0).
 * @param buf output buffer; needs MOQDATA_MSG_OVERHEAD + payload bytes
 * @param off write offset, advanced past the message
 * @param m message to encode
 * @return MOQDATA_OK, or MOQDATA_INSUFFICIENT (buf too small; *off
 *   unchanged) */
int moqdata_msg_build(wired_mspan buf, usz* off, const moqdata_msg* m);

/** Bytes per Object when moqdata_blob_build frames a blob: 16 KiB keeps
 * each Object a read()-sized unit for a browser subscriber while holding
 * the per-Object framing overhead under 0.1% of a multi-MB file. */
#define MOQDATA_BLOB_CHUNK 16384

/** Worst-case framed size of an n-byte blob, to size a moqdata_blob_build
 * buffer: the header + first-Object framing bound (MOQDATA_MSG_OVERHEAD)
 * plus, per further Object, a 1-byte Object ID Delta and a Payload Length
 * varint (<= 4 bytes for MOQDATA_BLOB_CHUNK) -- 8 per Object leaves
 * margin. */
#define MOQDATA_BLOB_WIRE_CAP(n) \
  ((n) + MOQDATA_MSG_OVERHEAD + 8 * ((n) / MOQDATA_BLOB_CHUNK + 1))

/** Multi-Object builder: moqdata_msg_build's SUBGROUP_HEADER (Type 0x70,
 * track_alias, Group 0) followed by ceil(blob.n / MOQDATA_BLOB_CHUNK)
 * Objects, each with Object ID Delta 0 -- FIRST_OBJECT makes the first
 * one's delta its absolute id 0 and the chaining rule (prev + delta + 1,
 * moqdata_obj_take) turns every later 0 into a plain increment, so ids run
 * 0,1,2,... The Object payloads concatenate back to blob.
 * @param buf destination, sized with MOQDATA_BLOB_WIRE_CAP(blob.n)
 * @param track_alias Track Alias carried by the header
 * @param blob the bytes to frame (non-empty)
 * @return framed length, or 0 when blob is empty or buf is too small (buf
 *   may then hold a partial write) */
usz moqdata_blob_build(wired_mspan buf, u64 track_alias, wired_span blob);

#endif
