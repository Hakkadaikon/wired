#ifndef MOQDG_H
#define MOQDG_H

#include "app/moqt/data/moqdata.h"
#include "common/bytes/span/span.h"
#include "common/platform/sys/syscall.h"

/** @file
 * draft-ietf-moq-transport-19 datagram plane: OBJECT_DATAGRAM codec
 * (11.3.1). One datagram carries exactly one Object; the stream plane
 * (SUBGROUP_HEADER, 11.4) lives in moqdata. Return codes are the shared
 * MOQDATA_OK / MOQDATA_INSUFFICIENT / MOQDATA_VIOLATION.
 */

/** OBJECT_DATAGRAM Type byte (11.3.1): 0b00X0XXXX, i.e. 0x00..0x0F and
 * 0x20..0x2F, minus the values with both STATUS (0x20) and END_OF_GROUP
 * (0x02) set (0x22/0x23/0x26/0x27/0x2A/0x2B/0x2E/0x2F). */
int moqdg_type_valid(u64 type);

/** Decoded OBJECT_DATAGRAM (11.3.1). The Type bits select which fields
 * are on the wire; absent fields read as their defaults here. */
typedef struct {
  /** Type byte; its bits say which fields below were on the wire. */
  u64 type;
  /** Track Alias (11.1). */
  u64 track_alias;
  /** Group ID. */
  u64 group_id;
  /** Object ID; 0 when the ZERO_OBJECT_ID bit (0x04) omits the field. */
  u64 object_id;
  /** Raw 8-bit Publisher Priority; 0 when the DEFAULT_PRIORITY bit
   * (0x08) omits the field. */
  u64 priority;
  /** Object Status; 0 (Normal) unless the STATUS bit (0x20) is set. */
  u64 status;
  /** Properties bytes after the Properties Length (11.2.1.2); empty
   * when the PROPERTIES bit (0x01) is clear. Borrowed view. */
  wired_span props;
  /** Object Payload (the rest of the datagram); empty when the STATUS
   * bit is set. Borrowed view. */
  wired_span payload;
} moqdg_obj;

/** Worst-case encoded size of the fields before Properties / Status /
 * Payload: Type(1) + Track Alias(9) + Group ID(9) + Object ID(9) +
 * Priority(1) = 29. */
#define MOQDG_HDR_MAX 29

/** Decodes one OBJECT_DATAGRAM spanning all of buf from *off. Returns
 * MOQDATA_OK/INSUFFICIENT/VIOLATION; on any outcome but OK, *off is left
 * unchanged. VIOLATION covers (11.3.1): an invalid Type, the PROPERTIES
 * bit with a Properties Length of 0, and STATUS + PROPERTIES with a
 * non-Normal Status. out's spans borrow from buf. */
int moqdg_take(wired_span buf, usz* off, moqdg_obj* out);

/** Encodes o at *off, minimal varints. Same violation rules as
 * moqdg_take applied to o before writing. Returns
 * MOQDATA_OK/INSUFFICIENT/VIOLATION; on any outcome but OK, *off is left
 * unchanged. */
int moqdg_put(wired_mspan buf, usz* off, const moqdg_obj* o);

#endif
