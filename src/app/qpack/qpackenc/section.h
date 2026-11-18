#ifndef QPACKENC_SECTION_H
#define QPACKENC_SECTION_H

#include "app/qpack/qpackenc/qpackenc.h"
#include "common/bytes/span/span.h"

/** @file
 * RFC 9204 4.5. One field section encoded against the server's own
 * encoder-side dynamic table: each line is an exact static-table entry
 * (Indexed Field Line, T=1), else an acknowledged dynamic entry (Indexed
 * Field Line, T=0, against one shared Base), else a literal. At most one
 * line per section plans an insert (sent on the encoder stream, referenced
 * by a later section once acknowledged: RFC 9204 2.1.2, no blocking). */

/** One field line to encode. */
typedef struct {
  qpack_field f; /**< the (name, value) pair */
  /** RFC 9204 App. A: the exact (name, value) static entry, or -1 */
  i64 static_index;
  /** RFC 9204 App. A: the static name entry a literal references, or -1
   * for a Literal Field Line With Literal Name */
  i64 name_index;
  /** 0 keeps this line out of the dynamic table (RFC 9204 7.1.3: values an
   * attacker could probe, or values that change on every response) */
  int may_insert;
} qpackenc_line;

/** The section-wide outcome the caller acts on after the field lines are
 * written. */
typedef struct {
  /** RFC 9204 4.5.1.1: the encoded Required Insert Count in the Prefix */
  u64 required_insert_count;
  /** RFC 9204 4.3.1 + 4.3.3 instruction bytes for the encoder stream */
  u8  insert_instr[QPACK_DYN_MAX_CAPACITY + 8];
  usz insert_len; /**< bytes at insert_instr; 0 = no insert this section */
  /** the field that insert_instr inserts, viewing inserted_bytes (the line
   * it came from may not outlive the encode call) */
  qpack_field inserted;
  /** the inserted name then value; an entry that fits the table fits here
   * (RFC 9204 3.2.1: name + value + 32 <= capacity) */
  u8 inserted_bytes[QPACK_DYN_MAX_CAPACITY];
} qpackenc_section_result;

/** RFC 9204 4.5. Encode the Prefix and lines[0..n) into out against st
 * (unchanged: a planned insert takes effect only through
 * qpackenc_section_commit).
 * @return 1 ok, 0 when out is too small */
int qpackenc_section_encode(
    const qpackenc_state*    st,
    const qpackenc_line*     lines,
    usz                      n,
    wired_obuf*              out,
    qpackenc_section_result* r);

/** RFC 9204 2.1.4: apply r's planned insert to st once its instruction is
 * staged on the encoder stream; a no-op when r planned none. */
void qpackenc_section_commit(
    qpackenc_state* st, const qpackenc_section_result* r);

#endif
