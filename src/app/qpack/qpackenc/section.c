#include "app/qpack/qpackenc/section.h"

#include "app/qpack/qpack/fieldline.h"
#include "app/qpack/qpack/insertcount.h"
#include "app/qpack/qpack/literal.h"
#include "app/qpack/qpack/prefix.h"
#include "app/qpack/qpackdyn/field_encode.h"
#include "common/bytes/util/bytes.h"
#include "common/bytes/util/num.h"

/* The dynamic-table plan for a line with no exact static entry; a static
 * line plans nothing. */
static void sec_plan(
    const qpackenc_state* st, const qpackenc_line* l, qpackenc_plan* p) {
  p->insert_len   = 0;
  p->used_dynamic = 0;
  if (l->static_index < 0) {
    qpackenc_plan_field(st, &l->f, p);
  }
}

/* 1 when l's planned insert is the section's one insert. */
static int sec_takes_insert(
    const qpackenc_line*           l,
    const qpackenc_plan*           p,
    const qpackenc_section_result* r) {
  return l->may_insert && p->insert_len && !r->insert_len;
}

/* Carry p's instruction into r as the section's insert of l. */
static void sec_carry(
    const qpackenc_line*     l,
    const qpackenc_plan*     p,
    qpackenc_section_result* r) {
  u8* v = r->inserted_bytes + l->f.name.n;
  bytes_memcpy(r->insert_instr, p->insert_instr, p->insert_len);
  bytes_memcpy(r->inserted_bytes, l->f.name.p, l->f.name.n);
  bytes_memcpy(v, l->f.value.p, l->f.value.n);
  r->insert_len = p->insert_len;
  r->inserted   = (qpack_field){
      wired_span_of(r->inserted_bytes, l->f.name.n),
      wired_span_of(v, l->f.value.n)};
}

/* Pass 1 for one line: raise *ric past a referenced entry, or carry the
 * section's insert. */
static void sec_scan_one(
    const qpackenc_state*    st,
    const qpackenc_line*     l,
    u64*                     ric,
    qpackenc_section_result* r) {
  qpackenc_plan p;
  sec_plan(st, l, &p);
  if (p.used_dynamic) {
    *ric = u64_max(*ric, p.abs_index + 1);
  }
  if (sec_takes_insert(l, &p, r)) {
    sec_carry(l, &p, r);
  }
}

/* A literal line: a static name reference when l has one, else a literal
 * name (RFC 9204 4.5.4 / 4.5.6). */
static usz sec_literal(const qpackenc_line* l, wired_mspan out) {
  qpack_nameref ref = {(u64)l->name_index, 1, 0};
  if (l->name_index < 0) {
    return qpack_literal_name_encode(out, 0, &l->f);
  }
  return qpack_literal_namref_encode(out, &ref, l->f.value);
}

/* RFC 9204 4.5.2: a dynamic reference relative to Base (= the section's
 * Required Insert Count, so Delta Base is 0). */
static usz sec_dynamic(u64 base, u64 abs_index, wired_mspan out) {
  wired_obuf ob = obuf_of(out.p, out.n);
  return qdyn_indexed_dynamic(base - 1 - abs_index, &ob) ? ob.len : 0;
}

/* Pass 2 for one line: its field line bytes at out, 0 when out is full. */
static usz sec_line(
    const qpackenc_state* st,
    const qpackenc_line*  l,
    u64                   base,
    wired_mspan           out) {
  qpackenc_plan p;
  if (l->static_index >= 0) {
    return qpack_indexed_encode(out, (u64)l->static_index, 1);
  }
  sec_plan(st, l, &p);
  if (p.used_dynamic) {
    return sec_dynamic(base, p.abs_index, out);
  }
  return sec_literal(l, out);
}

/* The Prefix for Required Insert Count ric with Base == ric. */
static usz sec_prefix(
    const qpackenc_state*    st,
    u64                      ric,
    wired_obuf*              out,
    qpackenc_section_result* r) {
  qpack_prefix pfx;
  r->required_insert_count = qpack_ric_encode(ric, st->dyn.max_capacity / 32);
  pfx                      = (qpack_prefix){r->required_insert_count, 0, 0};
  out->len                 = qpack_prefix_encode(out->p, out->cap, &pfx);
  return out->len;
}

/* Pass 2: every line after the Prefix. */
static int sec_lines(
    const qpackenc_state* st,
    const qpackenc_line*  lines,
    usz                   n,
    u64                   base,
    wired_obuf*           out) {
  for (usz i = 0; i < n; i++) {
    usz w = sec_line(
        st, &lines[i], base,
        wired_mspan_of(out->p + out->len, out->cap - out->len));
    if (!w) {
      return 0;
    }
    out->len += w;
  }
  return 1;
}

int qpackenc_section_encode(
    const qpackenc_state*    st,
    const qpackenc_line*     lines,
    usz                      n,
    wired_obuf*              out,
    qpackenc_section_result* r) {
  u64 ric       = 0;
  r->insert_len = 0;
  for (usz i = 0; i < n; i++) {
    sec_scan_one(st, &lines[i], &ric, r);
  }
  if (!sec_prefix(st, ric, out, r)) {
    return 0;
  }
  return sec_lines(st, lines, n, ric, out);
}

void qpackenc_section_commit(
    qpackenc_state* st, const qpackenc_section_result* r) {
  if (r->insert_len) {
    qpackenc_commit_field(st, &r->inserted);
  }
}
