#ifndef COMMON_FMT_FMT_IMPL_H
#define COMMON_FMT_FMT_IMPL_H

/* Internal to the fmt*.c pieces of this directory: shared types, macros
 * and the functions and tables more than one piece uses. Not public API. */

#include "common/arch/sysops.h"
#include "common/fmt/fmt.h"

#define FMT_MINUS 1u
#define FMT_ZERO 2u
#define FMT_PLUS 4u
#define FMT_SPACE 8u
#define FMT_HASH 16u

enum { FMT_LEN_INT, FMT_LEN_H, FMT_LEN_HH, FMT_LEN_L, FMT_LEN_LL, FMT_LEN_Z };

typedef struct {
  char* out;
  usz   cap;
  usz   n;
} fmt_sink;

typedef struct {
  u32  flags;
  int  width;
  int  prec; /* -1: absent */
  int  len;
  char conv;
} fmt_spec;

/* One conversion's output: prefix, precision zeros, body. */
typedef struct {
  const char* pre;
  usz         prelen;
  usz         zeros;
  const char* body;
  usz         bodylen;
  int         zpad; /* pad with zeros instead of spaces (ignored with '-') */
} fmt_piece;

typedef void (*fmt_handler)(fmt_sink*, const fmt_spec*, wired_va_list);

/* ---- integers ---- */

typedef struct {
  u64 v;
  int neg;
  u32 base;
  int upper;
  int hash; /* always emit the 0x prefix (%p); else only '#' and v != 0 */
} fmt_int;

/* ---- %f: exact binary-to-decimal, round half to even ---- */

typedef struct {
  u64 ip;
  u64 f; /* fraction numerator over 2^s */
  u32 s; /* 0..60 */
} fmt_fparts;

void fmt_put(fmt_sink* s, char c);
void fmt_field(fmt_sink* s, const fmt_spec* sp, const fmt_piece* pc);
char fmt_sign(const fmt_spec* sp, int neg);
u64  fmt_get(const fmt_spec* sp, wired_va_list ap, int sgn);
usz  fmt_idigits(char* tmp, const fmt_spec* sp, const fmt_int* a);
void fmt_h_d(fmt_sink* s, const fmt_spec* sp, wired_va_list ap);
void fmt_h_u(fmt_sink* s, const fmt_spec* sp, wired_va_list ap);
void fmt_h_x(fmt_sink* s, const fmt_spec* sp, wired_va_list ap);
void fmt_h_p(fmt_sink* s, const fmt_spec* sp, wired_va_list ap);
usz  fmt_nlen(const char* p, usz lim);
void fmt_h_s(fmt_sink* s, const fmt_spec* sp, wired_va_list ap);
void fmt_h_c(fmt_sink* s, const fmt_spec* sp, wired_va_list ap);
void fmt_h_pct(fmt_sink* s, const fmt_spec* sp, wired_va_list ap);
void fmt_split(fmt_fparts* r, u64 bits);
int  fmt_round_up(const fmt_fparts* r, char last);
void fmt_carry(char* b, usz end);
usz  fmt_ip_digits(char* b, u64 v);
void fmt_run(fmt_sink* s, const char* fmt, wired_va_list ap);

extern const fmt_handler fmt_tab[128];

#endif
