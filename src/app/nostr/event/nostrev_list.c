#include "app/nostr/event/nostrev_impl.h"

static int nostrev_list_sep(nostrev_lx* lx, int close);
static int nostrev_list_items(nostrev_lx* lx, int close, nostrev_item item);
static int nostrev_skip_str(nostrev_lx* lx);
static int nostrev_skip_num(nostrev_lx* lx);
static int nostrev_skip_true(nostrev_lx* lx);
static int nostrev_skip_false(nostrev_lx* lx);
static int nostrev_skip_null(nostrev_lx* lx);
static int nostrev_skip_nest(nostrev_lx* lx, int close, nostrev_item item);
static int nostrev_skip_arr(nostrev_lx* lx);
static int nostrev_skip_member(nostrev_lx* lx);
static int nostrev_skip_obj(nostrev_lx* lx);

/* 1 more items, 2 end of list, 0 anything else (close is ']' or '}', so
 * at most one term is set). */
static int nostrev_list_sep(nostrev_lx* lx, int close) {
  int c;
  nostrev_ws(lx);
  c = nostrev_take(lx);
  return (c == ',') | ((c == close) << 1);
}

static int nostrev_list_items(nostrev_lx* lx, int close, nostrev_item item) {
  int s;
  do {
    nostrev_ws(lx);
    if (!item(lx)) {
      return 0;
    }
    s = nostrev_list_sep(lx, close);
  } while (s == 1);
  return s == 2;
}

int nostrev_list(nostrev_lx* lx, int close, nostrev_item item) {
  nostrev_ws(lx);
  if (nostrev_peek(lx) == close) {
    lx->i++;
    return 1;
  }
  return nostrev_list_items(lx, close, item);
}

int nostrev_colon(nostrev_lx* lx) {
  nostrev_ws(lx);
  if (nostrev_take(lx) != ':') {
    return 0;
  }
  nostrev_ws(lx);
  return 1;
}

/* Ignored values are decoded into the buffer for validation, then
 * dropped. */
static int nostrev_skip_str(nostrev_lx* lx) {
  nostrev_str s;
  usz         mark = lx->olen;
  int         ok   = nostrev_lex_str(lx, &s);
  lx->olen         = mark;
  return ok;
}

static int nostrev_skip_num(nostrev_lx* lx) {
  u64 v;
  return nostrev_lex_uint(lx, &v);
}

static int nostrev_skip_true(nostrev_lx* lx) {
  return nostrev_lit(lx, "true", 4);
}

static int nostrev_skip_false(nostrev_lx* lx) {
  return nostrev_lit(lx, "false", 5);
}

static int nostrev_skip_null(nostrev_lx* lx) {
  return nostrev_lit(lx, "null", 4);
}

static int nostrev_skip_nest(nostrev_lx* lx, int close, nostrev_item item) {
  int ok;
  if (++lx->depth > NOSTREV_MAX_DEPTH) {
    return 0;
  }
  lx->i++; /* the opening bracket */
  ok = nostrev_list(lx, close, item);
  lx->depth--;
  return ok;
}

static int nostrev_skip_arr(nostrev_lx* lx) {
  return nostrev_skip_nest(lx, ']', nostrev_skip);
}

static int nostrev_skip_member(nostrev_lx* lx) {
  return nostrev_skip_str(lx) && nostrev_colon(lx) && nostrev_skip(lx);
}

static int nostrev_skip_obj(nostrev_lx* lx) {
  return nostrev_skip_nest(lx, '}', nostrev_skip_member);
}

/* Dispatch on the first byte; anything else must be an integer. */
int nostrev_skip(nostrev_lx* lx) {
  static const struct {
    int          c;
    nostrev_item fn;
  } kinds[] = {
      {'"', nostrev_skip_str},   {'[', nostrev_skip_arr},
      {'{', nostrev_skip_obj},   {'t', nostrev_skip_true},
      {'f', nostrev_skip_false}, {'n', nostrev_skip_null},
  };
  int c = nostrev_peek(lx);
  for (usz k = 0; k < sizeof(kinds) / sizeof(kinds[0]); k++) {
    if (kinds[k].c == c) {
      return kinds[k].fn(lx);
    }
  }
  return nostrev_skip_num(lx);
}
