#include "app/moqt/ctl/moqctl_impl.h"

static int  moqctl_token_take_alias(wired_span v, usz* at, moqctl_token* t);
static int  moqctl_token_at_end(wired_span v, usz at);
static int  moqctl_token_take_value(wired_span v, usz* at, moqctl_token* t);
static int  moqctl_token_take_head(wired_span v, usz* at, moqctl_token* t);
static int  moqctl_token_take(wired_span v, moqctl_token* t);
static int  moqctl_locfilter_exact(wired_span v, moqctl_locfilter* f);
static int  moqctl_locfilter_is_quirk(wired_span v);
static void moqctl_locfilter_set_largest(moqctl_param* p);

int moqctl_pv_bytes(wired_span buf, usz* at, moqctl_param* p) {
  u64 len;
  if (!moqctl_span_take_len(buf, at, &len)) return MOQCTL_INSUFFICIENT;
  return moqctl_bytes_take(buf, at, len, &p->bytes);
}

/* ===== AUTHORIZATION TOKEN (SS10.2.2 Figure 5) ===== */

/* Per Alias Type (index = MOQCTL_TOKEN_*): does the Token carry an Alias
 * field, and does it carry Token Type + Token Value. */
static const int MOQCTL_TOKEN_HAS_ALIAS[4] = {1, 1, 1, 0};

static const int MOQCTL_TOKEN_HAS_VALUE[4] = {0, 1, 0, 1};

static int moqctl_token_take_alias(wired_span v, usz* at, moqctl_token* t) {
  if (!MOQCTL_TOKEN_HAS_ALIAS[t->alias_type]) return MOQCTL_OK;
  if (!moqvi_take(v, at, &t->alias)) return MOQCTL_PARAMS_KVFMT;
  return MOQCTL_OK;
}

/* Token Value is the remainder of the Length-prefixed value; an Alias-only
 * shape must end exactly at the Alias. */
static int moqctl_token_at_end(wired_span v, usz at) {
  return at == v.n ? MOQCTL_OK : MOQCTL_PARAMS_KVFMT;
}

static int moqctl_token_take_value(wired_span v, usz* at, moqctl_token* t) {
  if (!MOQCTL_TOKEN_HAS_VALUE[t->alias_type])
    return moqctl_token_at_end(v, *at);
  if (!moqvi_take(v, at, &t->token_type)) return MOQCTL_PARAMS_KVFMT;
  t->value = wired_span_of(v.p + *at, v.n - *at);
  return MOQCTL_OK;
}

static int moqctl_token_take_head(wired_span v, usz* at, moqctl_token* t) {
  if (!moqvi_take(v, at, &t->alias_type)) return MOQCTL_PARAMS_KVFMT;
  if (t->alias_type > MOQCTL_TOKEN_USE_VALUE) return MOQCTL_PARAMS_KVFMT;
  return moqctl_token_take_alias(v, at, t);
}

/* v is exactly the parameter's Length bytes. "If the Token structure
 * cannot be decoded, the receiver MUST close the Session with
 * KEY_VALUE_FORMATTING_ERROR" -- surfaced as MOQCTL_PARAMS_KVFMT. */
static int moqctl_token_take(wired_span v, moqctl_token* t) {
  usz at = 0;
  int r  = moqctl_token_take_head(v, &at, t);
  if (r != MOQCTL_OK) return r;
  return moqctl_token_take_value(v, &at, t);
}

int moqctl_pv_token(wired_span buf, usz* at, moqctl_param* p) {
  int r = moqctl_pv_bytes(buf, at, p);
  if (r != MOQCTL_OK) return r;
  return moqctl_token_take(p->bytes, &p->token);
}

/* A Location Filter must fill its Length exactly (SS5.1.2). */
static int moqctl_locfilter_exact(wired_span v, moqctl_locfilter* f) {
  usz a = 0;
  if (moqctl_locfilter_take(v, &a, f) != MOQCTL_OK) return MOQCTL_VIOLATION;
  return a == v.n ? MOQCTL_OK : MOQCTL_VIOLATION;
}

static int moqctl_locfilter_is_quirk(wired_span v) {
  usz a = 0;
  u64 t = 0;
  return moqvi_take(v, &a, &t) && a == v.n &&
         t == MOQCTL_FILTER_MOXYGEN_LARGEST_GROUP;
}

static void moqctl_locfilter_set_largest(moqctl_param* p) {
  p->lf      = (moqctl_locfilter){0};
  p->lf.type = MOQCTL_FILTER_LARGEST;
  p->rl      = (moqctl_rangeloc){0};
  moqctl_rangeloc19_largest(&p->rl);
}

/* Also into the version-neutral p->rl (has_filter 1), the one form the
 * hub resolves for every draft. */
int moqctl_pv_locfilter(wired_span buf, usz* at, moqctl_param* p) {
  usz a = 0;
  int r = moqctl_pv_bytes(buf, at, p);
  if (r != MOQCTL_OK) return r;
  p->has_filter = 1;
  if (moqctl_locfilter_is_quirk(p->bytes)) {
    moqctl_locfilter_set_largest(p);
    return MOQCTL_OK;
  }
  moqctl_rangeloc19_take(p->bytes, &a, &p->rl);
  return moqctl_locfilter_exact(p->bytes, &p->lf);
}
