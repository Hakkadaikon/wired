#include "app/http3/core/sfield/sfield_dict_impl.h"

/* RFC 8941 4.2.2 Dictionary parsing (with 4.2.1.2 inner lists and 4.2.3
 * parameters); bare items live in sfield_dict_bare.c. See sfield.h. */

/* RFC 8941 4.2.3.2: one parameter after its ';' -- *SP key [ "=" bare ]. */
static int sfd_param(sfield_iter* it) {
  sfield_item ignored;
  wired_span  k;
  sfd_skip(it, " ");
  if (!sfd_key(it, &k)) {
    return 0;
  }
  if (!sfd_eat(it, '=')) {
    return 1;
  }
  return sfd_bare(it, &ignored);
}

/* Every parameter at the cursor, which are ignored. */
static int sfd_params(sfield_iter* it) {
  while (sfd_eat(it, ';')) {
    if (!sfd_param(it)) {
      return 0;
    }
  }
  return 1;
}

static int sfd_item(sfield_iter* it, sfield_item* v) {
  return sfd_bare(it, v) && sfd_params(it);
}

static int sfd_inner_sep(int c) { return c == ' ' || c == ')'; }

/* One inner-list position: 2 the closing ')', 1 an item, 0 invalid. */
static int sfd_inner_step(sfield_iter* it) {
  sfield_item x;
  sfd_skip(it, " ");
  if (sfd_eat(it, ')')) {
    return 2;
  }
  if (!sfd_item(it, &x)) {
    return 0;
  }
  return sfd_inner_sep(sfd_peek(it));
}

/* RFC 8941 4.2.1.2: "(" *SP [ item *( 1*SP item ) *SP ] ")" parameters. */
static int sfd_inner(sfield_iter* it, sfield_item* v) {
  int r = 1;
  it->off++;
  v->kind = SFIELD_OTHER;
  while (r == 1) {
    r = sfd_inner_step(it);
  }
  return r == 2 && sfd_params(it);
}

static int sfd_value(sfield_iter* it, sfield_item* v) {
  if (sfd_peek(it) == '(') {
    return sfd_inner(it, v);
  }
  return sfd_item(it, v);
}

/* key ( "=" member-value / parameters ): a bare key is Boolean true. */
static int sfd_member(sfield_iter* it, wired_span* k, sfield_item* v) {
  if (!sfd_key(it, k)) {
    return 0;
  }
  if (sfd_eat(it, '=')) {
    return sfd_value(it, v);
  }
  v->kind = SFIELD_BOOLEAN;
  v->num  = 1;
  return sfd_params(it);
}

/* OWS [ "," OWS member-follows ]: 0 on anything else, or a trailing comma. */
static int sfd_after_member(sfield_iter* it) {
  sfd_skip(it, " \t");
  if (it->off >= it->n) {
    return 1;
  }
  if (!sfd_eat(it, ',')) {
    return 0;
  }
  sfd_skip(it, " \t");
  return it->off < it->n;
}

/* One member and its separator: 1 ok, -1 a syntax error. */
static int sfd_member_sep(sfield_iter* it, wired_span* k, sfield_item* v) {
  return sfd_member(it, k, v) && sfd_after_member(it) ? 1 : -1;
}

int sfield_dict_next(sfield_iter* it, wired_span* key, sfield_item* v) {
  sfd_skip(it, " "); /* 4.2: leading SP of the field value */
  if (it->off >= it->n) {
    return 0;
  }
  return sfd_member_sep(it, key, v);
}
