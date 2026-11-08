#include "app/moqt/run/moqtrun_impl.h"

/* draft-ietf-moq-transport-23 12.2 replaced PROTOCOL_VIOLATION with
 * specific session codes. Each class's code before draft-23 (the
 * first column, what draft-18..22 sessions keep) and from draft-23 on. */
static const u32 moqtrun_cc_tbl[MOQTRUN_CC_N][2] = {
    {WIRED_MOQTRUN_CLOSE_PROTOCOL_VIOLATION,
     WIRED_MOQTRUN_CLOSE_PROTOCOL_VIOLATION},
    {WIRED_MOQTRUN_CLOSE_PROTOCOL_VIOLATION,
     WIRED_MOQTRUN_CLOSE_MALFORMED_MESSAGE},
    {WIRED_MOQTRUN_CLOSE_PROTOCOL_VIOLATION, WIRED_MOQTRUN_CLOSE_INVALID_FIELD},
    {WIRED_MOQTRUN_CLOSE_PROTOCOL_VIOLATION,
     WIRED_MOQTRUN_CLOSE_INVALID_TRACK_NAMESPACE},
    {WIRED_MOQTRUN_CLOSE_PROTOCOL_VIOLATION,
     WIRED_MOQTRUN_CLOSE_UNEXPECTED_MESSAGE},
    {WIRED_MOQTRUN_CLOSE_PROTOCOL_VIOLATION,
     WIRED_MOQTRUN_CLOSE_ROLE_VIOLATION},
    {WIRED_MOQTRUN_CLOSE_PROTOCOL_VIOLATION,
     WIRED_MOQTRUN_CLOSE_INVALID_PARAMETER},
    {WIRED_MOQTRUN_CLOSE_PROTOCOL_VIOLATION,
     WIRED_MOQTRUN_CLOSE_CLOSED_CONTROL_STREAM},
    {WIRED_MOQTRUN_CLOSE_PROTOCOL_VIOLATION,
     WIRED_MOQTRUN_CLOSE_INVALID_STREAM_HEADER},
    {WIRED_MOQTRUN_CLOSE_PROTOCOL_VIOLATION,
     WIRED_MOQTRUN_CLOSE_MALFORMED_OBJECT},
    {WIRED_MOQTRUN_CLOSE_PROTOCOL_VIOLATION,
     WIRED_MOQTRUN_CLOSE_INVALID_OBJECT_STATUS},
    {WIRED_MOQTRUN_CLOSE_PROTOCOL_VIOLATION,
     WIRED_MOQTRUN_CLOSE_TRUNCATED_OBJECT},
    {WIRED_MOQTRUN_CLOSE_PROTOCOL_VIOLATION,
     WIRED_MOQTRUN_CLOSE_DELTA_ENCODING_OVERFLOW},
    {WIRED_MOQTRUN_CLOSE_PROTOCOL_VIOLATION,
     WIRED_MOQTRUN_CLOSE_FIELD_LENGTH_EXCEEDED},
    {WIRED_MOQTRUN_CLOSE_MALFORMED_KEY_VALUE,
     WIRED_MOQTRUN_CLOSE_MALFORMED_KEY_VALUE},
    {WIRED_MOQTRUN_CLOSE_MALFORMED_KEY_VALUE,
     WIRED_MOQTRUN_CLOSE_MALFORMED_AUTH_TOKEN},
    {WIRED_MOQTRUN_CLOSE_PROTOCOL_VIOLATION,
     WIRED_MOQTRUN_CLOSE_MALFORMED_KEY_VALUE},
};

/* Class of a failed decode result r (MOQCTL_INSUFFICIENT .. MOQCTL_R_ROLE,
 * indexed by -r): a body cut short or left over is a Length mismatch. */
static const u8 moqtrun_cc_take_tbl[] = {
    MOQTRUN_CC_MALFORMED_MSG, /* INSUFFICIENT */
    MOQTRUN_CC_MALFORMED_MSG, /* VIOLATION */
    MOQTRUN_CC_UNEXPECTED,    /* UNKNOWN_TYPE */
    MOQTRUN_CC_UNEXPECTED,    /* KNOWN_UNIMPLEMENTED */
    MOQTRUN_CC_KVFMT,         /* PARAMS_KVFMT */
    MOQTRUN_CC_TRACK_NS,      /* R_TRACK_NS */
    MOQTRUN_CC_FIELD_LEN,     /* R_FIELD_LEN */
    MOQTRUN_CC_DELTA,         /* R_DELTA */
    MOQTRUN_CC_PARAM,         /* R_PARAM */
    MOQTRUN_CC_AUTH_TOKEN,    /* R_AUTH_TOKEN */
    MOQTRUN_CC_FIELD,         /* R_FIELD */
    MOQTRUN_CC_ROLE,          /* R_ROLE */
    MOQTRUN_CC_MALFORMED_OBJ, /* R_OBJ */
};

#define MOQTRUN_CC_TAKE_N (sizeof moqtrun_cc_take_tbl)

u32 moqtrun_cc_code(int ver, moqtrun_cc c) {
  return moqtrun_cc_tbl[c][!!(moqver_caps(ver) & MOQVER_CAP_CLOSE_CODES23)];
}

/* A result outside the table (none today) keeps PROTOCOL_VIOLATION. */
moqtrun_cc moqtrun_cc_of_take(int r) {
  usz i = (usz)(unsigned)-r;
  return i < MOQTRUN_CC_TAKE_N ? (moqtrun_cc)moqtrun_cc_take_tbl[i]
                               : MOQTRUN_CC_PV;
}

/* Class of a failed Object decode r (MOQDATA_INSUFFICIENT .. MOQDATA_R_OBJ,
 * indexed by -r): a datagram cut short is a malformed Object. */
static const u8 moqtrun_cc_data_tbl[] = {
    MOQTRUN_CC_MALFORMED_OBJ, /* INSUFFICIENT */
    MOQTRUN_CC_MALFORMED_OBJ, /* VIOLATION */
    MOQTRUN_CC_OBJ_STATUS,    /* R_STATUS */
    MOQTRUN_CC_DELTA,         /* R_DELTA */
    MOQTRUN_CC_STREAM_HDR,    /* R_HDR */
    MOQTRUN_CC_MALFORMED_OBJ, /* R_OBJ */
};

#define MOQTRUN_CC_DATA_N (sizeof moqtrun_cc_data_tbl)

moqtrun_cc moqtrun_cc_of_data(int r) {
  usz i = (usz)(unsigned)-r;
  return i < MOQTRUN_CC_DATA_N ? (moqtrun_cc)moqtrun_cc_data_tbl[i]
                               : MOQTRUN_CC_PV;
}

void moqtrun_close_cc(
    wired_moqt_hub* hub, wired_moqtrun_peer* p, moqtrun_cc c) {
  moqtrun_close_with(hub, p, moqtrun_cc_code(p->ver, c));
}

/* A decode failure r that draft-18..22 close PROTOCOL_VIOLATION whatever
 * its cause (FETCH, FILL_PARAMETERS); draft-23 names the cause's code. */
void moqtrun_close_take_pv(wired_moqt_hub* hub, wired_moqtrun_peer* p, int r) {
  u64 d23 = moqver_caps(p->ver) & MOQVER_CAP_CLOSE_CODES23;
  moqtrun_close_cc(hub, p, d23 ? moqtrun_cc_of_take(r) : MOQTRUN_CC_PV);
}
