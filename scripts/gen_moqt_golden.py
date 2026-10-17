#!/usr/bin/env python3
"""Generate tests/app/moqt_golden.h from examples/moqt_chat/testvectors/moqt_golden.json."""

import json
import sys

GROUPS = ["varint", "kvp", "ctl", "data", "name"]
TYPEONLY_OP = {"accept": 0, "decode": 0}  # any other op -> 1
VARINT_OP = {"decode": 0, "encode": 1, "reject": 2}


def cname(s):
    return "".join(c if c.isalnum() else "_" for c in s)


def as_int(t):
    return int(t, 0) if isinstance(t, str) else t


def hexlist(b):
    return ", ".join("0x%02x" % x for x in b)


def is_mod256(tail):
    return all(tail[i] == (i % 256) for i in range(len(tail)))


def pattern_start(b):
    """Shortest prefix (< 64 bytes) after which b is the mod-256 pattern, or None."""
    return next((s for s in range(min(64, len(b))) if is_mod256(b[s:])), None)


def emit_compact(ctx, name, b, start):
    out, compact = ctx
    out.append(
        "/* %s: %d bytes = %d-byte prefix + mod256 pattern tail */"
        % (name, len(b), start)
    )
    out.append("static const u8 %s_prefix[] = {%s};" % (name, hexlist(b[:start])))
    out.append("#define %s_PREFIX_LEN %d" % (name.upper(), start))
    out.append("#define %s_TOTAL_LEN %d" % (name.upper(), len(b)))
    compact.append(name)


def compact_start(b):
    return pattern_start(b) if len(b) > 1024 else None  # big but no pattern: emit full


def emit_bytes(ctx, name, hex_str):
    b = bytes.fromhex(hex_str)
    start = compact_start(b)
    if start is not None:
        return emit_compact(ctx, name, b, start)
    emit_full(ctx, name, b)


def emit_full(ctx, name, b):
    ctx[0].append("static const u8 %s[] = {%s};" % (name, hexlist(b) or "0"))
    ctx[0].append("#define %s_LEN %d" % (name.upper(), len(b)))


def emit_typeonly(ctx, group, v):
    up = cname(v["name"]).upper()
    ctx[0].append(
        "#define G_MOQT_%s_%s_TYPE 0x%02x" % (group.upper(), up, as_int(v["type"]))
    )
    ctx[0].append(
        "#define G_MOQT_%s_%s_OP %d" % (group.upper(), up, TYPEONLY_OP.get(v["op"], 1))
    )


def extra_data(ctx, n, v):
    # Per-draft data variants (e.g. a fetch stream with a draft-22-only
    # marker): bytes only, suffixed _Dnn.
    for ver, vv in sorted(v.get("versions", {}).items()):
        emit_bytes(ctx, "%s_d%s" % (n, ver), vv["hex"])


def extra_varint(ctx, n, v):
    up = cname(v["name"]).upper()
    ctx[0].append("#define G_MOQT_VARINT_%s_OP %d" % (up, VARINT_OP[v["op"]]))
    if "value" in v:
        ctx[0].append("#define G_MOQT_VARINT_%s_VALUE %sULL" % (up, v["value"]))


def extra_ctl(ctx, n, v):
    up = cname(v["name"]).upper()
    ctx[0].append("#define G_MOQT_CTL_%s_TYPE 0x%xULL" % (up, as_int(v["type"])))
    ctx[0].append("#define G_MOQT_CTL_%s_MSG_LEN %d" % (up, v["msg_len"]))
    # Per-draft wire variants (versions: {"18": {...}, "22": {...}}):
    # bytes that differ by draft get their own array + LEN/MSG_LEN,
    # suffixed _Dnn. Drafts with no entry share the array above.
    for ver, vv in sorted(v.get("versions", {}).items()):
        emit_bytes(ctx, "%s_d%s" % (n, ver), vv["hex"])
        ctx[0].append("#define G_MOQT_CTL_%s_D%s_MSG_LEN %d" % (up, ver, vv["msg_len"]))


def extra_none(ctx, n, v):
    pass


EXTRA = {"data": extra_data, "varint": extra_varint, "ctl": extra_ctl}


def emit_entry(ctx, group, v):
    if "hex" not in v:
        return emit_typeonly(ctx, group, v)
    n = "g_moqt_%s_%s" % (group, cname(v["name"]))
    emit_bytes(ctx, n, v["hex"])
    EXTRA.get(group, extra_none)(ctx, n, v)


def header(d):
    return [
        "/* Generated from examples/moqt_chat/testvectors/moqt_golden.json.",
        " * Do not edit by hand: edit the JSON, then regenerate",
        " * (python3 scripts/gen_moqt_golden.py). Baseline draft: %s;"
        " entries with a 'versions' key also emit _D18/_D22 variants. */"
        % d["meta"]["draft"],
        "#ifndef MOQT_GOLDEN_H",
        "#define MOQT_GOLDEN_H",
    ]


def emit_groups(ctx, d):
    for group in GROUPS:
        ctx[0].extend(["", "/* === %s === */" % group])
        for v in d[group]:
            emit_entry(ctx, group, v)


def main(argv):
    d = json.load(open("examples/moqt_chat/testvectors/moqt_golden.json"))
    ctx = (header(d), [])
    emit_groups(ctx, d)
    out, compact = ctx
    out.extend(["", "#endif /* MOQT_GOLDEN_H */"])
    outpath = (argv[1:] or ["tests/app/moqt_golden.h"])[0]
    open(outpath, "w").write("\n".join(out) + "\n")
    print("written to", outpath, "lines:", len(out), "compact:", compact)


if __name__ == "__main__":
    main(sys.argv)
