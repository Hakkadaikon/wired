#!/usr/bin/env python3
"""Generate tests/app/moqt_golden.h from examples/moqt_chat/testvectors/moqt_golden.json."""
import json
import sys
d = json.load(open('examples/moqt_chat/testvectors/moqt_golden.json'))
def cname(s): return ''.join(c if c.isalnum() else '_' for c in s)
out = []
out.append("/* Generated from examples/moqt_chat/testvectors/moqt_golden.json.")
out.append(" * Do not edit by hand: edit the JSON, then regenerate")
out.append(" * (python3 scripts/gen_moqt_golden.py). Draft: %s. */" % d['meta']['draft'])
out.append("#ifndef MOQT_GOLDEN_H")
out.append("#define MOQT_GOLDEN_H")
compact = []
def emit_bytes(name, hex_str):
    b = bytes.fromhex(hex_str)
    if len(b) > 1024:
        for start in range(0, min(64, len(b))):
            tail = b[start:]
            if all(tail[i] == (i % 256) for i in range(len(tail))):
                out.append("/* %s: %d bytes = %d-byte prefix + mod256 pattern tail */" % (name, len(b), start))
                pre = ', '.join('0x%02x' % x for x in b[:start])
                out.append("static const u8 %s_prefix[] = {%s};" % (name, pre))
                out.append("#define %s_PREFIX_LEN %d" % (name.upper(), start))
                out.append("#define %s_TOTAL_LEN %d" % (name.upper(), len(b)))
                compact.append(name)
                return
        body = ', '.join('0x%02x' % x for x in b)  # big but no pattern: emit full
    else:
        body = ', '.join('0x%02x' % x for x in b)
    out.append("static const u8 %s[] = {%s};" % (name, body if body else '0'))
    out.append("#define %s_LEN %d" % (name.upper(), len(b)))
for group in ['varint', 'kvp', 'ctl', 'data', 'name']:
    out.append("")
    out.append("/* === %s === */" % group)
    for v in d[group]:
        n = "g_moqt_%s_%s" % (group, cname(v['name']))
        if 'hex' not in v:
            up = cname(v['name']).upper()
            tv = int(v['type'], 0) if isinstance(v['type'], str) else v['type']
            out.append("#define G_MOQT_%s_%s_TYPE 0x%02x" % (group.upper(), up, tv))
            out.append("#define G_MOQT_%s_%s_OP %d" % (group.upper(), up, 0 if v['op'] in ('accept', 'decode') else 1))
            continue
        emit_bytes(n, v['hex'])
        if group == 'varint':
            up = cname(v['name']).upper()
            out.append("#define G_MOQT_VARINT_%s_OP %d" % (up, {'decode': 0, 'encode': 1, 'reject': 2}[v['op']]))
            if 'value' in v:
                out.append("#define G_MOQT_VARINT_%s_VALUE %sULL" % (up, v['value']))
        if group == 'ctl':
            up = cname(v['name']).upper()
            out.append("#define G_MOQT_CTL_%s_TYPE 0x%xULL" % (up, int(v['type'], 0) if isinstance(v['type'], str) else v['type']))
            out.append("#define G_MOQT_CTL_%s_MSG_LEN %d" % (up, v['msg_len']))
out.append("")
out.append("#endif /* MOQT_GOLDEN_H */")
outpath = sys.argv[1] if len(sys.argv) > 1 else 'tests/app/moqt_golden.h'
open(outpath, 'w').write('\n'.join(out) + '\n')
print("written to", outpath, "lines:", len(out), "compact:", compact)
