#!/usr/bin/env python3
"""Check generated schemes against real .xnb files (LZX or uncompressed).
usage: python verify_xnb.py schemes-1.6.json file1.xnb [file2.xnb ...]
Decodes each file using ONLY the schemes (the same rules xnb.js applies) and reports whether
every byte was consumed.  A mismatch (or a crash) means a scheme in that file is wrong."""
import sys, os, struct, json
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from xnbread import XnbDoc, parse_reader_name

VALUE = {'Int32':'<i','Boolean':'<?','Single':'<f','Double':'<d','Byte':'<B','SByte':'<b','Int16':'<h','UInt16':'<H','UInt32':'<I','Int64':'<q','UInt64':'<Q','Char':'<B'}
STRUCT = {'Point':2,'Vector2':2,'Rectangle':4}
def is_value(t): return isinstance(t, str) and (t in VALUE or t in STRUCT)

class SchemeReader:
    def __init__(self, schemes, doc):
        self.S = schemes; self.d = doc
    def prim(self, t):
        d = self.d
        if t in VALUE:
            f = VALUE[t]; v = struct.unpack_from(f, d.b, d.p)[0]; d.p += struct.calcsize(f); return v
        if t == 'Point': return [self.prim('Int32') for _ in range(2)]
        if t == 'Rectangle': return [self.prim('Int32') for _ in range(4)]
        if t == 'Vector2': return [self.prim('Single') for _ in range(2)]
        if t == 'String':
            n = d.r7(); s = d.b[d.p:d.p+n].decode('utf8'); d.p += n; return s
        raise ValueError('unknown primitive ' + t)
    def body(self, t):
        d = self.d
        if isinstance(t, list):
            n = d.i32(); return [self.value(t[0]) for _ in range(n)]
        if isinstance(t, dict):
            (kt, vt), = t.items(); n = d.i32()
            return [(self.value(kt), self.value(vt)) for _ in range(n)]
        if t in self.S: return self.obj(t)
        if t.startswith('Array<'):
            n = d.i32(); inner = t[6:-1]; return [self.value(inner) for _ in range(n)]
        return self.prim(t)
    def value(self, t):            # element of a container / declared type
        if is_value(t): return self.prim(t)
        tid = self.d.r7()          # reference type: type-reader id prefix, 0 = null
        return None if tid == 0 else self.body(t)
    def obj(self, name):
        out = {}
        for key, t in self.S[name].items():
            if key.startswith('$'):
                if is_value(t):    # Nullable<T>: bool + value
                    out[key[1:]] = self.prim(t) if self.prim('Boolean') else None
                else: out[key[1:]] = self.value(t)
            else: out[key] = self.value(t)
        return out

def verify(schemes, path):
    doc = XnbDoc(path); r = SchemeReader(schemes, doc)
    info = [parse_reader_name(n) for n in doc.readers]
    tid = doc.r7(); base, args = info[tid-1]
    def top(base, args):
        if base == 'DictionaryReader':
            n = doc.i32(); k, v = args
            def one(nm):
                short = nm.split('.')[-1] if nm.startswith('System.') else nm
                return short
            kt, vt = one(k), one(v); vt = vt if vt in schemes or vt in VALUE or vt == 'String' else vt
            return [(r.value(kt), r.value(vt)) for _ in range(n)]
        if base == 'ListReader':
            n = doc.i32(); return [r.value(args[0]) for _ in range(n)]
        if base == 'ReflectiveReader': return r.obj(args[0])
        raise NotImplementedError(base)
    obj = top(base, args)
    ok = doc.p == len(doc.b)
    return ok, len(doc.b) - doc.p, obj

if __name__ == '__main__':
    if len(sys.argv) < 3: sys.exit(__doc__)
    schemes = json.load(open(sys.argv[1]))['schemes']
    for p in sys.argv[2:]:
        try:
            ok, left, obj = verify(schemes, p)
            print(('OK  ' if ok else 'BAD ') + os.path.basename(p) + ('' if ok else ' (%d bytes unread)' % left) + '  entries=%s' % (len(obj) if hasattr(obj, '__len__') else '?'))
        except Exception as e:
            print('FAIL ' + os.path.basename(p) + ': %s: %s' % (type(e).__name__, e))
