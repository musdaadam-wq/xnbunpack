#!/usr/bin/env python3
"""Generate xnb.js custom schemes (Stardew Valley 1.6+) straight from StardewValley.GameData.dll.

usage: python gen_schemes.py path/to/StardewValley.GameData.dll [out_dir]
Writes schemes-1.6.js (ES module) and schemes-1.6.json.
Rules (verified against real 1.6.15 XNBs by verify_xnb.py):
  * members = public get+set properties, then public fields; honours [ContentSerializer]/[ContentSerializerIgnore]
  * base class members come first (flattened into the derived scheme)
  * "$" prefix = reference type (string/class/List/Dictionary/array) or Nullable<T>
  * enums are stored as Int32
"""
import sys, os, json
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from xnbread import Model

PRIMS = {'Int32','String','Boolean','Single','Double','Char','Byte','SByte','Int16','UInt16','UInt32','Int64','UInt64'}
XNA = {'Point','Vector2','Rectangle'}

def full(t): return (t['ns']+'.' if t['ns'] else '')+t['name']

def build(dll):
    m = Model([dll])
    meta = m.metas[0]
    asm = meta.T[0x20][0]
    version = '%d.%d.%d.%d' % (asm['Maj'], asm['Min'], asm['Bld'], asm['Rev'])
    # enclosing names for nested types
    uniq = {}
    for t in m.types.values(): uniq[t['idx']] = t
    ts = [uniq[i] for i in sorted(uniq)]
    nest = {r['Nested']: r['Encl'] for r in meta.T.get(0x29, [])}
    def reflname(t):
        if t['idx'] in nest:
            e = ts[nest[t['idx']]-1]; return reflname(e) + '+' + t['name']
        return full(t)
    by_td = {t['idx']: t for t in ts}
    def resolve(ty):
        """-> TypeDef dict for class/valuetype refs into this dll, else None"""
        tab, i = ty.get('ref', (None, None))
        return by_td.get(i) if tab == 2 else None
    enums = []
    def conv(ty):
        k = ty['k']
        if k == 'prim': return ty['n']
        if k == 'sz': return 'Array<%s>' % conv(ty['e'])
        if k in ('class', 'valuetype'):
            n = ty['n']
            if n[0] == 'Microsoft.Xna.Framework' and n[1] in XNA: return n[1]
            t = resolve(ty)
            if t is None: raise ValueError('unresolved type %r' % (n,))
            if t['ext'] == ('System', 'Enum'):
                rn = reflname(t)
                if rn not in enums: enums.append(rn)
                return 'Int32'
            return reflname(t)
        if k == 'generic':
            b = ty['base']['n']; a = ty['args']
            if b == ('System.Collections.Generic', 'List`1'): return [conv(a[0])]
            if b == ('System.Collections.Generic', 'Dictionary`2'): return {conv(a[0]): conv(a[1])}
            if b == ('System', 'Nullable`1'): return conv(a[0])
        raise ValueError('unsupported type %r' % (ty,))
    def is_ref(ty):
        k = ty['k']
        if k == 'prim': return ty['n'] in ('String', 'Object')
        if k in ('class', 'sz'): return True
        if k == 'valuetype': return False
        if k == 'generic': return ty['base']['n'] != ('System', 'Nullable`1') and ty['base']['k'] == 'class'
        return False
    def is_nullable(ty): return ty['k'] == 'generic' and ty['base']['n'] == ('System', 'Nullable`1')
    def flat_members(t):
        out = []
        if t['ext'] and t['ext'] != ('System', 'Object'):
            bt = m.types.get(full_name(t['ext']))
            if bt: out += flat_members(bt)
        out += m.members(t, 'pf')
        return out
    def full_name(n): return (n[0]+'.' if n[0] else '')+n[1]
    schemes = {}; unsupported = []
    for t in ts:
        if t['name'] == '<Module>' or t['ext'] == ('System', 'Enum') or t['flags'] & 0x20: continue
        if t['ext'] in (('System', 'MulticastDelegate'), ('System', 'Attribute')): continue
        sch = {}
        for name, ty, kind in flat_members(t):
            try: c = conv(ty)
            except ValueError as e:
                unsupported.append((reflname(t), name, str(e))); continue
            key = ('$' + name) if (is_ref(ty) or is_nullable(ty)) else name
            sch[key] = c
        schemes[reflname(t)] = sch
    return version, schemes, sorted(set(enums)), unsupported

def main():
    if len(sys.argv) < 2: sys.exit(__doc__)
    out = sys.argv[2] if len(sys.argv) > 2 else '.'
    version, schemes, enums, unsupported = build(sys.argv[1])
    header = '// Generated from StardewValley.GameData.dll %s by gen_schemes.py\n' % version
    js = header + 'export const schemes = ' + json.dumps(schemes, indent=1) + ';\n\n'
    js += 'export const enums = ' + json.dumps(enums, indent=1) + ';\n\nexport default { schemes, enums };\n'
    open(os.path.join(out, 'schemes-1.6.js'), 'w', encoding='utf8').write(js)
    json.dump({'version': version, 'schemes': schemes, 'enums': enums}, open(os.path.join(out, 'schemes-1.6.json'), 'w'), indent=1)
    print('GameData %s: %d schemes, %d enums' % (version, len(schemes), len(enums)))
    for u in unsupported: print('  skipped member:', u)

if __name__ == '__main__': main()
