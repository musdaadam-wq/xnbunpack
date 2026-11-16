import struct, re, sys, json
sys.path.insert(0,'/home/claude/tools')
from dotnet_meta import *
from lzx import decompress_xnb_payload

class Model:
    def __init__(self, dll_paths):
        self.metas=[]; self.types={}
        for p in dll_paths:
            m=Meta(p); self.metas.append(m)
            # accessor visibility
            md=m.T.get(6,[])
            sem={}
            for r in m.T.get(0x18,[]):
                if r['Assoc']&1==1:
                    prop=r['Assoc']>>1
                    meth=md[r['Method']-1]
                    pub=(meth['Flags']&7)==6
                    sem.setdefault(prop,{})['set' if r['Sem']&1 else 'get']=pub
            # properties index
            pidx=0
            ts=m.types()
            propcount={}
            T=m.T[2]; pm={}
            for r in m.T.get(0x15,[]): pm[r['Parent']]=r['PropList']
            for i,t in enumerate(ts):
                t['meta']=m
                if (i+1) in pm:
                    p0=pm[i+1]
                    t['prop_ids']=list(range(p0,p0+len(t['props'])))
                else: t['prop_ids']=[]
                t['sem']=sem
                t['idx']=i+1
                full=(t['ns']+'.' if t['ns'] else '')+t['name']
                self.types[full]=t
            nest={r['Nested']:r['Encl'] for r in m.T.get(0x29,[])}
            for t in ts:
                if t['idx'] in nest:
                    e=ts[nest[t['idx']]-1]; 
                    self.types[(e['ns']+'.' if e['ns'] else '')+e['name']+'+'+t['name']]=t
        # nested types: map names
    def is_value_type(self, ty):
        k=ty['k']
        if k=='prim': return ty['n']!='String' and ty['n']!='Object'
        if k=='valuetype': return True
        if k=='generic': return ty['base']['k']=='valuetype'
        return False
    def attrs(self, t, tag, idx):
        m=t['meta']
        if not hasattr(m,'_ca'):
            ca={}
            for r in m.T.get(0xC,[]):
                ctype=r['Type']&7; cidx=r['Type']>>3
                if ctype!=3: continue
                mr=m.T[0xA][cidx-1]; cls=mr['Class']; ct=cls&7; ci=cls>>3
                if ct not in (1,2): continue
                nm=m.typename(ct,ci)
                ca.setdefault((r['Parent']&31, r['Parent']>>5),[]).append((nm[1], m.B(r['Value'])))
            m._ca=ca
        return m._ca.get((tag,idx),[])
    def members(self, t, order='pf'):
        m=t['meta']
        f0=m.T[2][t['idx']-1]['FieldList']
        props=[]
        for (name,sig),pid in zip(t['props'],t['prop_ids']):
            a=self.attrs(t,9,pid); names=[x[0] for x in a]
            if 'ContentSerializerIgnoreAttribute' in names: continue
            s=t['sem'].get(pid,{})
            has=('ContentSerializerAttribute' in names)
            if (s.get('get') and s.get('set')) or (has and ('get' in s or 'set' in s)):
                props.append((name,prop_type(m,sig),'prop'))
        fields=[]
        for k,(name,flags,sig) in enumerate(t['fields']):
            if (flags&0x10) or (flags&0x40): continue   # static / literal
            a=[x[0] for x in self.attrs(t,1,f0+k)]
            if 'ContentSerializerIgnoreAttribute' in a: continue
            if (flags&7)==6 or 'ContentSerializerAttribute' in a:
                fields.append((name,field_type(m,sig),'field'))
        return props+fields if order=='pf' else fields+props

def tyname(ty):
    n=ty['n']; return n[0]+'.'+n[1] if n[0] else n[1]

class XnbDoc:
    def __init__(self, path):
        d=open(path,'rb').read()
        assert d[:3]==b'XNB'
        flags=d[5]; size=int.from_bytes(d[6:10],'little')
        if flags&0x80:
            dec=int.from_bytes(d[10:14],'little'); b=decompress_xnb_payload(d[14:],dec)
        else: b=d[10:]
        self.b=b; self.p=0
        self.readers=[]
        n=self.r7()
        for _ in range(n):
            nm=self.rstr(); ver=self.i32(); self.readers.append(nm)
        self.shared=self.r7()
    def r7(self):
        v=0; s=0
        while True:
            x=self.b[self.p]; self.p+=1; v|=(x&0x7f)<<s; s+=7
            if x<0x80: return v
    def i32(self): v=struct.unpack_from('<i',self.b,self.p)[0]; self.p+=4; return v
    def rstr(self):
        n=self.r7(); s=self.b[self.p:self.p+n].decode('utf8'); self.p+=n; return s

def parse_reader_name(nm):
    # returns (kind, [typeargs as strings])
    m=re.match(r'^([\w\.]+?)(`\d+)?(\[\[.*\]\])?(,|$)',nm)
    base=m.group(1).split('.')[-1]
    args=[]
    if m.group(3):
        inner=m.group(3)[1:-1]
        depth=0; cur=''
        for ch in inner:
            if ch=='[': depth+=1; 
            if ch==']': depth-=1
            cur+=ch
            if depth==0 and ch==']':
                args.append(cur[1:-1]); cur=''
            elif depth==0 and ch==',': cur=''
    return base,[a.split(',')[0].strip() for a in args]


class Reader:
    def __init__(self, model, doc, order='pf'):
        self.m=model; self.doc=doc; self.order=order
        self.info=[parse_reader_name(n) for n in doc.readers]
        self.trace=[]
    def read_prim(self,n):
        d=self.doc
        fm={'Int32':'<i','Boolean':'<?','Single':'<f','Double':'<d','Byte':'<B','SByte':'<b','Int16':'<h','UInt16':'<H','UInt32':'<I','Int64':'<q','UInt64':'<Q'}
        if n=='String':
            ln=d.r7(); s=d.b[d.p:d.p+ln].decode('utf8'); d.p+=ln; return s
        if n=='Char':
            c=d.b[d.p]; d.p+=1; return chr(c)
        f=fm[n]; v=struct.unpack_from(f,d.b,d.p)[0]; d.p+=struct.calcsize(f); return v
    def read_obj_typed(self, ty):
        """read value of declared type ty, handling ref-type prefix"""
        if self.m.is_value_type(ty): return self.read_value(ty)
        tid=self.doc.r7()
        if tid==0: return None
        base,args=self.info[tid-1]
        return self.read_by_reader(base,args)
    def read_by_reader(self, base, args):
        d=self.doc
        if base.endswith('Reader') and base[:-6] in ('Int32','Boolean','Single','Double','Byte','SByte','Int16','UInt16','UInt32','Int64','UInt64','String','Char'):
            return self.read_prim(base[:-6])
        if base=='Vector2Reader': return [self.read_prim('Single') for _ in range(2)]
        if base=='PointReader': return [self.read_prim('Int32') for _ in range(2)]
        if base=='RectangleReader': return [self.read_prim('Int32') for _ in range(4)]
        if base=='ListReader':
            n=d.i32(); et=self.type_from_name(args[0]); return [self.read_obj_typed(et) for _ in range(n)]
        if base=='DictionaryReader':
            n=d.i32(); kt=self.type_from_name(args[0]); vt=self.type_from_name(args[1])
            out=[]
            for _ in range(n):
                k=self.read_obj_typed(kt); v=self.read_obj_typed(vt); out.append((k,v))
            return out
        if base=='NullableReader':
            has=self.read_prim('Boolean')
            return self.read_obj_typed(self.type_from_name(args[0])) if has else None
        if base=='EnumReader': return self.read_prim('Int32')
        if base=='ReflectiveReader': return self.read_class(args[0])
        raise NotImplementedError(base)
    def type_from_name(self, nm):
        if nm.startswith('System.'):
            short=nm.split('.')[-1]
            vt={'Int32','Boolean','Single','Double','Byte','SByte','Int16','UInt16','UInt32','Int64','UInt64','Char'}
            return {'k':'prim','n':short} if short in vt|{'String','Object'} else {'k':'valuetype','n':('System',short),'sysname':nm}
        if nm in ('Microsoft.Xna.Framework.Vector2','Microsoft.Xna.Framework.Point','Microsoft.Xna.Framework.Rectangle'):
            return {'k':'valuetype','n':('Microsoft.Xna.Framework',nm.split('.')[-1]),'xna':True}
        t=self.m.types[nm]
        isenum=t['ext']==('System','Enum')
        isvt=isenum or t['ext']==('System','ValueType')
        return {'k':'valuetype' if isvt else 'class','n':(t['ns'],t['name']),'full':nm}
    def read_value(self, ty):
        if ty['k']=='prim': return self.read_prim(ty['n'])
        if ty['k']=='valuetype':
            n=ty['n']
            if n==('Microsoft.Xna.Framework','Vector2'): return [self.read_prim('Single') for _ in range(2)]
            if n==('Microsoft.Xna.Framework','Point'): return [self.read_prim('Int32') for _ in range(2)]
            if n==('Microsoft.Xna.Framework','Rectangle'): return [self.read_prim('Int32') for _ in range(4)]
            full=(n[0]+'.' if n[0] else '')+n[1]
            t=self.m.types.get(full)
            if t and t['ext']==('System','Enum'): return self.read_prim('Int32')
            raise NotImplementedError('valuetype '+str(n))
        if ty['k']=='generic':
            b=ty['base']['n']
            if b==('System','Nullable`1'):
                has=self.read_prim('Boolean'); return self.read_value_or_obj(ty['args'][0]) if has else None
        raise NotImplementedError(str(ty))
    def read_value_or_obj(self,ty): return self.read_obj_typed(self.sigtype_to_ty(ty))
    def sigtype_to_ty(self,ty): return ty
    def read_class(self, full):
        return self.read_class_members(self.m.types[full],full)
    def read_class_members(self,t,full):
        out={}
        if t['ext'] and t['ext']!=('System','Object'):
            bn=(t['ext'][0]+'.' if t['ext'][0] else '')+t['ext'][1]
            if bn in self.m.types: out.update(self.read_class_members(self.m.types[bn],bn))
        for name,ty,kind in self.m.members(t,self.order):
            self.trace.append((full,name,self.doc.p))
            out[name]=self.read_obj_typed(self.sig_resolve(ty))
        return out
    def sig_resolve(self, ty):
        k=ty['k']
        if k=='class' or k=='valuetype':
            n=ty['n']
            full=(n[0]+'.' if n[0] else '')+n[1]
            # nested types appear as TypeDef w/ no ns: find by name match
            if ty['k']=='class' and n[0]=='' :
                pass
            if full in self.m.types:
                t=self.m.types[full]
                isvt= t['ext'] in (('System','Enum'),('System','ValueType'))
                return {'k':'valuetype' if isvt else 'class','n':n,'full':full}
            if n[0]=='System' and n[1]=='String': return {'k':'prim','n':'String'}
            return ty
        if k=='generic':
            return {'k':'generic','base':ty['base'],'args':[self.sig_resolve(a) for a in ty['args']]}
        return ty
