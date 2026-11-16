import struct, sys

class Meta:
    def __init__(self, path):
        d = open(path,'rb').read(); self.d = d
        pe = struct.unpack_from('<I', d, 0x3c)[0]
        nsec = struct.unpack_from('<H', d, pe+6)[0]
        optsz = struct.unpack_from('<H', d, pe+20)[0]
        opt = pe+24
        magic = struct.unpack_from('<H', d, opt)[0]
        ddoff = opt + (96 if magic==0x10b else 112)
        clirva = struct.unpack_from('<I', d, ddoff+14*8)[0]
        secs=[]; so = opt+optsz
        for i in range(nsec):
            vs,va,rs,rp = struct.unpack_from('<IIII', d, so+i*40+8)
            secs.append((va,vs,rp,rs))
        def r2o(rva):
            for va,vs,rp,rs in secs:
                if va<=rva<va+max(vs,rs): return rva-va+rp
            raise ValueError
        cli = r2o(clirva)
        mdrva = struct.unpack_from('<I', d, cli+8)[0]
        md = r2o(mdrva); self.md=md
        vlen = struct.unpack_from('<I', d, md+12)[0]
        p = md+16+vlen+2
        ns = struct.unpack_from('<H', d, p)[0]; p+=2
        self.streams={}
        for _ in range(ns):
            off,sz = struct.unpack_from('<II', d, p); p+=8
            e = d.index(b'\0', p); name=d[p:e].decode(); 
            p = (e+1+3)&~3
            self.streams[name]=(md+off,sz)
        self.parse_tables()
    def S(self, i):
        o,_=self.streams['#Strings']; e=self.d.index(b'\0', o+i); return self.d[o+i:e].decode('utf8')
    def B(self, i):
        o,_=self.streams['#Blob']; p=o+i; b=self.d[p]
        if b<0x80: n=b; p+=1
        elif b<0xC0: n=((b&0x3f)<<8)|self.d[p+1]; p+=2
        else: n=((b&0x1f)<<24)|(self.d[p+1]<<16)|(self.d[p+2]<<8)|self.d[p+3]; p+=4
        return self.d[p:p+n]
    def parse_tables(self):
        d=self.d; o,_=self.streams['#~']
        heap = d[o+6]; valid = struct.unpack_from('<Q', d, o+8)[0]
        p=o+24; rows={}
        for t in range(64):
            if valid>>t&1: rows[t]=struct.unpack_from('<I', d, p)[0]; p+=4
        self.rows=rows
        sS=4 if heap&1 else 2; sG=4 if heap&2 else 2; sB=4 if heap&4 else 2
        def idx(t): return 4 if rows.get(t,0)>=65536 else 2
        def coded(bits, tabs):
            m=max(rows.get(t,0) for t in tabs if t is not None)
            return 4 if m >= (1<<(16-bits)) else 2
        TDR=coded(2,[2,1,0x1B]); HC=coded(2,[4,8,0x17])
        HCA=coded(5,[6,4,1,2,8,9,0xA,0,0xE,0x17,0x14,0x11,0x1A,0x1B,0x20,0x23,0x26,0x27,0x28,0x2A,0x2C,0x2B])
        HFM=coded(1,[4,8]); HDS=coded(2,[2,6,0x20]); MRP=coded(3,[2,1,0x1A,6,0x1B])
        HS=coded(1,[0x14,0x17]); MDR=coded(1,[6,0xA]); MF=coded(1,[4,6]); IMP=coded(2,[0x26,0x23,0x27])
        CAT=coded(3,[None,None,6,0xA,None]); RS=coded(2,[0,0x1A,0x23,1]); TMD=coded(1,[2,6])
        S_,G_,B_='S','G','B'
        sch={
         0:[('Gen',2),('Name',sS),('Mvid',sG),('EncId',sG),('EncBase',sG)],
         1:[('Scope',RS),('Name',sS),('Namespace',sS)],
         2:[('Flags',4),('Name',sS),('Namespace',sS),('Extends',TDR),('FieldList',idx(4)),('MethodList',idx(6))],
         3:[('F',idx(4))],
         4:[('Flags',2),('Name',sS),('Sig',sB)],
         5:[('M',idx(6))],
         6:[('RVA',4),('Impl',2),('Flags',2),('Name',sS),('Sig',sB),('ParamList',idx(8))],
         7:[('P',idx(8))],
         8:[('Flags',2),('Seq',2),('Name',sS)],
         9:[('Class',idx(2)),('Iface',TDR)],
         0xA:[('Class',MRP),('Name',sS),('Sig',sB)],
         0xB:[('Type',1),('Pad',1),('Parent',HC),('Value',sB)],
         0xC:[('Parent',HCA),('Type',CAT),('Value',sB)],
         0xD:[('Parent',HFM),('NT',sB)],
         0xE:[('Act',2),('Parent',HDS),('PS',sB)],
         0xF:[('Pack',2),('Size',4),('Parent',idx(2))],
         0x10:[('Off',4),('Field',idx(4))],
         0x11:[('Sig',sB)],
         0x12:[('Parent',idx(2)),('EventList',idx(0x14))],
         0x13:[('E',idx(0x14))],
         0x14:[('Flags',2),('Name',sS),('Type',TDR)],
         0x15:[('Parent',idx(2)),('PropList',idx(0x17))],
         0x16:[('P',idx(0x17))],
         0x17:[('Flags',2),('Name',sS),('Type',sB)],
         0x18:[('Sem',2),('Method',idx(6)),('Assoc',HS)],
         0x19:[('Class',idx(2)),('Body',MDR),('Decl',MDR)],
         0x1A:[('Name',sS)],
         0x1B:[('Sig',sB)],
         0x1C:[('Flags',2),('Fwd',MF),('Name',sS),('Scope',idx(0x1A))],
         0x1D:[('RVA',4),('Field',idx(4))],
         0x1E:[('Tok',4),('Func',4)],
         0x1F:[('Tok',4)],
         0x20:[('Hash',4),('Maj',2),('Min',2),('Bld',2),('Rev',2),('Flags',4),('Key',sB),('Name',sS),('Culture',sS)],
         0x21:[('P',4)],
         0x22:[('A',4),('B',4),('C',4)],
         0x23:[('Maj',2),('Min',2),('Bld',2),('Rev',2),('Flags',4),('Key',sB),('Name',sS),('Culture',sS),('Hash',sB)],
         0x24:[('P',4),('Ref',idx(0x23))],
         0x25:[('A',4),('B',4),('C',4),('Ref',idx(0x23))],
         0x26:[('Flags',4),('Name',sS),('Hash',sB)],
         0x27:[('Flags',4),('TypeDefId',4),('Name',sS),('Namespace',sS),('Impl',IMP)],
         0x28:[('Off',4),('Flags',4),('Name',sS),('Impl',IMP)],
         0x29:[('Nested',idx(2)),('Encl',idx(2))],
         0x2A:[('Num',2),('Flags',2),('Owner',TMD),('Name',sS)],
         0x2B:[('Method',MDR),('Inst',sB)],
         0x2C:[('Owner',idx(0x2A)),('Constraint',TDR)],
        }
        self.T={}
        for t in range(64):
            if t not in rows: continue
            cols=sch[t]; lst=[]
            for _ in range(rows[t]):
                row={}
                for n,sz in cols:
                    row[n]=int.from_bytes(d[p:p+sz],'little'); p+=sz
                lst.append(row)
            self.T[t]=lst
        self.TDR=TDR

    def tdr(self, v):
        tag=v&3; i=v>>2
        return [(2,i),(1,i),(0x1B,i)][tag]
    def typename(self, tab, i):
        if i==0: return None
        if tab==2:
            r=self.T[2][i-1]; return (self.S(r['Namespace']), self.S(r['Name']))
        if tab==1:
            r=self.T[1][i-1]; return (self.S(r['Namespace']), self.S(r['Name']))
        return None
    def types(self):
        out=[]
        T=self.T[2]; nf=len(self.T.get(4,[])); nprops=len(self.T.get(0x17,[]))
        pm={}
        for r in self.T.get(0x15,[]): pm[r['Parent']]=r['PropList']
        for i,r in enumerate(T):
            f0=r['FieldList']; f1=T[i+1]['FieldList'] if i+1<len(T) else nf+1
            t=dict(ns=self.S(r['Namespace']),name=self.S(r['Name']),flags=r['Flags'],
                   ext=self.typename(*self.tdr(r['Extends'])) if r['Extends'] else None,
                   fields=[(self.S(self.T[4][k-1]['Name']),self.T[4][k-1]['Flags'],self.B(self.T[4][k-1]['Sig'])) for k in range(f0,f1)])
            if (i+1) in pm:
                p0=pm[i+1]; nxt=[v for k,v in pm.items() if k>i+1]
                p1=min(nxt) if nxt else nprops+1
                t['props']=[(self.S(self.T[0x17][k-1]['Name']),self.B(self.T[0x17][k-1]['Type'])) for k in range(p0,p1)]
            else: t['props']=[]
            out.append(t)
        return out

# signature decoding
def read_compressed(b,p):
    x=b[p]
    if x<0x80: return x,p+1
    if x<0xC0: return ((x&0x3f)<<8)|b[p+1],p+2
    return ((x&0x1f)<<24)|(b[p+1]<<16)|(b[p+2]<<8)|b[p+3],p+4

PRIM={1:'Void',2:'Boolean',3:'Char',4:'SByte',5:'Byte',6:'Int16',7:'UInt16',8:'Int32',9:'UInt32',10:'Int64',11:'UInt64',12:'Single',13:'Double',14:'String',0x16:'TypedReference',0x18:'IntPtr',0x19:'UIntPtr',0x1c:'Object'}
def decode_type(m,b,p):
    """returns (type_tree, newpos). type_tree: dict(kind=prim|class|valuetype|generic|sz|var, ...)"""
    t=b[p]; p+=1
    if t in PRIM: return {'k':'prim','n':PRIM[t]},p
    if t in (0x11,0x12):
        v,p=read_compressed(b,p); tab,i=m.tdr(v<<0 if False else v)
        return {'k':'valuetype' if t==0x11 else 'class','n':m.typename(tab,i),'ref':(tab,i)},p
    if t==0x15:
        base,p=decode_type(m,b,p); n,p=read_compressed(b,p); args=[]
        for _ in range(n):
            a,p=decode_type(m,b,p); args.append(a)
        return {'k':'generic','base':base,'args':args},p
    if t==0x1d:
        e,p=decode_type(m,b,p); return {'k':'sz','e':e},p
    if t==0x13:
        n,p=read_compressed(b,p); return {'k':'var','n':n},p
    if t in (0x1f,0x20): # modreq/modopt
        v,p=read_compressed(b,p); return decode_type(m,b,p)
    raise ValueError(f'unsupported sig {t:#x}')
def field_type(m,sig):
    assert sig[0]==6
    return decode_type(m,sig,1)[0]
def prop_type(m,sig):
    p=1; _,p=read_compressed(sig,p)  # param count
    return decode_type(m,sig,p)[0]
