# Minimal LZX decoder for XNB (window 2^16). Written from the public LZX spec (as used in CAB / XNB).
import struct
class Bits:
    def __init__(s, data): s.d=data; s.p=0; s.buf=0; s.n=0
    def ensure(s, k):
        while s.n<k:
            w = s.d[s.p]|(s.d[s.p+1]<<8) if s.p+1<len(s.d) else 0
            s.p+=2; s.buf=(s.buf<<16)|w; s.n+=16
    def peek(s,k):
        s.ensure(k); return (s.buf>>(s.n-k))&((1<<k)-1)
    def skip(s,k):
        s.ensure(k); s.n-=k; s.buf&=(1<<s.n)-1
    def read(s,k):
        if k==0: return 0
        v=s.peek(k); s.skip(k); return v
class Huff:
    def __init__(s, lens):
        s.maxb=max(lens) if lens else 0
        # canonical: assign codes by length then symbol
        s.dec={}
        code=0
        for L in range(1,17):
            for sym,l in enumerate(lens):
                if l==L:
                    s.dec[(L,code)]=sym; code+=1
            code<<=1
    def sym(s, br):
        code=0
        for L in range(1,17):
            code=(code<<1)|br.read(1)
            r=s.dec.get((L,code))
            if r is not None: return r
        raise ValueError('bad huffman code')
class LZX:
    def __init__(s, window_bits=16):
        s.slots={15:30,16:32,17:36,18:42,19:50,20:42,21:50}.get(window_bits, window_bits*2)
        s.slots=32 if window_bits==16 else s.slots
        s.eb=[0]*51; s.pb=[0]*51
        j=0
        for i in range(0,51,2):
            s.eb[i]=j
            if i+1<51: s.eb[i+1]=j
            if i!=0 and j<17: j+=1
        j=0
        for i in range(51):
            s.pb[i]=j; j+=1<<s.eb[i]
        s.main_elems=256+s.slots*8
        s.R=[1,1,1]; s.header=False; s.block_remaining=0; s.block_type=0
        s.main=[0]*s.main_elems; s.length=[0]*249
        s.out=bytearray()
    def read_lengths(s, br, tbl, first, last):
        pre=[br.read(4) for _ in range(20)]
        ph=Huff(pre); x=first
        while x<last:
            z=ph.sym(br)
            if z==17:
                y=br.read(4)+4
                for _ in range(y): tbl[x]=0; x+=1
            elif z==18:
                y=br.read(5)+20
                for _ in range(y): tbl[x]=0; x+=1
            elif z==19:
                y=br.read(1)+4
                z=ph.sym(br); z=tbl[x]-z
                if z<0: z+=17
                for _ in range(y): tbl[x]=z; x+=1
            else:
                z=tbl[x]-z
                if z<0: z+=17
                tbl[x]=z; x+=1
    def decode_frame(s, data, frame_size):
        br=Bits(data)
        if not s.header:
            if br.read(1):
                br.read(16); br.read(16)
            s.header=True
        produced=0; out=s.out
        while produced<frame_size:
            if s.block_remaining==0:
                s.block_type=br.read(3)
                hi=br.read(16); lo=br.read(8); s.block_remaining=(hi<<8)|lo
                if s.block_type in (1,2):
                    if s.block_type==2:
                        s.aligned_h=Huff([br.read(3) for _ in range(8)])
                    s.read_lengths(br,s.main,0,256)
                    s.read_lengths(br,s.main,256,s.main_elems)
                    s.read_lengths(br,s.length,0,249)
                    s.main_h=Huff(s.main); s.len_h=Huff(s.length)
                else:
                    raise NotImplementedError('uncompressed lzx block')
            run=min(s.block_remaining, frame_size-produced)
            done=0
            while done<run:
                m=s.main_h.sym(br)
                if m<256:
                    out.append(m); done+=1; continue
                m-=256
                ml=m&7
                if ml==7: ml+=s.len_h.sym(br)
                ml+=2
                slot=m>>3
                if slot==0: off=s.R[0]
                elif slot==1: off=s.R[1]; s.R[1]=s.R[0]; s.R[0]=off
                elif slot==2: off=s.R[2]; s.R[2]=s.R[0]; s.R[0]=off
                else:
                    e=s.eb[slot]
                    if s.block_type==2:
                        if e>3:
                            v=br.read(e-3)<<3; v+=s.aligned_h.sym(br)
                        elif e==3: v=s.aligned_h.sym(br)
                        elif e>0: v=br.read(e)
                        else: v=0
                    else:
                        v=br.read(e) if e>0 else 0
                    off=s.pb[slot]-2+v
                    s.R[2]=s.R[1]; s.R[1]=s.R[0]; s.R[0]=off
                for _ in range(ml):
                    out.append(out[-off])
                done+=ml
            s.block_remaining-=done; produced+=done
            if done!=run: raise ValueError(f'match crossed frame boundary {done} {run}')
        return produced

def decompress_xnb_payload(data, decompressed_size):
    d=LZX(16); p=0; total=0
    while total<decompressed_size and p<len(data):
        if data[p]==0xFF:
            fs=(data[p+1]<<8)|data[p+2]; bs=(data[p+3]<<8)|data[p+4]; p+=5
        else:
            fs=0x8000; bs=(data[p]<<8)|data[p+1]; p+=2
        if bs==0 or fs==0: break
        d.decode_frame(data[p:p+bs], fs); p+=bs; total+=fs
    return bytes(d.out)
