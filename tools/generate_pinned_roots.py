"""Build a real-DER lookup experiment from the unchanged, hash-pinned PEM."""
from pathlib import Path
import base64,hashlib,json,re
R=Path(__file__).resolve().parents[1]
P=R/'certificates/cacert-2026-10-20.pem'
assert hashlib.sha256(P.read_bytes()).hexdigest()=='796f1389bfea13c0ed78f663b765baaff54a508e5483786bd6ece73c5e3e3cbe'
def tlv(b,i):
 start=i;tag=b[i];i+=1;n=b[i];i+=1
 if n&128:
  k=n&127;assert 0<k<=4;n=int.from_bytes(b[i:i+k],'big');i+=k
 assert i+n<=len(b)
 return tag,i,i+n,start
def children(b,start,end):
 while start<end:
  t,a,z,s=tlv(b,start);yield t,a,z,s;start=z
 assert start==end
def cn_of(der):
 _,a,z,_=tlv(der,0);_,a,z,_=tlv(der,a);fields=list(children(der,a,z))
 # optional explicit version precedes serial, signature, issuer, validity, subject
 idx=5 if fields[0][0]==0xa0 else 4
 _,a,z,_=fields[idx]
 for _,ra,rz,_ in children(der,a,z):
  for _,aa,az,_ in children(der,ra,rz):
   attrs=list(children(der,aa,az));ot,oa,oz,_=attrs[0];vt,va,vz,_=attrs[1]
   if der[oa:oz]==b'\x55\x04\x03':return der[va:vz]
 return b''
def arr(name,b):return 'static const unsigned char '+name+'[] = {'+','.join(str(x) for x in b)+'};\n'
blocks=re.findall(rb'-----BEGIN CERTIFICATE-----\s*(.*?)-----END CERTIFICATE-----',P.read_bytes(),re.S)
assert len(blocks)==118
out=[];rows=[];manifest=[]
for i,b in enumerate(blocks):
 der=base64.b64decode(b);cn=cn_of(der);out.append(arr(f'root_{i}',der))
 if cn:out.append(arr(f'cn_{i}',cn))
 rows.append('{root_%d,sizeof(root_%d),%s,%d}'%(i,i,f'cn_{i}' if cn else 'NULL',len(cn)))
 manifest.append(dict(index=i,sha256=hashlib.sha256(der).hexdigest(),bytes=len(der),cn_hex=cn.hex()))
# CN is an overinclusive prefilter, never the trust decision. Native SDK checks full DN.
nocn=sum(not x['cn_hex'] for x in manifest)
groups={}
for x in manifest:
 cn=bytes.fromhex(x['cn_hex']).lower()
 if cn:groups.setdefault(cn,[]).append(x)
cap=max([nocn]+[len(v)+nocn for v in groups.values()])
bytecap=max([sum(x['bytes'] for x in manifest if not x['cn_hex'])]+[sum(x['bytes'] for x in v)+sum(x['bytes'] for x in manifest if not x['cn_hex']) for v in groups.values()])
out.append('static const root_entry roots[] = {\n'+',\n'.join(rows)+'\n};\n')
out.append(f'#define ROOT_COUNT 118\n#define ROOT_CANDIDATE_CAP {cap}\n#define ROOT_DER_CAP {bytecap}\n')
(R/'components/pinned_roots').mkdir(exist_ok=True)
(R/'components/pinned_roots/roots.inc').write_text(''.join(out))
(R/'components/pinned_roots/root-identities.json').write_text(json.dumps(dict(pem_sha256=hashlib.sha256(P.read_bytes()).hexdigest(),candidate_cap=cap,candidate_der_cap=bytecap,no_cn=nocn,der_bytes=sum(x['bytes'] for x in manifest),roots=manifest),indent=2))
print('roots',len(manifest),'DER bytes',sum(x['bytes'] for x in manifest),'max candidates',cap,'max candidate DER bytes',bytecap,'no CN',nocn)
