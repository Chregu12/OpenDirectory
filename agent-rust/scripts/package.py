#!/usr/bin/env python3
"""Package one verified native agent; never label host code as another architecture."""
import argparse, gzip, hashlib, io, json, os, pathlib, re, struct, tarfile, zipfile
ROOT=pathlib.Path(__file__).resolve().parents[1]
TARGETS={'x86_64-unknown-linux-gnu':('linux','x86_64'),'aarch64-unknown-linux-gnu':('linux','aarch64'),'x86_64-apple-darwin':('macos','x86_64'),'aarch64-apple-darwin':('macos','aarch64'),'x86_64-pc-windows-msvc':('windows','x86_64')}
def identity(data):
 if data[:4]==b'\x7fELF' and data[4:6]==b'\x02\x01':return ('linux',{62:'x86_64',183:'aarch64'}.get(struct.unpack_from('<H',data,18)[0]))
 if data[:4]==b'\xcf\xfa\xed\xfe':return ('macos',{0x01000007:'x86_64',0x0100000c:'aarch64'}.get(struct.unpack_from('<I',data,4)[0]))
 if data[:2]==b'MZ':
  offset=struct.unpack_from('<I',data,60)[0]
  if data[offset:offset+4]==b'PE\0\0':return ('windows',{0x8664:'x86_64'}.get(struct.unpack_from('<H',data,offset+4)[0]))
 raise ValueError('Unsupported executable header')
def package(binary,target,output,commit,epoch):
 if target not in TARGETS or not re.fullmatch('[a-f0-9]{40}',commit):raise ValueError('Exact supported target and source commit required')
 version=re.search(r'\nversion = "([0-9]+\.[0-9]+\.[0-9]+)"', (ROOT/'Cargo.toml').read_text()).group(1)
 raw=binary.read_bytes();platform,architecture=TARGETS[target]
 if identity(raw)!=(platform,architecture):raise ValueError('Binary architecture/platform does not match package target')
 name=f'opendirectory-agent-{version}-{platform}-{architecture}';filename='od-agent-service'+('.exe' if platform=='windows' else '')
 manifest={'schemaVersion':1,'version':version,'platform':platform,'architecture':architecture,'target':target,'sourceCommit':commit,'binary':filename,'binarySha256':hashlib.sha256(raw).hexdigest(),'osCodeSigning':'not-configured','minimumServerVersion':'1.0.48','linuxRuntime':'glibc 2.39 or newer and OpenSSL 3 runtime libraries' if platform=='linux' else None}
 files={filename:(raw,0o755),'manifest.json':((json.dumps(manifest,indent=2)+'\n').encode(),0o644),'README.md':((ROOT/'PACKAGE-README.md').read_bytes(),0o644)}
 output.mkdir(parents=True,exist_ok=True)
 if platform=='windows':
  path=output/(name+'.zip')
  with zipfile.ZipFile(path,'w',compression=zipfile.ZIP_DEFLATED) as archive:
   for key,(data,mode) in files.items():
    info=zipfile.ZipInfo(key,(2026,1,1,0,0,0));info.external_attr=(mode|0o100000)<<16;info.compress_type=zipfile.ZIP_DEFLATED;archive.writestr(info,data)
 else:
  path=output/(name+'.tar.gz')
  with path.open('wb') as dest,gzip.GzipFile(filename='',mode='wb',fileobj=dest,mtime=epoch) as compressed,tarfile.open(fileobj=compressed,mode='w') as archive:
   for key,(data,mode) in files.items():
    info=tarfile.TarInfo(key);info.size=len(data);info.mode=mode;info.mtime=epoch;info.uid=info.gid=0;info.uname=info.gname='';archive.addfile(info,io.BytesIO(data))
 digest=hashlib.sha256(path.read_bytes()).hexdigest();(output/(path.name+'.sha256')).write_text(digest+'  '+path.name+'\n');return path
if __name__=='__main__':
 parser=argparse.ArgumentParser();parser.add_argument('--binary',required=True,type=pathlib.Path);parser.add_argument('--target',required=True,choices=TARGETS);parser.add_argument('--output',type=pathlib.Path,default=ROOT/'dist');parser.add_argument('--commit',required=True);parser.add_argument('--epoch',type=int,required=True);args=parser.parse_args();print(package(args.binary,args.target,args.output,args.commit,args.epoch))
