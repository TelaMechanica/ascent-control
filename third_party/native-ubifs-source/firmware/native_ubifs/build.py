#!/usr/bin/env python3
"""Build the GPLv2 inventory helper from pinned mtd-utils sources; no device I/O."""
from pathlib import Path
import sys,shutil,subprocess,hashlib,json
HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[1]
UP=HERE/'upstream'
OUT=Path(sys.argv[1]).resolve() if len(sys.argv)>1 else ROOT/'artifacts/native-windows-builder-2026-11-06/helper/linux'
OUT.mkdir(parents=True,exist_ok=True)
SRC=OUT/'src'
shutil.copytree(UP,SRC,ignore=shutil.ignore_patterns('.git'),dirs_exist_ok=True)
sub=SRC/'ubifs-utils/mkfs.ubifs'
for n in ('inventory.h','inventory.c','main.c'):shutil.copyfile(HERE/n,sub/n)
p=sub/'mkfs.ubifs.c';s=p.read_text()
s=s.replace('#include "mkfs.ubifs.h"','#include "mkfs.ubifs.h"\n#include "inventory.h"')
def replacefn(name,body):
 global s
 import re
 pat=re.compile(r'(?:static )?(?:int|void) '+re.escape(name)+r'\([^;]*?\)\n\{',re.S)
 m=pat.search(s)
 if not m:raise ValueError(name)
 start=m.start();pos=m.end();depth=1
 while depth:
  if s[pos]=='{':depth+=1
  elif s[pos]=='}':depth-=1
  pos+=1
 s=s[:start]+body+s[pos:]
replacefn('open_ubi','static int open_ubi(const char *node) { (void)node; return -1; }')
replacefn('check_volume_empty','static int check_volume_empty(void) { return -1; }')
replacefn('open_target','''static int open_target(void) {
 struct stat existing;if(!stat(output,&existing)&&!S_ISREG(existing.st_mode))return err_msg("output must be an ordinary file");
 out_fd=open(output,O_CREAT|O_RDWR|O_TRUNC|O_BINARY,0600);
 if(out_fd<0)return sys_err_msg("cannot create output");return 0;
}''')
replacefn('close_target','''static int close_target(void) {if(out_fd>=0&&close(out_fd))return -1;free(output);return 0;}''')
s=s.replace('if (out_ubi)\n\t\tif (ubi_leb_change_start(ubi, out_fd, lnum, c->leb_size))\n\t\t\treturn sys_err_msg("ubi_leb_change_start failed");','if(out_ubi) return err_msg("device output disabled");')
replacefn('write_data','static int write_data(void) {return ascent_write_data();}')
s=s.replace('static int write_data(void)', '#include "inventory.c"\nstatic int write_data(void)',1)
# The writer uses manifest scalars, never host stat attributes. Keep dummy stat for upstream file reads.
s=s.replace('ino->atime_nsec = 0;\n\tino->ctime_nsec = 0;\n\tino->mtime_nsec = 0;', 'ino->atime_nsec = 0;\n\tino->ctime_nsec = 0;\n\tino->mtime_nsec = 0;')
needle='ino->compr_type = cpu_to_le16(c->default_compr);'
replacement='''ino->compr_type = cpu_to_le16(c->default_compr);
 if(!ascent_active) return err_msg("missing explicit inode metadata");
 ino->size=cpu_to_le64(ascent_active->size);ino->nlink=cpu_to_le32(ascent_active->nlink);
 ino->uid=cpu_to_le32(ascent_active->uid);ino->gid=cpu_to_le32(ascent_active->gid);
 ino->mode=cpu_to_le32(ascent_active->mode);ino->flags=cpu_to_le32(ascent_active->flags);
 ino->atime_sec=cpu_to_le64(ascent_active->atime);ino->atime_nsec=cpu_to_le32(ascent_active->ansec);
 ino->mtime_sec=cpu_to_le64(ascent_active->mtime);ino->mtime_nsec=cpu_to_le32(ascent_active->mnsec);
 ino->ctime_sec=cpu_to_le64(ascent_active->ctime);ino->ctime_nsec=cpu_to_le32(ascent_active->cnsec);'''
pos=s.index('static int add_inode('); before,after=s[:pos],s[pos:];assert after.count(needle)==1;s=before+after.replace(needle,replacement)
s=s.replace('int main(int argc, char *argv[])','static int upstream_main(int argc, char *argv[])')
s+='\n#include "main.c"\n'
p.write_text(s)
if '--prepare-only' in sys.argv:
 print(json.dumps({'source':str(SRC),'upstream':'mtd-utils-2.2.0','inventory_adapter':3}))
 raise SystemExit(0)
common=['-std=gnu11','-O2','-ffunction-sections','-fdata-sections','-D_GNU_SOURCE','-D_FILE_OFFSET_BITS=64','-DWITH_ZLIB','-DVERSION="2.2.0"','-DPROGRAM_NAME="mkfs.ubifs"','-include',str(HERE/'portable.h'),'-I/usr/include/uuid','-I'+str(SRC/'include'),'-I'+str(sub)]
files=[sub/'mkfs.ubifs.c',sub/'lpt.c',sub/'compr.c',sub/'crc16.c',sub/'devtable.c',sub/'hashtable/hashtable.c',sub/'hashtable/hashtable_itr.c',SRC/'lib/libcrc32.c',SRC/'lib/common.c']
cmd=['gcc',*common,*map(str,files),'-Wl,--gc-sections','-lz','-luuid','-lm','-o',str(OUT/'ascent-mkfs.ubifs')]
runid=len(list(OUT.glob('build-*.log')))+1
(OUT/f'build-command-{runid}.json').write_text(json.dumps(cmd,indent=2))
r=subprocess.run(cmd,capture_output=True,text=True);(OUT/f'build-{runid}.log').write_text(r.stdout+r.stderr);print(r.stdout+r.stderr);raise SystemExit(r.returncode)
