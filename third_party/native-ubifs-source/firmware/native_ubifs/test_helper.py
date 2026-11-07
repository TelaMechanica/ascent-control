"""Behavioral helper regression using synthetic manifests and no device access."""
from pathlib import Path
import copy,json,subprocess,sys
helper,fixture,work=map(Path,sys.argv[1:4]);work.mkdir(exist_ok=False)
original=json.loads((fixture/'inventory.json').read_text());geometry=json.loads((fixture/'geometry.json').read_text());cases=[]
def case(name,change):
 d=copy.deepcopy(original);change(d);cases.append((name,json.dumps(d),False))
cases.append(('valid',json.dumps(original),True))
case('wrong-schema',lambda d:d.update(schema='other'))
case('missing-root',lambda d:d['entries'].pop(0))
case('negative-owner',lambda d:d['entries'][2].update(uid=-1))
case('fractional-owner',lambda d:d['entries'][2].update(uid=0.5))
case('boolean-owner',lambda d:d['entries'][2].update(uid=True))
case('oversized-owner',lambda d:d['entries'][2].update(uid=2**32))
case('negative-time',lambda d:d['entries'][2].update(mtime=[-1,0]))
case('invalid-nanoseconds',lambda d:d['entries'][2].update(mtime=[10,10**9]))
case('missing-mode',lambda d:d['entries'][2].pop('mode'))
case('wrong-mode',lambda d:d['entries'][2].update(mode=0o40755))
case('unknown-inode-kind',lambda d:d['entries'][2].update(type='device'))
case('hardlink',lambda d:d['entries'][2].update(nlink=2))
case('escaping-blob',lambda d:d['entries'][2].update(content_file='../0000.bin'))
case('relative-device-path',lambda d:d['entries'][2].update(path='relative'))
case('traversal-device-path',lambda d:d['entries'][2].update(path='/education/../escape'))
case('missing-parent',lambda d:d['entries'][2].update(path='/absent/file'))
case('duplicate-path',lambda d:d['entries'].append(copy.deepcopy(d['entries'][2])))
case('wrong-link-size',lambda d:d['entries'][3].update(size=1))
case('unknown-flags',lambda d:d['entries'][2].update(flags=32))
case('wrong-directory-links',lambda d:d['entries'][0].update(nlink=2))
case('wrong-directory-size',lambda d:d['entries'][0].update(size=160))
case('unknown-field',lambda d:d['entries'][0].update(unexpected=1))
cases.extend([('truncated-json','{"schema":',False),('duplicate-field',json.dumps(original).replace('"schema":','"schema":"ascent.ubifs.inventory.v1","schema":',1),False),('trailing-data',json.dumps(original)+'false',False)])
results=[]
for name,text,expected in cases:
 manifest=work/(name+'.json');manifest.write_text(text,encoding='utf-8');target=work/(name+'.ubifs')
 cmd=[str(helper),'--ascent-inventory',str(manifest),'-r',str(fixture/'payload'),'-o',str(target),*geometry]
 r=subprocess.run(cmd,capture_output=True,text=True,encoding='utf-8',errors='replace',timeout=45)
 good=(r.returncode==0)==expected and (expected or r.returncode in (2,255,4294967295))
 results.append({'case':name,'expected_success':expected,'returncode':r.returncode,'pass':good,'stderr':r.stderr,'output_exists':target.exists()})
(work/'results.json').write_text(json.dumps({'pass':all(r['pass'] for r in results),'cases':results},indent=2),encoding='utf-8')
print(json.dumps({'pass':all(r['pass'] for r in results),'cases':len(results),'failures':[r for r in results if not r['pass']]}))
raise SystemExit(0 if all(r['pass'] for r in results) else 1)
