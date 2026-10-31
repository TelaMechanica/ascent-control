"""Portable source privacy check; local account tokens are not serialized."""
from pathlib import Path
import os,re,subprocess
root=Path(__file__).resolve().parents[1]
if (root/'.git').exists():
 names=subprocess.check_output(['git','ls-files','--cached','--others','--exclude-standard'],cwd=root,text=True).splitlines()
else:
 names=[str(p.relative_to(root)) for p in root.rglob('*') if p.is_file() and '.git' not in p.parts]
address=re.compile(r'(?<![0-9A-Fa-f:])(?:[0-9A-Fa-f]{2}:){3}(?:[0-9A-Fa-f]{2}:){0,2}[0-9A-Fa-f]{2}(?![0-9A-Fa-f:])')
home_path=re.compile(r'(?:/(?:home|Users)/|/mnt/[a-z]/Users/|[A-Za-z]:\\Users\\)[A-Za-z0-9_.-]+',re.I)
operator=Path.home().name
failures=[]
for name in sorted(set(names)):
 p=root/name
 if not p.is_file() or '__pycache__' in p.parts or p.suffix=='.pyc':continue
 try:text=p.read_bytes().decode('utf-8')
 except UnicodeDecodeError:continue
 reasons=[]
 if home_path.search(text):reasons.append('literal personal home path')
 if address.search(text):reasons.append('literal device address; generate synthetic fixtures instead')
 if not os.environ.get('CI') and operator.lower() not in {'root','runner','user','builder','ci'} and re.search(r'(?<![A-Za-z0-9])'+re.escape(operator)+r'(?![A-Za-z0-9])',text,re.I):reasons.append('local account reference')
 if reasons:failures.append((name,reasons))
for name,reasons in failures:print(name+': '+', '.join(reasons))
if failures:raise SystemExit(1)
print('Source privacy checks passed; no hardware access.')
