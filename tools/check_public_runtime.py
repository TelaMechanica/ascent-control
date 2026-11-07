"""Enforce the desktop boundary and the original shared-helper contract."""
import ast
import hashlib
import json
from pathlib import Path

root=Path(__file__).resolve().parents[1]
receipt=json.loads((root/'docs/SHARED_SOURCE_IMPORT.json').read_text())
expected={item['path']:item for item in receipt['files'] if item['path'].startswith('runtime/')}
actual={p.relative_to(root).as_posix() for p in (root/'runtime').rglob('*') if p.is_file() and '__pycache__' not in p.parts and p.suffix!='.pyc'}
profile=json.loads((root/'release/public-payload.json').read_text())
desktop={item['source']:item for item in profile['files'] if item['source'].startswith('runtime/')}
reviewed=set(expected)|set(desktop)
if actual!=reviewed:
    raise SystemExit('Runtime inventory differs from the reviewed import manifest.')
from verify_public_build import check_python
for name,item in desktop.items():
    path=root/name
    if path.stat().st_size!=item['bytes'] or hashlib.sha256(path.read_bytes()).hexdigest()!=item['sha256']:
        raise SystemExit(name+': desktop source differs from the reviewed payload')
    if path.suffix=='.py':check_python(path)
allowed={'__future__','math','re','struct'}
for name,item in expected.items():
    data=(root/name).read_bytes()
    if hashlib.sha256(data).hexdigest()!=item['sha256']:
        raise SystemExit(name+': source changed without a reviewed manifest update')
    for node in ast.walk(ast.parse(data)):
        imports=[]
        if isinstance(node,ast.Import):imports=[alias.name for alias in node.names]
        if isinstance(node,ast.ImportFrom):
            if node.level:raise SystemExit(name+': relative import requires dependency review')
            imports=[node.module or '']
        if any(value.split('.')[0] not in allowed for value in imports):
            raise SystemExit(name+': import outside the reviewed pure runtime closure')
        if isinstance(node,ast.Call) and isinstance(node.func,ast.Name) and node.func.id in {'__import__','eval','exec','compile'}:
            raise SystemExit(name+': dynamic execution requires dependency review')
print('Reviewed runtime inventory, source hashes and static dependency closure passed.')
