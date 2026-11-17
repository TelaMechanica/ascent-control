"""Build/validate the SDK example or scan a local catalog; no installation."""
import argparse
import hashlib
import json
from pathlib import Path
import sys
import zipfile
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from ascent_core.widget_sdk import inspect_package
from ascent_core.widget_catalog import scan_folder


def build_example(output):
    view = b'{"type":"text","text":"Hello from a widget"}\n'
    manifest = {'schema': 'ascent.widget.v0', 'id': 'example-hello', 'version': '0.1.0',
                'sdk': '0.1', 'display_name': 'Hello widget', 'capabilities': [],
                'files': {'view.json': hashlib.sha256(view).hexdigest()}, 'view': 'view.json'}
    with output.open('xb') as target:
        with zipfile.ZipFile(target, 'w', compression=zipfile.ZIP_STORED) as archive:
            for name, data in [('widget.json', json.dumps(manifest, sort_keys=True).encode()), ('view.json', view)]:
                info = zipfile.ZipInfo(name, date_time=(2026, 1, 1, 0, 0, 0))
                info.external_attr = 0o100644 << 16
                archive.writestr(info, data)
    return inspect_package(output)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('example', 'validate', 'catalog'))
    parser.add_argument('package', type=Path)
    args = parser.parse_args()
    result = (build_example(args.package) if args.action == 'example' else
              scan_folder(args.package) if args.action == 'catalog' else inspect_package(args.package))
    print(json.dumps(result, sort_keys=True))
    if args.action == 'catalog' and (not result['complete'] or
            any(row['status'] != 'VALIDATED_PREVIEW' for row in result['entries'])):
        raise SystemExit(1)
