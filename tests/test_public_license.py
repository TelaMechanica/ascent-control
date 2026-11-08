"""Release license consistency and retention of component boundaries."""
from pathlib import Path
import json
import hashlib
import xml.etree.ElementTree as ET
ROOT=Path(__file__).resolve().parents[1]


def test_gpl_version_scope_and_original_component_licenses():
    assert (ROOT/'LICENSE').read_bytes()==(ROOT/'third_party/licenses/native-ubifs/notices/GPL-3.0.txt').read_bytes()
    scope=json.loads((ROOT/'PROJECT_LICENSE_SCOPE.json').read_text())
    assert scope['license']=='GPL-3.0-only'
    assert 'SPDX-License-Identifier: GPL-3.0-only' in (ROOT/'COPYRIGHT').read_text()
    assert scope['additional_permissions'][0]['file']=='FIRMWARE-LINKING-PERMISSION.txt'
    assert scope['excluded_material']
    assert b'Version 2, June 1991' in (ROOT/'third_party/licenses/native-ubifs/LICENSE.GPL-2.0.txt').read_bytes()


def test_original_license_and_additional_permission_ship_together():
    profile=json.loads((ROOT/'release/public-payload.json').read_text())
    entries={row['target']:row for row in profile['files']}
    project=ET.parse(ROOT/'src/Ascent.Desktop/Ascent.Desktop.csproj').getroot()
    links={node.text for node in project.iter('Link')}
    for name in ('LICENSE','COPYRIGHT','PROJECT_LICENSE_SCOPE.json','FIRMWARE-LINKING-PERMISSION.txt','THIRD-PARTY-NOTICES.md'):
        row=entries[name];data=(ROOT/row['source']).read_bytes()
        assert row['sha256']==hashlib.sha256(data).hexdigest()
        assert name in links
