"""Explicit read-only core inputs do not admit private widget implementations."""
from pathlib import Path
import json
import xml.etree.ElementTree as ET
import pytest
from tools.verify_public_build import check_python

ROOT = Path(__file__).resolve().parents[1]


def test_only_curated_read_only_widget_modules_are_shipped():
    profile = json.loads((ROOT / 'release/public-payload.json').read_text())
    targets = {r['target'] for r in profile['files'] if r['target'].startswith('ascent_core/widget_')}
    expected = {'ascent_core/' + n + '.py' for n in
                ('widget_sdk', 'widget_catalog', 'widget_catalog_io', 'widget_catalog_host')}
    assert targets == expected
    links = {n.text.replace(chr(92), '/') for n in ET.parse(ROOT / 'src/Ascent.Desktop/Ascent.Desktop.csproj').iter('Link')}
    assert targets <= links
    for name in expected:
        check_python(ROOT / name)
    check_python(ROOT / 'runtime/dev_harness.py')


@pytest.mark.parametrize('parent,name,code', [
    ('ascent_core', 'widget_catalog.py', 'from .widget_manager import install'),
    ('ascent_core', 'widget_catalog_host.py', 'from .widget_runtime import execute'),
    ('runtime', 'dev_harness.py', 'from ascent_core.widget_manager import install'),
    ('runtime', 'other.py', 'from ascent_core.widget_catalog_host import CatalogCoordinator'),
    ('runtime', 'widget_catalog.py', 'from .widget_sdk import inspect_package'),
    ('ascent_core', 'widget_catalog.py', 'import ascent_core.widget_manager'),
    ('ascent_core', 'widget_catalog.py', 'from private_receiver import credential'),
    ('ascent_core', 'widget_catalog.py', 'from .widget_sdk.extra import run'),
])
def test_allowlist_does_not_expand_to_other_modules_importers_or_private_paths(tmp_path, parent, name, code):
    p = tmp_path / parent / name
    p.parent.mkdir()
    p.write_text(code)
    with pytest.raises(ValueError, match='private import'):
        check_python(p)
