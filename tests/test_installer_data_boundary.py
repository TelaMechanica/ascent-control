"""Static current-installer boundaries; these do not prove Windows transitions."""
from pathlib import Path
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
NS = {'w':'http://wixtoolset.org/schemas/v4/wxs'}


def authoring():
    return ET.parse(ROOT/'installer/AscentControl.wxs').getroot()


def test_existing_shared_product_upgrade_identity_is_preserved():
    package = authoring().find('w:Package', NS)
    # Identity is supplied per edition by Build-Installer.ps1; the wxs is
    # parameterized. Changing an edition's UpgradeCode creates a parallel product.
    assert package.attrib['UpgradeCode'] == '$(var.UpgradeCode)'
    assert package.attrib['Scope'] == 'perMachine'
    upgrade = package.find('w:MajorUpgrade', NS)
    assert upgrade is not None and upgrade.attrib['AllowSameVersionUpgrades'] == 'yes'
    # AC keeps its original UpgradeCode (stable identity); AC+ is a distinct product.
    build = (ROOT/'tools/Build-Installer.ps1').read_text()
    assert '353ECEAF-B574-563B-9587-39464C4F0131' in build
    assert '95810E93-1BC3-5750-9CC8-99249572FC78' in build


def test_uninstall_has_no_authored_user_data_or_provider_cleanup():
    root = authoring()
    assert not root.findall('.//w:RemoveFile', NS)
    assert not root.findall('.//w:RemoveRegistryKey', NS)
    assert not root.findall('.//w:CustomAction', NS)
    removals = root.findall('.//w:RemoveFolder', NS)
    assert len(removals) == 1 and removals[0].attrib['Directory'] == 'ShortcutFolder'
    assert removals[0].attrib['On'] == 'uninstall'


def test_payload_harvest_and_shortcut_stay_out_of_user_data_roots():
    root = authoring()
    directories = {node.attrib['Id'] for node in root.findall('.//w:StandardDirectory', NS)}
    assert directories == {'ProgramFiles6432Folder', 'ProgramMenuFolder'}
    groups = root.findall('.//w:ComponentGroup', NS)
    assert len(groups) == 1 and groups[0].attrib['Directory'] == 'INSTALLFOLDER'
    files = root.findall('.//w:Files', NS)
    assert len(files) == 1 and files[0].attrib['Include'] == '$(var.PublishDir)\\**'
    assert not root.findall('.//w:CopyFile', NS)
    registry = root.findall('.//w:RegistryValue', NS)
    assert len(registry) == 1
    assert registry[0].attrib['Name'] == 'Installed'


def test_settings_root_survives_application_location_changes(tmp_path, monkeypatch):
    monkeypatch.syspath_prepend(str(ROOT/'runtime'))
    import local_settings
    monkeypatch.setenv('LOCALAPPDATA', str(tmp_path/'profile'))
    initial = local_settings.config_root()
    local_settings._write({'schema':local_settings.SCHEMA, 'synthetic_preserved':True})
    saved = local_settings.settings_path().read_bytes()
    monkeypatch.setattr(local_settings, '_ROOT', tmp_path/'new-install'/'runtime')
    assert local_settings.config_root() == initial
    assert local_settings.settings_path().read_bytes() == saved
    assert local_settings.load()['synthetic_preserved'] is True
