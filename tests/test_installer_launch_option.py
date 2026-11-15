"""Interactive completion is opt-in; installer execution must never auto-launch."""
from pathlib import Path
import xml.etree.ElementTree as ET

ROOT=Path(__file__).resolve().parents[1]
NS={'w':'http://wixtoolset.org/schemas/v4/wxs'}


def test_completion_checkbox_is_opt_in_and_finish_only():
    tree=ET.parse(ROOT/'installer/AscentControl.wxs')
    dialog=tree.find(".//w:Dialog[@Id='ACExitDialog']",NS)
    assert dialog is not None
    checkbox=dialog.find("w:Control[@Id='Launch']",NS)
    assert checkbox.attrib['Type']=='CheckBox'
    assert checkbox.attrib['Text']=='Launch AC'
    prop=checkbox.attrib['Property']
    assert not tree.findall(".//w:Property[@Id='"+prop+"']",NS)
    finish=dialog.find("w:Control[@Id='Finish']",NS)
    events=finish.findall('w:Publish',NS)
    assert [event.attrib['Event'] for event in events]==['DoAction','EndDialog']
    assert events[0].attrib['Order']=='1' and events[1].attrib['Order']=='2'
    condition=events[0].attrib['Condition']
    assert prop+' = 1' in condition
    assert 'NOT Installed' in condition and 'NOT REMOVE~="ALL"' in condition and 'UILevel = 5' in condition


def test_launch_has_no_execute_sequence_and_success_is_required():
    tree=ET.parse(ROOT/'installer/AscentControl.wxs')
    show=tree.find(".//w:InstallUISequence/w:Show[@Dialog='ACExitDialog']",NS)
    assert show.attrib['OnExit']=='success'
    assert 'NOT Installed' in show.attrib['Condition'] and 'UILevel = 5' in show.attrib['Condition']
    action=tree.find(".//w:CustomAction[@Id='LaunchAC']",NS)
    assert action.attrib['ExeCommand']=='"[INSTALLFOLDER]AscentControl.exe"'
    assert action.attrib['Execute']=='immediate' and action.attrib['Impersonate']=='yes'
    for name in ('InstallExecuteSequence','AdminExecuteSequence'):
        assert tree.find('.//w:'+name+"/w:Custom[@Action='LaunchAC']",NS) is None
