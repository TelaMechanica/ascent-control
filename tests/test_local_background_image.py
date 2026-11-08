"""Host image preparation and diagnostics do not require receiver access."""
from pathlib import Path
import struct
import subprocess
import sys
import zlib

import pytest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'runtime'))
import dev_harness as app
import wallpaper_image as image
from test_public_desktop_boundary import server, request as http_request


def png(width=32,height=24):
    def chunk(kind,data):
        return struct.pack('>I',len(data))+kind+data+struct.pack('>I',zlib.crc32(kind+data)&0xffffffff)
    pixels=b''.join(b'\0'+bytes([40,120,200])*width for _ in range(height))
    return b'\x89PNG\r\n\x1a\n'+chunk(b'IHDR',struct.pack('>IIBBBBB',width,height,8,2,0,0,0))+chunk(b'IDAT',zlib.compress(pixels))+chunk(b'IEND',b'')


@pytest.mark.parametrize('width,height,mode',[(1920,1080,'resize'),(2134,1200,'resize'),(2000,1000,'crop'),(1000,1000,'crop')])
def test_existing_fit_rules_preserve_aspect(width,height,mode):
    plan=image.plan_fit(width,height)
    assert plan['mode']==mode
    if mode=='crop':
        crop=plan['crop']
        assert abs(crop['width']/crop['height']-16/9)<0.003
        assert crop['x']>=0 and crop['y']>=0 and plan['needs_review']


def test_conversion_quotes_paths_and_uses_vendor_filename():
    script=image.resize_powershell("a'b.png","c'd.jpg",image.plan_fit(32,24))
    assert "FromFile('a''b.png')" in script and "Save('c''d.jpg'" in script
    assert image.REMOTE_NAME=='fpv_new_bg_1920x1080.jpg'
    assert 'ssh' not in script.lower() and 'reboot' not in script.lower()


def test_public_image_chooser_is_host_only(server,monkeypatch):
    seen=[]
    monkeypatch.setattr(app,'firmware_browse',lambda **kwargs:seen.append(kwargs) or {'ok':True,'cancelled':True})
    status,doc=http_request(server,'POST','/api/wallpaper/browse',{})
    assert status==200 and doc['cancelled'] and '*.png' in seen[0]['file_filter']


def test_prepare_rejects_non_image_and_does_not_have_deploy_route(server,tmp_path):
    source=tmp_path/'not-an-image.txt';source.write_text('not an image')
    status,doc=http_request(server,'POST','/api/wallpaper/prepare',{'path':str(source)})
    assert status==200 and not doc['ok'] and doc['error']=='IMAGE_UNREADABLE'
    assert http_request(server,'POST','/api/wallpaper/deploy',{'apply':True,'confirmed':True})[0]==405
    assert http_request(server,'GET','/api/wallpaper/deploy')[0]==404


def test_local_prepare_requires_no_connected_receiver(tmp_path):
    source=tmp_path/'source.png';source.write_bytes(png())
    result=app.wallpaper_prepare({'path':str(source)})
    assert result['ok'] and result['source']['width']==32
    if sys.platform=='win32':
        import base64
        prepared=image.measure(base64.b64decode(result['jpeg_base64']))
        assert result['prepared'] and (prepared['width'],prepared['height'])==(1920,1080)
    else:
        assert result['prepared'] is False and 'jpeg_base64' not in result


def test_diagnostics_navigation_and_background_flow():
    result=subprocess.run(['node','tests/public_diagnostics_flow.cjs'],cwd=ROOT,capture_output=True,text=True)
    assert result.returncode==0,result.stdout+result.stderr
