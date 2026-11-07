"""Behavioral regressions retained independently of private application imports."""
from pathlib import Path
import hashlib
import json
import struct
import sys
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'runtime'))
import caddx_fw_version as firmware
import caddx_mgrs as mgrs
import caddx_tile_image as tile


def png(width,height):
    return bytes([137])+b'PNG\r\n'+bytes([26])+b'\n'+struct.pack('>I',13)+b'IHDR'+struct.pack('>II',width,height)


def jpeg(width,height):
    return bytes.fromhex('ff d8 ff c0 00 11 08')+struct.pack('>HH',height,width)+bytes(12)


class SharedSourceTests(unittest.TestCase):
    def test_imported_source_matches_frozen_provenance(self):
        receipt=json.loads((ROOT/'docs/SHARED_SOURCE_IMPORT.json').read_text())
        for item in receipt['files']:
            with self.subTest(path=item['path']):
                data=(ROOT/item['path']).read_bytes()
                self.assertEqual(len(data),item['bytes'])
                self.assertEqual(hashlib.sha256(data).hexdigest(),item['sha256'])

    def test_numeric_firmware_order_and_unknown_fail_closed(self):
        self.assertGreater(firmware.compare('19.2.14','19.2.4'),0)
        self.assertLess(firmware.compare('19.2','19.2.1'),0)
        for unknown in ('',None,'unrecognized',17):
            with self.subTest(value=unknown):
                self.assertIsNone(firmware.parse(unknown))
                self.assertIsNone(firmware.is_at_least(unknown,'19.2.4'))

    def test_firmware_forms_and_zero_padding(self):
        for value in ('Ascent_VRX_Max_19_2_14','19.2.14','V19.2.14','Ascent_VRX_Max_19_2_14.img'):
            self.assertEqual(firmware.parse(value),(19,2,14))
        self.assertEqual(firmware.compare('19.2','19.2.0'),0)
        firmware.selftest()

    def test_grid_round_trips_and_zone_exceptions(self):
        for lat,lon in ((38.8894838,-77.0352791),(51.5007,-0.1246),(-33.8568,151.2153),(64.1355,-21.8954)):
            with self.subTest(lat=lat,lon=lon):
                back=mgrs.from_mgrs(mgrs.to_mgrs(lat,lon,5))
                self.assertLess(abs(back[0]-lat)*111320,1.5)
                self.assertLess(abs(back[1]-lon)*111320,1.5)
        self.assertTrue(mgrs.to_mgrs(60,5,0).startswith('32'))
        self.assertTrue(mgrs.to_mgrs(78,15,0).startswith('33'))
        self.assertTrue(mgrs.selftest()['ok'])

    def test_invalid_and_unsupported_grid_references_refuse(self):
        for value in ('','nonsense','18S','18SUJ123','99SUJ1234512345'):
            with self.subTest(value=value),self.assertRaises(mgrs.MgrsError):
                mgrs.from_mgrs(value)
        with self.assertRaisesRegex(mgrs.MgrsError,'UPS'):
            mgrs.to_mgrs(87,10)

    def test_grid_alphabets_and_precision(self):
        for lat in range(-75,80,5):
            for lon in range(-175,180,45):
                value=mgrs.to_mgrs(lat,lon,0)
                self.assertNotIn('I',value[2:])
                self.assertNotIn('O',value[2:])
        fine=mgrs.to_mgrs(38.8894838,-77.0352791,5)
        coarse=mgrs.to_mgrs(38.8894838,-77.0352791,1)
        self.assertEqual(len(fine),len(coarse)+8)
        self.assertEqual(fine[:5],coarse[:5])

    def test_tile_formats_dimensions_and_oversize_refusal(self):
        for maker in (png,jpeg):
            self.assertEqual(tile.check(maker(256,256))['width'],256)
            self.assertEqual(tile.sniff(maker(123,45))['height'],45)
            with self.assertRaises(tile.TileImageError) as error:
                tile.check(maker(512,512),source='Synthetic')
            self.assertEqual(error.exception.code,'TILE_TOO_LARGE')
            self.assertEqual(error.exception.evidence['source'],'Synthetic')
        for width,height in ((200,256),(256,200),(128,128)):
            with self.assertRaises(tile.TileImageError) as error:
                tile.check(png(width,height))
            self.assertEqual(error.exception.code,'TILE_WRONG_SIZE')

    def test_bad_tiles_and_provider_errors_are_not_silently_stored(self):
        for data,code in ((b'','TILE_EMPTY'),(b'GIF89a'+bytes(40),'TILE_FORMAT_UNSUPPORTED'),
                          (b'RIFF'+bytes(4)+b'WEBP'+bytes(40),'TILE_FORMAT_UNSUPPORTED'),
                          (b'<ExceptionReport/>','TILE_PROVIDER_ERROR'),
                          (bytes([137])+b'PNG\r\n'+bytes([26])+b'\n','TILE_TRUNCATED'),
                          (bytes.fromhex('ff d8 ff e0 00 10')+b'JFIF','TILE_TRUNCATED')):
            with self.subTest(code=code):
                accepted,detail=tile.is_storable(data)
                self.assertFalse(accepted)
                self.assertEqual(detail['code'],code)

if __name__=='__main__':unittest.main()
