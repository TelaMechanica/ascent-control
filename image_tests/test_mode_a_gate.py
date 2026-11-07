"""Adversarial tests for the Mode A gate: each check must fire on a targeted mutation.

Needs the 19.2.14 donor and a gate-1 rebuild; paths via env MODE_A_DONOR / MODE_A_REBUILT.
Skipped (not passed) when they are absent.
"""
import os, struct, sys, zlib, unittest, importlib.util
sys.path.insert(0, os.path.dirname(__file__))
import ubifs_inventory as U
import mode_a_build as M

DONOR = os.environ.get("MODE_A_DONOR")
REBUILT = os.environ.get("MODE_A_REBUILT")
VERIFIER = os.environ.get("MODE_A_VERIFIER", M.DEFAULT_VERIFIER)


def _crc(b):
    return (~zlib.crc32(b)) & 0xFFFFFFFF


@unittest.skipUnless(DONOR and REBUILT and os.path.exists(DONOR) and os.path.exists(REBUILT),
                     "donor/rebuild not provided")
class GateFires(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.T, _ = M.load_verifier(VERIFIER)
        cls.donor = open(DONOR, "rb").read()
        cls.rebuilt = open(REBUILT, "rb").read()

    def vol(self, img, cid):
        return M.volume_of(self.T, img, cid)[0]

    def test_rebuild_semantically_identical(self):
        for cid in (4, 5):
            self.assertEqual(M.compare_inventories(U.inventory(self.vol(self.donor, cid)),
                                                   U.inventory(self.vol(self.rebuilt, cid))), [])

    def test_asw_crc_mutation_fires(self):
        bad = bytearray(self.rebuilt)
        bad[-1] ^= 0xFF
        with self.assertRaises(SystemExit) as cm:
            M.check_asw_seal(bytes(bad))
        self.assertIn("ASW_CRC", str(cm.exception))

    def test_asw_size_mutation_fires(self):
        bad = bytearray(self.rebuilt)
        struct.pack_into("<I", bad, M.ASW_SIZE_OFF, len(bad) - 1)
        struct.pack_into("<I", bad, M.ASW_CRC_OFF, zlib.crc32(bytes(bad[M.ASW_HDR:])) & 0xFFFFFFFF)
        with self.assertRaises(SystemExit) as cm:
            M.check_asw_seal(bytes(bad))
        self.assertIn("ASW_SIZE", str(cm.exception))

    def _mutate_first(self, vol, ntype, fn):
        """Mutate the first CRC-valid node of ntype and re-sign it (CRC stays valid)."""
        v = bytearray(vol)
        off = 0
        while True:
            off = v.find(U.UBIFS_MAGIC, off)
            ln = struct.unpack_from("<I", v, off + 16)[0]
            node = bytes(v[off:off + ln])
            if v[off + 20] == ntype and struct.unpack_from("<I", node, 4)[0] == _crc(node[8:]) \
                    and (ntype != U.INO or (ln >= 160 and struct.unpack_from("<I", node, 24)[0] > 1)):
                fn(v, off, ln)
                struct.pack_into("<I", v, off + 4, _crc(bytes(v[off + 8:off + ln])))
                return bytes(v)
            off += 8

    def test_resigned_mode_change_is_a_semantic_diff(self):
        vol = self.vol(self.rebuilt, 5)
        bad = self._mutate_first(vol, U.INO, lambda v, o, l: struct.pack_into(
            "<I", v, o + 104, struct.unpack_from("<I", v, o + 104)[0] ^ 0o002))
        diffs = M.compare_inventories(U.inventory(vol), U.inventory(bad))
        self.assertTrue(any("mode" in d for d in diffs), diffs[:3])

    def test_resigned_uncompressed_data_change_is_a_semantic_diff(self):
        vol = bytearray(self.vol(self.rebuilt, 5))
        off = 0
        while True:
            off = vol.find(U.UBIFS_MAGIC, off)
            self.assertNotEqual(off, -1, "no uncompressed data node found")
            ln = struct.unpack_from("<I", vol, off + 16)[0]
            node = bytes(vol[off:off + ln])
            if vol[off + 20] == U.DATA and struct.unpack_from("<I", node, 4)[0] == _crc(node[8:]) \
                    and struct.unpack_from("<H", vol, off + 44)[0] == U.COMPR_NONE \
                    and struct.unpack_from("<I", vol, off + 40)[0] > 0:
                break
            off += 8
        vol[off + 48] ^= 1
        struct.pack_into("<I", vol, off + 4, _crc(bytes(vol[off + 8:off + ln])))
        diffs = M.compare_inventories(U.inventory(self.vol(self.rebuilt, 5)), U.inventory(bytes(vol)))
        self.assertTrue(any("sha256" in d for d in diffs), diffs[:3])

    def test_wide_window_stream_is_refused(self):
        # A stream with a 3000-byte back-reference must be refused by the gate's window
        # check. (zlib with wbits=-11 would inflate it without complaint.)
        import deflate_distance as DD
        data = os.urandom(3000)
        data = data + data
        c = zlib.compressobj(9, zlib.DEFLATED, -15)
        stream = c.compress(data) + c.flush()
        out, md = DD.inflate_measure(stream)
        self.assertEqual(out, data)
        self.assertGreater(md, M.DEVICE_WINDOW)
        # inject it as a data node into a copy of the rebuilt usrdata volume
        vol = bytearray(self.vol(self.rebuilt, 5))
        off = 0
        while True:
            off = vol.find(U.UBIFS_MAGIC, off)
            ln = struct.unpack_from("<I", vol, off + 16)[0]
            if vol[off + 20] == U.DATA and struct.unpack_from("<H", vol, off + 44)[0] == U.COMPR_ZLIB \
                    and ln - 48 >= len(stream) and struct.unpack_from("<I", vol, off + 40)[0] >= 4096:
                break
            off += 8
        small = data[:4096]
        c = zlib.compressobj(9, zlib.DEFLATED, -15); st = c.compress(small) + c.flush()
        self.assertGreater(DD.inflate_measure(st)[1], M.DEVICE_WINDOW)
        if 48 + len(st) > ln:
            self.skipTest("no data node large enough to host the mutated stream")
        vol[off + 48:off + 48 + len(st)] = st
        struct.pack_into("<I", vol, off + 16, 48 + len(st))
        struct.pack_into("<I", vol, off + 40, len(small))
        struct.pack_into("<I", vol, off + 4, _crc(bytes(vol[off + 8:off + 48 + len(st)])))
        with self.assertRaises(SystemExit) as cm:
            M.check_window(bytes(vol), 5)
        self.assertIn("DEFLATE_WINDOW", str(cm.exception))

    def test_existing_verifier_passes_rebuild(self):
        self.T.verify(self.rebuilt, donor=self.T.characterize(DONOR))


if __name__ == "__main__":
    unittest.main(verbosity=2)
