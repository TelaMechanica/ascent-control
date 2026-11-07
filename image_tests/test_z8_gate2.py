"""Adversarial fail-closed tests for the Z8 Mode A Gate 2 image. Each mutation is re-signed
(node/UBI/ASW CRCs recomputed) so the SEMANTIC check must catch it, not an incidental CRC fault.

Reuses mode_a_build with PHASE1_DELTA overridden to the Z8 delta (process-local; file untouched).

Env: MODE_A_DONOR (19.2.14 img), MODE_A_GATE2 (Z8 candidate img). Skipped if absent.
"""
import os, struct, sys, zlib, unittest
sys.path.insert(0, os.path.dirname(__file__))
import ubifs_inventory as U
import mode_a_build as M
from z8_gate2 import Z8_DELTA


DONOR = os.environ.get("MODE_A_DONOR")
GATE2 = os.environ.get("MODE_A_GATE2")
APP = "/fpv/ar_ldyhs_sky"
XG1 = "/fpv/tunning/cam_imx586_50fps_z8_xg1.bin"


def _crc(b):
    return (~zlib.crc32(b)) & 0xFFFFFFFF


@unittest.skipUnless(DONOR and GATE2 and os.path.exists(DONOR or "") and os.path.exists(GATE2 or ""),
                     "donor/gate-2 image not provided")
class Z8Gate2Fires(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.T, _ = M.load_verifier(M.DEFAULT_VERIFIER)
        cls.donor = open(DONOR, "rb").read()
        # Reproduce gate2's pinned updater delta from the donor, never the candidate.
        from variant_identity import patch_updater, EXPECTED_SHA, UPDATER_PATH
        donor_entries = U.inventory(M.volume_of(cls.T, cls.donor, 5)[0],
                                    with_content=True)["entries"]
        updater = patch_updater(donor_entries[UPDATER_PATH]["content"], 'z8')
        M.CAMERA_SUBTYPE = 'z8'
        cls.delta = dict(Z8_DELTA)
        cls.delta[UPDATER_PATH] = ("replace", EXPECTED_SHA['z8'], len(updater))
        M.PHASE1_DELTA = dict(cls.delta)
        cls.img = open(GATE2, "rb").read()
        cls.char = cls.T.characterize(DONOR)
        asw = cls.T.parse_asw(cls.img)
        cls.c5 = next(c for c in asw["components"] if c["id"] == 5)
        cls.c4 = next(c for c in asw["components"] if c["id"] == 4)
        ubi = cls.T.parse_ubi(cls.img[cls.c5["offset"]:cls.c5["offset"] + cls.c5["bytes"]], name="c5")
        cls.peb, cls.doff, cls.leb = ubi["peb_size"], ubi["data_offset"], ubi["leb_size"]

    def reseal(self, img):
        img = bytearray(img)
        struct.pack_into("<I", img, M.ASW_CRC_OFF, zlib.crc32(bytes(img[M.ASW_HDR:])) & 0xFFFFFFFF)
        return bytes(img)

    def vol(self):
        return M.volume_of(self.T, self.img, 5)[0]

    def put_vol(self, vol):
        img = bytearray(self.img)
        for lnum in range(len(vol) // self.leb):
            at = self.c5["offset"] + (2 + lnum) * self.peb + self.doff
            img[at:at + self.leb] = vol[lnum * self.leb:(lnum + 1) * self.leb]
        return self.reseal(img)

    def inum_of(self, path):
        return U.inventory(self.vol())["entries"][path]["inum"]

    def latest(self, vol, ntype, pred):
        best = None
        off = 0
        while True:
            off = vol.find(U.UBIFS_MAGIC, off)
            if off < 0:
                return best
            ln = struct.unpack_from("<I", vol, off + 16)[0]
            node = bytes(vol[off:off + ln])
            if 24 <= ln and vol[off + 20] == ntype and struct.unpack_from("<I", node, 4)[0] == _crc(node[8:]) and pred(node):
                best = (off, ln)
            off += 8

    def resign(self, vol, off, ln):
        struct.pack_into("<I", vol, off + 4, _crc(bytes(vol[off + 8:off + ln])))

    def fails(self, img, code):
        with self.assertRaises(SystemExit) as cm:
            M.verify_gate2(self.T, self.donor, self.char, img)
        self.assertIn(code, str(cm.exception))

    # ---- the candidate itself ----
    def test_candidate_passes(self):
        v = M.verify_gate2(self.T, self.donor, self.char, self.img)
        self.assertEqual(set(v["fs_delta"]["files"]), set(self.delta))

    # ---- container / non-usrdata ----
    def test_asw_crc_mutation_fires(self):
        bad = bytearray(self.img); bad[-1] ^= 0xFF
        with self.assertRaises(SystemExit):
            M.verify_gate2(self.T, self.donor, self.char, bytes(bad))

    def test_rootfs_padding_change_fires(self):
        img = bytearray(self.img)
        at = self.c4["offset"] + 2 * self.peb + 1000
        img[at] ^= 0xFF
        self.fails(self.reseal(img), "COMPONENT_CHANGED 4")

    def test_vtbl_reserved_pebs_understated_fires(self):
        img = bytearray(self.img)
        for copy in (0, 1):
            at = self.c5["offset"] + copy * self.peb + self.doff
            struct.pack_into(">I", img, at, 71)
            struct.pack_into(">I", img, at + M.VTBL_REC - 4, self.T.ubi_crc32(bytes(img[at:at + M.VTBL_REC - 4])))
        self.fails(self.reseal(img), "EXISTING_VERIFIER")

    # ---- usrdata semantic ----
    def test_resigned_mode_change_on_added_file_fires(self):
        vol = bytearray(self.vol()); n = self.inum_of(XG1)
        off, ln = self.latest(vol, U.INO, lambda nd: struct.unpack_from("<I", nd, 24)[0] == n)
        struct.pack_into("<I", vol, off + 104, struct.unpack_from("<I", vol, off + 104)[0] ^ 0o002)
        self.resign(vol, off, ln)
        self.fails(self.put_vol(vol), "ADDED_METADATA")

    def test_resigned_tunning_dir_mtime_change_fires(self):
        vol = bytearray(self.vol()); n = self.inum_of("/fpv/tunning")
        off, ln = self.latest(vol, U.INO, lambda nd: struct.unpack_from("<I", nd, 24)[0] == n)
        struct.pack_into("<Q", vol, off + 72, struct.unpack_from("<Q", vol, off + 72)[0] + 1)
        self.resign(vol, off, ln)
        self.fails(self.put_vol(vol), "UNEXPECTED_FS_DELTA")

    def test_resigned_app_content_change_fires(self):
        # flip one uncompressed byte of a data node and confirm the sha readback diff fires
        vol = bytearray(self.vol()); n = self.inum_of(APP)
        hit = self.latest(vol, U.DATA, lambda nd: struct.unpack_from("<I", nd, 24)[0] == n
                          and struct.unpack_from("<H", nd, 44)[0] == U.COMPR_NONE
                          and struct.unpack_from("<I", nd, 40)[0] > 0)
        if hit is None:
            self.skipTest("no uncompressed app data node")
        off, ln = hit
        vol[off + 48] ^= 1
        self.resign(vol, off, ln)
        self.fails(self.put_vol(vol), "UNEXPECTED_FS_DELTA")

    def test_wide_window_stream_in_candidate_fires(self):
        import deflate_distance as DD
        vol = bytearray(self.vol())
        small = (os.urandom(2100) * 2)[:4096]
        c = zlib.compressobj(9, zlib.DEFLATED, -15); st = c.compress(small) + c.flush()
        self.assertGreater(DD.inflate_measure(st)[1], M.DEVICE_WINDOW)
        hit = self.latest(vol, U.DATA, lambda nd: len(nd) - 48 >= len(st) and struct.unpack_from("<I", nd, 40)[0] >= 4096)
        if hit is None:
            self.skipTest("no data node large enough")
        off, ln = hit
        vol[off + 48:off + 48 + len(st)] = st
        struct.pack_into("<I", vol, off + 16, 48 + len(st))
        struct.pack_into("<I", vol, off + 40, len(small))
        struct.pack_into("<H", vol, off + 44, U.COMPR_ZLIB)
        self.resign(vol, off, 48 + len(st))
        with self.assertRaises(SystemExit) as cm:
            M.check_window(bytes(vol), 5)
        self.assertIn("DEFLATE_WINDOW", str(cm.exception))

    # ---- overlay pinning ----
    def _sources(self):
        inv = U.inventory(self.vol(), with_content=True)["entries"]
        return {p: inv[p]["content"] for p in self.delta}

    def test_overlay_accepts_exact_delta(self):
        dinv = U.inventory(M.volume_of(self.T, self.donor, 5)[0], with_content=True)
        M.apply_phase1_delta(dinv, self._sources())

    def test_overlay_refuses_wrong_app(self):
        dinv = U.inventory(M.volume_of(self.T, self.donor, 5)[0], with_content=True)
        src = self._sources(); src[APP] = src[APP] + b"x"      # size/sha no longer match
        with self.assertRaises(SystemExit) as cm:
            M.apply_phase1_delta(dinv, src)
        self.assertIn("REFUSED", str(cm.exception))

    def test_overlay_refuses_extra_path(self):
        dinv = U.inventory(M.volume_of(self.T, self.donor, 5)[0], with_content=True)
        src = self._sources(); src["/fpv/extra.bin"] = b"x"
        with self.assertRaises(SystemExit):
            M.apply_phase1_delta(dinv, src)


if __name__ == "__main__":
    unittest.main(verbosity=2)
