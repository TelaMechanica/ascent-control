"""Adversarial tests for Mode A gate 2: every check must fire on a targeted mutation of the
built candidate. Each mutation is re-signed (node CRC, UBI CRC, ASW CRC recomputed) so it is
the semantic check under test that has to catch it, not an incidental CRC failure.

Paths via env MODE_A_DONOR, MODE_A_GATE2 (built candidate), MODE_A_FALLBACK_PS5280 (the
17.5.8 Z40 cam_ps5280_50fps_z40.bin, fb2f2d56...). Skipped (not passed) when absent.
"""
import os, struct, sys, zlib, unittest
sys.path.insert(0, os.path.dirname(__file__))
import ubifs_inventory as U
import mode_a_build as M

DONOR = os.environ.get("MODE_A_DONOR")
GATE2 = os.environ.get("MODE_A_GATE2")
FALLBACK = os.environ.get("MODE_A_FALLBACK_PS5280")
VERIFIER = os.environ.get("MODE_A_VERIFIER", M.DEFAULT_VERIFIER)
PS = "/fpv/tunning/cam_ps5280_50fps_z40.bin"


def _crc(b):
    return (~zlib.crc32(b)) & 0xFFFFFFFF


@unittest.skipUnless(DONOR and GATE2 and os.path.exists(DONOR) and os.path.exists(GATE2),
                     "donor/gate-2 image not provided")
class Gate2Fires(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.T, _ = M.load_verifier(VERIFIER)
        cls.donor = open(DONOR, "rb").read()
        # Reproduce gate2's pinned updater delta from the donor, never the candidate.
        from variant_identity import patch_updater, EXPECTED_SHA, UPDATER_PATH
        donor_entries = U.inventory(M.volume_of(cls.T, cls.donor, 5)[0],
                                    with_content=True)["entries"]
        updater = patch_updater(donor_entries[UPDATER_PATH]["content"], 'z40')
        M.CAMERA_SUBTYPE = 'z40'
        M.PHASE1_DELTA = dict(M.PHASE1_DELTA)
        M.PHASE1_DELTA[UPDATER_PATH] = ("replace", EXPECTED_SHA['z40'], len(updater))
        cls.img = open(GATE2, "rb").read()
        cls.char = cls.T.characterize(DONOR)
        asw = cls.T.parse_asw(cls.img)
        cls.c5 = next(c for c in asw["components"] if c["id"] == 5)
        cls.c4 = next(c for c in asw["components"] if c["id"] == 4)
        ubi = cls.T.parse_ubi(cls.img[cls.c5["offset"]:cls.c5["offset"] + cls.c5["bytes"]], name="c5")
        cls.peb, cls.doff, cls.leb = ubi["peb_size"], ubi["data_offset"], ubi["leb_size"]

    # ---- helpers ------------------------------------------------------------------
    def reseal(self, img):
        img = bytearray(img)
        struct.pack_into("<I", img, M.ASW_CRC_OFF, zlib.crc32(bytes(img[M.ASW_HDR:])) & 0xFFFFFFFF)
        return bytes(img)

    def vol(self):
        return M.volume_of(self.T, self.img, 5)[0]

    def put_vol(self, vol):
        """Write a (same-length) mutated usrdata volume back through the LEB->PEB map."""
        img = bytearray(self.img)
        for lnum in range(len(vol) // self.leb):
            at = self.c5["offset"] + (2 + lnum) * self.peb + self.doff
            img[at:at + self.leb] = vol[lnum * self.leb:(lnum + 1) * self.leb]
        return self.reseal(img)

    def inum_of(self, path):
        return U.inventory(self.vol())["entries"][path]["inum"]

    def latest(self, vol, ntype, pred):
        s = U.sweep(bytes(vol))
        best = None
        off = 0
        while True:
            off = vol.find(U.UBIFS_MAGIC, off)
            if off < 0:
                return best
            ln = struct.unpack_from("<I", vol, off + 16)[0]
            node = bytes(vol[off:off + ln])
            if 24 <= ln and vol[off + 20] == ntype and struct.unpack_from("<I", node, 4)[0] == _crc(node[8:]) \
                    and pred(node):
                best = (off, ln)
            off += 8

    def resign(self, vol, off, ln):
        struct.pack_into("<I", vol, off + 4, _crc(bytes(vol[off + 8:off + ln])))

    def fails(self, img, code):
        with self.assertRaises(SystemExit) as cm:
            M.verify_gate2(self.T, self.donor, self.char, img)
        self.assertIn(code, str(cm.exception))

    # ---- the candidate itself -------------------------------------------------------
    def test_candidate_passes(self):
        v = M.verify_gate2(self.T, self.donor, self.char, self.img)
        self.assertEqual(set(v["fs_delta"]["files"]), set(M.PHASE1_DELTA))

    # ---- container / non-usrdata components -------------------------------------------
    def test_asw_crc_mutation_fires(self):
        bad = bytearray(self.img); bad[-1] ^= 0xFF
        with self.assertRaises(SystemExit):
            M.verify_gate2(self.T, self.donor, self.char, bytes(bad))

    def test_rootfs_padding_change_fires(self):
        # an 0xFF padding byte inside component 4 between the EC header (64 B) and the VID
        # header (2048) of data PEB 2: no CRC covers it, only the identity check can see it
        img = bytearray(self.img)
        at = self.c4["offset"] + 2 * self.peb + 1000
        self.assertEqual(img[at], 0xFF)
        img[at] = 0xFE
        self.fails(self.reseal(img), "COMPONENT_CHANGED 4")

    def test_vtbl_reserved_pebs_understated_fires(self):
        img = bytearray(self.img)
        for copy in (0, 1):
            at = self.c5["offset"] + copy * self.peb + self.doff
            struct.pack_into(">I", img, at, 71)
            struct.pack_into(">I", img, at + M.VTBL_REC - 4, self.T.ubi_crc32(bytes(img[at:at + M.VTBL_REC - 4])))
        self.fails(self.reseal(img), "EXISTING_VERIFIER")

    # ---- usrdata semantic checks ------------------------------------------------------
    def test_resigned_mode_change_on_added_file_fires(self):
        vol = bytearray(self.vol()); n = self.inum_of(PS)
        off, ln = self.latest(vol, U.INO, lambda nd: struct.unpack_from("<Q", nd, 8 + 0)[0] >= 0
                              and struct.unpack_from("<I", nd, 24)[0] == n)
        struct.pack_into("<I", vol, off + 104, struct.unpack_from("<I", vol, off + 104)[0] ^ 0o002)
        self.resign(vol, off, ln)
        self.fails(self.put_vol(vol), "ADDED_METADATA")

    def test_resigned_tunning_dir_mtime_change_fires(self):
        vol = bytearray(self.vol()); n = self.inum_of("/fpv/tunning")
        off, ln = self.latest(vol, U.INO, lambda nd: struct.unpack_from("<I", nd, 24)[0] == n)
        struct.pack_into("<Q", vol, off + 72, struct.unpack_from("<Q", vol, off + 72)[0] + 1)   # mtime sec
        self.resign(vol, off, ln)
        self.fails(self.put_vol(vol), "UNEXPECTED_FS_DELTA")

    def test_resigned_owner_change_on_unrelated_file_fires(self):
        vol = bytearray(self.vol()); n = self.inum_of("/fpv/tunning/cam_ps5280_60fps_xg1_day.bin")
        off, ln = self.latest(vol, U.INO, lambda nd: struct.unpack_from("<I", nd, 24)[0] == n)
        struct.pack_into("<I", vol, off + 96, 1000)                                              # uid
        self.resign(vol, off, ln)
        self.fails(self.put_vol(vol), "UNEXPECTED_FS_DELTA")

    @unittest.skipUnless(FALLBACK and os.path.exists(FALLBACK), "17.5.8 PS5280 not provided")
    def test_ps5280_block_swapped_for_fallback_calibration_fires(self):
        """Replace one PS5280 data block with the same block of the 17.5.8 calibration."""
        with open(FALLBACK, "rb") as fh:
            fb = fh.read()
        hub = U.inventory(self.vol(), with_content=True)["entries"][PS]["content"]
        vol = bytearray(self.vol()); n = self.inum_of(PS)
        for blk in range(len(hub) // 4096):
            a, b = hub[blk * 4096:(blk + 1) * 4096], fb[blk * 4096:(blk + 1) * 4096]
            if a == b:
                continue
            hit = self.latest(vol, U.DATA, lambda nd: struct.unpack_from("<I", nd, 24)[0] == n
                              and struct.unpack_from("<I", nd, 28)[0] & 0x1FFFFFFF == blk)
            if hit is None:
                continue
            off, ln = hit
            c = zlib.compressobj(6, zlib.DEFLATED, -11, 8)
            st = c.compress(b) + c.flush()
            if 48 + len(st) > ln:
                continue
            vol[off + 48:off + ln] = st + b"\0" * (ln - 48 - len(st))
            struct.pack_into("<I", vol, off + 16, 48 + len(st))
            struct.pack_into("<H", vol, off + 44, U.COMPR_ZLIB)
            self.resign(vol, off, 48 + len(st))
            break
        else:
            self.skipTest("no differing block fits its slot")
        self.fails(self.put_vol(vol), "FAIL")

    def test_wide_window_stream_in_candidate_fires(self):
        import deflate_distance as DD
        vol = bytearray(self.vol())
        small = os.urandom(2100) + b"x" * 0
        small = (small + small)[:4096]
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

    # ---- overlay pinning -------------------------------------------------------------
    def _sources(self):
        inv = U.inventory(self.vol(), with_content=True)["entries"]
        return {p: inv[p]["content"] for p in M.PHASE1_DELTA}

    def test_overlay_accepts_exact_delta(self):
        dinv = U.inventory(M.volume_of(self.T, self.donor, 5)[0], with_content=True)
        M.apply_phase1_delta(dinv, self._sources())

    @unittest.skipUnless(FALLBACK and os.path.exists(FALLBACK), "17.5.8 PS5280 not provided")
    def test_overlay_refuses_fallback_ps5280(self):
        dinv = U.inventory(M.volume_of(self.T, self.donor, 5)[0], with_content=True)
        src = self._sources()
        with open(FALLBACK, "rb") as fh:
            src[PS] = fh.read()
        with self.assertRaises(SystemExit) as cm:
            M.apply_phase1_delta(dinv, src)
        self.assertIn("REFUSED", str(cm.exception))

    def test_overlay_refuses_extra_path(self):
        dinv = U.inventory(M.volume_of(self.T, self.donor, 5)[0], with_content=True)
        src = self._sources(); src["/fpv/extra.bin"] = b"x"
        with self.assertRaises(SystemExit):
            M.apply_phase1_delta(dinv, src)

    def test_overlay_refuses_missing_path(self):
        dinv = U.inventory(M.volume_of(self.T, self.donor, 5)[0], with_content=True)
        src = self._sources(); src.pop(PS)
        with self.assertRaises(SystemExit):
            M.apply_phase1_delta(dinv, src)


if __name__ == "__main__":
    unittest.main(verbosity=2)
