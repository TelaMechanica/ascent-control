"""Pinned product-identity regression tests; all execution is offline ARM emulation."""
import hashlib
import importlib.util
import os
from pathlib import Path
import struct
import subprocess
import tempfile
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'firmware/mode_a'))
import variant_identity as identity


class Refusal(unittest.TestCase):
    def test_unknown_updater_is_refused(self):
        with self.assertRaisesRegex(ValueError, 'exact normal'):
            identity.patch_updater(b'not a qualified donor', 'z40')

    def test_unknown_subtype_is_refused(self):
        with self.assertRaisesRegex(ValueError, 'unsupported'):
            identity.patch_updater(b'', 'generic')

    def test_payloads_reassemble_from_retained_source(self):
        from arm_tools import tool
        with tempfile.TemporaryDirectory() as td:
            for subtype in ('z8', 'z40', 'Hub'):
                source = ROOT / 'firmware/mode_a/hooks' / (subtype + '-identity-hook.s')
                obj, elf, binary = (str(Path(td) / x) for x in ('a.o', 'a.elf', 'a.bin'))
                subprocess.run([tool('as'), '-mthumb', '-o', obj, str(source)], check=True, capture_output=True)
                subprocess.run([tool('ld'), '-Ttext=0x48710', '--defsym=compare=0x1b6f8', '--defsym=copy=0x1b578', '--defsym=format=0x1b4c4', '-e', 'identity_hook', '-o', elf, obj], check=True, capture_output=True)
                subprocess.run([tool('objcopy'), '-O', 'binary', '--only-section=.text', elf, binary], check=True, capture_output=True)
                self.assertEqual(Path(binary).read_bytes(), identity.PAYLOADS[subtype])

    def test_same_size_replacement_requires_hash_change_without_invented_size_delta(self):
        from unittest.mock import patch
        import mode_a_build as build
        donor = {'entries': {'/fpv/updater': {'sha256': 'old', 'size': 10}}}
        with patch.object(build, 'PHASE1_DELTA', {'/fpv/updater': ('replace', 'new', 10)}):
            self.assertEqual(build.expected_semantic_delta(donor), {'/fpv/updater': {'sha256': ('old', 'new')}})
