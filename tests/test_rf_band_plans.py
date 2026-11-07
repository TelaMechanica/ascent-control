"""Local reusable RF band plans.

A plan is a named set of band arrays kept on this computer so a frequency layout can
be reused instead of retyped. The three properties these tests exist to hold are the
ones that make the feature safe to have at all.

**One validator, not two.** Band-array rules live in exactly one place --
``caddx_vendor_write.validate_band_collection``, which the write path's serializer
calls and which the plan store calls. Before this feature that loop was inline inside
``serialize_rf_table``; extracting it is the whole of the change to the write path,
and ``test_shared_validator_is_the_writer_s_own`` pins that the extraction changed no
behaviour -- the bench table still serializes to its exact 2018 bytes.

**A plan cannot transmit.** ``runtime/rf_band_plans.py`` imports no transport, opens
no port, and builds no frame. Applying a plan means loading its values into the
existing editor and committing them through the existing qualified cmd-121
transaction. No eligibility gate is consulted here, relaxed here, or reachable from
here -- ``test_module_holds_no_transport`` and
``test_plan_endpoints_do_not_touch_write_qualification`` pin both halves.

**Compatibility is measured or it is absent.** ``CAPABILITY_PROFILES`` holds one
entry, read from this project's own MD5-verified command-116 bench artefact. It is
keyed on the exact ``(rf_board_code, hardware)`` pair: no prefix, substring, casefold
or pattern match, because a hardware string this project has not measured must not
inherit a similar-looking neighbour's limits. Unknown hardware yields
``Compatibility limits not established`` -- which is neither permission nor refusal,
and the tests check it is rendered as neither.

Nothing here models whether a frequency is legal to transmit. Every assessment
carries ``transmission_legality: "not assessed"`` and no code path ever sets it to
anything else.

The operator-facing word for this feature is "plan". The repo-wide guard in
``tests/test_vtx_recovery.py`` already refuses the retired term everywhere, so this
module does not restate it -- one authority, as with the band rules.
"""

import io
import json
import os
import re
import pathlib
import shutil
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "runtime"))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import local_identity  # noqa: E402

import caddx_vendor_write as vw          # noqa: E402
import local_settings                     # noqa: E402
import rf_band_plans as plans             # noqa: E402

FIXTURE = ROOT / "fixtures" / "vrxmax_cmd115_116_integrity.json"


def bench_table() -> dict:
    return json.loads(json.loads(FIXTURE.read_text(encoding="utf-8"))["cmd116_payload_ascii"])


def bench_bands() -> dict:
    return {k: v for k, v in bench_table().items() if k.startswith("band")}


class IsolatedStore(unittest.TestCase):
    """Each test gets its own application-data root; nothing touches a real store."""

    def setUp(self):
        self._tmp = tempfile.mkdtemp(prefix="ascent-plans-")
        self._appdata = os.environ.get("LOCALAPPDATA")
        os.environ["LOCALAPPDATA"] = str(pathlib.Path(self._tmp) / "appdata")

    def tearDown(self):
        if self._appdata is None:
            os.environ.pop("LOCALAPPDATA", None)
        else:
            os.environ["LOCALAPPDATA"] = self._appdata
        shutil.rmtree(self._tmp, ignore_errors=True)


# ----------------------------------------------------------------------------------
# The shared validator
# ----------------------------------------------------------------------------------

class SharedValidator(unittest.TestCase):

    def test_shared_validator_is_the_writer_s_own(self):
        """Extracting the loop out of serialize_rf_table changed nothing on the wire."""
        table = bench_table()
        self.assertEqual(plans.validate_band_collection, vw.validate_band_collection)
        self.assertEqual(vw.validate_band_collection(table), 107)
        self.assertEqual(len(vw.serialize_rf_table(table, table)), 2018)

    def test_plan_store_rejects_exactly_what_the_writer_rejects(self):
        """Every vendor editor rule reaches a plan through the same function."""
        cases = {
            "RF_FREQUENCY_NOT_MULTIPLE": [4495000, 4495500, 5440000, 5839000],
            "RF_BAND_MIN_NOT_FIRST": [5440000, 4495000, 4525000, 5839000],
            "RF_BAND_MAX_NOT_LAST": [4495000, 5440000, 4525000, 5839000],
            "RF_FREQUENCY_DUPLICATED": [4495000, 4495000, 5440000, 5839000],
            "RF_FREQUENCY_OUT_OF_RANGE": [4495000, 9000000, 5839000],
            "RF_BAND_TOO_LONG": list(range(4000000, 4000000 + 1000 * 38, 1000)),
        }
        for code, values in cases.items():
            with self.subTest(code=code):
                with self.assertRaises(plans.RfPlanError) as ctx:
                    plans.normalize_bands({"bandA": values})
                self.assertEqual(ctx.exception.code, code)

    def test_cross_band_total_is_enforced_on_a_plan(self):
        wide = {}
        for i, key in enumerate(("bandA", "bandB", "bandC", "bandD")):
            base = 3_000_000 + i * 500_000
            wide[key] = [base + 1000 * n for n in range(36)] + [base]
        with self.assertRaises(plans.RfPlanError) as ctx:
            plans.normalize_bands(wide)
        self.assertEqual(ctx.exception.code, "RF_TOTAL_CHANNELS_EXCEEDED")

    def test_bench_table_is_a_valid_plan(self):
        self.assertEqual(sum(len(v) - 1 for v in plans.normalize_bands(bench_bands()).values()), 107)


# ----------------------------------------------------------------------------------
# Storage
# ----------------------------------------------------------------------------------

class Storage(IsolatedStore):

    def test_store_sits_beside_the_naming_master_via_the_shared_resolver(self):
        import vtx_nicknames
        self.assertEqual(plans.store_path().parent, local_settings.config_root())
        self.assertEqual(plans.store_path().parent, vtx_nicknames.store_path().parent)
        self.assertNotEqual(plans.store_path(), vtx_nicknames.store_path())

    def test_save_and_load_round_trip(self):
        plans.save_plan(name="Bench baseline", bands=bench_bands(), note="from the 2026-09-06 read")
        stored = plans.get_plan("bench BASELINE")
        self.assertEqual(stored["name"], "Bench baseline")
        self.assertEqual(stored["bands"], bench_bands())
        self.assertEqual(stored["note"], "from the 2026-09-06 read")

    def test_names_are_unique_case_insensitively_and_collision_refuses(self):
        plans.save_plan(name="Range day", bands=bench_bands())
        with self.assertRaises(plans.RfPlanError) as ctx:
            plans.save_plan(name="RANGE DAY", bands=bench_bands())
        self.assertEqual(ctx.exception.code, "PLAN_NAME_IN_USE")
        self.assertEqual(len(plans.load_all()), 1)

    def test_replace_updates_in_place_and_keeps_created_at(self):
        first = plans.save_plan(name="Range day", bands=bench_bands())
        edited = bench_bands()
        edited["bandA"] = edited["bandA"][:-1] + [4200000]
        second = plans.save_plan(name="range day", bands=edited, replace=True)
        self.assertEqual(second["created_at"], first["created_at"])
        self.assertEqual(plans.get_plan("Range day")["bands"]["bandA"][-1], 4200000)

    def test_delete_removes_only_the_named_plan(self):
        plans.save_plan(name="One", bands=bench_bands())
        plans.save_plan(name="Two", bands=bench_bands())
        plans.delete_plan("one")
        self.assertEqual(sorted(p["name"] for p in plans.load_all().values()), ["Two"])
        with self.assertRaises(plans.RfPlanError) as ctx:
            plans.delete_plan("one")
        self.assertEqual(ctx.exception.code, "PLAN_NOT_FOUND")

    def test_store_is_written_atomically_and_leaves_no_temp_file(self):
        plans.save_plan(name="One", bands=bench_bands())
        leftovers = list(plans.store_path().parent.glob("*.tmp"))
        self.assertEqual(leftovers, [])
        doc = json.loads(plans.store_path().read_text(encoding="utf-8"))
        self.assertEqual(doc["schema"], "ascent.rf_band_plans.v1")

    def test_a_corrupt_store_loads_as_empty_rather_than_raising(self):
        plans.store_path().parent.mkdir(parents=True, exist_ok=True)
        plans.store_path().write_text("{ not json", encoding="utf-8")
        self.assertEqual(plans.load_all(), {})

    def test_an_unreadable_row_is_dropped_and_the_rest_survive(self):
        plans.save_plan(name="Good", bands=bench_bands())
        doc = json.loads(plans.store_path().read_text(encoding="utf-8"))
        doc["plans"]["broken"] = {"name": "Broken", "bands": {"bandA": [1, 2, 3]}}
        plans.store_path().write_text(json.dumps(doc), encoding="utf-8")
        loaded = plans.load_all()
        self.assertEqual(sorted(p["name"] for p in loaded.values()), ["Good"])

    def test_no_host_or_device_identity_is_ever_stored(self):
        """The store records product facts, never anything that identifies a unit or a PC."""
        plans.save_plan(name="Bench baseline", bands=bench_bands(),
                        compatibility={"rf_board_code": 160,
                                       "hardware": "Ascent-VRX-Max-V2.2-10.0",
                                       # All of these are offered and all must be dropped.
                                       "serial_number": "9005", "bb_id": (':'.join(('F2', '00', '00', '22'))),
                                       "firmware_md5": "f36ad83490bfe0cd947271c2144918ef",
                                       "port": "COM10",
                                       "username": local_identity.local_username() or "u"})
        raw = plans.store_path().read_text(encoding="utf-8")
        for leaked in ("9005", (':'.join(('F2', '00', '00', '22'))), "f36ad834", "COM10",
                       local_identity.local_username() or "u", "C:\\\\", "/home/"):
            self.assertNotIn(leaked, raw)
        self.assertEqual(plans.get_plan("Bench baseline")["compatibility"],
                         {"rf_board_code": 160, "hardware": "Ascent-VRX-Max-V2.2-10.0"})


# ----------------------------------------------------------------------------------
# Input normalization -- untrusted in, never silently coerced
# ----------------------------------------------------------------------------------

class Normalization(IsolatedStore):

    def test_a_non_integer_frequency_is_refused_not_coerced(self):
        for bad in (4495000.0, "4495000", True, None):
            with self.subTest(bad=repr(bad)):
                with self.assertRaises(plans.RfPlanError):
                    plans.normalize_bands({"bandA": [bad, 5440000, 5839000]})

    def test_a_non_vendor_band_key_is_refused(self):
        for key in ("BAND_A", "bandA ", "band", "banda-1", "channels", "bandTooLongSuffix"):
            with self.subTest(key=key):
                with self.assertRaises(plans.RfPlanError) as ctx:
                    plans.normalize_bands({key: [4495000, 5440000, 5839000]})
                self.assertIn(ctx.exception.code,
                              {"PLAN_BAND_KEY_INVALID", "RF_NO_BANDS"})

    def test_names_are_bounded_and_control_characters_refused(self):
        with self.assertRaises(plans.RfPlanError):
            plans.normalize_name("x" * (plans.NAME_MAX_CHARS + 1))
        with self.assertRaises(plans.RfPlanError):
            plans.normalize_name("range\x07day")
        with self.assertRaises(plans.RfPlanError):
            plans.normalize_name("   ")
        self.assertEqual(plans.normalize_name("  Range day  "), "Range day")

    def test_notes_are_bounded(self):
        with self.assertRaises(plans.RfPlanError):
            plans.normalize_note("x" * (plans.NOTE_MAX_CHARS + 1))


# ----------------------------------------------------------------------------------
# Hardware capability profiles
# ----------------------------------------------------------------------------------

class Capability(unittest.TestCase):

    def test_the_only_profile_matches_the_bench_artefact_exactly(self):
        """CAPABILITY_PROFILES is transcribed from the measured table, not estimated."""
        profile = plans.capability_profile(0xA0, "Ascent-VRX-Max-V2.2-10.0")
        self.assertIsNotNone(profile)
        for key, values in bench_bands().items():
            channels = values[:-1]
            limits = profile["bands"][key]
            self.assertEqual(limits["channels"], len(channels), key)
            self.assertEqual(limits["min_khz"], min(channels), key)
            self.assertEqual(limits["max_khz"], max(channels), key)
            self.assertEqual(limits["default_khz"], values[-1], key)

    def test_profiles_hold_only_the_one_measured_unit(self):
        self.assertEqual(list(plans.CAPABILITY_PROFILES), [(0xA0, "Ascent-VRX-Max-V2.2-10.0")])

    def test_matching_is_exact_with_no_fuzzy_prefix_or_case_fallback(self):
        for code, hardware in [
            (0xA0, "Ascent-VRX-Max-V2.2-10"),          # prefix
            (0xA0, "Ascent-VRX-Max-V2.2-10.0-B"),      # superstring
            (0xA0, "ascent-vrx-max-v2.2-10.0"),        # case
            (0xA0, " Ascent-VRX-Max-V2.2-10.0"),       # whitespace
            (0x10, "Ascent-VRX-Max-V2.2-10.0"),        # different board
            (None, "Ascent-VRX-Max-V2.2-10.0"),
            (0xA0, None),
        ]:
            with self.subTest(code=code, hardware=hardware):
                self.assertIsNone(plans.capability_profile(code, hardware))

    def test_unknown_hardware_fails_closed_with_the_required_wording(self):
        result = plans.assess({"bands": bench_bands()},
                              rf_board_code=0x10, hardware="Ascent_GT_Pro-V1.0")
        self.assertEqual(result["state"], "not_established")
        self.assertIsNone(result["profile"])
        self.assertTrue(any("Compatibility limits not established" in f["detail"]
                            for f in result["findings"]))

    def test_unknown_hardware_is_neither_permission_nor_refusal(self):
        """`not_established` is its own third state, worded as neither yes nor no."""
        result = plans.assess({"bands": bench_bands()}, rf_board_code=0x10, hardware="Other")
        self.assertNotIn(result["state"], ("proven", "incompatible"))
        detail = " ".join(f["detail"] for f in result["findings"]).lower()
        for forbidden in ("permitted", "allowed", "approved", "safe to transmit",
                          "rejected", "forbidden", "must not"):
            self.assertNotIn(forbidden, detail, forbidden)
        self.assertIn("nothing here says these values are accepted, or that they are not", detail)


# ----------------------------------------------------------------------------------
# Assessment
# ----------------------------------------------------------------------------------

class Assessment(unittest.TestCase):

    def test_the_bench_table_on_its_own_hardware_is_proven(self):
        result = plans.assess({"bands": bench_bands()}, rf_board_code=0xA0,
                              hardware="Ascent-VRX-Max-V2.2-10.0", live_bands=bench_bands())
        self.assertEqual(result["state"], "proven")
        self.assertEqual(result["findings"], [])

    def test_values_outside_the_measured_extent_are_unestablished_not_rejected(self):
        bands = bench_bands()
        bands["bandD"] = [2000000] + bands["bandD"][1:]
        result = plans.assess({"bands": bands}, rf_board_code=0xA0,
                              hardware="Ascent-VRX-Max-V2.2-10.0")
        self.assertEqual(result["state"], "not_established")
        finding = next(f for f in result["findings"] if f["code"] == "OUTSIDE_PROVEN_EXTENT")
        self.assertIn("not known-bad", finding["detail"])

    def test_a_band_the_device_table_lacks_is_structurally_incompatible(self):
        bands = bench_bands()
        bands["bandE"] = [4495000, 5440000, 5839000]
        live = bench_bands()
        result = plans.assess({"bands": bands}, rf_board_code=0xA0,
                              hardware="Ascent-VRX-Max-V2.2-10.0", live_bands=live)
        self.assertEqual(result["state"], "incompatible")
        self.assertTrue(any(f["code"] == "BAND_ABSENT_FROM_DEVICE_TABLE" for f in result["findings"]))

    def test_a_partial_plan_notes_the_bands_it_leaves_alone(self):
        result = plans.assess({"bands": {"bandA": bench_bands()["bandA"]}},
                              rf_board_code=0xA0, hardware="Ascent-VRX-Max-V2.2-10.0",
                              live_bands=bench_bands())
        note = next(f for f in result["findings"] if f["code"] == "DEVICE_BANDS_NOT_IN_PLAN")
        self.assertEqual(note["bands"], ["bandB", "bandC", "bandD"])
        self.assertEqual(note["severity"], "note")

    def test_every_assessment_disclaims_transmission_legality(self):
        for kwargs in ({"rf_board_code": 0xA0, "hardware": "Ascent-VRX-Max-V2.2-10.0"},
                       {"rf_board_code": None, "hardware": None}):
            self.assertEqual(plans.assess({"bands": bench_bands()}, **kwargs)["transmission_legality"],
                             "not assessed")


# ----------------------------------------------------------------------------------
# CSV interchange
# ----------------------------------------------------------------------------------

class Csv(unittest.TestCase):

    def test_export_import_round_trips_the_bench_table_exactly(self):
        plan = {"name": "Bench baseline", "bands": bench_bands()}
        parsed = plans.from_csv(plans.to_csv(plan))
        self.assertEqual(parsed["bands"], bench_bands())
        self.assertEqual(parsed["name"], "Bench baseline")

    def test_export_marks_the_trailing_entry_as_the_default_not_a_channel(self):
        rows = list(io.StringIO(plans.to_csv({"name": "P", "bands": {"bandA": bench_bands()["bandA"]}})))
        self.assertEqual(rows[0].strip(), ",".join(plans.CSV_COLUMNS))
        self.assertEqual(rows[1].strip().split(",")[3], "CHANNEL")
        self.assertEqual(rows[-1].strip().split(",")[3], "DEFAULT")
        self.assertEqual(rows[-1].strip().split(",")[4], str(bench_bands()["bandA"][-1]))

    def test_an_unexpected_header_is_refused_rather_than_guessed(self):
        with self.assertRaises(plans.RfPlanError) as ctx:
            plans.from_csv("band,freq\nbandA,4495000\n")
        self.assertEqual(ctx.exception.code, "CSV_HEADER_UNEXPECTED")

    def test_every_bad_row_is_named_and_nothing_is_coerced(self):
        text = (",".join(plans.CSV_COLUMNS) + "\n"
                "P,bandA,1,CHANNEL,4495000.0\n"
                "P,bandA,2,CHANNEL, 4525000 \n"
                "P,bandA,3,CHANNEL,4555\n"
                "P,BAND_A,4,CHANNEL,4585000\n"
                "P,bandA,5,SPARE,4615000\n")
        with self.assertRaises(plans.RfPlanError) as ctx:
            plans.from_csv(text)
        self.assertEqual(ctx.exception.code, "CSV_INVALID")
        codes = [e["code"] for e in ctx.exception.evidence["errors"]]
        self.assertIn("CSV_FREQUENCY_NOT_INTEGER", codes)
        self.assertIn("CSV_BAND_KEY_INVALID", codes)
        self.assertIn("CSV_ROLE_INVALID", codes)
        self.assertTrue(all(isinstance(e["line"], int) for e in ctx.exception.evidence["errors"]))

    def test_a_gap_in_channel_positions_refuses_rather_than_silently_shifting(self):
        text = (",".join(plans.CSV_COLUMNS) + "\n"
                "P,bandA,1,CHANNEL,4495000\n"
                "P,bandA,3,CHANNEL,4555000\n"
                "P,bandA,29,DEFAULT,5839000\n")
        with self.assertRaises(plans.RfPlanError) as ctx:
            plans.from_csv(text)
        self.assertEqual(ctx.exception.code, "CSV_INCOMPLETE")
        self.assertEqual(ctx.exception.evidence["gaps"][0]["missing_positions"], [2])

    def test_a_band_without_a_default_row_refuses(self):
        text = (",".join(plans.CSV_COLUMNS) + "\n"
                "P,bandA,1,CHANNEL,4495000\n"
                "P,bandA,2,CHANNEL,5440000\n")
        with self.assertRaises(plans.RfPlanError) as ctx:
            plans.from_csv(text)
        self.assertEqual(ctx.exception.code, "CSV_INCOMPLETE")
        self.assertTrue(ctx.exception.evidence["gaps"][0]["missing_default"])

    def test_a_duplicate_position_refuses_rather_than_keeping_the_last(self):
        text = (",".join(plans.CSV_COLUMNS) + "\n"
                "P,bandA,1,CHANNEL,4495000\n"
                "P,bandA,1,CHANNEL,4525000\n"
                "P,bandA,2,CHANNEL,5440000\n"
                "P,bandA,2,DEFAULT,5839000\n")
        with self.assertRaises(plans.RfPlanError) as ctx:
            plans.from_csv(text)
        self.assertIn("CSV_POSITION_DUPLICATED", [e["code"] for e in ctx.exception.evidence["errors"]])

    def test_an_imported_csv_still_passes_the_writer_s_validator(self):
        """Import is not a back door around the vendor editor rules."""
        text = (",".join(plans.CSV_COLUMNS) + "\n"
                "P,bandA,1,CHANNEL,4495500\n"       # not a multiple of 1000 kHz
                "P,bandA,2,CHANNEL,5440000\n"
                "P,bandA,2,DEFAULT,5839000\n")
        with self.assertRaises(plans.RfPlanError) as ctx:
            plans.from_csv(text)
        self.assertEqual(ctx.exception.code, "RF_FREQUENCY_NOT_MULTIPLE")

    def test_two_plan_names_in_one_file_refuse_unless_a_name_is_given(self):
        text = (",".join(plans.CSV_COLUMNS) + "\n"
                "A,bandA,1,CHANNEL,4495000\n"
                "B,bandA,2,CHANNEL,5440000\n"
                "A,bandA,2,DEFAULT,5839000\n")
        with self.assertRaises(plans.RfPlanError) as ctx:
            plans.from_csv(text)
        self.assertEqual(ctx.exception.code, "CSV_PLAN_NAME_AMBIGUOUS")
        self.assertEqual(plans.from_csv(text, name="Merged")["name"], "Merged")

    def test_an_oversized_input_is_refused_before_parsing(self):
        with self.assertRaises(plans.RfPlanError) as ctx:
            plans.from_csv("x" * (plans.MAX_STORE_BYTES + 1))
        self.assertEqual(ctx.exception.code, "CSV_TOO_LARGE")


# ----------------------------------------------------------------------------------
# The feature cannot transmit, and it cannot widen a write
# ----------------------------------------------------------------------------------

class NoTransport(unittest.TestCase):

    SOURCE = (ROOT / "runtime" / "rf_band_plans.py").read_text(encoding="utf-8")
    # Executable lines only: docstrings and comments legitimately discuss the write
    # path this feature hands values to, and must not trip a "no transport" check.
    CODE = "\n".join(line.split("#")[0]
                     for line in re.sub(r'(?s)""".*?"""', "", SOURCE).splitlines())

    def test_module_holds_no_transport(self):
        for forbidden in ("import socket", "import serial", "urllib", "http.client",
                          "subprocess", "VendorWriteSession", "build_request", "exchange("):
            self.assertNotIn(forbidden, self.SOURCE, forbidden)

    def test_module_never_names_a_vendor_opcode_or_a_port(self):
        """Checked against code only -- the prose may discuss the write path it feeds."""
        for forbidden in (r"\bCOM\d", r"115200", r"0x4152544F", r"SENDFILE", r"\bserial\b"):
            self.assertIsNone(re.search(forbidden, self.CODE), forbidden)

    def test_the_only_legality_statement_is_the_disclaimer(self):
        """The module may say legality is not assessed. It may never assert one."""
        self.assertIn('"transmission_legality": "not assessed"', self.SOURCE)
        self.assertEqual(set(re.findall(r'"transmission_legality":\s*"([^"]*)"', self.SOURCE)),
                         {"not assessed"})


class WriteQualificationUntouched(unittest.TestCase):

    HARNESS = (ROOT / "runtime" / "dev_harness.py").read_text(encoding="utf-8")

    def test_plan_endpoints_do_not_touch_write_qualification(self):
        """Nothing in the plan handlers calls, caches or rewrites QUALIFY."""
        start = self.HARNESS.index("def _plan_target()")
        end = self.HARNESS.index("def write_rf_band_table(")
        section = self.HARNESS[start:end]
        for forbidden in ("qualify_rf_write", "RF_WRITE_PROFILES", "SERIAL_GATE",
                          "DEVICE_MUTATION_LOCK", "VendorWriteSession"):
            self.assertNotIn(forbidden, section, forbidden)

    def test_the_write_path_still_gates_on_an_exact_profile_match(self):
        """The existing gate is unchanged: exact equality on all six identity facts."""
        result = vw.qualify_rf_write(
            candidate={"identity_proven": True, "serial_com": "COM10",
                       "serial_container_id": "{x}",
                       "serial_pnp_device_id": "USB\\VID_1D77&PID_A4A2\\x"},
            identity={"device_name": "Ascent_VRX_max_WF", "firmware": "Ascent_VRX_Max_19_2_4",
                      "hardware": "Ascent-VRX-Max-V2.2-10.1",   # one character off
                      "rf_board_code": 0xA0},
            rf_reading={"available": True, "state": "ok", "data": {"RFBoardType": 0xA0},
                        "integrity": {"method": "vendor_md5_cmd115", "verified": True}})
        self.assertFalse(result["eligible"])
        self.assertIn("NO_OPERATION_SPECIFIC_WRITE_PROFILE", result["reasons"])

    def test_plans_add_no_new_device_write_route(self):
        """The only routes that reach a device write are the two that already existed."""
        import re
        routes = set(re.findall(r'p == "(/api/rf-band[^"]*)"', self.HARNESS))
        routes |= set(re.findall(r'p\.startswith\("(/api/rf-band[^"]*)"\)', self.HARNESS))
        self.assertEqual(routes, {"/api/rf-bands", "/api/rf-bands/write-eligibility",
                                  "/api/rf-bands/write-preview", "/api/rf-bands/write",
                                  "/api/rf-band-plans", "/api/rf-band-plans/"})


# ----------------------------------------------------------------------------------
# The HTTP surface, served for real
# ----------------------------------------------------------------------------------

class Endpoints(IsolatedStore):
    """Against a live server, because the routing faults this project has actually
    shipped were prefix collisions and mutations answered on the wrong verb -- both
    invisible to a test that calls the handler function directly."""

    def setUp(self):
        super().setUp()
        import threading
        import dev_harness
        self.dh = dev_harness
        self._saved = dict(dev_harness.ACTIVE_CONNECTION)
        dev_harness.ACTIVE_CONNECTION["serial_identity"] = {
            "device_name": "Ascent_VRX_max_WF", "hardware": "Ascent-VRX-Max-V2.2-10.0",
            "rf_board_code": 0xA0}
        dev_harness.ACTIVE_CONNECTION["rf_bands"] = {
            "available": True, "state": "ok", "data": bench_table(),
            "integrity": {"verified": True, "method": "vendor_md5_cmd115"}}
        self.server = dev_harness.AscentHTTPServer(("127.0.0.1", 0), dev_harness.Handler)
        self.port = self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def tearDown(self):
        self.server.shutdown()
        self.dh.ACTIVE_CONNECTION.clear()
        self.dh.ACTIVE_CONNECTION.update(self._saved)
        super().tearDown()

    def get(self, path):
        import urllib.request
        with urllib.request.urlopen(f"http://127.0.0.1:{self.port}{path}") as r:
            return r.status, json.load(r)

    def post(self, path, body):
        import urllib.error
        import urllib.request
        req = urllib.request.Request(f"http://127.0.0.1:{self.port}{path}",
                                     data=json.dumps(body).encode("utf-8"),
                                     headers={"Content-Type": "application/json"},
                                     method="POST")
        try:
            with urllib.request.urlopen(req) as r:
                return r.status, json.load(r)
        except urllib.error.HTTPError as e:
            return e.code, json.load(e)

    def test_the_list_is_served_on_get_and_the_actions_on_post(self):
        status, doc = self.get("/api/rf-band-plans")
        self.assertEqual(status, 200)
        self.assertEqual(doc["count"], 0)
        self.assertEqual(doc["transmission_legality"], "not assessed")

    def test_the_plan_route_does_not_swallow_the_rf_table_route(self):
        """/api/rf-bands and /api/rf-band-plans are neighbours; neither may shadow the other."""
        status, doc = self.get("/api/rf-bands")
        self.assertEqual(status, 200)
        # No device is attached here, so this is the RF read's own failure shape --
        # which is the point: it is the RF table route answering, not the plan route.
        self.assertNotIn("plans", doc)
        self.assertEqual(doc.get("command", 120), 120)
        _, plan_doc = self.get("/api/rf-band-plans")
        self.assertIn("plans", plan_doc)
        self.assertNotIn("command", plan_doc)

    def test_capture_export_import_round_trip_over_http(self):
        self.assertEqual(self.post("/api/rf-band-plans/save", {"name": "Bench baseline"})[0], 200)
        _, doc = self.get("/api/rf-band-plans")
        entry = doc["plans"][0]
        self.assertEqual(entry["channel_count"], 107)
        self.assertEqual(entry["assessment"]["state"], "proven")
        self.assertEqual(entry["compatibility"],
                         {"rf_board_code": 160, "hardware": "Ascent-VRX-Max-V2.2-10.0"})
        _, exported = self.post("/api/rf-band-plans/export", {"name": "bench BASELINE"})
        # 1 header + 107 channel rows + one default row per band.
        self.assertEqual(len(exported["csv"].strip().splitlines()), 1 + 107 + 4)
        _, imported = self.post("/api/rf-band-plans/import",
                                {"csv": exported["csv"], "name": "Copy", "save": True})
        self.assertTrue(imported["stored"])
        self.assertEqual(self.get("/api/rf-band-plans")[1]["count"], 2)
        self.assertEqual(plans.get_plan("Copy")["bands"], bench_bands())

    def test_a_parse_only_import_stores_nothing(self):
        _, exported = self.post("/api/rf-band-plans/export", {"name": "x"})
        self.post("/api/rf-band-plans/save", {"name": "Bench baseline"})
        _, exported = self.post("/api/rf-band-plans/export", {"name": "Bench baseline"})
        _, parsed = self.post("/api/rf-band-plans/import",
                              {"csv": exported["csv"], "name": "Preview only"})
        self.assertFalse(parsed["stored"])
        self.assertEqual(parsed["channel_count"], 107)
        self.assertEqual(self.get("/api/rf-band-plans")[1]["count"], 1)

    def test_capture_without_a_verified_read_refuses(self):
        self.dh.ACTIVE_CONNECTION["rf_bands"] = {"available": True, "state": "ok",
                                                 "data": bench_table(),
                                                 "integrity": {"verified": False}}
        status, body = self.post("/api/rf-band-plans/save", {"name": "Unverified"})
        self.assertEqual(status, 409)
        self.assertEqual(body["error"], "FRESH_RF_READ_NOT_AVAILABLE")

    def test_error_codes_and_statuses(self):
        self.post("/api/rf-band-plans/save", {"name": "Bench baseline"})
        for path, body, status, code in [
            ("/api/rf-band-plans/save", {"name": "bench baseline"}, 409, "PLAN_NAME_IN_USE"),
            ("/api/rf-band-plans/delete", {"name": "absent"}, 409, "PLAN_NOT_FOUND"),
            ("/api/rf-band-plans/nonsense", {}, 404, "UNKNOWN_PLAN_ACTION"),
            ("/api/rf-band-plans/save", {"name": "", "bands": bench_bands()}, 400, "PLAN_NAME_REQUIRED"),
            ("/api/rf-band-plans/import",
             {"csv": "plan,band,position,role,frequency_khz\nP,bandA,1,CHANNEL,4495000.5\n"},
             400, "CSV_INVALID"),
        ]:
            with self.subTest(path=path, code=code):
                got_status, got = self.post(path, body)
                self.assertEqual(got_status, status)
                self.assertEqual(got["error"], code)

    def test_the_plan_document_names_no_host_or_device_identity(self):
        self.post("/api/rf-band-plans/save", {"name": "Bench baseline"})
        raw = json.dumps(self.get("/api/rf-band-plans")[1])
        for leaked in ("COM", "serial_number", "bb_id", "md5", "LOCALAPPDATA", "/home/"):
            self.assertNotIn(leaked, raw, leaked)


if __name__ == "__main__":
    unittest.main(verbosity=2)
