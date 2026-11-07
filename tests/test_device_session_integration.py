# Public profile: stock assertions retained; absent Picker API must stay404.
"""End-to-end session test: connect_host() -> what the six routes actually return.

BACKEND_INVENTORY.md 2.4 defect 8: every other test module injects ACTIVE_CONNECTION
directly or calls _build_connection_candidates() on canned inventory. Nothing drove
connect_host() and then asserted what /api/rf-bands, /api/status and /api/rf return,
so the 3.2 defects were untested by construction. This module closes that.

The HTTP routes are exercised through a real ThreadingHTTPServer running the real
Handler, so the route table, status codes and JSON shapes are the production ones.

What is faked, and only this:

  * The Windows USB/RNDIS inventory. One mutable dict stands in for the two
    PowerShell queries, so a test can change ifIndex, IPv4 or ContainerId mid-session
    exactly the way Windows does and nothing else has to move.
  * The vendor serial read. caddx_read_bundle is replaced with a report built from
    fixtures/vrxmax_cmd115_116_integrity.json, so the real command-115 MD5 sidecar is
    recomputed against the real 2018-byte command-116 payload by the real verifier.
  * The Ground socket exchanges. The fakes call the production _require_binding(), so
    the source address / ifIndex resolution under test is the real one; only sendall
    and recv are gone.

None of this is a claim about live device or network behaviour. Per CLAUDE.md, WSL
cannot prove a device or network path -- serial, RNDIS, IP_UNICAST_IF and the
elevated host-address helper all still need the Windows bench.
"""
import json
import pathlib
import sys
import threading
import urllib.request
from http.server import ThreadingHTTPServer

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "runtime"))

import caddx_read_bundle as cb
import device_session as ds
import dev_harness as h

CID = "{11111111-2222-3333-4444-555555555555}"
OTHER_CID = "{F200001E-BBBB-CCCC-DDDD-EEEEEEEEEEEE}"
SERIAL_PNP = r"USB\VID_1D77&PID_A4A2&MI_02\7&2AB797F4&0&0002"
NET_PNP = r"USB\VID_1D77&PID_A4A2&MI_00\7&2AB797F4&0&0000"

_FIXTURE = json.loads((ROOT / "fixtures" / "vrxmax_cmd115_116_integrity.json").read_text(encoding="utf-8"))
RF_PAYLOAD = _FIXTURE["cmd116_payload_ascii"].encode("ascii")
RF_MD5 = _FIXTURE["expected_md5"]
RF_TABLE = json.loads(RF_PAYLOAD.decode("ascii"))

DEVICE_INFO = {
    "state": "ok",
    "device_name": "Ascent_VRX_max_WF",
    "firmware": "Ascent_VRX_Max_19_2_4",
    "hardware": "Ascent-VRX-Max-V2.2-10.0",
    "serial_number": "9005",
    "sdk_version": "19.2.4",
    "cpu_temp": 44,
    "status": 0,
    "detail": "ok",
    "receive_max_size": 1048576,
    "pc_tool_rf_board_code_candidate": 160,
    "pc_tool_rf_board_name": "FPV_SKY_RF_424_v11",
    "pc_tool_rf_board_enum_defined": True,
    "request_seq": 0,
    "response_seq": 0,
    "payload_length": 300,
}


# --------------------------------------------------------------------------- #
# Fake Windows state
# --------------------------------------------------------------------------- #

class FakeWindows:
    """One mutable stand-in for the two PowerShell inventory queries."""

    def __init__(self):
        self.serial_com = "COM10"
        self.serial_container_id = CID
        self.network_container_id = CID
        self.ifindex = 29
        self.ipv4 = []          # Windows has not assigned the host address yet
        self.adapter_status = "Up"
        self.include_network = True
        self.calls = 0
        # Additional physical Ascent units, each a dict of the same shape. Every unit
        # exposes the SAME device-side IP; only ContainerId, ifIndex and the host-side
        # address differ, which is exactly the multi-device case CLAUDE.md calls out.
        self.extra: list[dict] = []

    def inventory(self) -> dict:
        self.calls += 1
        usb = [{
            "Name": f"USB Serial Device ({self.serial_com})", "Status": "OK",
            "PNPClass": "Ports", "DeviceID": SERIAL_PNP, "PNPDeviceID": SERIAL_PNP,
            "ContainerId": self.serial_container_id,
        }]
        network = []
        if self.include_network:
            network.append({
                "Name": "Ethernet 4", "InterfaceDescription": "Remote NDIS Compatible Device #2",
                "ifIndex": self.ifindex, "Status": self.adapter_status, "PnPDeviceID": NET_PNP,
                "ContainerId": self.network_container_id, "MacAddress": "02-00-DE-AD-BE-ED",
                "LinkSpeed": "426 Mbps", "IPv4": list(self.ipv4),
            })
        for unit in self.extra:
            pnp_serial = SERIAL_PNP.replace("7&2AB797F4", unit["root"])
            pnp_net = NET_PNP.replace("7&2AB797F4", unit["root"])
            usb.append({"Name": f'USB Serial Device ({unit["com"]})', "Status": "OK",
                        "PNPClass": "Ports", "DeviceID": pnp_serial, "PNPDeviceID": pnp_serial,
                        "ContainerId": unit["cid"]})
            network.append({"Name": unit["adapter"], "InterfaceDescription": "Remote NDIS Compatible Device #3",
                            "ifIndex": unit["ifindex"], "Status": "Up", "PnPDeviceID": pnp_net,
                            "ContainerId": unit["cid"], "MacAddress": "02-00-DE-AD-BE-EE",
                            "LinkSpeed": "426 Mbps",
                            "IPv4": [{"IPAddress": unit["host_ip"], "PrefixLength": 24,
                                      "AddressState": "Preferred"}]})
        return {"platform": "Windows", "supported": True, "usb": usb, "network": network,
                "captured_at": "fixture"}

    def assign_host_address(self, ip="192.168.3.103", prefix=24, state="Preferred"):
        self.ipv4 = [{"IPAddress": ip, "PrefixLength": prefix, "PrefixOrigin": "Manual",
                      "SuffixOrigin": "Manual", "AddressState": state}]


class FakeSerial:
    """Stands in for caddx_read_bundle.run(). Command 120 can be made to fail."""

    def __init__(self):
        self.rf_ok = True
        self.reads = 0
        self.ports = []

    def __call__(self, port, include_frequency=True, include_nics=False):
        self.reads += 1
        self.ports.append(port)
        report = {"captured_at": "fixture", "port": port, "device_info": dict(DEVICE_INFO)}
        if include_frequency:
            if self.rf_ok:
                # Real sidecar, real payload, real verifier.
                sidecar = RF_MD5.encode("ascii") + b"\x00" * 8
                report["bb_frequency"] = {
                    "state": "ok", "json": json.loads(RF_PAYLOAD.decode("ascii")),
                    "payload": RF_PAYLOAD, "request_seq": 1, "response_seq": 1,
                    "payload_length": len(RF_PAYLOAD),
                    "integrity": cb.verify_cmd115_md5(RF_PAYLOAD, sidecar),
                }
            else:
                report["bb_frequency"] = {"state": "no_matching_frequency_response",
                                          "received_commands": [60]}
        return report


def _fake_bb_status(source_ip=None, if_index=None):
    # Production binding resolution, faked socket exchange.
    source_ip, if_index = h._require_binding(source_ip, if_index, "Ground RPC")
    return {"connected": True, "host": h.HOST_CFG["ground"], "port": h.HOST_CFG["rpc_port"],
            "source_ip": source_ip, "ifindex": if_index, "local_bb_id": (':'.join(('F2', '00', '00', '0B'))),
            "link": "LINKED", "link_raw": 2, "rx_mcs": 7, "peer_diagnostic": (':'.join(('66', '00', '00', '00'))),
            "peer_raw_when_unlinked": None, "peer_is_authoritative": False,
            "captured_at": h.utc_now()}


def _fake_gc_query(command, timeout=0.75, source_ip=None, if_index=None):
    source_ip, if_index = h._require_binding(source_ip, if_index, "Ground UDP")
    payload = bytes([command, 0x01])
    return {"direction": 0xA2, "payload_length": len(payload), "command": command,
            "payload_hex": payload.hex(" ").upper(), "frame_hex": "",
            "host": h.HOST_CFG["ground"], "port": h.HOST_CFG["ctrl_udp_port"],
            "source_ip": source_ip, "ifindex": if_index,
            "peer": f'{h.HOST_CFG["ground"]}:{h.HOST_CFG["ctrl_udp_port"]}',
            "tx_hex": "", "captured_at": h.utc_now(), "decode_status": "RAW_VALIDATED_ONLY"}


def _fake_mgmt_get_json(path, source_ip=None, if_index=None):
    source_ip, if_index = h._require_binding(source_ip, if_index, "the management API")
    if path == "/v1/picker/fleet":
        return {"schema": "ascent.picker.fleet.v1", "api_version": 1, "available": True,
                "mode": "normal", "fleet_source": "normal_user_cfg", "warnings": [],
                "fleet": [{"mac": (':'.join(('F2', '00', '00', '04'))), "slot_index": -1, "source_key": "bb_mac_addr"},
                          {"mac": (':'.join(('F2', '00', '00', '13'))), "slot_index": 0, "source_key": "bb_mac_addr_0"}]}
    if path == "/v1/picker/aliases":
        return {"schema": "ascent.picker.aliases.v1", "api_version": 1, "available": True,
                "aliases": {(':'.join(('F2', '00', '00', '04'))): "LEAD"}, "warnings": []}
    raise RuntimeError("unsupported management resource")


# --------------------------------------------------------------------------- #
# Harness
# --------------------------------------------------------------------------- #

class Bench:
    """Real Handler on a real socket, with the fakes installed for its lifetime."""

    ROUTES = ("/api/connection-state", "/api/rf", "/api/rf-bands",
              "/api/status", "/api/fleet", "/api/connections")

    def __init__(self, tmp_path):
        self.windows = FakeWindows()
        self.serial = FakeSerial()
        self._saved = {}
        self._tmp = tmp_path

    def __enter__(self):
        for name in ("windows_usb_inventory", "caddx_read_bundle", "bb_status", "gc_query",
                     "_configure_rndis_elevated", "caddx_legacy_query",
                     "HOST_IP_WAIT_SECONDS", "RF_FAILURE_BACKOFF"):
            self._saved[name] = getattr(h, name)
        h.windows_usb_inventory = self.windows.inventory
        h.caddx_read_bundle = self.serial
        h.bb_status = _fake_bb_status
        h.gc_query = _fake_gc_query
        h._configure_rndis_elevated = lambda ifindex: {"ok": True, "ifindex": int(ifindex)}
        h.caddx_legacy_query = lambda port, cmd: {"device_info": dict(DEVICE_INFO)}
        h.HOST_IP_WAIT_SECONDS = 0.05
        h.RF_FAILURE_BACKOFF = 0.0

        h.SESSION.clear()
        h.INVENTORY_CACHE.invalidate()
        with h.DISCOVERY_LOCK:
            h.DISCOVERY_IDENTITY.clear()

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), h.Handler)
        self.base = f"http://127.0.0.1:{self.server.server_address[1]}"
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True,
                                       name="AscentTestServer")
        self.thread.start()
        return self

    def __exit__(self, *_):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)
        h.SESSION.clear()
        h.INVENTORY_CACHE.invalidate()
        with h.DISCOVERY_LOCK:
            h.DISCOVERY_IDENTITY.clear()
        for name, value in self._saved.items():
            setattr(h, name, value)
        return False

    def get(self, path) -> tuple[int, dict]:
        req = urllib.request.Request(self.base + path)
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                return r.status, json.loads(r.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read().decode("utf-8"))

    def post(self, path, body=None) -> tuple[int, dict]:
        data = json.dumps(body or {}).encode("utf-8")
        req = urllib.request.Request(self.base + path, data=data,
                                     headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                return r.status, json.loads(r.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read().decode("utf-8"))

    def get_fresh(self, path) -> tuple[int, dict]:
        """Hit exactly one route against fresh Windows state.

        Deliberately does not touch any other route first: the point of several of
        these tests is that a consumer resolves the binding itself, rather than
        depending on some earlier request having refreshed shared state for it.
        """
        h.INVENTORY_CACHE.invalidate()
        return self.get(path)

    def all_routes(self) -> dict:
        # The inventory cache is short-TTL by design; a test that mutates fake Windows
        # state and immediately asserts is faster than that TTL, so expire it
        # explicitly rather than sleeping.
        h.INVENTORY_CACHE.invalidate()
        return {p: self.get(p) for p in self.ROUTES}

    def connect(self) -> dict:
        h.INVENTORY_CACHE.invalidate()
        status, doc = self.post("/api/connect", {"candidate_id": "auto"})
        assert status == 200, (status, doc)
        return doc


# --------------------------------------------------------------------------- #
# Tests
# --------------------------------------------------------------------------- #

def test_connect_then_all_six_routes_share_one_selected_device(tmp_path):
    with Bench(tmp_path) as bench:
        bench.windows.assign_host_address()
        connected = bench.connect()
        assert connected["connected"] is True
        assert connected["serial_identity"]["device_name"] == "Ascent_VRX_max_WF"

        r = bench.all_routes()

        # /api/connection-state -- the authoritative document.
        code, cs = r["/api/connection-state"]
        active = cs["active"]
        assert code == 200 and active["connected"] is True
        assert active["serial_identity"]["device_name"] == "Ascent_VRX_max_WF"
        assert active["stable_keys"]["serial_container_id"] == CID
        assert active["stable_keys"]["serial_number"] == "9005"
        assert active["candidate"]["ifindex"] == 29
        assert active["candidate"]["serial_com"] == "COM10"
        assert active["candidate"]["topology_qualified"] is True
        assert active["network_binding"] == {"container_id": CID, "source_ip": "192.168.3.103",
                                             "ifindex": 29}

        # /api/rf-bands -- the real persistent table, MD5-verified.
        code, bands = r["/api/rf-bands"]
        assert code == 200 and bands["available"] is True and bands["state"] == "ok"
        assert bands["data"] == RF_TABLE
        assert bands["integrity"]["actual_md5"] == RF_MD5
        assert bands["integrity"]["verified"] is True

        # /api/status, /api/rf, /api/fleet -- all bound to the same device.
        code, st = r["/api/status"]
        assert code == 200 and st["source_ip"] == "192.168.3.103" and st["ifindex"] == 29
        code, rf = r["/api/rf"]
        assert code == 200 and rf["available"] is True
        assert all(q["ok"] for q in rf["queries"].values())
        assert {q["ifindex"] for q in rf["queries"].values()} == {29}
        code, fleet = r["/api/fleet"]
        assert code == 404 and fleet["error"] == "UNKNOWN_API_ROUTE"
        assert not hasattr(h,"_mgmt_get_json")

        # /api/connections -- the same physical device, named as the active one.
        code, conns = r["/api/connections"]
        assert code == 200 and conns["detected"] is True
        assert conns["active_candidate_id"] == active["candidate_id"]
        assert [c["serial_com"] for c in conns["candidates"]] == ["COM10"]


def test_host_address_arriving_after_connect_is_picked_up_without_reconnect(tmp_path):
    """The BACKEND_INVENTORY.md 3.2.1 failure, as a regression test.

    Alpha14 froze the connect-time candidate row. A device whose RNDIS address landed
    after the connect window left every network consumer permanently reporting no
    topology-qualified source address, for the rest of the session, while Device Info
    kept showing the device.
    """
    with Bench(tmp_path) as bench:
        # Connect with no host address assigned yet.
        connected = bench.connect()
        assert connected["connected"] is True, connected

        r = bench.all_routes()
        code, cs = r["/api/connection-state"]
        active = cs["active"]
        assert active["serial_identity"]["device_name"] == "Ascent_VRX_max_WF"
        assert active["network_binding"] is None
        assert active["transport"]["state"] == "host_address_pending"
        # The reason is named, not a bare UNAVAILABLE.
        assert active["candidate"]["network_binding_error"]
        assert r["/api/status"][0] == 503
        assert r["/api/rf"][0] == 503
        assert r["/api/fleet"][0] == 404
        # Serial is independent and still works.
        assert r["/api/rf-bands"][1]["available"] is True

        # Windows finishes address assignment. Nothing reconnects; nothing is told.
        bench.windows.assign_host_address()

        # Resolved by the consumer itself, with no prior request to warm anything.
        h.INVENTORY_CACHE.invalidate()
        assert h._active_network_binding() == ("192.168.3.103", 29)
        assert bench.get_fresh("/api/status")[0] == 200
        assert bench.get_fresh("/api/fleet")[0] == 404
        assert bench.get_fresh("/api/rf")[0] == 200

        r = bench.all_routes()
        code, cs = r["/api/connection-state"]
        active = cs["active"]
        assert active["network_binding"] == {"container_id": CID, "source_ip": "192.168.3.103",
                                             "ifindex": 29}
        assert active["transport"]["state"] == "resolved"
        assert active["candidate"]["host_ip_ready"] is True
        assert r["/api/status"][0] == 200
        assert r["/api/rf"][0] == 200
        assert r["/api/fleet"][0] == 404


def test_volatile_transport_facts_are_reresolved_not_stored(tmp_path):
    with Bench(tmp_path) as bench:
        bench.windows.assign_host_address()
        bench.connect()
        assert bench.get("/api/status")[1]["ifindex"] == 29

        # The adapter is re-enumerated: new ifIndex, new host address, same physical
        # device and same ContainerId.
        bench.windows.ifindex = 44
        bench.windows.assign_host_address("192.168.3.105")

        # /api/status alone, against fresh state, with nothing refreshed on its behalf.
        code, st = bench.get_fresh("/api/status")
        assert code == 200 and st["ifindex"] == 44 and st["source_ip"] == "192.168.3.105"

        r = bench.all_routes()
        active = r["/api/connection-state"][1]["active"]
        assert active["candidate"]["ifindex"] == 44
        assert active["network_binding"]["ifindex"] == 44
        # Stable identity did not move with it.
        assert active["stable_keys"]["serial_container_id"] == CID
        assert active["serial_identity"]["serial_number"] == "9005"


def test_correlation_still_fails_closed_on_live_state(tmp_path):
    with Bench(tmp_path) as bench:
        bench.windows.assign_host_address()
        bench.connect()
        assert bench.get("/api/status")[0] == 200

        # Same device-side subnet, same address, different physical device. Destination
        # IP is not identity, and the RNDIS sibling must share the ContainerId.
        bench.windows.network_container_id = OTHER_CID
        assert bench.get_fresh("/api/status")[0] == 503
        r = bench.all_routes()
        assert r["/api/status"][0] == 503
        assert r["/api/rf"][0] == 503
        assert r["/api/fleet"][0] == 404
        active = r["/api/connection-state"][1]["active"]
        assert active["network_binding"] is None
        assert active["candidate"]["topology_qualified"] is False
        assert active["candidate"]["network_qualification_error"]

        # A duplicate/tentative host address is not a usable source address either.
        bench.windows.network_container_id = CID
        bench.windows.assign_host_address(state="Duplicate")
        active = bench.all_routes()["/api/connection-state"][1]["active"]
        assert active["network_binding"] is None
        assert active["transport"]["state"] == "address_not_usable"

        bench.windows.assign_host_address()
        assert bench.all_routes()["/api/status"][0] == 200


def test_failed_rf_read_is_not_a_cached_table(tmp_path):
    """BACKEND_INVENTORY.md 3.2: the truthy-failure-dict gate at rf_band_table().

    Alpha14 stored the failure dict in ACTIVE_CONNECTION["rf_bands"] and re-served it
    because a non-empty dict is truthy, so one failed command-120 at connect time
    pinned "RF table unavailable" for the whole session and force_refresh had no
    caller.
    """
    with Bench(tmp_path) as bench:
        bench.windows.assign_host_address()
        bench.serial.rf_ok = False
        bench.connect()

        code, bands = bench.get("/api/rf-bands")
        assert code == 200
        assert bands["available"] is False
        assert bands["error_code"] == "GET_BB_FREQ_NO_RESPONSE"
        assert bands["freshness"]["read_state"] == "absent"
        # A failure is never presented as a cached table.
        assert bands["cache_state"] != "cached"
        # Write qualification sees no RF record at all, and fails closed on it.
        assert h.ACTIVE_CONNECTION["rf_bands"] is None
        assert "FRESH_RF_READ_NOT_AVAILABLE" in bench.get("/api/rf-bands/write-eligibility")[1]["reasons"]

        reads_before = bench.serial.reads
        bench.serial.rf_ok = True
        code, bands = bench.get("/api/rf-bands")
        assert code == 200, bands
        assert bench.serial.reads > reads_before, "a failed read must be retried, not pinned"
        assert bands["available"] is True and bands["state"] == "ok"
        assert bands["data"] == RF_TABLE
        assert bands["cache_state"] == "fresh"
        assert bands["freshness"]["read_state"] == "value"

        # A verified table is reused within its TTL rather than reopening COM per page.
        reads_before = bench.serial.reads
        code, again = bench.get("/api/rf-bands")
        assert again["cache_state"] == "cached" and again["data"] == RF_TABLE
        assert bench.serial.reads == reads_before


def test_one_serial_gate_excludes_every_com_session(tmp_path):
    with Bench(tmp_path) as bench:
        bench.windows.assign_host_address()
        bench.connect()

        holder_ready = threading.Event()
        release = threading.Event()

        def hold():
            with h.SERIAL_GATE.hold("test-holder", timeout=5.0):
                holder_ready.set()
                release.wait(10)

        t = threading.Thread(target=hold, daemon=True, name="AscentTestHolder")
        t.start()
        assert holder_ready.wait(5)
        try:
            assert h.SERIAL_GATE.busy is True
            assert h.SERIAL_GATE.status()["owner"] == "test-holder"

            # A background discovery probe skips its turn instead of racing the handle.
            reads_before = bench.serial.reads
            h._probe_serial_cache(SERIAL_PNP, "COM10")
            assert bench.serial.reads == reads_before

            # An RF read that actually needs the port reports a named busy holder
            # rather than racing for the handle.
            saved = (h.SERIAL_GATE_TIMEOUT, h.RF_SUCCESS_TTL)
            h.SERIAL_GATE_TIMEOUT, h.RF_SUCCESS_TTL = 0.05, 0.0
            try:
                code, bands = bench.get("/api/rf-bands")
            finally:
                h.SERIAL_GATE_TIMEOUT, h.RF_SUCCESS_TTL = saved
            assert bands["error_code"] == "SERIAL_BUSY"
            assert bands["holder"]["owner"] == "test-holder"
        finally:
            release.set()
            t.join(timeout=5)

        assert h.SERIAL_GATE.busy is False
        assert bench.get("/api/rf-bands", )[1]["available"] is True


def test_disconnect_clears_every_route(tmp_path):
    with Bench(tmp_path) as bench:
        bench.windows.assign_host_address()
        bench.connect()
        assert bench.get("/api/status")[0] == 200

        code, out = bench.post("/api/disconnect")
        assert code == 200 and out["connected"] is False

        r = bench.all_routes()
        active = r["/api/connection-state"][1]["active"]
        assert active["connected"] is False
        assert active["serial_identity"] is None and active["candidate"] is None
        assert r["/api/status"][0] == 503
        assert r["/api/rf"][0] == 503
        assert r["/api/fleet"][0] == 404
        assert r["/api/rf-bands"][1]["error_code"] == "NO_CONNECTED_SERIAL_DEVICE"
        # Discovery keeps working; it never depended on a selected device.
        assert r["/api/connections"][1]["detected"] is True
        assert r["/api/connections"][1]["active_candidate_id"] is None


def test_inventory_cache_shares_one_refresh(tmp_path):
    with Bench(tmp_path) as bench:
        bench.windows.assign_host_address()
        bench.connect()
        h.INVENTORY_CACHE.invalidate()
        before = bench.windows.calls
        # Four consumers, one refresh: the 1 Hz discovery poll must not multiply the
        # two PowerShell processes across every transport resolution.
        bench.get("/api/connections")
        bench.get("/api/connection-state")
        bench.get("/api/status")
        bench.get("/api/rf")
        assert bench.windows.calls - before == 1, bench.windows.calls - before


def test_reconnect_budget_outlasts_the_observed_107s_outlier():
    # Reopen_Json is settle-then-poll, and the two are additive: the vendor's
    # ReOpenTimeout_Asce window starts AFTER its settle sleep. So the model is
    # 11 s settle + 110 s poll budget, not one flat number.
    # docs/PROTOCOL_SPEC.md section 7.
    #
    # The observed 107 s reconnect was measured by a stopwatch that started before
    # Close() and therefore includes the settle, so it must fit inside the TOTAL.
    assert h.RECONNECT_SETTLE == 11.0
    assert h.RECONNECT_POLL_BUDGET == 110.0
    assert h.RECONNECT_VERIFY_TIMEOUT == h.RECONNECT_SETTLE + h.RECONNECT_POLL_BUDGET
    assert h.RECONNECT_VERIFY_TIMEOUT > 107.0
    # The poll budget alone already exceeds the outlier, so a slow-but-healthy unit
    # cannot be reported as RECONNECT_VERIFY_TIMEOUT with write_may_have_applied.
    assert h.RECONNECT_POLL_BUDGET > 107.0
    # 100 s is the wrong deadline and must not be reintroduced.
    assert h.RECONNECT_VERIFY_TIMEOUT > 100.0
    import inspect
    sig = inspect.signature(h._find_reconnected_serial)
    assert sig.parameters["settle"].default == h.RECONNECT_SETTLE
    assert sig.parameters["timeout"].default == h.RECONNECT_POLL_BUDGET
    # The settle is a blind wait, matching the vendor: during it the device is
    # expected to be absent, so polling Windows would only observe stale enumeration.
    src = (ROOT / "runtime" / "dev_harness.py").read_text(encoding="utf-8")
    assert "if settle > 0:\n        time.sleep(settle)" in src
    # The WPF host's close path must outlast the longest mutation, or it hard-kills
    # Python mid-commit on a healthy unit.
    host = (ROOT / "src" / "Ascent.Desktop" / "BackendHost.cs").read_text(encoding="utf-8")
    assert "MutationDrainBudget = TimeSpan.FromSeconds(180)" in host
    assert "p.WaitForExit(5000)" not in host
    assert "TimeSpan.FromSeconds(45)" not in host


def test_device_session_module_selftest():
    # Pure model checks: ContainerId resolution, fail-closed ambiguity, failure-vs-
    # absence, and serial-gate reentrancy. No Windows, no device, no subprocess.
    ds.selftest()


def test_two_units_share_a_device_ip_and_are_never_merged(tmp_path):
    """CLAUDE.md multi-device correlation: destination IP is not identity.

    Both units answer on 192.168.3.102. Only ContainerId separates them, and the
    selected device's Ground traffic must leave through that unit's own local address
    and ifIndex -- never the first RNDIS adapter, never the other unit's.
    """
    with Bench(tmp_path) as bench:
        bench.windows.assign_host_address("192.168.3.103")
        bench.windows.extra.append({
            "cid": OTHER_CID, "com": "COM21", "root": "9&1BCDEF12",
            "ifindex": 44, "adapter": "Ethernet 7", "host_ip": "192.168.3.107",
        })
        assert h.HOST_CFG["ground"] == "192.168.3.102"

        code, conns = bench.get("/api/connections")
        assert code == 200
        ids = {c["serial_com"]: c["id"] for c in conns["candidates"]}
        assert set(ids) == {"COM10", "COM21"}, ids

        # Select the second unit explicitly.
        h.INVENTORY_CACHE.invalidate()
        status, doc = bench.post("/api/connect", {"candidate_id": ids["COM21"]})
        assert status == 200 and doc["connected"] is True

        r = bench.all_routes()
        active = r["/api/connection-state"][1]["active"]
        assert active["stable_keys"]["serial_container_id"] == OTHER_CID
        assert active["candidate"]["serial_com"] == "COM21"
        assert active["network_binding"] == {"container_id": OTHER_CID,
                                             "source_ip": "192.168.3.107", "ifindex": 44}
        # The mirror the qualified write path still reads must have moved too.
        assert h.ACTIVE_CONNECTION["candidate"]["serial_container_id"] == OTHER_CID
        assert h.ACTIVE_CONNECTION["candidate"]["serial_com"] == "COM21"
        st = r["/api/status"][1]
        assert st["source_ip"] == "192.168.3.107" and st["ifindex"] == 44
        assert st["host"] == "192.168.3.102"      # same destination as the other unit
        assert {q["ifindex"] for q in r["/api/rf"][1]["queries"].values()} == {44}

        # Switch to the first unit. No state from the second may survive the switch.
        h.INVENTORY_CACHE.invalidate()
        status, doc = bench.post("/api/connect", {"candidate_id": ids["COM10"]})
        assert status == 200 and doc["connected"] is True

        r = bench.all_routes()
        active = r["/api/connection-state"][1]["active"]
        assert active["stable_keys"]["serial_container_id"] == CID
        assert active["candidate"]["serial_com"] == "COM10"
        assert active["candidate"]["ifindex"] == 29
        assert active["network_binding"] == {"container_id": CID,
                                             "source_ip": "192.168.3.103", "ifindex": 29}
        assert h.ACTIVE_CONNECTION["candidate"]["serial_container_id"] == CID
        assert h.ACTIVE_CONNECTION["candidate"]["serial_com"] == "COM10"
        assert r["/api/status"][1]["ifindex"] == 29
        assert bench.get_fresh("/api/status")[1]["source_ip"] == "192.168.3.103"
