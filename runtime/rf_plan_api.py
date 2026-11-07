"""Host-only RF plan API. Receives current target evidence; cannot write a device.

The route facade owns session state. Dependencies are passed per request, retaining
existing monkeypatch contracts without importing the API server or copying globals.
"""
from __future__ import annotations

class RfPlanApi:
    def __init__(self, *, target, now, store):
        self.target, self.now, self.store = target, now, store

    def document(self) -> dict:
        target = self.target()
        plans = self.store.load_all()
        rows = []
        for key in sorted(plans):
            entry = plans[key]
            bands = entry["bands"]
            rows.append({
                "name": entry["name"],
                "note": entry["note"],
                "bands": bands,
                "band_names": sorted(bands),
                "channel_count": sum(len(v) - 1 for v in bands.values()),
                "compatibility": entry["compatibility"],
                "created_at": entry["created_at"],
                "updated_at": entry["updated_at"],
                "assessment": self.store.assess(
                    entry,
                    rf_board_code=target["rf_board_code"],
                    hardware=target["hardware"],
                    live_bands=target["live_bands"]),
            })
        return {
            "schema": self.store.SCHEMA,
            "plans": rows,
            "count": len(rows),
            "limits": self.store.limits_document(),
            "target": {k: target[k] for k in ("connected", "device_name", "hardware",
                                              "rf_board_code", "live_table_verified")},
            # Stated in the document itself so no page can render a plan list without it.
            "transmission_legality": "not assessed",
            "captured_at": self.now(),
        }


    def save(self, body: dict) -> dict:
        """Store a plan. `bands` is taken verbatim; an absent one captures the live table."""
        bands = body.get("bands")
        if bands is None:
            target = self.target()
            if not target["live_table_verified"] or not target["live_bands"]:
                raise self.store.RfPlanError(
                    "FRESH_RF_READ_NOT_AVAILABLE",
                    "capturing a plan needs an MD5-verified live table; refresh the device table first")
            bands = target["live_bands"]
            compat = {"rf_board_code": target["rf_board_code"], "hardware": target["hardware"]}
        else:
            compat = body.get("compatibility")
        entry = self.store.save_plan(name=body.get("name"), bands=bands,
                                        note=body.get("note"), compatibility=compat,
                                        replace=bool(body.get("replace")))
        return {"ok": True, "plan": entry["name"], "store": self.document()}


    def delete(self, body: dict) -> dict:
        entry = self.store.delete_plan(body.get("name"))
        return {"ok": True, "deleted": entry["name"], "store": self.document()}


    def export(self, body: dict) -> dict:
        entry = self.store.get_plan(body.get("name"))
        return {"ok": True, "plan": entry["name"], "format": "csv",
                "columns": list(self.store.CSV_COLUMNS),
                "csv": self.store.to_csv(entry)}


    def import_csv(self, body: dict) -> dict:
        """Parse an untrusted CSV into a plan. Parsing alone stores nothing."""
        parsed = self.store.from_csv(body.get("csv"), name=body.get("name"))
        if body.get("save"):
            entry = self.store.save_plan(name=parsed["name"], bands=parsed["bands"],
                                            note=body.get("note"),
                                            replace=bool(body.get("replace")))
            return {"ok": True, "stored": True, "plan": entry["name"],
                    "store": self.document()}
        target = self.target()
        return {"ok": True, "stored": False, "plan": parsed["name"], "bands": parsed["bands"],
                "channel_count": sum(len(v) - 1 for v in parsed["bands"].values()),
                "assessment": self.store.assess(parsed,
                                                   rf_board_code=target["rf_board_code"],
                                                   hardware=target["hardware"],
                                                   live_bands=target["live_bands"])}


