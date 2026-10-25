#!/usr/bin/env python3
"""Seed the ChangeGuard graph with the demo topology (times relative to now).

Builds the same documents the Splunk loaders would write, from the same CSVs:
  - cis / devices / device_is  from changeguard_dev_stubs/lookups/itam_ci_seed.csv
  - changes / chg_affects / implemented_by / people  from changeguard/lookups/cg_demo_changes.csv
plus what only HELIX relationship/incident tables would provide in production:
ci_rel, incidents, inc_on, and ha_peer edges for the 01/02 firewall pairs.

    python3 arango/seed_demo.py [--reset]
Then run "CG - Demo - Seed" in Splunk and the pipeline (README).
"""

import argparse
import csv
import os
import re
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
APPS = os.path.join(HERE, "..", "splunk_app")
sys.path.insert(0, os.path.join(APPS, "changeguard", "bin"))

from bootstrap import EDGES, VERTICES  # noqa: E402
from changeguard_core.keys import edge_key, normalise_host, safe_key  # noqa: E402

from changeguard_core.config import client_from_env  # noqa: E402

CI_CSV = os.path.join(APPS, "changeguard_dev_stubs", "lookups", "itam_ci_seed.csv")
CHANGES_CSV = os.path.join(APPS, "changeguard", "lookups", "cg_demo_changes.csv")

SERVICE_RE = re.compile(r"service", re.I)
NETWORK_RE = re.compile(r"network|firewall|router|switch|load ?balancer", re.I)


def _rows(path):
    with open(path, newline="") as handle:
        return list(csv.DictReader(handle))


def _edge(frm, to, **attrs):
    doc = {"_from": frm, "_to": to, "_key": edge_key(frm, to)}
    doc.update(attrs)
    return doc


def _offset(now, value):
    return now + int(value) if value not in (None, "") else None


def ha_peer_name(device):
    """Naming rule for HA pairs, mirrors the cg_ha_peer macro: ...01 <-> ...02."""
    if device.endswith("01"):
        return device[:-2] + "02"
    if device.endswith("02"):
        return device[:-2] + "01"
    return None


def topology():
    cis, devices, device_is = [], [], []
    for row in _rows(CI_CSV):
        text = " ".join([row["Category"], row["Type"], row["SystemRole"]])
        doc = {k: v for k, v in row.items() if v}
        doc.update({"_key": safe_key(row["CI_Name"]), "is_service": int(bool(SERVICE_RE.search(row["Category"]))),
                    "is_network": int(bool(NETWORK_RE.search(text)))})
        cis.append(doc)
        device = normalise_host(row["CI_Name"])
        devices.append({"_key": safe_key(device), "device_name": device})
        device_is.append(_edge("devices/" + safe_key(device), "cis/" + safe_key(row["CI_Name"])))
    names = {d["_key"] for d in devices}
    ha = []
    for name in sorted(names):
        peer = ha_peer_name(name)
        if peer in names and name < peer:
            ha.append(_edge("devices/" + name, "devices/" + peer, a=name, b=peer))
    return cis, devices, device_is, ha


def change_docs(now):
    changes, affects, implemented, people = {}, [], [], {}
    for row in _rows(CHANGES_CSV):
        cid = row["change_id"]
        changes[cid] = {k: v for k, v in {
            "_key": safe_key(cid), "change_id": cid, "source": row["source"], "status": row["status"],
            "approval": row["approval"], "approved": int(row["approved"]), "risk": row["risk"],
            "chg_type": row["chg_type"], "planned_start": _offset(now, row["start_offset_s"]),
            "planned_end": _offset(now, row["end_offset_s"]), "created_at": _offset(now, row["created_offset_s"]),
            "implementer": row["implementer"] or None, "imp_group": row["imp_group"], "summary": row["summary"],
            "description": row["description"],
        }.items() if v not in (None, "")}
        affects.append(_edge("changes/" + safe_key(cid), "devices/" + safe_key(row["device"]), change_id=cid))
        if row["ci_name"]:
            affects.append(_edge("changes/" + safe_key(cid), "cis/" + safe_key(row["ci_name"]), change_id=cid))
        if row["implementer"]:
            people[row["implementer"]] = {"_key": safe_key(row["implementer"]), "person": row["implementer"]}
            implemented.append(_edge("changes/" + safe_key(cid), "people/" + safe_key(row["implementer"]),
                                     change_id=cid))
    return list(changes.values()), affects, implemented, list(people.values())


def build(now):
    cis, devices, device_is, ha = topology()
    changes, affects, implemented, people = change_docs(now)

    def ci(name):
        return "cis/" + safe_key(name)

    ci_rel = [
        _edge(ci("nspnfp7perb01.nsp.com.au"), ci("lb-per-01.nsp.com.au"), rel_type="Dependency"),
        _edge(ci("nspnfp7perb02.nsp.com.au"), ci("lb-per-01.nsp.com.au"), rel_type="Dependency"),
        _edge(ci("lb-per-01.nsp.com.au"), ci("Payments API"), rel_type="Dependency"),
        _edge(ci("nspvfp1822da01.nsp.com.au"), ci("web-portal-app.nsp.com.au"), rel_type="Dependency"),
        _edge(ci("web-portal-app.nsp.com.au"), ci("Customer Web Portal"), rel_type="Dependency"),
    ]
    incidents = [{
        # Scenario 04: P2 on Payments API ~25 min after the DG-7PERB push (demo session ends ~3400 s ago).
        "_key": "INC000009004", "summary": "Payments API timeouts calling card processor", "priority": 2,
        "status": "In Progress", "opened_at": now - 1900, "inc_ci": "Payments API",
    }]
    inc_on = [_edge("incidents/INC000009004", ci("Payments API"))]
    vertices = {"cis": cis, "devices": devices, "changes": changes, "people": people, "incidents": incidents}
    edges = {"device_is": device_is, "ha_peer": ha, "ci_rel": ci_rel, "chg_affects": affects,
             "implemented_by": implemented, "inc_on": inc_on}
    return vertices, edges


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--reset", action="store_true", help="empty every ChangeGuard collection first")
    args = parser.parse_args()
    client = client_from_env()
    if args.reset:
        for name in VERTICES + [e[0] for e in EDGES]:
            client.aql("FOR d IN @@c REMOVE d IN @@c", {"@c": name})
        print("emptied all collections")
    vertices, edges = build(time.time())
    for name, docs in list(vertices.items()) + list(edges.items()):
        print("%-15s %d" % (name, client.upsert(name, docs)))


if __name__ == "__main__":
    main()
