#!/usr/bin/env python3
"""Seed the graph with demo data for scenarios 01-04 and 06 (times relative to now).

Pairs with splunk_app/changeguard/lookups/cg_demo_detections.csv, whose event
offsets line up with the change windows below. Run this, then the
"CG - Demo - Seed detections" search, then the pipeline (see README).

    python3 arango/seed_demo.py [--reset]
"""

import argparse
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "splunk_app", "changeguard", "bin"))

from bootstrap import EDGES, VERTICES  # noqa: E402
from changeguard_core.config import client_from_env  # noqa: E402
from changeguard_core.keys import edge_key  # noqa: E402

H = 3600


def build(now):
    def ci(key, name, ci_class, env="Production"):
        return {"_key": key, "name": name, "ci_class": ci_class, "environment": env}

    devices = [
        {"_key": "fw-syd-01", "name": "fw-syd-01", "platform": "paloalto"},
        {"_key": "fw-syd-02", "name": "fw-syd-02", "platform": "paloalto"},
        {"_key": "fw-mel-01", "name": "fw-mel-01", "platform": "paloalto"},
        {"_key": "fw-per-01", "name": "fw-per-01", "platform": "paloalto"},
        {"_key": "rtr-mel-01", "name": "rtr-mel-01", "platform": "cisco_ios"},
    ]
    cis = [
        ci("OI-FW-SYD-01", "fw-syd-01", "Firewall"),
        ci("OI-FW-SYD-02", "fw-syd-02", "Firewall"),
        ci("OI-FW-MEL-01", "fw-mel-01", "Firewall"),
        ci("OI-FW-PER-01", "fw-per-01", "Firewall"),
        ci("OI-RTR-MEL-01", "rtr-mel-01", "Router"),
        ci("OI-LB-PER-01", "lb-per-01", "Load Balancer"),
        ci("OI-APP-WEB-01", "web-portal-app", "Application"),
    ]
    services = [
        {"_key": "SVC-PAYMENTS", "name": "Payments API", "ci_class": "Business Service"},
        {"_key": "SVC-WEBPORTAL", "name": "Customer Web Portal", "ci_class": "Business Service"},
    ]
    people = [
        {"_key": "jsmith", "name": "John Smith", "team": "Network Security"},
        {"_key": "akumar", "name": "Asha Kumar", "team": "Network Security"},
        {"_key": "bwilson", "name": "Ben Wilson", "team": "Network Operations"},
    ]
    changes = [
        {   # 01 legitimate (also authorises the HA-peer session, 02b)
            "_key": "CRQ000001001", "summary": "Publish WEB-SRV-01 on tcp/443 through fw-syd-01",
            "description": "Add address object WEB-SRV-01 (10.20.30.40/32) and security rule allow-web-443 "
                           "from zone DMZ to zone WEB, service tcp/443 only, action allow. Apply to the "
                           "fw-syd-01/02 HA pair.",
            "plan": "1. set address WEB-SRV-01 ip-netmask 10.20.30.40/32\n2. add rule allow-web-443 DMZ->WEB "
                    "service-https allow\n3. commit and validate",
            "status": "Implementation In Progress", "approval": "Approved", "chg_class": "Normal",
            "risk": "Low", "implementer": "jsmith",
            "planned_start": now - 3 * H, "planned_end": now + 1 * H, "created_at": now - 72 * H,
        },
        {   # 03 approved but implemented wrongly
            "_key": "CRQ000001003", "summary": "Allow web-portal access from branch subnet",
            "description": "Permit tcp/443 from 10.1.1.0/24 (branch users) to 10.50.0.10 (web-portal). "
                           "No other services or sources.",
            "plan": "Add rule branch-to-portal: source 10.1.1.0/24, destination 10.50.0.10, "
                    "service-https, action allow. Commit.",
            "status": "Implementation In Progress", "approval": "Approved", "chg_class": "Normal",
            "risk": "Medium", "implementer": "akumar",
            "planned_start": now - 2 * H, "planned_end": now + 2 * H, "created_at": now - 96 * H,
        },
        {   # 04 approved, compliant, then causes an incident downstream
            "_key": "CRQ000001004", "summary": "Tighten outbound rules on fw-per-01",
            "description": "Replace the broad outbound rule out-any with out-https (tcp/443 only) as part of "
                           "the PCI hardening programme.",
            "plan": "delete rule out-any; add rule out-https service-https allow; commit",
            "status": "Implementation In Progress", "approval": "Approved", "chg_class": "Normal",
            "risk": "Medium", "implementer": "jsmith",
            "planned_start": now - 4 * H, "planned_end": now, "created_at": now - 120 * H,
        },
        {   # 06 proposed change to score
            "_key": "CRQ000001006", "summary": "Upgrade PAN-OS on fw-per-01",
            "description": "Upgrade fw-per-01 from 10.2 to 11.1 during the weekend window.",
            "plan": "Download, install, reboot, validate.", "status": "Scheduled",
            "approval": "Approved", "chg_class": "Normal", "risk": "High", "implementer": "jsmith",
            "planned_start": now + 72 * H, "planned_end": now + 76 * H, "created_at": now - 24 * H,
        },
    ]
    incidents = [
        {   # 04: P2 on the payments service 25 min ago (~25 min after the fw-per-01 change)
            "_key": "INC000009004", "summary": "Payments API timeouts calling card processor",
            "priority": 2, "status": "In Progress", "opened_at": now - 1500, "service": "Payments API",
        },
    ]

    def edge(frm, to, **attrs):
        doc = {"_from": frm, "_to": to, "_key": edge_key(frm, to)}
        doc.update(attrs)
        return doc

    edges = {
        "device_is": [edge("devices/%s" % d["_key"], "cis/OI-%s" % d["_key"].upper()) for d in devices],
        "ha_peer": [edge("devices/fw-syd-01", "devices/fw-syd-02")],
        "ci_rel": [
            edge("cis/OI-FW-PER-01", "cis/OI-LB-PER-01", rel_type="routes to"),
            edge("cis/OI-LB-PER-01", "services/SVC-PAYMENTS", rel_type="supports"),
            edge("cis/OI-FW-MEL-01", "cis/OI-APP-WEB-01", rel_type="protects"),
            edge("cis/OI-APP-WEB-01", "services/SVC-WEBPORTAL", rel_type="supports"),
        ],
        "chg_affects": [
            edge("changes/CRQ000001001", "cis/OI-FW-SYD-01"),
            edge("changes/CRQ000001003", "cis/OI-FW-MEL-01"),
            edge("changes/CRQ000001004", "cis/OI-FW-PER-01"),
            edge("changes/CRQ000001006", "cis/OI-FW-PER-01"),
        ],
        "implemented_by": [edge("changes/%s" % c["_key"], "people/%s" % c["implementer"]) for c in changes],
        "inc_on": [edge("incidents/INC000009004", "services/SVC-PAYMENTS")],
    }
    vertices = {"devices": devices, "cis": cis, "services": services, "people": people,
                "changes": changes, "incidents": incidents}
    return vertices, edges


def main():
    parser = argparse.ArgumentParser(description=__doc__)
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
