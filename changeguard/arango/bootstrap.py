#!/usr/bin/env python3
"""Create the ChangeGuard database, collections, indexes and named graph. Safe to re-run.

    export CG_ARANGO_URL=https://arango.example:8529 CG_ARANGO_USER=changeguard CG_ARANGO_PASSWORD=...
    python3 arango/bootstrap.py
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "splunk_app", "changeguard", "bin"))

from changeguard_core.config import client_from_env  # noqa: E402

GRAPH = "changeguard"

VERTICES = ["devices", "cis", "services", "changes", "incidents", "people", "cases"]

# collection, from, to
EDGES = [
    ("device_is", ["devices"], ["cis"]),
    ("ci_rel", ["cis", "services"], ["cis", "services"]),
    ("chg_affects", ["changes"], ["cis", "services"]),
    ("inc_on", ["incidents"], ["cis", "services"]),
    ("implemented_by", ["changes"], ["people"]),
    ("ha_peer", ["devices"], ["devices"]),
    ("case_on", ["cases"], ["devices"]),
    ("case_matched", ["cases"], ["changes"]),
    ("case_related", ["cases"], ["changes", "incidents", "cis", "services"]),
]

INDEXES = [
    ("cis", ["name"]),
    ("changes", ["planned_start"]),
    ("changes", ["created_at"]),
    ("changes", ["implementer"]),
    ("incidents", ["opened_at"]),
    ("cases", ["status"]),
    ("cases", ["verdict"]),
    ("cases", ["device"]),
    ("cases", ["first_seen"]),
    ("cases", ["itam_user"]),
]


def main():
    client = client_from_env()
    if client.ensure_database():
        print("created database %s" % client.database)
    for name in VERTICES:
        if client.ensure_collection(name):
            print("created collection %s" % name)
    for name, _, _ in EDGES:
        if client.ensure_collection(name, edge=True):
            print("created edge collection %s" % name)
    for collection, fields in INDEXES:
        client.ensure_index(collection, fields)
    definitions = [{"collection": n, "from": f, "to": t} for n, f, t in EDGES]
    created = client.ensure_graph(GRAPH, definitions)
    print("%s graph %s" % ("created" if created else "updated", GRAPH))


if __name__ == "__main__":
    main()
