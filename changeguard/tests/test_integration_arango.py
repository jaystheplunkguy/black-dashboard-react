"""Runs every named query against a real ArangoDB seeded with the demo data.

    docker run -d -p 8529:8529 -e ARANGO_ROOT_PASSWORD=pw arangodb:3.11
    CG_ARANGO_IT=1 CG_ARANGO_URL=http://127.0.0.1:8529 CG_ARANGO_PASSWORD=pw CG_ARANGO_DB=cg_it pytest tests/

WARNING: empties the ChangeGuard collections in CG_ARANGO_DB.
"""

import os
import time

import pytest

from changeguard_core.queries import QUERIES

pytestmark = pytest.mark.skipif(os.environ.get("CG_ARANGO_IT") != "1", reason="set CG_ARANGO_IT=1 to run")

TESTED = set()


@pytest.fixture(scope="module")
def graph():
    import bootstrap
    import seed_demo
    from changeguard_core.config import client_from_env

    client = client_from_env()
    bootstrap.main()
    for name in bootstrap.VERTICES + [e[0] for e in bootstrap.EDGES]:
        client.aql("FOR d IN @@c REMOVE d IN @@c", {"@c": name})
    now = time.time()
    vertices, edges = seed_demo.build(now)
    for name, docs in list(vertices.items()) + list(edges.items()):
        client.upsert(name, docs)
    return client, now


def run(client, name, **params):
    from changeguard_core.queries import bind
    TESTED.add(name)
    return client.aql(QUERIES[name].aql, bind(QUERIES[name], params))


def test_alt_explanations_finds_nothing_for_unplanned_router(graph):
    client, now = graph
    alt = run(client, "alt_explanations", devices=["nsprtr-mel-01"], first_seen=now - 3200, last_seen=now - 3200,
              itam_user="userb")[0]
    assert alt["total"] == 0  # CRQ000000999 is 10 days old: outside the -48h/+1d related window


def test_alt_explanations_reference_and_related(graph):
    client, now = graph
    alt = run(client, "alt_explanations", devices=["nspvmp1822da01"], first_seen=now - 3300, last_seen=now - 3100,
              itam_user="userc", chg_refs=["CRQ000001003"])[0]
    assert alt["ref_count"] == 1 and alt["person_count"] == 1
    assert alt["candidate_keys"] == ["CRQ000001003"]


def test_downstream_incident_two_hops_from_pushed_firewall(graph):
    client, now = graph
    r = run(client, "downstream_incidents", devices=["nspvmp1822da01", "nspnfp7perb01", "nspnfp7perb02"],
            last_seen=now - 3400)[0]
    assert r["top_incident"] == "INC000009004" and r["top_hops"] == 2 and r["top_score"] == 0.4
    assert r["top_via"] == "Payments API"
    assert run(client, "downstream_incidents", devices=["nspnfp7perb01"], last_seen=now - 3400,
               max_hops=1)[0]["incident_count"] == 0
    assert run(client, "downstream_incidents", devices=["nspnfp7perb01"], last_seen=now - 3400,
               exclude=["INC000009004"])[0]["incident_count"] == 0


def test_case_evidence_list_and_get(graph):
    client, now = graph
    client.upsert("cases", [{"_key": "it1", "session_device": "nspvmp1822da01", "doi": ["nspnfp7perb01"],
                             "platform": "paloalto", "status": "alert", "verdict": "POTENTIAL_FAILED_CHANGE",
                             "first_seen": now - 3500, "itam_user": "userd", "chg_number": "CALM-1004"}])
    client.upsert("case_on", [{"_key": "it1a", "_from": "cases/it1", "_to": "devices/nspvmp1822da01", "role": "session"},
                              {"_key": "it1b", "_from": "cases/it1", "_to": "devices/nspnfp7perb01", "role": "target"}])
    client.upsert("case_matched", [{"_key": "it1", "_from": "cases/it1", "_to": "changes/CALM-1004"}])
    ev = run(client, "case_evidence", case_id="it1")[0]
    assert ev["matched_changes"][0]["chg_number"] == "CALM-1004"
    assert any(d["name"] == "Payments API" and d["hops"] == 2 and d["service"] for d in ev["downstream"])
    assert "nspnfp7perb02" in ev["ha_peers"]
    assert run(client, "list_cases", status="alert", limit=5)[0]["_key"] == "it1"
    assert run(client, "list_cases", device="nspnfp7perb01")[0]["_key"] == "it1"
    assert run(client, "get_case", case_id="it1")[0]["verdict"] == "POTENTIAL_FAILED_CHANGE"


def test_related_changes_include_ha_peer(graph):
    client, now = graph
    near = run(client, "related_changes", device="nspnfp4aherb02", from_ts=now - 86400, to_ts=now)
    assert [(c["chg_number"], c["relation"]) for c in near] == [("CRQ000001001", "HA peer nspnfp4aherb01")]


def test_neighbourhood_upcoming_and_features(graph):
    client, now = graph
    hood = run(client, "device_neighbourhood", device="nspnfp7perb01.nsp.com.au", now=now)[0]
    assert hood["ha_peers"] == ["nspnfp7perb02"] and any(d["service"] for d in hood["downstream"])
    assert [c["chg_number"] for c in run(client, "upcoming_changes", now=now)] == ["CRQ000001006"]
    feats = run(client, "change_features", chg_number="CRQ000001006", now=now)[0]
    assert feats["downstream_count"] == 2 and feats["changes_90d"] == 1 and feats["device_count"] == 1


def test_every_query_was_exercised():
    if TESTED:
        assert TESTED == set(QUERIES)
