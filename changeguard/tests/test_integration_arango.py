"""Runs every scenario query against a real ArangoDB seeded with the demo data.

    docker run -d -p 8529:8529 -e ARANGO_ROOT_PASSWORD=pw arangodb:3.11
    CG_ARANGO_IT=1 CG_ARANGO_URL=http://127.0.0.1:8529 CG_ARANGO_PASSWORD=pw pytest tests/

WARNING: empties the ChangeGuard collections in CG_ARANGO_DB (default "changeguard").
"""

import os
import time

import pytest

pytestmark = pytest.mark.skipif(os.environ.get("CG_ARANGO_IT") != "1", reason="set CG_ARANGO_IT=1 to run")


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
    from changeguard_core.queries import QUERIES, bind
    return client.aql(QUERIES[name].aql, bind(QUERIES[name], params))


def test_scenario_01_legitimate_change_matches(graph):
    client, now = graph
    r = run(client, "best_change", device="FW-SYD-01.corp.example", first_seen=now - 3000,
            last_seen=now - 2700, itam_user="jsmith")[0]
    assert r["chg_number"] == "CRQ000001001"
    assert r["in_window"] and r["approved"] and r["user_ok"] and r["match_score"] == 7


def test_scenario_02_no_chg_and_no_alternatives(graph):
    client, now = graph
    best = run(client, "best_change", device="rtr-mel-01", first_seen=now - 3200, last_seen=now - 2900)[0]
    assert best["ci_count"] == 1 and best["chg_number"] is None
    alt = run(client, "alt_explanations", device="rtr-mel-01", first_seen=now - 3200, last_seen=now - 2900,
              itam_user="bwilson")[0]
    assert alt["total"] == 0


def test_scenario_02b_ha_peer_chg_is_found(graph):
    client, now = graph
    alt = run(client, "alt_explanations", device="fw-syd-02", first_seen=now - 2950, last_seen=now - 2750,
              itam_user="jsmith")[0]
    assert alt["peer_count"] == 1 and "CRQ000001001" in alt["candidate_keys"]


def test_unknown_device(graph):
    client, now = graph
    r = run(client, "best_change", device="nope-01", first_seen=now, last_seen=now)[0]
    assert r["device_found"] is False and r["ci_count"] == 0


def test_scenario_03_change_detail_for_intent_check(graph):
    client, _ = graph
    r = run(client, "change_detail", chg_number="CRQ000001003")[0]
    assert "10.1.1.0/24" in r["description"]


def test_scenario_04_downstream_incident_two_hops(graph):
    client, now = graph
    r = run(client, "downstream_incidents", device="fw-per-01", last_seen=now - 3000)[0]
    assert r["top_incident"] == "INC000009004" and r["top_hops"] == 2 and r["top_score"] == 0.4
    assert run(client, "downstream_incidents", device="fw-per-01", last_seen=now - 3000, max_hops=1)[0]["incident_count"] == 0
    assert run(client, "downstream_incidents", device="fw-per-01", last_seen=now - 3000,
               exclude=["INC000009004"])[0]["incident_count"] == 0


def test_case_evidence_and_listing(graph):
    client, now = graph
    client.upsert("cases", [{"_key": "it1", "device": "fw-per-01", "status": "alert", "verdict": "POTENTIAL_FAILED_CHANGE",
                             "first_seen": now - 3300, "itam_user": "jsmith", "chg_number": "CRQ000001004"}])
    client.upsert("case_on", [{"_key": "it1", "_from": "cases/it1", "_to": "devices/fw-per-01"}])
    client.upsert("case_matched", [{"_key": "it1", "_from": "cases/it1", "_to": "changes/CRQ000001004"}])
    ev = run(client, "case_evidence", case_id="it1")[0]
    assert ev["matched_changes"][0]["chg_number"] == "CRQ000001004"
    assert {"name": "Payments API", "id": "services/SVC-PAYMENTS", "hops": 2} in ev["downstream"]
    assert run(client, "list_cases", status="alert", limit=5)[0]["_key"] == "it1"
    assert run(client, "get_case", case_id="it1")[0]["verdict"] == "POTENTIAL_FAILED_CHANGE"


def test_agent_and_ml_queries(graph):
    client, now = graph
    near = run(client, "changes_near", device="fw-syd-02", from_ts=now - 86400, to_ts=now)
    assert [c["chg_number"] for c in near] == ["CRQ000001001"] and near[0]["relation"] == "HA peer fw-syd-01"
    hood = run(client, "device_neighbourhood", device="fw-per-01", now=now)[0]
    assert hood["ha_peers"] == [] and any(d["service"] for d in hood["downstream"])
    upcoming = run(client, "upcoming_changes", now=now)
    assert [c["chg_number"] for c in upcoming] == ["CRQ000001006"]
    feats = run(client, "change_features", chg_number="CRQ000001006", now=now)[0]
    assert feats["downstream_count"] == 2 and feats["ci_changes_90d"] == 1
