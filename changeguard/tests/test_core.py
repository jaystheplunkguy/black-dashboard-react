import json

import pytest
from conftest import FakeClient

from changeguard_core.arango import ArangoError
from changeguard_core.commands import enrich, write_chunk
from changeguard_core.docs import build_documents, coerce, flatten, uniform
from changeguard_core.keys import edge_key, normalise_host, safe_id, safe_key
from changeguard_core.queries import QUERIES, bind, referenced_params


# --- keys ---------------------------------------------------------------------

def test_normalise_host_matches_spl_macro_rules():
    assert normalise_host("FW-SYD-01.corp.example") == "fw-syd-01"
    assert normalise_host(" rtr-mel-01 ") == "rtr-mel-01"
    assert normalise_host("10.1.2.3") == "10.1.2.3"
    assert normalise_host("") is None


def test_safe_key_replaces_illegal_chars_and_is_stable():
    assert safe_key("CRQ000001001") == "CRQ000001001"
    assert safe_key("a b/c#d") == "a_b_c_d"
    long_key = safe_key("x" * 400)
    assert len(long_key) < 254 and long_key == safe_key("x" * 400)
    with pytest.raises(ValueError):
        safe_key("  ")


def test_safe_id_and_edge_key():
    assert safe_id(None, "cis/OI 1") == "cis/OI_1"
    assert safe_id("cis", "cis/OI-1") == "cis/OI-1"
    assert edge_key("a/1", "b/2") == edge_key("a/1", "b/2") != edge_key("b/2", "a/1")


# --- docs -----------------------------------------------------------------------

def test_coerce_keeps_ids_with_leading_zeros_as_strings():
    assert coerce("1792735522.07") == 1792735522.07
    assert coerce("42") == 42
    assert coerce("000123") == "000123"
    assert coerce("true") is True
    assert coerce("") is None
    assert coerce(["1", "", "x"]) == [1, "x"]


def test_build_documents_for_docs_and_edges():
    rows = [
        {"chg_number": "CRQ1", "summary": "s", "planned_start": "100", "_time": "1", "empty": ""},
        {"chg_number": "", "summary": "no key"},
    ]
    grouped, skipped = build_documents(rows, collection="changes", key_field="chg_number")
    assert skipped == 1
    assert grouped == {"changes": [{"_key": "CRQ1", "summary": "s", "planned_start": 100}]}

    edges, _ = build_documents([{"from": "changes/CRQ1", "to": "cis/OI 1", "reason": "x"}],
                               collection="chg_affects", from_field="from", to_field="to")
    edge = edges["chg_affects"][0]
    assert edge["_from"] == "changes/CRQ1" and edge["_to"] == "cis/OI_1"
    assert edge["_key"] == edge_key("changes/CRQ1", "cis/OI_1")
    assert "from" not in edge and edge["reason"] == "x"


def test_build_documents_collection_field_and_whitelist():
    rows = [{"ci_id": "1", "collection": "cis", "name": "a", "junk": "j"},
            {"ci_id": "2", "collection": "services", "name": "b"}]
    grouped, _ = build_documents(rows, collection_field="collection", key_field="ci_id", fields="ci_id,name")
    assert grouped["cis"] == [{"_key": "1", "ci_id": 1, "name": "a"}]
    assert grouped["services"][0]["_key"] == "2"

    grouped, _ = build_documents([{"k": "1", "reasons": "one", "tags": ["a", "b"]}], collection="cases",
                                 key_field="k", multivalue="reasons,tags")
    assert grouped["cases"][0]["reasons"] == ["one"] and grouped["cases"][0]["tags"] == ["a", "b"]


def test_flatten_and_uniform():
    flat = flatten({"_key": "k", "_id": "x", "a": True, "b": None, "c": [1, 2], "d": {"e": 1},
                    "f": [{"g": 1}]}, "p_")
    assert flat == {"p_key": "k", "p_a": "true", "p_b": None, "p_c": [1, 2], "p_d_e": 1,
                    "p_f": json.dumps([{"g": 1}])}
    rows = uniform([{"a": 1}, {"b": 2}])
    assert rows == [{"a": 1, "b": None}, {"b": 2, "a": None}]


# --- queries --------------------------------------------------------------------

@pytest.mark.parametrize("name", sorted(QUERIES))
def test_every_query_declares_exactly_its_bind_params(name):
    # ArangoDB rejects unused bind vars, and a missing one fails at runtime.
    query = QUERIES[name]
    assert referenced_params(query.aql) == set(query.params), name


def test_bind_converts_types_and_applies_defaults():
    vars_ = bind(QUERIES["downstream_incidents"], {"devices": ["FW-A.corp", "fw-b", "fw-a"], "last_seen": "10.5"})
    assert vars_ == {"devices": ["fw-a", "fw-b"], "last_seen": 10.5, "horizon": 259200, "max_hops": 2, "exclude": []}
    assert bind(QUERIES["alt_explanations"], {"devices": "d", "first_seen": 1, "last_seen": 2,
                                              "chg_refs": "CRQ1, CRQ2"})["chg_refs"] == ["CRQ1", "CRQ2"]
    with pytest.raises(ValueError):
        bind(QUERIES["downstream_incidents"], {"devices": "x"})


def test_param_types_are_known():
    for query in QUERIES.values():
        for name, (kind, _) in query.params.items():
            assert kind in ("host", "hosts", "key", "str", "num", "list"), (query.name, name)


# --- commands -------------------------------------------------------------------

def test_write_chunk_annotates_rows_and_marks_errors():
    client = FakeClient()
    rows = write_chunk(client, [{"case_id": "c1", "status": "new"}], collection="cases", key_field="case_id")
    assert client.upserts == [("cases", [{"_key": "c1", "status": "new"}])]
    assert rows[0]["arango_status"] == "ok"

    down = FakeClient(fail=ArangoError("down"))
    rows = write_chunk(down, [{"case_id": "c1"}], collection="cases", key_field="case_id", on_error="mark")
    assert rows[0]["arango_status"].startswith("error")
    with pytest.raises(ArangoError):
        write_chunk(down, [{"case_id": "c1"}], collection="cases", key_field="case_id")


def test_enrich_modes():
    rows = [{"devices": ["fw-a"], "last_seen": "2"}, {"devices": "fw-b", "last_seen": "2"}]
    client = FakeClient(results=[[{"top_incident": "INC1", "found": True}], []])
    out = enrich(client, [dict(r) for r in rows], "downstream_incidents", prefix="w_")
    assert out[0]["w_top_incident"] == "INC1" and out[0]["w_found"] == "true"
    assert out[1]["w_top_incident"] is None and out[1]["w_count"] == 0  # uniform columns

    client = FakeClient(results=[[{"a": 1}, {"a": 2}]])
    out = enrich(client, [dict(rows[0])], "downstream_incidents", mode="all")
    assert [r["a"] for r in out] == [1, 2]

    client = FakeClient(results=[[{"a": 1}]])
    out = enrich(client, [dict(rows[0])], "downstream_incidents", mode="json", out_field="j")
    assert json.loads(out[0]["j"]) == [{"a": 1}]


def test_enrich_param_mapping_and_errors():
    client = FakeClient(results=[[]])
    enrich(client, [{"doi": ["fw-a"], "last_seen": "5", "dismissed_incidents": ["INC1", "INC2"]}],
           "downstream_incidents", param_map="exclude=dismissed_incidents,devices=doi")
    assert client.queries[0][1]["exclude"] == ["INC1", "INC2"] and client.queries[0][1]["devices"] == ["fw-a"]

    out = enrich(FakeClient(), [{"devices": "fw-a"}], "downstream_incidents")  # missing last_seen
    assert "needs parameter" in out[0]["aql_error"]
    with pytest.raises(ValueError):
        enrich(FakeClient(), [{}], "no_such_query")
