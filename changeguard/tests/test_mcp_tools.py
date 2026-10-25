from conftest import FakeClient

import tools


def test_to_epoch_formats():
    assert tools.to_epoch(1700000000) == 1700000000.0
    assert tools.to_epoch("1700000000") == 1700000000.0
    assert tools.to_epoch("2023-11-14T22:13:20Z") == 1700000000.0
    assert tools.to_epoch("2023-11-14 22:13:20") == 1700000000.0
    assert tools.to_epoch(None, 5) == 5


def test_humanise_adds_iso_times():
    out = tools._humanise([{"first_seen": 1700000000, "nested": {"opened_at": 1700000000}}])
    assert out[0]["first_seen_iso"] == "2023-11-14T22:13:20Z"
    assert out[0]["nested"]["opened_at_iso"] == "2023-11-14T22:13:20Z"


def test_get_case_combines_case_and_evidence():
    client = FakeClient(results=[[{"_key": "c1", "verdict": "UNPLANNED_CHANGE"}], [{"edges": []}]])
    out = tools.get_case(client, "c1")
    assert out["case"]["verdict"] == "UNPLANNED_CHANGE" and out["evidence"] == {"edges": []}
    assert tools.get_case(FakeClient(), "missing") == {"error": "no case missing"}


def test_window_tools_bind_epochs():
    client = FakeClient()
    tools.find_related_changes(client, "FW-A.corp", around="1000000", hours_before=1, hours_after=2)
    binds = client.queries[0][1]
    assert binds == {"device": "fw-a", "from_ts": 1000000 - 3600, "to_ts": 1000000 + 7200}

    client = FakeClient()
    tools.find_other_authorisations(client, ["fw-a"], "1000", engineer="jsmith")
    assert client.queries[0][1]["last_seen"] == 1000 and client.queries[0][1]["itam_user"] == "jsmith"

    client = FakeClient()
    tools.find_incidents_downstream(client, ["fw-a"], "1000", hours=1, max_hops=3)
    assert client.queries[0][1]["horizon"] == 3600 and client.queries[0][1]["max_hops"] == 3


class _Resp(object):
    def __init__(self, body):
        self.body = body

    def read(self):
        return self.body


def test_run_spl_is_read_only_and_posts_search():
    kw = {"splunk_url": "https://splunk:8089", "token": "t"}
    for bad in ["| inputlookup cg_cases_lookup | outputlookup x", "index=a | collect index=b", "| `cg_sync_case`",
                "| makeresults | delete", "| rest /services/apps/local", "| inputlookup a [| map search=x]"]:
        assert "refused" in tools.run_spl(bad, **kw)["error"]
    assert "not configured" in tools.run_spl("index=a", splunk_url=None, token=None)["error"]
    seen = {}

    def opener(req):
        seen["url"], seen["body"] = req.full_url, req.data.decode()
        return _Resp(b'{"results": [{"a": "1"}], "messages": []}')

    out = tools.run_spl("index=changeguard_detect | stats count", opener=opener, **kw)
    assert out["results"] == [{"a": "1"}]
    assert seen["url"].endswith("/servicesNS/-/changeguard/search/jobs") and "search+index" in seen["body"]
