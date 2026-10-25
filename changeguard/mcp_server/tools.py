"""ChangeGuard agent tools: one tool per question, each backed by one named AQL query.

Read-only. The graph tools talk only to ArangoDB (case state is mirrored into
the `cases` vertex), so they need no Splunk token. run_spl is optional: it needs
CG_SPLUNK_URL + CG_SPLUNK_TOKEN, refuses anything that can write, and on
platforms where a token is not allowed the Splunk MCP Server's own search tool
can be used instead.
"""

import json
import os
import re
import ssl
import sys
import time
import urllib.parse
import urllib.request
from datetime import datetime, timezone

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "splunk_app", "changeguard", "bin"))

from changeguard_core.queries import QUERIES, bind  # noqa: E402

HOUR = 3600


def to_epoch(value, default=None):
    """Accept epoch seconds, ISO 8601 ('2026-10-23T14:05:00Z', '2026-10-23 14:05') or 'now'."""
    if value is None or value == "":
        return default
    if isinstance(value, (int, float)):
        return float(value)
    text = str(value).strip()
    if text.lower() == "now":
        return time.time()
    try:
        return float(text)
    except ValueError:
        pass
    parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.timestamp()


def iso(epoch):
    if epoch is None:
        return None
    return datetime.fromtimestamp(float(epoch), tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


_TIME_FIELDS = {"first_seen", "last_seen", "planned_start", "planned_end", "created_at", "opened_at",
                "watch_until", "alerted_at", "updated_at"}


def _humanise(obj):
    """Add ISO copies of epoch fields so the model never has to do time arithmetic."""
    if isinstance(obj, list):
        return [_humanise(o) for o in obj]
    if isinstance(obj, dict):
        out = {}
        for key, value in obj.items():
            out[key] = _humanise(value)
            if key in _TIME_FIELDS and isinstance(value, (int, float)):
                out[key + "_iso"] = iso(value)
        return out
    return obj


def run(client, name, **params):
    query = QUERIES[name]
    return _humanise(client.aql(query.aql, bind(query, params)))


def get_case(client, case_id):
    """A ChangeGuard case: verdict, reasons, AI output and its evidence subgraph."""
    case = run(client, "get_case", case_id=case_id)
    if not case:
        return {"error": "no case %s" % case_id}
    evidence = run(client, "case_evidence", case_id=case_id)
    return {"case": case[0], "evidence": evidence[0] if evidence else None}


def list_cases(client, status=None, verdict=None, platform=None, device=None, since_hours=168, limit=25):
    """Recent cases, newest first."""
    since = time.time() - float(since_hours) * HOUR
    return run(client, "list_cases", status=status, verdict=verdict, platform=platform, device=device,
               since=since, limit=int(limit))


def find_related_changes(client, device, around="now", hours_before=48, hours_after=24):
    """Changes on a device, its HA peers and directly related CIs overlapping a window
    (default -48h/+1d, the same window the correlation search uses for related changes)."""
    centre = to_epoch(around, time.time())
    return run(client, "related_changes", device=device, from_ts=centre - float(hours_before) * HOUR,
               to_ts=centre + float(hours_after) * HOUR)


def find_other_authorisations(client, devices, first_seen, last_seen=None, engineer=None, chg_refs=None):
    """For a session with no in-window CHG: CHGs near the time, on HA peers, on related CIs, the
    engineer's CHGs elsewhere, CHGs raised afterwards, CHG numbers in the commit comment."""
    start = to_epoch(first_seen)
    return run(client, "alt_explanations", devices=devices, first_seen=start,
               last_seen=to_epoch(last_seen, start), itam_user=engineer, chg_refs=chg_refs or [])


def find_incidents_downstream(client, devices, since, hours=72, max_hops=2, exclude=None):
    """Incidents on the devices' CIs or up to max_hops downstream opened after `since`, ranked by
    hops x delay x priority."""
    return run(client, "downstream_incidents", devices=devices, last_seen=to_epoch(since),
               horizon=float(hours) * HOUR, max_hops=int(max_hops), exclude=exclude or [])


# Commands that write, call out or run code. Macros are refused too: some ChangeGuard macros write.
_FORBIDDEN_SPL = re.compile(
    r"(\|\s*(collect|mcollect|meventcollect|tscollect|outputlookup|outputcsv|outputtext|delete|sendemail|"
    r"sendalert|script|run|runshellscript|map|rest|dbxquery|dbxoutput|cgarango|ai|fit|apply)\b)|`", re.I)


def run_spl(query, earliest="-24h", latest="now", max_rows=200, splunk_url=None, token=None, opener=None):
    """Run a READ-ONLY SPL search in the changeguard app and return up to max_rows results."""
    splunk_url = splunk_url or os.environ.get("CG_SPLUNK_URL")
    token = token or os.environ.get("CG_SPLUNK_TOKEN")
    if not splunk_url or not token:
        return {"error": "run_spl is not configured (CG_SPLUNK_URL / CG_SPLUNK_TOKEN). "
                         "Use the Splunk MCP Server's search tool instead."}
    text = query.strip()
    if _FORBIDDEN_SPL.search(text):
        return {"error": "refused: run_spl is read-only (no collect/outputlookup/delete/map/rest/macros/...)"}
    if not text.startswith("|") and not text.lower().startswith("search "):
        text = "search " + text
    body = urllib.parse.urlencode({
        "search": text, "exec_mode": "oneshot", "output_mode": "json", "count": int(max_rows),
        "earliest_time": earliest, "latest_time": latest,
    }).encode()
    req = urllib.request.Request(splunk_url.rstrip("/") + "/servicesNS/-/changeguard/search/jobs", data=body)
    req.add_header("Authorization", "Bearer " + token)
    context = ssl.create_default_context()
    if os.environ.get("CG_SPLUNK_VERIFY_SSL", "true").lower() in ("0", "false", "no"):
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    open_ = opener or (lambda r: urllib.request.urlopen(r, timeout=120, context=context))
    payload = json.loads(open_(req).read().decode("utf-8"))
    return {"results": payload.get("results", [])[: int(max_rows)],
            "messages": [m.get("text") for m in payload.get("messages", [])]}


def get_device_neighbourhood(client, device):
    """Everything connected to a device: CIs, HA peers, upstream/downstream, recent changes, incidents, cases."""
    result = run(client, "device_neighbourhood", device=device, now=time.time())
    return result[0] if result else {"error": "device %s is not in the graph" % device}
