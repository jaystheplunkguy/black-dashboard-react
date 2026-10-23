"""ChangeGuard agent tools: one tool per question, each backed by one named AQL query.

Read-only. Talks only to ArangoDB (case state is mirrored into the `cases`
vertex), so the agent needs no Splunk token. That sidesteps the Forge
token restriction.
"""

import os
import sys
import time
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


def list_cases(client, status=None, verdict=None, device=None, since_hours=168, limit=25):
    """Recent cases, newest first. status: new|intent_check|investigate|watch|impact_check|alert|alerted|review|closed."""
    since = time.time() - float(since_hours) * HOUR
    return run(client, "list_cases", status=status, verdict=verdict, device=device, since=since, limit=int(limit))


def find_changes_near(client, device, around="now", hours_before=24, hours_after=24):
    """Changes on the device's CIs, its HA peer and directly related CIs overlapping a time window."""
    centre = to_epoch(around, time.time())
    return run(client, "changes_near", device=device, from_ts=centre - float(hours_before) * HOUR,
               to_ts=centre + float(hours_after) * HOUR)


def find_other_authorisations(client, device, first_seen, last_seen=None, engineer=None, chg_refs=None):
    """For a change with no CHG on its own CI: HA-peer CHGs, CHGs on related CIs, the engineer's own
    CHGs on other CIs, CHGs raised afterwards, and CHG numbers mentioned in the config."""
    start = to_epoch(first_seen)
    return run(client, "alt_explanations", device=device, first_seen=start,
               last_seen=to_epoch(last_seen, start), itam_user=engineer, chg_refs=chg_refs or [])


def find_incidents_downstream(client, device, since, hours=72, max_hops=2, exclude=None):
    """Incidents on the device's CI or up to max_hops downstream opened after `since`, ranked by
    hops x delay x priority."""
    return run(client, "downstream_incidents", device=device, last_seen=to_epoch(since),
               horizon=float(hours) * HOUR, max_hops=int(max_hops), exclude=exclude or [])


def get_device_neighbourhood(client, device):
    """Everything connected to a device: CIs, HA peers, upstream/downstream, recent changes, incidents, cases."""
    result = run(client, "device_neighbourhood", device=device, now=time.time())
    return result[0] if result else {"error": "device %s is not in the graph" % device}
