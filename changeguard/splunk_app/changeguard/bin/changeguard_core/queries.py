"""Named, parameterised AQL queries: the only AQL ChangeGuard runs.

The graph answers *relationship* questions only (HA peers, related CIs,
downstream impact, evidence trail). The deterministic CHG checks (exists,
approved, implementer, window) are done in SPL against the cg_changes KV store.

Splunk (`cg_aq*` macros -> `| cgaql query=<name>`) and the MCP server call these
by name, so no free-form AQL reaches the database.

Graph conventions (arango/bootstrap.py):
  devices   _key = normalised short hostname (cg_norm_host)
  cis       _key = itam_ci_lookup CI_Name;  is_service / is_network flags
  changes   _key = change id (CRQ..., CALM id)
  device_is      devices -> cis
  ci_rel         provider -> consumer (impact flows along the edge: firewall -> app -> service)
  chg_affects    changes -> devices (always) and -> cis (when the CI is known)
  inc_on         incidents -> cis
  implemented_by changes -> people
  ha_peer        devices -> devices (treat as undirected)
  case_on        cases -> devices (role = session | target)
  case_matched   cases -> changes (the CHG the verdict is based on)
  case_related   cases -> changes | incidents (other evidence, e.reason / e.score)
All times are epoch seconds.
"""

import re

from .keys import normalise_host, safe_key

DAY = 86400
FAILED_VERDICTS = ["POTENTIAL_FAILED_CHANGE", "IMPLEMENTATION_DEVIATION", "UNPLANNED_CHANGE"]

# Compact change projection reused by several queries (c = change document).
_CHG = """{chg_number: c._key, source: c.source, summary: c.summary, status: c.status, approval: c.approval,
           implementer: c.implementer, imp_group: c.imp_group,
           planned_start: c.planned_start, planned_end: c.planned_end, created_at: c.created_at"""

REQUIRED = object()


class Query(object):
    def __init__(self, name, description, aql, params):
        self.name = name
        self.description = description
        self.aql = aql
        # params: {name: (type, default)}; REQUIRED means the caller must supply it.
        self.params = params


def _first(value):
    return value[0] if isinstance(value, list) else value


def _convert(kind, value):
    if value is None or value == "" or value == []:
        return [] if kind in ("list", "hosts") else None
    if kind == "host":
        return safe_key(normalise_host(_first(value)))
    if kind == "hosts":
        items = value if isinstance(value, list) else str(value).split(",")
        return sorted({safe_key(normalise_host(v)) for v in items if str(v).strip()})
    if kind == "key":
        return safe_key(_first(value))
    if kind == "str":
        return str(_first(value))
    if kind == "num":
        number = float(_first(value))
        return int(number) if number.is_integer() else number
    if kind == "list":
        items = value if isinstance(value, list) else str(value).split(",")
        return [str(v).strip() for v in items if str(v).strip()]
    raise ValueError("unknown param type %s" % kind)


def bind(query, values):
    """Build bindVars for `query` from a dict (missing optional params use defaults)."""
    bind_vars = {}
    for name, (kind, default) in query.params.items():
        raw = values.get(name)
        if raw is None or raw == "" or raw == []:
            if default is REQUIRED:
                raise ValueError("query %s needs parameter '%s'" % (query.name, name))
            bind_vars[name] = default
            continue
        bind_vars[name] = _convert(kind, raw)
    return bind_vars


def referenced_params(aql):
    return set(re.findall(r"(?<!@)@([A-Za-z_]\w*)", aql))


QUERIES = {}


def _register(name, description, params, aql):
    QUERIES[name] = Query(name, description, aql, params)


# --- Scenario 02: other explanations for a change with no matching CHG ------

_register(
    "alt_explanations",
    "Other credible authorisations for a change session with no in-window CHG: CHGs on its devices near "
    "the time, on HA peers (graph), on related CIs, the engineer's CHGs elsewhere, CHGs raised afterwards, "
    "and CHG numbers referenced in the commit comment.",
    {
        "devices": ("hosts", REQUIRED),
        "first_seen": ("num", REQUIRED),
        "last_seen": ("num", REQUIRED),
        "itam_user": ("str", None),
        "chg_refs": ("list", []),
        "slack": ("num", 1800),
        "before": ("num", 2 * DAY),
        "after": ("num", DAY),
        "late": ("num", 2 * DAY),
    },
    """
LET devs = (FOR d IN devices FILTER d._key IN @devices RETURN d)
LET peers = UNIQUE(FOR d IN devs FOR p IN 1..1 ANY d ha_peer FILTER p._key NOT IN @devices RETURN p)
LET own_related = (
  FOR d IN devs
    FOR c IN 1..1 INBOUND d chg_affects
      FILTER c.planned_start != null
      FILTER c.planned_start >= @first_seen - @before AND NOT_NULL(c.planned_end, c.planned_start) <= @last_seen + @after
      RETURN MERGE(%(chg)s}, {why: CONCAT("CHG on ", d._key, " near the time but not covering the change window")}))
LET peer_chgs = (
  FOR p IN peers
    FOR c IN 1..1 INBOUND p chg_affects
      FILTER c.planned_start != null AND ABS(c.planned_start - @first_seen) < @before
      RETURN MERGE(%(chg)s}, {why: CONCAT("CHG on HA peer ", p._key)}))
LET neighbour_chgs = (
  FOR d IN devs
    FOR ci IN 1..1 OUTBOUND d device_is
      FOR n IN 1..1 ANY ci ci_rel
        FOR c IN 1..1 INBOUND n chg_affects
          FILTER c.planned_start != null
          FILTER @first_seen >= c.planned_start - @slack AND @last_seen <= NOT_NULL(c.planned_end, c.planned_start) + @slack
          RETURN MERGE(%(chg)s}, {why: CONCAT("CHG in window on related CI ", n.CI_Name)}))
LET person_chgs = (
  FOR person IN people FILTER person._key == @itam_user
    FOR c IN 1..1 INBOUND person implemented_by
      FILTER c.planned_start != null
      FILTER @first_seen >= c.planned_start - @slack AND @last_seen <= NOT_NULL(c.planned_end, c.planned_start) + @slack
      RETURN MERGE(%(chg)s}, {why: "Engineer's own CHG in window on another device (missing CI association?)"}))
LET late_chgs = (
  FOR d IN devs
    FOR c IN 1..1 INBOUND d chg_affects
      FILTER c.created_at > @first_seen AND c.created_at < @first_seen + @late
      RETURN MERGE(%(chg)s}, {why: "CHG raised after the change (retrospective)"}))
LET ref_chgs = (
  FOR k IN @chg_refs
    FOR c IN changes FILTER c._key == k
      RETURN MERGE(%(chg)s}, {why: "CHG number referenced in the commit comment"}))
LET cands = UNION(own_related, peer_chgs, neighbour_chgs, person_chgs, late_chgs, ref_chgs)
RETURN {
  own_related_count: LENGTH(own_related), peer_count: LENGTH(peer_chgs), neighbour_count: LENGTH(neighbour_chgs),
  person_count: LENGTH(person_chgs), late_count: LENGTH(late_chgs), ref_count: LENGTH(ref_chgs),
  total: LENGTH(cands),
  graph_ha_peers: peers[*]._key,
  candidate_keys: UNIQUE(cands[*].chg_number),
  evidence: cands
}
""" % {"chg": _CHG},
)

# --- Scenario 04: downstream incidents ------------------------------------------

_register(
    "downstream_incidents",
    "Incidents on the devices' CIs or up to max_hops downstream, opened after last_seen, ranked by "
    "hops x delay x priority.",
    {
        "devices": ("hosts", REQUIRED),
        "last_seen": ("num", REQUIRED),
        "horizon": ("num", 3 * DAY),
        "max_hops": ("num", 2),
        "exclude": ("list", []),
    },
    """
LET hits = (
  FOR d IN devices FILTER d._key IN @devices
    FOR ci IN 1..1 OUTBOUND d device_is
      FOR v, e, p IN 0..3 OUTBOUND ci ci_rel
        LET hops = LENGTH(p.edges)
        FILTER hops <= @max_hops
        FOR inc IN 1..1 INBOUND v inc_on
          FILTER inc.opened_at > @last_seen AND inc.opened_at < @last_seen + @horizon
          FILTER inc._key NOT IN @exclude
          LET delay_min = (inc.opened_at - @last_seen) / 60
          LET w_hops = hops == 0 ? 1.0 : (hops == 1 ? 0.7 : (hops == 2 ? 0.5 : 0.3))
          LET w_delay = delay_min <= 60 ? 1.0 : (delay_min <= 240 ? 0.7 : (delay_min <= 1440 ? 0.4 : 0.2))
          LET w_prio = inc.priority == 1 ? 1.0 : (inc.priority == 2 ? 0.8 : (inc.priority == 3 ? 0.5 : 0.3))
          RETURN {incident: inc._key, summary: inc.summary, priority: inc.priority, opened_at: inc.opened_at,
                  hops: hops, via: NOT_NULL(v.Name, v.CI_Name), via_id: v._id, from_device: d._key,
                  delay_min: ROUND(delay_min), score: ROUND(w_hops * w_delay * w_prio * 100) / 100})
LET ranked = (
  FOR h IN hits
    COLLECT k = h.incident INTO g = h
    LET top = FIRST(FOR x IN g SORT x.score DESC RETURN x)
    SORT top.score DESC
    RETURN top)
LET best = FIRST(ranked)
RETURN {
  incident_count: LENGTH(ranked), top_incident: best.incident, top_summary: best.summary,
  top_priority: best.priority, top_hops: best.hops, top_via: best.via, top_delay_min: best.delay_min,
  top_score: NOT_NULL(best.score, 0), incident_keys: ranked[*].incident, incidents: ranked
}
""",
)

# --- Evidence package ------------------------------------------------------------

_register(
    "case_evidence",
    "A case's evidence subgraph: devices (session + targets), CIs, HA peers, matched and related "
    "changes/incidents, downstream CIs/services, plus raw nodes/edges for drawing.",
    {"case_id": ("key", REQUIRED)},
    """
FOR k IN cases FILTER k._key == @case_id
  LET devs = (FOR v, e IN 1..1 OUTBOUND k case_on RETURN {key: v._key, role: e.role})
  LET cis = UNIQUE(FOR d IN devs FOR v IN 1..1 OUTBOUND CONCAT("devices/", d.key) device_is RETURN v)
  LET peers = UNIQUE(FOR d IN devs FOR v IN 1..1 ANY CONCAT("devices/", d.key) ha_peer RETURN v._key)
  LET downstream = UNIQUE(
    FOR ci IN cis FOR v, e, p IN 1..3 OUTBOUND ci ci_rel
      RETURN {name: NOT_NULL(v.Name, v.CI_Name), id: v._id, hops: LENGTH(p.edges), service: v.is_service == 1})
  LET matched = (FOR c IN 1..1 OUTBOUND k case_matched RETURN %(chg)s})
  LET related = (
    FOR v, e IN 1..1 OUTBOUND k case_related
      RETURN {id: v._id, name: NOT_NULL(v.summary, v.Name, v._key), reason: e.reason, score: e.score})
  LET edges = UNIQUE(
    FOR v, e IN 1..4 OUTBOUND k case_on, case_matched, case_related, device_is, ci_rel
      OPTIONS {order: "bfs", uniqueVertices: "global"}
      RETURN {from: e._from, to: e._to, type: PARSE_IDENTIFIER(e._id).collection})
  RETURN {
    case_id: k._key, verdict: k.verdict, status: k.status, devices: devs,
    cis: cis[*].CI_Name, ha_peers: peers, downstream: downstream,
    matched_changes: matched, related: related,
    nodes: UNIQUE(UNION(edges[*].from, edges[*].to)), edges: edges
  }
""" % {"chg": _CHG},
)

# --- Agent tools (scenario 05) -------------------------------------------------

_register(
    "related_changes",
    "Changes on a device, its HA peers and directly related CIs whose window overlaps [from_ts, to_ts].",
    {"device": ("host", REQUIRED), "from_ts": ("num", REQUIRED), "to_ts": ("num", REQUIRED)},
    """
LET dev = FIRST(FOR d IN devices FILTER d._key == @device RETURN d)
LET own = dev == null ? [] : [{v: dev, rel: "device"}]
LET peer = dev == null ? [] : (FOR p IN 1..1 ANY dev ha_peer RETURN {v: p, rel: CONCAT("HA peer ", p._key)})
LET near = dev == null ? [] : (
  FOR ci IN 1..1 OUTBOUND dev device_is FOR n IN 1..1 ANY ci ci_rel
    RETURN {v: n, rel: CONCAT("related CI ", NOT_NULL(n.Name, n.CI_Name))})
FOR t IN UNION(own, peer, near)
  FOR c IN 1..1 INBOUND t.v chg_affects
    LET start = c.planned_start
    LET finish = NOT_NULL(c.planned_end, start)
    FILTER start != null AND start <= @to_ts AND finish >= @from_ts
    COLLECT chg = c, relation = t.rel
    SORT chg.planned_start
    RETURN MERGE((LET c = chg RETURN %(chg)s})[0], {relation: relation})
""" % {"chg": _CHG},
)

_register(
    "device_neighbourhood",
    "Everything connected to a device: CIs, HA peers, upstream/downstream CIs and services, changes "
    "(last 30 days and next 7), incidents (last 7 days) and ChangeGuard cases.",
    {"device": ("host", REQUIRED), "now": ("num", REQUIRED)},
    """
FOR dev IN devices FILTER dev._key == @device
  LET cis = (FOR ci IN 1..1 OUTBOUND dev device_is RETURN ci)
  LET peers = (FOR p IN 1..1 ANY dev ha_peer RETURN p._key)
  LET downstream = UNIQUE(FOR ci IN cis FOR v, e, p IN 1..3 OUTBOUND ci ci_rel
                            RETURN {name: NOT_NULL(v.Name, v.CI_Name), hops: LENGTH(p.edges), service: v.is_service == 1})
  LET upstream = UNIQUE(FOR ci IN cis FOR v, e, p IN 1..2 INBOUND ci ci_rel
                          RETURN {name: NOT_NULL(v.Name, v.CI_Name), hops: LENGTH(p.edges)})
  LET changes = (FOR c IN 1..1 INBOUND dev chg_affects
                   FILTER NOT_NULL(c.planned_start, 0) >= @now - 30 * 86400
                     AND NOT_NULL(c.planned_start, 0) <= @now + 7 * 86400
                   SORT c.planned_start DESC
                   RETURN %(chg)s})
  LET incidents = (FOR ci IN cis FOR i IN 1..1 INBOUND ci inc_on
                     FILTER i.opened_at >= @now - 7 * 86400
                     SORT i.opened_at DESC
                     RETURN {incident: i._key, summary: i.summary, priority: i.priority, opened_at: i.opened_at})
  LET cases = (FOR k IN 1..1 INBOUND dev case_on SORT k.first_seen DESC LIMIT 20
                 RETURN KEEP(k, "_key", "verdict", "status", "first_seen", "user", "chg_number"))
  RETURN {device: dev._key, platform: dev.platform, role: dev.role, cis: cis[*].CI_Name,
          ha_peers: peers, downstream, upstream, changes, incidents, cases}
""" % {"chg": _CHG},
)

_register(
    "list_cases",
    "ChangeGuard cases, newest first, optionally filtered by status, verdict, platform or device.",
    {
        "status": ("str", None),
        "verdict": ("str", None),
        "platform": ("str", None),
        "device": ("host", None),
        "since": ("num", 0),
        "limit": ("num", 25),
    },
    """
FOR k IN cases
  FILTER @status == null OR k.status == @status
  FILTER @verdict == null OR k.verdict == @verdict
  FILTER @platform == null OR k.platform == @platform
  FILTER @device == null OR k.session_device == @device OR @device IN NOT_NULL(k.doi, [])
  FILTER k.first_seen >= @since
  SORT k.first_seen DESC
  LIMIT @limit
  RETURN KEEP(k, "_key", "session_device", "targets", "platform", "user", "user_display", "first_seen",
              "last_seen", "verdict", "status", "severity", "chg_number", "match_via", "confidence", "reasons")
""",
)

_register(
    "get_case",
    "One case document from the graph (verdict, reasons, AI output).",
    {"case_id": ("key", REQUIRED)},
    """
FOR k IN cases FILTER k._key == @case_id RETURN UNSET(k, "_id", "_rev")
""",
)

# --- Scenario 06 ---------------------------------------------------------------

_register(
    "upcoming_changes",
    "Approved or scheduled changes starting within the next `days` days (input to the success model).",
    {"now": ("num", REQUIRED), "days": ("num", 14)},
    """
FOR c IN changes
  FILTER c.planned_start >= @now AND c.planned_start <= @now + @days * 86400
  FILTER c.status NOT IN ["Cancelled", "Rejected", "Completed", "Closed"]
  SORT c.planned_start
  RETURN %(chg)s}
""" % {"chg": _CHG},
)

_register(
    "change_features",
    "Graph features for the change-success model: device/CI history, downstream dependents, engineer "
    "history. Only history before @now and never the change's own cases, so training rows do not leak their label.",
    {"chg_number": ("key", REQUIRED), "now": ("num", REQUIRED), "failed_verdicts": ("list", FAILED_VERDICTS)},
    """
FOR c IN changes FILTER c._key == @chg_number
  LET since = @now - 90 * 86400
  LET targets = (FOR v IN 1..1 OUTBOUND c chg_affects RETURN v)
  LET devs = targets[* FILTER IS_SAME_COLLECTION("devices", CURRENT)]
  LET cis = UNIQUE(UNION(targets[* FILTER IS_SAME_COLLECTION("cis", CURRENT)],
                         (FOR d IN devs FOR ci IN 1..1 OUTBOUND d device_is RETURN ci)))
  LET downstream = LENGTH(UNIQUE(FOR ci IN cis FOR v IN 1..3 OUTBOUND ci ci_rel RETURN v._id))
  LET dev_changes = LENGTH(UNIQUE(FOR d IN devs FOR o IN 1..1 INBOUND d chg_affects
                                    FILTER o.planned_start >= since AND o.planned_start < @now RETURN o._key))
  LET ci_incidents = LENGTH(UNIQUE(FOR ci IN cis FOR i IN 1..1 INBOUND ci inc_on
                                     FILTER i.opened_at >= since AND i.opened_at < @now RETURN i._key))
  LET dev_failed = LENGTH(UNIQUE(FOR d IN devs FOR k IN 1..1 INBOUND d case_on
                                   FILTER k.verdict IN @failed_verdicts AND k.first_seen >= since AND k.first_seen < @now
                                   FILTER k.chg_number != c._key RETURN k._key))
  LET eng = (FOR k IN cases FILTER k.itam_user != null AND k.itam_user == c.implementer
               FILTER k.chg_number != c._key AND k.first_seen < @now RETURN k.verdict)
  LET eng_failed = LENGTH(eng[* FILTER CURRENT IN @failed_verdicts])
  RETURN {
    chg_number: c._key, source: NOT_NULL(c.source, "unknown"), risk: NOT_NULL(c.risk, "unknown"),
    ci_category: NOT_NULL(FIRST(cis).Category, "unknown"), device_count: LENGTH(devs),
    downstream_count: downstream, changes_90d: dev_changes, incidents_90d: ci_incidents,
    fail_rate_90d: dev_changes == 0 ? 0 : ROUND(100 * dev_failed / dev_changes) / 100,
    implementer_cases: LENGTH(eng),
    implementer_fail_rate: LENGTH(eng) == 0 ? 0 : ROUND(100 * eng_failed / LENGTH(eng)) / 100,
    duration_h: c.planned_end == null OR c.planned_start == null ? 0
                : ROUND(10 * (c.planned_end - c.planned_start) / 3600) / 10,
    start_hour: c.planned_start == null ? -1 : DATE_HOUR(c.planned_start * 1000),
    start_weekday: c.planned_start == null ? -1 : DATE_DAYOFWEEK(c.planned_start * 1000)
  }
""",
)
