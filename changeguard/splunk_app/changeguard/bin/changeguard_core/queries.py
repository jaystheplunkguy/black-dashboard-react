"""Named, parameterised AQL queries: the only AQL ChangeGuard runs.

Splunk (`| cgaql query=<name>`) and the MCP server both call these by name,
so no free-form AQL ever reaches the database and the agent's tools and
the scheduled pipeline always answer a question the same way.

Graph direction conventions (see arango/bootstrap.py):
  device_is      devices  -> cis          hostname normalisation happens once, here
  ci_rel         provider -> consumer     impact flows along the edge (firewall -> app -> service)
  chg_affects    changes  -> cis|services
  inc_on         incidents -> cis|services
  implemented_by changes  -> people
  ha_peer        devices  -> devices      treat as undirected (ANY)
  case_on        cases    -> devices
  case_matched   cases    -> changes      the CHG the verdict is based on
  case_related   cases    -> changes|incidents   other evidence, with e.reason / e.score
All times are epoch seconds.
"""

import re

from .keys import normalise_host, safe_key

DAY = 86400
FAILED_VERDICTS = ["POTENTIAL_FAILED_CHANGE", "IMPLEMENTATION_DEVIATION", "UNPLANNED_CHANGE"]

# Compact change projection reused by several queries.
_CHG = """{chg_number: c._key, summary: c.summary, status: c.status, approval: c.approval,
           chg_class: c.chg_class, implementer: c.implementer,
           planned_start: c.planned_start, planned_end: c.planned_end, created_at: c.created_at"""


class Query(object):
    def __init__(self, name, description, aql, params):
        self.name = name
        self.description = description
        self.aql = aql
        # params: {name: (type, default)}; default REQUIRED means the caller must supply it.
        self.params = params


REQUIRED = object()


def _convert(kind, value):
    if value is None or value == "" or value == []:
        if kind == "list":
            return []
        return None
    if kind == "host":
        return safe_key(normalise_host(value if not isinstance(value, list) else value[0]))
    if kind == "key":
        return safe_key(value if not isinstance(value, list) else value[0])
    if kind == "str":
        return str(value if not isinstance(value, list) else value[0])
    if kind == "num":
        number = float(value if not isinstance(value, list) else value[0])
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
            bind_vars[name] = default if not callable(default) else default()
            continue
        bind_vars[name] = _convert(kind, raw)
    return bind_vars


def referenced_params(aql):
    return set(re.findall(r"(?<!@)@([A-Za-z_]\w*)", aql))


QUERIES = {}


def _register(name, description, params, aql):
    QUERIES[name] = Query(name, description, aql, params)


# --- L4: scenarios 01-03 ---------------------------------------------------

_register(
    "best_change",
    "Best-matching CHG for a change session on a device (window, approval, implementer).",
    {
        "device": ("host", REQUIRED),
        "first_seen": ("num", REQUIRED),
        "last_seen": ("num", REQUIRED),
        "itam_user": ("str", None),
        "slack": ("num", 1800),
        "horizon": ("num", 7 * DAY),
    },
    """
LET dev = FIRST(FOR d IN devices FILTER d._key == @device RETURN d)
LET cis = dev == null ? [] : (FOR ci IN 1..1 OUTBOUND dev device_is RETURN ci)
LET services = UNIQUE(
  FOR ci IN cis
    FOR v IN 0..3 OUTBOUND ci ci_rel
      FILTER IS_SAME_COLLECTION("services", v)
      RETURN v.name)
LET candidates = (
  FOR ci IN cis
    FOR c IN 1..1 INBOUND ci chg_affects
      LET start = NOT_NULL(c.planned_start, c.actual_start)
      LET finish = NOT_NULL(c.planned_end, c.actual_end, start)
      FILTER start != null
      FILTER start <= @last_seen + @horizon AND finish >= @first_seen - @horizon
      LET in_window = @first_seen >= start - @slack AND @last_seen <= finish + @slack
      LET approved = (c.approval == "Approved" OR c.chg_class == "Standard")
                     AND c.status NOT IN ["Cancelled", "Rejected", "Draft"]
      LET user_ok = @itam_user != null AND LOWER(c.implementer) == LOWER(@itam_user)
      LET score = (in_window ? 4 : 0) + (approved ? 2 : 0) + (user_ok ? 1 : 0)
      SORT score DESC, ABS(start - @first_seen) ASC
      RETURN {c, ci, start, finish, in_window, approved, user_ok, score})
LET best = FIRST(candidates)
RETURN {
  device_found: dev != null,
  ci_count: LENGTH(cis),
  ci_key: FIRST(cis)._key,
  ci_name: FIRST(cis).name,
  services: services,
  candidate_count: LENGTH(candidates),
  chg_number: best.c._key,
  chg_summary: best.c.summary,
  chg_status: best.c.status,
  chg_approval: best.c.approval,
  chg_class: best.c.chg_class,
  chg_implementer: best.c.implementer,
  planned_start: best.start,
  planned_end: best.finish,
  in_window: best.in_window,
  approved: best.approved,
  user_ok: best.user_ok,
  match_score: best.score
}
""",
)

_register(
    "change_detail",
    "Full text of a change (summary, description, implementation plan) for the intent check.",
    {"chg_number": ("key", REQUIRED)},
    """
FOR c IN changes FILTER c._key == @chg_number
  RETURN {chg_number: c._key, summary: c.summary, description: c.description,
          plan: c.plan, chg_class: c.chg_class, risk: c.risk, implementer: c.implementer,
          planned_start: c.planned_start, planned_end: c.planned_end}
""",
)

# --- L4/L5b: scenario 02 -------------------------------------------------------

_register(
    "alt_explanations",
    "Other credible authorisations for a change with no matching CHG: HA peer CHGs, CHGs on "
    "related CIs, the engineer's own CHGs on other CIs, CHGs raised afterwards, CHG numbers in the config text.",
    {
        "device": ("host", REQUIRED),
        "first_seen": ("num", REQUIRED),
        "last_seen": ("num", REQUIRED),
        "itam_user": ("str", None),
        "chg_refs": ("list", []),
        "slack": ("num", 1800),
        "window": ("num", DAY),
        "late": ("num", 2 * DAY),
    },
    """
LET dev = FIRST(FOR d IN devices FILTER d._key == @device RETURN d)
LET my_cis = dev == null ? [] : (FOR ci IN 1..1 OUTBOUND dev device_is RETURN ci)
LET peers = dev == null ? [] : (FOR p IN 1..1 ANY dev ha_peer RETURN p)
LET peer_chgs = (
  FOR p IN peers
    FOR ci IN 1..1 OUTBOUND p device_is
      FOR c IN 1..1 INBOUND ci chg_affects
        LET start = NOT_NULL(c.planned_start, c.actual_start)
        FILTER start != null AND ABS(start - @first_seen) < @window
        RETURN MERGE(%(chg)s}, {why: CONCAT("CHG on HA peer ", p._key)}))
LET neighbour_chgs = (
  FOR ci IN my_cis
    FOR n IN 1..1 ANY ci ci_rel
      FOR c IN 1..1 INBOUND n chg_affects
        LET start = NOT_NULL(c.planned_start, c.actual_start)
        FILTER start != null
        FILTER @first_seen >= start - @slack AND @last_seen <= NOT_NULL(c.planned_end, start) + @slack
        RETURN MERGE(%(chg)s}, {why: CONCAT("CHG in window on related CI ", n.name)}))
LET person_chgs = (
  FOR person IN people FILTER person._key == @itam_user
    FOR c IN 1..1 INBOUND person implemented_by
      LET start = NOT_NULL(c.planned_start, c.actual_start)
      FILTER start != null
      FILTER @first_seen >= start - @slack AND @last_seen <= NOT_NULL(c.planned_end, start) + @slack
      RETURN MERGE(%(chg)s}, {why: "Engineer's own CHG in window on another CI (missing CI association?)"}))
LET late_chgs = (
  FOR ci IN my_cis
    FOR c IN 1..1 INBOUND ci chg_affects
      FILTER c.created_at > @first_seen AND c.created_at < @first_seen + @late
      RETURN MERGE(%(chg)s}, {why: "CHG raised after the change (retrospective)"}))
LET ref_chgs = (
  FOR k IN @chg_refs
    FOR c IN changes FILTER c._key == k
      RETURN MERGE(%(chg)s}, {why: "CHG number referenced in the config/commit text"}))
LET cands = UNION(peer_chgs, neighbour_chgs, person_chgs, late_chgs, ref_chgs)
RETURN {
  peer_count: LENGTH(peer_chgs),
  neighbour_count: LENGTH(neighbour_chgs),
  person_count: LENGTH(person_chgs),
  late_count: LENGTH(late_chgs),
  ref_count: LENGTH(ref_chgs),
  total: LENGTH(cands),
  ha_peers: peers[*]._key,
  candidate_keys: UNIQUE(cands[*].chg_number),
  evidence: cands
}
""" % {"chg": _CHG},
)

# --- L6: scenario 04 -----------------------------------------------------------

_register(
    "downstream_incidents",
    "Incidents on the device's CI or up to max_hops downstream, opened after the change, ranked by "
    "a score of hops x delay x priority.",
    {
        "device": ("host", REQUIRED),
        "last_seen": ("num", REQUIRED),
        "horizon": ("num", 3 * DAY),
        "max_hops": ("num", 2),
        "exclude": ("list", []),
    },
    """
LET dev = FIRST(FOR d IN devices FILTER d._key == @device RETURN d)
LET hits = dev == null ? [] : (
  FOR ci IN 1..1 OUTBOUND dev device_is
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
        RETURN {incident: inc._key, summary: inc.summary, priority: inc.priority,
                opened_at: inc.opened_at, hops: hops, via: v.name, via_id: v._id,
                delay_min: ROUND(delay_min), score: ROUND(w_hops * w_delay * w_prio * 100) / 100})
LET ranked = (
  FOR h IN hits
    COLLECT k = h.incident INTO g = h
    LET top = FIRST(FOR x IN g SORT x.score DESC RETURN x)
    SORT top.score DESC
    RETURN top)
LET best = FIRST(ranked)
RETURN {
  incident_count: LENGTH(ranked),
  top_incident: best.incident,
  top_summary: best.summary,
  top_priority: best.priority,
  top_hops: best.hops,
  top_via: best.via,
  top_delay_min: best.delay_min,
  top_score: NOT_NULL(best.score, 0),
  incident_keys: ranked[*].incident,
  incidents: ranked
}
""",
)

# --- L7: evidence package ----------------------------------------------------

_register(
    "case_evidence",
    "A case's evidence subgraph: device, CIs, HA peers, matched and related changes/incidents, "
    "downstream services, plus the raw nodes/edges for drawing.",
    {"case_id": ("key", REQUIRED)},
    """
FOR k IN cases FILTER k._key == @case_id
  LET dev = FIRST(FOR v IN 1..1 OUTBOUND k case_on RETURN v)
  LET cis = dev == null ? [] : (FOR v IN 1..1 OUTBOUND dev device_is RETURN v)
  LET peers = dev == null ? [] : (FOR v IN 1..1 ANY dev ha_peer RETURN v._key)
  LET downstream = UNIQUE(
    FOR ci IN cis FOR v, e, p IN 1..3 OUTBOUND ci ci_rel
      RETURN {name: v.name, id: v._id, hops: LENGTH(p.edges)})
  LET matched = (FOR c IN 1..1 OUTBOUND k case_matched RETURN %(chg)s})
  LET related = (
    FOR v, e IN 1..1 OUTBOUND k case_related
      RETURN {id: v._id, name: NOT_NULL(v.summary, v.name, v._key), reason: e.reason, score: e.score})
  LET edges = UNIQUE(
    FOR v, e IN 1..4 OUTBOUND k case_on, case_matched, case_related, device_is, ci_rel, chg_affects
      OPTIONS {order: "bfs", uniqueVertices: "global"}
      RETURN {from: e._from, to: e._to, type: PARSE_IDENTIFIER(e._id).collection})
  RETURN {
    case_id: k._key, verdict: k.verdict, status: k.status,
    device: dev._key, cis: cis[*].name, ha_peers: peers,
    downstream: downstream, matched_changes: matched, related: related,
    nodes: UNIQUE(UNION(edges[*].from, edges[*].to)), edges: edges
  }
""" % {"chg": _CHG},
)

# --- Agent tools (scenario 05) -------------------------------------------------

_register(
    "changes_near",
    "Changes on a device's CIs, its HA peer and directly related CIs whose window overlaps [from_ts, to_ts].",
    {"device": ("host", REQUIRED), "from_ts": ("num", REQUIRED), "to_ts": ("num", REQUIRED)},
    """
LET dev = FIRST(FOR d IN devices FILTER d._key == @device RETURN d)
LET own = dev == null ? [] : (FOR ci IN 1..1 OUTBOUND dev device_is RETURN {ci, rel: "own CI"})
LET peer = dev == null ? [] : (
  FOR p IN 1..1 ANY dev ha_peer FOR ci IN 1..1 OUTBOUND p device_is RETURN {ci, rel: CONCAT("HA peer ", p._key)})
LET near = (FOR o IN own FOR n IN 1..1 ANY o.ci ci_rel RETURN {ci: n, rel: CONCAT("related CI ", n.name)})
FOR t IN UNION(own, peer, near)
  FOR c IN 1..1 INBOUND t.ci chg_affects
    LET start = NOT_NULL(c.planned_start, c.actual_start)
    LET finish = NOT_NULL(c.planned_end, c.actual_end, start)
    FILTER start != null AND start <= @to_ts AND finish >= @from_ts
    SORT start
    RETURN MERGE(%(chg)s}, {ci: t.ci.name, relation: t.rel})
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
                            RETURN {name: v.name, hops: LENGTH(p.edges), service: IS_SAME_COLLECTION("services", v)})
  LET upstream = UNIQUE(FOR ci IN cis FOR v, e, p IN 1..2 INBOUND ci ci_rel
                          RETURN {name: v.name, hops: LENGTH(p.edges)})
  LET changes = (FOR ci IN cis FOR c IN 1..1 INBOUND ci chg_affects
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
  RETURN {device: dev._key, platform: dev.platform, cis: cis[*].name, ci_classes: cis[*].ci_class,
          ha_peers: peers, downstream, upstream, changes, incidents, cases}
""" % {"chg": _CHG},
)

_register(
    "list_cases",
    "ChangeGuard cases, newest first, optionally filtered by status, verdict or device.",
    {
        "status": ("str", None),
        "verdict": ("str", None),
        "device": ("host", None),
        "since": ("num", 0),
        "limit": ("num", 25),
    },
    """
FOR k IN cases
  FILTER @status == null OR k.status == @status
  FILTER @verdict == null OR k.verdict == @verdict
  FILTER @device == null OR k.device == @device
  FILTER k.first_seen >= @since
  SORT k.first_seen DESC
  LIMIT @limit
  RETURN KEEP(k, "_key", "device", "user", "platform", "first_seen", "last_seen", "verdict", "status",
              "chg_number", "confidence", "reasons", "ci_name", "services")
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
    "Graph features for the change-success model: CI history, downstream dependents, engineer history. "
    "Only history before @now and never the change's own cases, so training rows do not leak their label.",
    {"chg_number": ("key", REQUIRED), "now": ("num", REQUIRED), "failed_verdicts": ("list", FAILED_VERDICTS)},
    """
FOR c IN changes FILTER c._key == @chg_number
  LET cis = (FOR ci IN 1..1 OUTBOUND c chg_affects RETURN ci)
  LET since = @now - 90 * 86400
  LET downstream = LENGTH(UNIQUE(FOR ci IN cis FOR v IN 1..3 OUTBOUND ci ci_rel RETURN v._id))
  LET ci_changes = LENGTH(UNIQUE(FOR ci IN cis FOR o IN 1..1 INBOUND ci chg_affects
                                   FILTER o.planned_start >= since AND o.planned_start < @now RETURN o._key))
  LET ci_incidents = LENGTH(UNIQUE(FOR ci IN cis FOR i IN 1..1 INBOUND ci inc_on
                                     FILTER i.opened_at >= since RETURN i._key))
  LET ci_failed = LENGTH(UNIQUE(FOR ci IN cis FOR d IN 1..1 INBOUND ci device_is FOR k IN 1..1 INBOUND d case_on
                                  FILTER k.verdict IN @failed_verdicts AND k.first_seen >= since AND k.first_seen < @now
                                  FILTER k.chg_number != c._key RETURN k._key))
  LET eng = (FOR k IN cases FILTER k.itam_user != null AND k.itam_user == c.implementer
               FILTER k.chg_number != c._key AND k.first_seen < @now RETURN k.verdict)
  LET eng_failed = LENGTH(eng[* FILTER CURRENT IN @failed_verdicts])
  RETURN {
    chg_number: c._key, chg_class: NOT_NULL(c.chg_class, "unknown"), risk: NOT_NULL(c.risk, "unknown"),
    ci_class: NOT_NULL(FIRST(cis).ci_class, "unknown"), ci_count: LENGTH(cis),
    downstream_count: downstream, ci_changes_90d: ci_changes, ci_incidents_90d: ci_incidents,
    ci_fail_rate_90d: ci_changes == 0 ? 0 : ROUND(100 * ci_failed / ci_changes) / 100,
    implementer_cases: LENGTH(eng),
    implementer_fail_rate: LENGTH(eng) == 0 ? 0 : ROUND(100 * eng_failed / LENGTH(eng)) / 100,
    duration_h: c.planned_end == null OR c.planned_start == null ? 0
                : ROUND(10 * (c.planned_end - c.planned_start) / 3600) / 10,
    start_hour: c.planned_start == null ? -1 : DATE_HOUR(c.planned_start * 1000),
    start_weekday: c.planned_start == null ? -1 : DATE_DAYOFWEEK(c.planned_start * 1000)
  }
""",
)
