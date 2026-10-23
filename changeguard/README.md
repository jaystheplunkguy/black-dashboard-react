# ChangeGuard AI

Continuous assurance for network configuration changes (Palo Alto, IOS routers/switches, Cisco FTD).

> Splunk detects the facts, the graph explains how they connect, and the AI decides what needs human attention.

For every change it answers: **should it have happened, did it happen correctly, and did anything bad happen afterwards?**

| # | Scenario | Path through the pipeline | Outcome |
|---|---|---|---|
| 01 | Legitimate change | L4 CHG approved, in window, right engineer → L5a intent matches → L6 72h watch, no impact | 🟢 `COMPLIANT`, no alert |
| 02 | No approved CHG | L4 no CHG on CI, graph finds no other authorisation | 🔴 `UNPLANNED_CHANGE` + evidence |
| 02b | No CHG on own CI, but one on the HA peer | L4 → L5b AI weighs the graph's candidates | `AUTHORISED_OTHER_CHG` (watched like 01) or 🔴 |
| 03 | Approved, wrongly implemented | L5a AI compares Palo Alto before/after with the CHG text | 🟠 `IMPLEMENTATION_DEVIATION` + evidence |
| 04 | Approved, then impact | L6a incident on the CI or ≤2 hops downstream (+ deny spike) → L6b AI | 🟣 `POTENTIAL_FAILED_CHANGE` + evidence |
| 05 | Operator questions | MCP agent tools (or the dashboard's *Ask ChangeGuard* box) | Answer citing cases/CHGs |
| 06 | Success probability of a proposed CHG | Graph features → AI Toolkit `RandomForestClassifier` + AI explanation | % per upcoming CHG |

Plus: `UNAPPROVED`, `OUT_OF_WINDOW`, `WRONG_IMPLEMENTER` (alerts), `UNKNOWN_CI` and `NEEDS_REVIEW` (dashboard only).

## Architecture

```
L1 DETECT     3 trigger searches (every 5 min, -10m@m..-5m@m)        -> index=changeguard_detect
L2 SESSIONISE device+user sessions (30 min gap), new cases only     -> KV cg_cases + Arango cases/case_on
L3 GRAPH      HELIX -> ArangoDB every 15 min (CIs, services, devices, relationships, CHGs, approvals,
              CHG-CI links, incidents, people, HA pairs)
L4 CORRELATE  per case: AQL best_change + alt_explanations, rule-based verdict
L5 REASON     L5a `| ai` intent check (03)   L5b `| ai` judge alternative authorisations (02)
L6 WATCH      L6s deny spikes, L6a AQL downstream incidents (04), L6b `| ai` "plausible cause?"
L7 ACT        evidence package (case subgraph + AI write-up), alert, Dashboard Studio
AGENT         MCP server: get_case, list_cases, find_changes_near, find_other_authorisations,
              find_incidents_downstream, get_device_neighbourhood (reads ArangoDB only)
```

Three stores, one job each:

| Store | Holds | Why |
|---|---|---|
| Summary index `changeguard_detect` | Normalised config events (append-only) | Audit evidence that can't be changed |
| KV store `cg_cases` | Case state, verdict, confidence, AI output | Source of truth; drives alerts and the dashboard |
| ArangoDB graph `changeguard` | Devices, CIs, services, changes, incidents, people, cases + edges | Multi-hop questions; the evidence package is the case subgraph |

### Case state machine

Each scheduled stage reads and writes **only the cases in the status it owns**, so stages can never overwrite each other's verdicts. This fixes the original design, where re-running `outputlookup` reset AI verdicts. L2 inserts only case ids that aren't already in the KV store.

| Status | Owned by | Moves to |
|---|---|---|
| `new` | L4 | `review` (UNKNOWN_CI) · `investigate` · `intent_check` · `watch` · `alert` |
| `intent_check` | L5a | `watch` · `alert` · `review` |
| `investigate` | L5b | `watch` · `alert` · `review` |
| `watch` | L6a (hourly) | `impact_check` · `closed` (after 72h → COMPLIANT) |
| `impact_check` | L6b | `alert` · `watch` (incidents dismissed so they aren't asked about again) |
| `alert` | L7 | `alerted` |

If ArangoDB is down, `cgaql` marks the row with `aql_error`. The case keeps its status and is retried on the next run. If an LLM call fails, the case is retried up to 3 times and then goes to `review`.

### Graph model (`arango/bootstrap.py`)

Vertices: `devices cis services changes incidents people cases`

| Edge | Direction | Source |
|---|---|---|
| `device_is` | device → CI | name match done once in *L3 Load devices* (+ `cg_device_ci_override.csv`) |
| `ci_rel` | provider → consumer (impact flows along the edge) | `Asset_*` parent/child relationship tables |
| `chg_affects` | change → CI/service | `Change_CI_Assoc` |
| `inc_on` | incident → CI/service | `Incident_Data` |
| `implemented_by` | change → person | `Change_Information` assignee |
| `ha_peer` | device ↔ device | `cg_ha_pairs.csv` |
| `case_on` / `case_matched` / `case_related` | case → device / CHG / CHGs & incidents | the pipeline (evidence trail) |

All AQL lives in `bin/changeguard_core/queries.py` as **named, parameterised queries**. Splunk (`| cgaql query=...`) and the MCP tools call the same queries by name, and no free-form AQL ever runs.

## Layout

```
splunk_app/changeguard/        the Splunk app
  bin/cgarango.py              | cgarango  upsert rows as documents/edges (batched per chunk)
  bin/cgaql.py                 | cgaql     run a named query per row
  bin/changeguard_core/        shared library (keys, AQL registry, Arango HTTP client)
  default/macros.conf          ALL environment-specific settings (EDIT ME sections)
  default/savedsearches.conf   the pipeline (23 searches, all prefixed "CG - ")
  default/collections.conf     KV store cg_cases
  default/data/ui/views/       Dashboard Studio: changeguard_overview
  lookups/                     identity, device alias/override, HA pairs, demo events
arango/bootstrap.py            create DB, collections, indexes, named graph
arango/seed_demo.py            demo graph for scenarios 01-04, 06
mcp_server/                    agent tools (scenarios 02/05)
agent/system_prompt.md         agent instructions (also served as MCP instructions)
tests/                         unit tests + ArangoDB integration tests
build.sh                       vendors splunklib, builds dist/changeguard-<v>.tgz
```

## Setup

1. **ArangoDB.** Create a user for ChangeGuard, then:
   ```bash
   export CG_ARANGO_URL=https://arango.internal:8529 CG_ARANGO_USER=changeguard CG_ARANGO_PASSWORD=...
   python3 arango/bootstrap.py
   ```
2. **Build and install the app.** Run `./build.sh` (it needs `pip` to vendor `splunk-sdk`), then install `dist/changeguard-0.1.0.tgz` on the search head. Deploy `indexes.conf` (the `changeguard_detect` index) to the indexers too. The pipeline also needs the AI Toolkit (≥ 6.2 for `| ai`; `fit`/`apply` for scenario 06).
3. **Connect Splunk to ArangoDB.** Create `local/changeguard.conf`:
   ```ini
   [arango]
   url = https://arango.internal:8529
   username = changeguard
   ```
   Then store the password encrypted (realm must be `changeguard`):
   ```bash
   curl -k -u admin https://splunk:8089/servicesNS/nobody/changeguard/storage/passwords \
        -d realm=changeguard -d name=changeguard -d password='...'
   ```
   The scheduled searches' owner needs `list_storage_passwords`.

   If your team's existing Arango write/lookup commands are already approved for production, you can swap them in. Every write goes through `cgarango`, and the case mirror is one macro (`cg_sync_case`).
4. **Edit the `EDIT ME` sections of `macros.conf`** (put your changes in `local/macros.conf`):
   - the trigger sources;
   - how each HELIX table lands in the index;
   - **the HELIX column mapping**: check it against real rows on day one with `` `cg_helix_change_info` | head 5 | fieldsummary ``;
   - **the `| ai` call**: confirm the option and output field names against Gareth's working AITK 6.2 example. Until then, point `cg_llm` at `cg_llm_mock` to build and test offline.
5. **Lookups.** Fill in `cg_identity.csv` (device/TACACS/FMC user → HELIX login), `cg_ha_pairs.csv`, and, where needed, `cg_device_alias.csv` (log hostname/IP → device) and `cg_device_ci_override.csv` (device → CI id).
6. **First full graph load.** Run each `CG - L3 - Load ...` search once over *All time*, CIs first. After that they run incrementally every 15 minutes.
7. **Check the matching** (the biggest risk). Then turn on email/webhook on `CG - L7`.
   ```spl
   | inputlookup cg_cases_lookup where verdict="UNKNOWN_CI" | stats count by device       ``` devices with no CI ```
   | inputlookup cg_cases_lookup | lookup cg_identity device_user AS user OUTPUT itam_user AS mapped | where isnull(mapped) | stats count by user   ``` users with no identity mapping ```
   ```

## Demo runbook (about 5 minutes, works offline with the mock LLM)

```bash
python3 arango/seed_demo.py --reset          # graph for scenarios 01-04, 06 (times relative to now)
```
Then run these in Splunk within about 45 minutes. L2 only opens sessions that ended 30–90 minutes ago, and the demo sessions end about 45 minutes before the seed time:
```spl
| savedsearch "CG - Demo - Seed detections"
| savedsearch "CG - L2 - Sessionise and open cases"
| savedsearch "CG - L4 - Correlate new cases"
| savedsearch "CG - L5a - Intent check (AI)"
| savedsearch "CG - L5b - Investigate unplanned (AI)"
| savedsearch "CG - L6a - Watch approved changes"
| savedsearch "CG - L6b - Impact check (AI)"
| savedsearch "CG - L7 - Raise alerts with evidence"
```
Expected result, verified on Splunk 9.4 + ArangoDB 3.11:

| Device | Verdict |
|---|---|
| fw-syd-01 | `COMPLIANT_WATCH` (→ `COMPLIANT` when the watch ends) |
| fw-syd-02 | `AUTHORISED_OTHER_CHG` via HA peer CRQ000001001 |
| rtr-mel-01 | `UNPLANNED_CHANGE` |
| fw-mel-01 | `IMPLEMENTATION_DEVIATION` (`source any`, `service any`) |
| fw-per-01 | `POTENTIAL_FAILED_CHANGE` (P2 Payments API incident 2 hops downstream, 25 min later) |

Then open the **ChangeGuard AI** dashboard.

## Agent (scenarios 02 and 05)

```bash
pip install -r mcp_server/requirements.txt          # MCP Python SDK 1.x or 2.x
python3 mcp_server/server.py                        # stdio
python3 mcp_server/server.py --transport streamable-http --port 8765
```
The tools read ArangoDB only, because every stage mirrors the case into the `cases` vertex. The agent therefore needs Arango credentials, **not a Splunk token**, which avoids the Forge token restriction. Run it on Agent Launchpad if inference stays on-prem; otherwise run it on Forge. If neither is cleared in time, the dashboard's *Ask ChangeGuard* panel answers questions through `| ai` on-prem.

## Tests

```bash
pip install pytest splunk-sdk
pytest tests                                                     # unit tests
CG_ARANGO_IT=1 CG_ARANGO_URL=http://127.0.0.1:8529 CG_ARANGO_PASSWORD=pw CG_ARANGO_DB=cg_it pytest tests   # + real ArangoDB
```

## Known limits

- **IOS:** `%SYS-5-CONFIG_I` doesn't record *what* changed. Enable `archive / log config / logging enable / notify syslog` to get `%PARSER-5-CFGLOG_LOGGEDCMD` commands. Without it, IOS changes skip the intent check (`COMPLIANT_WATCH`, "intent cannot be verified"). FTD audit lines are treated the same way. Demo scenario 03 on Palo Alto.
- **Deletes in HELIX** (CI relationships, CHG-CI links) aren't removed from the graph. A periodic full reload into a fresh database is the simple fix.
- **Timezones:** `cg_helix_time` parses text dates in the search user's timezone. Run the scheduled searches as a user set to the HELIX database's timezone, or adjust the macro.
- **L6s** searches raw `pan:traffic` hourly. Use `tstats` if the Network_Traffic data model is accelerated.
- **Scenario 06** needs both outcomes in the training data. Until you have real history, seed some closed cases.
