# ChangeGuard AI (NPT AI Hackathon 2026)

Continuous assurance for network configuration changes on Palo Alto (Panorama + firewalls), IOS routers/switches and Cisco FTD.

> ONESPLUNK detects the facts, the ArangoDB graph explains how they connect, and the AI decides what needs human attention.

| # | Scenario | How it is decided | Outcome |
|---|---|---|---|
| 01 | Change with approved CHG | SPL: CHG on the device, push target or HA peer; in window, approved, right implementer → AI intent check → 72h watch | 🟢 `COMPLIANT`, no alert |
| 02 | No CHG | SPL finds nothing → AQL looks for other explanations → none: alert. Some, or automation account: AI judges | 🔴 `UNPLANNED_CHANGE` or `AUTHORISED_OTHER_CHG` |
| 03 | Change doesn't match CHG intent | AI compares the changed objects (config xpaths / commands) with the CHG text | 🟠 `IMPLEMENTATION_DEVIATION` |
| 04 | Compliant change, then failure | Watcher: rollback / follow-up session in 24h (SPL) + incidents on the CI or ≤2 hops downstream (AQL) → AI | 🟣 `POTENTIAL_FAILED_CHANGE` |
| 05 | Natural-language queries | MCP tools for the agent (or the dashboard's *Ask ChangeGuard* box via `\| ai`) | Answer citing cases/CHGs |
| 06 | Success probability (stretch) | Graph features → AI Toolkit `RandomForestClassifier` + AI explanation | % per upcoming CHG |

There are also deterministic exceptions: `UNAPPROVED` (high severity), `OUT_OF_WINDOW` and `WRONG_IMPLEMENTER` (medium). `UNKNOWN_CI` and `NEEDS_REVIEW` go to the dashboard for review instead of alerting.

**Verified end-to-end** on Splunk 9.4 + ArangoDB 3.11, with the offline mock LLM. The run covered the demo data, the sample PAN-OS CONFIG event, synthetic CALM/HELIX/ITAM rows and every validation and dashboard search. The real `| ai` call and your actual HELIX column names could not be tested here: see [Assumed field names](#assumed-field-names).

## Design

```
                      ┌────────────── HELIX / CALM / ITAM (Splunk indexes) ──────────────┐
itam-ci-extract ─► CG - CI - Refresh itam_ci_lookup ─► itam_ci_lookup (KV, existing)      │
CALM + HELIX CRQ ─► CG - Changes - * feeds ──────────► cg_changes (KV, 120 days)          │
                                                                                          ▼
PAN / IOS / FTD ─► CG - Detect ─► changeguard_detect ─► CG - Correlate (sessions, SPL checks) ─► cg_cases (KV)
                    (one schema, identity + CI)          insert-only, scored best CHG + related     │
                                                                                                   ▼
 intent_check ─► CG - AI - Intent check (| ai)          investigate ─► CG - Investigate (AQL) ─► explain ─► CG - AI - Explain (| ai)
 watch ─► CG - Watch (rollback/follow-up SPL + downstream AQL) ─► impact_check ─► CG - AI - Impact check (| ai)
 alert ─► CG - Alert (case subgraph + AI write-up) ─► alerted          every stage mirrors the case into ArangoDB
ArangoDB graph ◄─ CG - Graph - * loaders (CIs, devices, relationships, changes, incidents, HA pairs, people)
```

The three stores, and the constraint each one meets:

| Store | Holds | Note |
|---|---|---|
| Summary index `changeguard_detect` | Normalised config events | Append-only audit evidence. Contiguous windows and deterministic `event_id = md5(_raw)` (re-deduplicated in correlation) |
| KV `cg_changes` | CALM + HELIX changes, one row per change + device (`_key = change_id\|device`) | Upserted by key; daily cleanup keeps 120 days |
| KV `cg_cases` | Case state, verdict, confidence, AI JSON output, related changes, watcher signals | The correlation search is **insert-only**. Each later stage reads and writes only the cases in the status it owns, so a rerun never overwrites a verdict the AI or the watcher set |
| ArangoDB `changeguard` graph | `devices cis changes incidents people cases` + `device_is ci_rel chg_affects inc_on implemented_by ha_peer case_on case_matched case_related` | Relationship questions only: HA peers, related CIs, downstream impact, evidence trail |

**Who does what:**
- **SPL decides deterministically:** CHG exists, approved, right implementer, within window, plus the score and related changes.
- **AQL answers relationship questions:** other explanations, downstream incidents and the evidence subgraph.
- **The LLM answers only judgement questions:** intent match, whether an alternative is credible, plausible cause of an incident, and the alert write-up. Every prompt asks for JSON `{verdict, confidence, reasons[], evidence_refs[]}`. The parsed reply goes back into the case (`verdict`, `confidence`, `reasons`, `deviations`, `evidence_refs`, `ai_raw`).

There are no ITSI lookups. CI matching uses `itam_ci_lookup`, identity uses `global_address_lookup`, automation accounts use `roboID.csv`, and service context comes from the HELIX CI relationships in ArangoDB.

### Case status flow

| Status | Owner (search) | Next |
|---|---|---|
| (new session) | Correlate | `review` UNKNOWN_CI · `investigate` · `intent_check` · `watch` (no config detail) · `alert` (UNAPPROVED / OUT_OF_WINDOW / WRONG_IMPLEMENTER) |
| `intent_check` | AI - Intent check | `watch` · `alert` DEVIATION · `review` (low confidence, or 3 failed LLM calls) |
| `investigate` | Investigate - Gather alternatives | `alert` UNPLANNED (nothing found, not automation) · `explain` |
| `explain` | AI - Explain unplanned | `watch` AUTHORISED_OTHER_CHG (only a CHG from the candidate list) · `alert` UNPLANNED · `review` |
| `watch` | Watch - Approved changes | `impact_check` (score ≥ 0.35) · `closed` COMPLIANT after 72h |
| `impact_check` | AI - Impact check | `alert` POTENTIAL_FAILED · `watch` (incidents dismissed) |
| `alert` | Alert - Raise alerts | `alerted` |

### Correlation details

- **Session:** `session_device` + `user`, a new session after a 30-minute gap. The search looks back 4h and picks a session up once it has been quiet for 30 minutes. `case_id = md5(session_device|user|first_seen)`.
- **Palo Alto / Panorama:**
  - `device` is the PAN-OS `device_name` field, not the syslog host (in your sample the host `nspnmp4aherb01` is a log collector).
  - Edits (`set/move/delete/edit/rename/multi-clone`) and `commit`/`commit-and-push` happen on Panorama (`cg_is_panorama`: `^nspvmp`).
  - `commit-all` events logged by a firewall are pushes. Their `session_device` is that firewall's Panorama (`cg_panorama_members.csv`, default `nspvmp1822da01`), so they join the Panorama session, and the firewalls become its `targets`.
  - Local edits on a firewall form their own session.
- **Devices of interest** = session device + targets + their HA peers. HA peers come from the `…01`↔`…02` naming rule (kept only if the peer is in `itam_ci_lookup`) plus `cg_ha_pairs.csv`.
- **Candidate changes:** every `cg_changes` row on a device of interest, plus every change ID referenced in a commit comment (`cg_chg_ref_rex`).
- **Scoring:** ref in comment = 8, in window (±30 min slack) = 4, approved = 2, implementer = 1.
  - The best candidate wins, but only authorises the session if it is in window or referenced.
  - Every candidate in the related window goes into `related_changes`. The related window is the existing −48h/+1d logic, relative to the session: start ≥ first_seen − 48h, end ≤ last_seen + 1d, and the change ended no more than 1h before the session.
  - `match_via` = `self | target | ha_peer | ai_alternative`.
- **Implementer:** compares `lower(user without @domain)` with the change's implementer login. If the change has only a group (CALM), the implementer is "not recorded" and isn't penalised.

### Fixes to the existing queries

| Existing query | Problem | Fixed in |
|---|---|---|
| itam_ci_lookup refresh | `where isnull(lookupCI)`: existing CIs were never updated; `_key` was dropped; `split(".")` truncated IP-named CIs | `CG - CI - Refresh itam_ci_lookup` upserts every CI by `_key=CI_Name`; `CI` uses `cg_norm_host` (IPs kept whole). Verified: an updated Site is written back |
| Config Change Monitor | `mvexpand CHANGE_ID` attached every CHG on the device (no window/status/implementer check) | Scored candidates; only an in-window or referenced CHG authorises; others are `related_changes` |
| Config Change Monitor | `search CIName=*` dropped devices with no CI | Those become `UNKNOWN_CI` cases; `CG - Validate - Unmatched devices` lists them |
| Config Change Monitor | Several `rex` wrote to the same `user` field | One field per pattern, then `coalesce` in priority order |
| Config Change Monitor | ITSI lookups (`itsientities.csv`, `entityservicelookup.csv`) | `itam_ci_lookup` + ArangoDB CI relationships |
| CALM feed | `values()` on CE_START/CE_END returned several values after an update and broke `strptime`; `changes.csv` grew forever; `itsi_entities` mapping | `latest()`; KV store upsert by `CALM_ID\|device`; 120-day cleanup; `cg_norm_host` device mapping |
| Maintenance summary | `CHANGE_ID != "CRQ*"`: CRQs never came in; ITSI service lookups | HELIX feed (`Change_Information` + `Change_Approvals` + `Change_CI_Assoc`) into the same KV store |

Bugs found while testing this build, and fixed:
- **Subsearch rows.** A subsearch that returns a `search` field on several rows only applies the first row. The HELIX feed now returns one row.
- **Macro quoting.** Splunk strips quotes from macro arguments, so the Arango macros re-quote them.
- **Cleanup that deleted nothing.** `outputlookup … key_field=_key` only upserts, so the cleanup now replaces the collection instead.
- **Dropped fields.** splunklib was dropping fields that only appear in later rows; the commands now give every row the same fields.

## Files

```
splunk_app/changeguard/
  default/macros.conf          ALL environment settings ([ASSUMED] = check on day one), cg_norm_host, scoring,
                               LLM backend, and the ONLY place the Arango commands are named (cg_aw_* / cg_aq*)
  default/savedsearches.conf   28 searches, all "CG - ..." (schedule table below)
  default/collections.conf     cg_cases, cg_changes
  default/transforms.conf      cg_cases_lookup, cg_changes_lookup, cg_ha_pairs, cg_panorama_members, demo lookups
  default/indexes.conf         changeguard_detect
  default/data/ui/views/       Dashboard Studio: changeguard_overview
  bin/cgarango.py, cgaql.py    reference Arango write / named-query commands (swappable, see below)
  bin/changeguard_core/        shared Python: AQL registry (queries.py), keys, HTTP client
  lookups/                     cg_ha_pairs.csv, cg_panorama_members.csv, demo CSVs
splunk_app/changeguard_dev_stubs/   DEV/DEMO ONLY stand-ins for itam_ci_lookup, roboID.csv, global_address_lookup
arango/bootstrap.py            database, collections, indexes, named graph
arango/seed_demo.py            demo topology (same documents the loaders write)
mcp_server/                    agent tools: get_case, list_cases, find_related_changes, find_other_authorisations,
                               find_incidents_downstream, get_device_neighbourhood, run_spl (read-only)
agent/system_prompt.md, agent/tools.json   agent instructions and tool definitions (JSON schema)
tests/                         unit tests + ArangoDB integration tests
```

### Your existing ArangoDB commands

Every Arango call in the SPL goes through five macros in `macros.conf` §6:

| Macro | What it does |
|---|---|
| `cg_aw_docs(collection, key, "fields")` | Upsert documents |
| `cg_aw_edges(collection, "fields")` | Upsert edges from the `from`/`to` fields (`collection/key`) |
| `cg_aq(query, prefix, "params")` | Run a named AQL query per row |
| `cg_aq_all(query)` | Run a named AQL query, one output row per result |
| `cg_aq_json(query, out)` | Run a named AQL query, results as JSON in one field |
| `cg_sync_case` | Mirror a case into the `cases` vertex |

The bundled `cgarango`/`cgaql` commands work and are tested. To use your team's commands instead, change only those definitions. The AQL text for each named query is in `bin/changeguard_core/queries.py`. Keys must stay as in the graph conventions at the top of that file (`devices` = `cg_norm_host`, `cis` = `CI_Name`, `changes` = change ID).

## Schedules and time ranges

| Search | cron | dispatch earliest .. latest |
|---|---|---|
| CG - CI - Refresh itam_ci_lookup | `5 */4 * * *` | `-25h@h` .. `now` |
| CG - Changes - CALM feed | `*/10 * * * *` | `-12m@m` .. `-2m@m` |
| CG - Changes - HELIX CRQ feed | `3-59/10 * * * *` | `-120d@d` .. `now` (subsearch: `-12m@m` .. `-2m@m`) |
| CG - Changes - Cleanup 120 days | `17 3 * * *` | KV only |
| CG - Detect - NPT config changes | `*/5 * * * *` (`realtime_schedule = 0`) | `-10m@m` .. `-5m@m` |
| CG - Correlate - Sessions to cases | `2-59/5 * * * *` | `-4h@m` .. `now` |
| CG - AI - Intent check | `*/5 * * * *` | KV only |
| CG - Investigate - Gather alternatives | `*/5 * * * *` | KV only |
| CG - AI - Explain unplanned | `*/5 * * * *` | KV only |
| CG - Watch - Approved changes | `*/15 * * * *` | KV only |
| CG - AI - Impact check | `*/15 * * * *` | KV only |
| CG - Alert - Raise alerts with evidence | `*/5 * * * *` | KV only |
| CG - Graph - Load CIs and devices | `23 */4 * * *` | KV only |
| CG - Graph - Load CI relationships | `33 */4 * * *` | `-25h@h` .. `now` |
| CG - Graph - Load changes | `*/15 * * * *` | KV, `updated_at` in the last 20 min |
| CG - Graph - Load incidents | `*/15 * * * *` | `-20m@m` .. `now` |
| CG - Graph - Load devices, HA pairs and people | `41 * * * *` | `-2h@h` .. `now` |
| CG - Graph - Resync cases | `47 2 * * *` | KV only |
| CG - Validate - * (6 reports) | manual | `-7d@d` .. `now` |
| CG - ML - Train / Score | `23 3 * * 0` / `41 6 * * *` | KV + graph |
| CG - Demo - Seed changes / detections | manual | |

Every state search has `max_concurrent = 1`.

## Assumed field names

Check each with `` `<macro>` | head 20 | fieldsummary ``, then fix the named macro or search.

| Where | Assumed | Fix in |
|---|---|---|
| HELIX table → index | `source="*Change_Information*"`, `*Change_Approvals*`, `*Change_CI_Assoc*`, `*Incident_Data*` | `cg_helix_*`, `cg_helix_table` macros |
| Change_Information | `Infrastructure_Change_ID`, `Description`, `Detailed_Description`, `Implementation_Plan`, `Change_Request_Status`, `Change_Timing`, `Risk_Level`, `ASLOGID` (assignee login), `ASGRP`, `Scheduled_Start_Date`, `Scheduled_End_Date`, `Actual_*_Date`, `Submit_Date` | HELIX CRQ feed |
| Change_Approvals | `Approval_Status` ("Approved" / "Rejected" / other) | HELIX CRQ feed |
| Change_CI_Assoc | the CI as `CI_Name` / `CI Name` / `Request_Description02`, or an InstanceId in `CI_ReconID` / `Request_ID02` | HELIX CRQ feed |
| HELIX approval rule | approved if Approval_Status = Approved, else status Scheduled / Implementation In Progress / Completed | `cg_helix_approved` |
| CALM | `SUMMARY`, `DESCRIPTION`, `CHG_IMP_GROUP`, `IMPLEMENTER` exist (they were referenced but never populated in the old feed); `REQUEST_STATE` containing `RT` = approved | CALM feed, `cg_calm_approved` |
| Incident_Data | `Incident_Number`, `Description`, `Priority`, `Status`, `Reported_Date`/`Submit_Date`, `HPD_CI`, `ServiceCI` | Graph - Load incidents |
| Asset_* relationships | `source="*Asset*Relationship*"`, `Parent Name`, `Child Name`, `Relationship Type`; child = provider, parent = consumer | `cg_helix_ci_rel`, Graph - Load CI relationships |
| Services | `Category`/`Type` containing "service" | `cg_is_service_ci` |
| Palo Alto | TA fields `admin cmd path comment result device_name client_ip` win when present; otherwise the CSV positions of the sample (device_name = field 22, comment = field 24) | Detect search |
| Panorama / HA | Panorama = `^nspvmp`, default `nspvmp1822da01`; HA peer = `…01`↔`…02`; the `commit-all` admin is the pushing admin | `cg_is_panorama`, `cg_default_panorama`, `cg_ha_peer`, CSVs |
| CHG refs in comments | `CRQ\d{6,12}`, `CHG\d{5,12}`, `CALM-?\d{3,12}` | `cg_chg_ref_rex` |
| Identity | `global_address_lookup` keyed by `uid` = login without @domain; HELIX implementer login = the same uid | `cg_enrich_user` |
| `\| ai` (AITK 6.2) | `ai prompt="{field}"`, output in `ai_result_1` / `ai_result` / `response` | `cg_llm_aitk` |

## Setup

1. **ArangoDB.** Run `python3 arango/bootstrap.py` with `CG_ARANGO_URL`, `CG_ARANGO_USER`, `CG_ARANGO_PASSWORD` and `CG_ARANGO_DB` set.
2. **Build and install.** Run `./build.sh` (it vendors `splunk-sdk`) and install `dist/changeguard-0.1.0.tgz` on the search head. Deploy `indexes.conf` to the indexers as well. Don't install `changeguard_dev_stubs` in production.
3. **Share the existing lookups** with the app: `itam_ci_lookup`, `roboID.csv` and `global_address_lookup` must be readable from the `changeguard` app (global sharing).
4. **Arango connection.** Create `local/changeguard.conf` with an `[arango]` stanza containing `url`, `database` and `username`. Then store the password:
   ```
   curl -k -u admin https://sh:8089/servicesNS/nobody/changeguard/storage/passwords -d realm=changeguard -d name=<username> -d password=...
   ```
   The search owner needs `list_storage_passwords`.
5. **LLM.** Confirm `cg_llm_aitk` against a working AITK 6.2 `| ai` search. Until then, set `cg_llm` to `` `cg_llm_mock($prompt_field$, $task$)` ``.
6. **Disable the old `itam_ci_lookup` refresh**; `CG - CI - Refresh itam_ci_lookup` replaces it.
7. **First full load.** Run `CG - Changes - HELIX CRQ feed` once with the subsearch's `earliest=-120d@d`, and `CG - Graph - Load changes` once without its `where` line.
8. **Check the data quality** with the `CG - Validate - *` reports (CI match rate, change coverage, verdicts, feed health, identity) before trusting the alerts. Then enable email/webhook on `CG - Alert`.

## Demo runbook (about 5 minutes, offline with the mock LLM)

```bash
python3 arango/seed_demo.py --reset
```
Then, within about 30 minutes (the demo sessions end 47–57 minutes before the seed, and a session is picked up while it is 30–90 minutes old), run these in Splunk:
```
| savedsearch "STUB - Seed itam_ci_lookup"            (dev stub app; once)
| savedsearch "CG - Demo - Seed changes"
| savedsearch "CG - Demo - Seed detections"
| savedsearch "CG - Graph - Load CIs and devices"
| savedsearch "CG - Graph - Load changes"
| savedsearch "CG - Correlate - Sessions to cases"
| savedsearch "CG - AI - Intent check"
| savedsearch "CG - Investigate - Gather alternatives"
| savedsearch "CG - AI - Explain unplanned"
| savedsearch "CG - Watch - Approved changes"
| savedsearch "CG - AI - Impact check"
| savedsearch "CG - Alert - Raise alerts with evidence"
```
Verified result:

| Session | Verdict |
|---|---|
| Panorama `usera` → `nspnfp4aherb01/02`, comment `CRQ000001001` | `COMPLIANT_WATCH` via push target, score 15 → `COMPLIANT` after 72h |
| Local edit on `nspnfp4aherb02` by `usera` | `COMPLIANT_WATCH` via HA peer (CHG raised on `…01`) |
| `nsprtr-mel-01` by `userb`, no CHG (one 10 days old) | `UNPLANNED_CHANGE` (high), without calling the LLM |
| `nsprtr-syd-02` by `svc_netauto` (roboID) | `UNPLANNED_CHANGE` (medium), via the AI |
| Panorama `userc` → `nspvfp1822da01/02`, also adds `allow-any-temp` | `IMPLEMENTATION_DEVIATION` |
| Panorama `userd` → `nspnfp7perb01/02`, CALM-1004 | `POTENTIAL_FAILED_CHANGE`: P2 *Payments API* incident 2 hops downstream, 25 minutes later |
| FTD `nspftd-bne-09` (not in itam_ci_lookup) | `UNKNOWN_CI` (review) |

Also verified:
- An engineer's in-window CHG on another device is accepted as `AUTHORISED_OTHER_CHG`, but only from the graph's candidate list.
- A rollback session 10 minutes after a compliant push scores 0.6 and becomes `POTENTIAL_FAILED_CHANGE`.

## Agent (scenarios 02 and 05)

```bash
pip install -r mcp_server/requirements.txt
CG_ARANGO_URL=... CG_ARANGO_USER=... CG_ARANGO_PASSWORD=... python3 mcp_server/server.py   # stdio
python3 mcp_server/server.py --transport streamable-http --port 8765
```
- The graph tools need only Arango credentials, because every stage mirrors the case into the `cases` vertex.
- `run_spl` needs `CG_SPLUNK_URL` + `CG_SPLUNK_TOKEN`. It refuses writing commands (`collect`, `outputlookup`, `delete`, `map`, `rest`, `ai`, macros and more).
- Where Splunk tokens aren't allowed (Forge), use the Splunk MCP Server's own search tool instead.
- Tool definitions: `agent/tools.json`. Instructions: `agent/system_prompt.md`.

## Tests

```bash
pip install pytest splunk-sdk mcp
pytest tests
CG_ARANGO_IT=1 CG_ARANGO_URL=http://127.0.0.1:8529 CG_ARANGO_PASSWORD=pw CG_ARANGO_DB=cg_it pytest tests
```

## Known limits

- **Values aren't logged.** Default PAN-OS syslog and IOS `CONFIG_I` don't carry before/after values. The intent check judges by object names (xpaths), and IOS needs `archive / log config` for commands. Without them, a CHG-matched session goes straight to the watch, marked "intent cannot be checked".
- **FTD audit lines come from the FMC host.** The FTD device that changed isn't in the log, so CI matching is against the FMC.
- **Follow-up detection compares each session only with the next session** on the same device.
- **Deletions in HELIX** (relationships, CHG-CI links) aren't removed from the graph.
- **`cg_time` parses text dates in the search owner's timezone.** Set the owner to the HELIX database's timezone.
- **Scenario 06 needs history.** `fit` needs closed cases with both outcomes.
