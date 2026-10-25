#!/usr/bin/env python3
"""ChangeGuard MCP server (scenarios 02 and 05): exposes the graph questions as tools for an agent
(Agent Launchpad, Forge, Claude Desktop, ...).

    pip install -r mcp_server/requirements.txt
    export CG_ARANGO_URL=... CG_ARANGO_USER=... CG_ARANGO_PASSWORD=...
    python3 mcp_server/server.py                              # stdio
    python3 mcp_server/server.py --transport streamable-http --port 8765
"""

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import tools  # noqa: E402
from changeguard_core.config import client_from_env  # noqa: E402

try:  # MCP Python SDK 2.x
    from mcp.server.mcpserver import MCPServer as Server
except ImportError:  # 1.x
    from mcp.server.fastmcp import FastMCP as Server

with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "agent", "system_prompt.md")) as handle:
    INSTRUCTIONS = handle.read()

server = Server("changeguard", instructions=INSTRUCTIONS)
_client = client_from_env()


@server.tool()
def get_case(case_id: str) -> dict:
    """Get a ChangeGuard case (verdict, reasons, confidence, AI output, matched and related changes) and its
    evidence subgraph: session device and push targets, CIs, HA peers, downstream CIs/services, incidents."""
    return tools.get_case(_client, case_id)


@server.tool()
def list_cases(status: str | None = None, verdict: str | None = None, platform: str | None = None,
               device: str | None = None, since_hours: float = 168, limit: int = 25) -> list:
    """List recent cases, newest first. verdict: COMPLIANT, COMPLIANT_WATCH, AUTHORISED_OTHER_CHG,
    UNPLANNED_CHANGE, UNAPPROVED, OUT_OF_WINDOW, WRONG_IMPLEMENTER, IMPLEMENTATION_DEVIATION,
    POTENTIAL_FAILED_CHANGE, UNKNOWN_CI, NEEDS_REVIEW. status: new, intent_check, investigate, explain,
    watch, impact_check, alert, alerted, review, closed. platform: paloalto, cisco_ios, cisco_ftd."""
    return tools.list_cases(_client, status, verdict, platform, device, since_hours, limit)


@server.tool()
def find_related_changes(device: str, around: str = "now", hours_before: float = 48, hours_after: float = 24) -> list:
    """Change records (CRQ/CALM) on a device, its HA peers and directly related CIs whose window overlaps
    [around - hours_before, around + hours_after]. `around` is ISO 8601 UTC, epoch seconds or 'now'."""
    return tools.find_related_changes(_client, device, around, hours_before, hours_after)


@server.tool()
def find_other_authorisations(devices: list[str], first_seen: str, last_seen: str | None = None,
                              engineer: str | None = None, chg_refs: list[str] | None = None) -> list:
    """For a change session with no in-window CHG: CHGs near the time on its devices, on HA peers, on
    related CIs, the engineer's CHGs on other devices, CHGs raised afterwards, CHG numbers in the comment."""
    return tools.find_other_authorisations(_client, devices, first_seen, last_seen, engineer, chg_refs)


@server.tool()
def find_incidents_downstream(devices: list[str], since: str, hours: float = 72, max_hops: int = 2) -> list:
    """Incidents opened after `since` on the devices' CIs or on CIs/services up to max_hops downstream,
    ranked by score (closer, sooner and higher-priority incidents score higher)."""
    return tools.find_incidents_downstream(_client, devices, since, hours, max_hops)


@server.tool()
def get_device_neighbourhood(device: str) -> dict:
    """Everything connected to a device: its CIs, HA peers, upstream and downstream CIs/services,
    changes (last 30 days, next 7), incidents (last 7 days) and ChangeGuard cases."""
    return tools.get_device_neighbourhood(_client, device)


@server.tool()
def run_spl(query: str, earliest: str = "-24h", latest: str = "now", max_rows: int = 200) -> dict:
    """Run a read-only SPL search, e.g. `| inputlookup cg_cases_lookup | where platform="paloalto"` or
    `index=changeguard_detect session_device=nspvmp1822da01`. Writing commands and macros are refused."""
    return tools.run_spl(query, earliest, latest, max_rows)


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--transport", default="stdio", choices=["stdio", "streamable-http", "sse"])
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    args = parser.parse_args()
    if args.transport == "stdio":
        server.run("stdio")
        return
    if hasattr(server, "settings"):  # 1.x reads host/port from settings
        server.settings.host, server.settings.port = args.host, args.port
        server.run(args.transport)
    else:
        server.run(args.transport, host=args.host, port=args.port)


if __name__ == "__main__":
    main()
