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
    """Get a ChangeGuard case (verdict, reasons, confidence, AI output) and its evidence subgraph:
    device, CIs, HA peers, matched/related changes and incidents, downstream services."""
    return tools.get_case(_client, case_id)


@server.tool()
def list_cases(status: str | None = None, verdict: str | None = None, device: str | None = None,
               since_hours: float = 168, limit: int = 25) -> list:
    """List recent cases, newest first. verdict: COMPLIANT, COMPLIANT_WATCH, AUTHORISED_OTHER_CHG,
    UNPLANNED_CHANGE, UNAPPROVED, OUT_OF_WINDOW, WRONG_IMPLEMENTER, IMPLEMENTATION_DEVIATION,
    POTENTIAL_FAILED_CHANGE, UNKNOWN_CI, NEEDS_REVIEW. status: new, intent_check, investigate, watch,
    impact_check, alert, alerted, review, closed."""
    return tools.list_cases(_client, status, verdict, device, since_hours, limit)


@server.tool()
def find_changes_near(device: str, around: str = "now", hours_before: float = 24, hours_after: float = 24) -> list:
    """Change records (CHGs) on the device's CIs, its HA peer and directly related CIs whose window overlaps
    [around - hours_before, around + hours_after]. `around` is ISO 8601 UTC, epoch seconds or 'now'."""
    return tools.find_changes_near(_client, device, around, hours_before, hours_after)


@server.tool()
def find_other_authorisations(device: str, first_seen: str, last_seen: str | None = None,
                              engineer: str | None = None, chg_refs: list[str] | None = None) -> list:
    """For a config change with no CHG on the device's own CI, find other credible authorisations:
    CHGs on the HA peer, on related CIs, the engineer's own CHGs on other CIs, CHGs raised afterwards,
    and CHG numbers mentioned in the config. `engineer` is the HELIX login id."""
    return tools.find_other_authorisations(_client, device, first_seen, last_seen, engineer, chg_refs)


@server.tool()
def find_incidents_downstream(device: str, since: str, hours: float = 72, max_hops: int = 2) -> list:
    """Incidents opened after `since` on the device's CI or on CIs/services up to max_hops downstream of it,
    ranked by score (closer, sooner and higher-priority incidents score higher)."""
    return tools.find_incidents_downstream(_client, device, since, hours, max_hops)


@server.tool()
def get_device_neighbourhood(device: str) -> dict:
    """Everything connected to a device: its CIs, HA peers, upstream and downstream CIs/services,
    changes (last 30 days, next 7), incidents (last 7 days) and ChangeGuard cases."""
    return tools.get_device_neighbourhood(_client, device)


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
