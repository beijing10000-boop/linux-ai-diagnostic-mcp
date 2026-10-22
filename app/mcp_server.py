"""Local stdio MCP adapter; intentionally has no publicly exposed HTTP listener.

Only invoke this process from a trusted OS/service account. It never accepts a
free-form command or a network target supplied by an LLM.
"""

from mcp.server.fastmcp import FastMCP
from . import diagnostics, inventory, security

mcp = FastMCP(
    "Linux AI Diagnostic",
    instructions=(
        "Execute read-only diagnostics against registered Linux hosts. "
        "Only the enumerated operations are available. Never request arbitrary commands."
    ),
)


@mcp.tool()
def list_linux_hosts() -> list[dict]:
    """List registered Linux hosts (IDs and display names only)."""
    return [
        {
            "id": h["id"],
            "name": h["name"],
            "group_id": h["group_id"],
            "proxy_id": h["proxy_id"],
        }
        for h in inventory.list_rows("hosts")
    ]


@mcp.tool()
def diagnose_linux_host(host_id: int, action: str, service: str | None = None) -> dict:
    """Read-only Linux diagnosis: cpu, memory, disk, network, sockets,
    processes or service <validated service name>. No arbitrary shell access."""
    return diagnostics.run(host_id, action, service, "mcp-stdio")


if __name__ == "__main__":
    security.init()
    inventory.initialize()
    diagnostics.initialize()
    mcp.run(transport="stdio")
