"""Start the real local MCP process and use the official client protocol."""

import asyncio
import json
import sys

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from app import inventory, security, storage
from .test_inventory_diagnostics import valid_host_key


def test_local_mcp_protocol_and_denied_commands(configured):
    host_id = inventory.save_host(
        "mcp-test", "172.20.1.30", 22, None, None, valid_host_key()
    )

    async def scenario():
        params = StdioServerParameters(
            command=sys.executable,
            args=["-m", "app.mcp_server"],
            env={"DIAG_DATA_DIR": str(storage.DATA)},
        )
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                tools = await session.list_tools()
                assert {t.name for t in tools.tools} == {
                    "list_linux_hosts",
                    "diagnose_linux_host",
                }
                hosts = await session.call_tool("list_linux_hosts", {})
                encoded = " ".join(c.text for c in hosts.content if hasattr(c, "text"))
                assert (
                    "mcp-test" in encoded
                    and "host_key" not in encoded
                    and "address" not in encoded
                )
                denied = await session.call_tool(
                    "diagnose_linux_host", {"host_id": host_id, "action": "cpu; reboot"}
                )
                assert (
                    denied.isError
                    and "Unsupported diagnostic request"
                    in json.dumps(denied.model_dump(), default=str)
                )

    asyncio.run(scenario())
    assert any("failed" in row["action"] for row in security.recent_audit())
