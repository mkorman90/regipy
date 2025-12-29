"""MCP server implementation for regipy."""

import argparse
import json
import logging
import os
from pathlib import Path
from typing import Any

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import TextContent, Tool

logging.basicConfig(level=logging.INFO)

from regipy.plugins.plugin import PLUGINS
from regipy.plugins.utils import run_relevant_plugins
from regipy.registry import RegistryHive

logger = logging.getLogger(__name__)

# Global state for loaded hives
_hive_directory: Path | None = None
_hives_by_type: dict[str, RegistryHive] = {}  # hive_type -> RegistryHive
_hive_paths: dict[str, str] = {}  # hive_type -> path


def _detect_and_load_hives() -> dict[str, Any]:
    """Detect and load all hive files in the configured directory."""
    if not _hive_directory or not _hive_directory.exists():
        return {"error": "No hive directory configured"}

    loaded = []
    errors = []

    for f in _hive_directory.iterdir():
        if not f.is_file() or f.name.startswith("."):
            continue
        # Skip transaction logs and other non-hive files
        if f.suffix.lower() in (".log", ".log1", ".log2", ".blf", ".regtrans-ms"):
            continue

        try:
            hive = RegistryHive(str(f))
            hive_type = hive.hive_type.upper() if hive.hive_type else "UNKNOWN"

            # Store by type (later files override earlier ones)
            _hives_by_type[hive_type] = hive
            _hive_paths[hive_type] = str(f)

            loaded.append({
                "path": str(f),
                "name": f.name,
                "type": hive_type,
            })
        except Exception as e:
            errors.append({"path": str(f), "error": str(e)})

    return {
        "directory": str(_hive_directory),
        "loaded": loaded,
        "errors": errors if errors else None,
        "available_types": list(_hives_by_type.keys()),
    }


def _get_hive_for_plugin(plugin_class) -> tuple[RegistryHive | None, str | None]:
    """Get the appropriate hive for a plugin based on its COMPATIBLE_HIVE."""
    compatible = plugin_class.COMPATIBLE_HIVE.upper() if plugin_class.COMPATIBLE_HIVE else None
    if compatible and compatible in _hives_by_type:
        return _hives_by_type[compatible], _hive_paths[compatible]
    return None, None


def _get_plugin_by_name(name: str):
    """Find a plugin class by its NAME attribute."""
    for plugin_class in PLUGINS:
        if plugin_class.NAME == name:
            return plugin_class
    return None


def list_hives() -> dict[str, Any]:
    """List available registry hive files and their types."""
    if not _hives_by_type:
        # Try to load hives if not already loaded
        result = _detect_and_load_hives()
        if "error" in result:
            return result

    return {
        "hive_directory": str(_hive_directory) if _hive_directory else None,
        "hives": [
            {"type": hive_type, "path": _hive_paths[hive_type]}
            for hive_type in sorted(_hives_by_type.keys())
        ],
    }


def list_plugins() -> list[dict[str, str]]:
    """List all available regipy plugins grouped by hive type."""
    # Group plugins by hive type
    by_type: dict[str, list[dict]] = {}
    for p in PLUGINS:
        if not p.NAME:
            continue
        hive_type = p.COMPATIBLE_HIVE.upper() if p.COMPATIBLE_HIVE else "UNKNOWN"
        if hive_type not in by_type:
            by_type[hive_type] = []
        by_type[hive_type].append({
            "name": p.NAME,
            "description": p.DESCRIPTION,
        })

    # Mark which hive types are available
    result = []
    for hive_type in sorted(by_type.keys()):
        available = hive_type in _hives_by_type
        result.append({
            "hive_type": hive_type,
            "hive_available": available,
            "plugins": by_type[hive_type],
        })

    return result


def run_plugin(plugin_name: str) -> dict[str, Any]:
    """Run a specific plugin, automatically selecting the correct hive."""
    plugin_class = _get_plugin_by_name(plugin_name)

    if not plugin_class:
        return {"error": f"Plugin '{plugin_name}' not found"}

    hive, hive_path = _get_hive_for_plugin(plugin_class)

    if not hive:
        return {
            "error": f"No compatible hive found for plugin '{plugin_name}'",
            "required_hive_type": plugin_class.COMPATIBLE_HIVE,
            "available_hive_types": list(_hives_by_type.keys()),
        }

    plugin = plugin_class(hive, as_json=True)
    plugin.run()

    return {
        "plugin": plugin_name,
        "hive_path": hive_path,
        "hive_type": hive.hive_type,
        "entries": plugin.entries,
        "entry_count": len(plugin.entries) if isinstance(plugin.entries, list) else None,
    }


def run_all_plugins() -> dict[str, Any]:
    """Run all compatible plugins on all available hives."""
    if not _hives_by_type:
        return {"error": "No hives loaded. Set REGIPY_HIVE_DIRECTORY environment variable."}

    all_results = {}

    for hive_type, hive in _hives_by_type.items():
        hive_results = run_relevant_plugins(hive, as_json=True)
        for plugin_name, entries in hive_results.items():
            all_results[plugin_name] = {
                "hive_type": hive_type,
                "hive_path": _hive_paths[hive_type],
                "entries": entries,
            }

    return {
        "hives_analyzed": list(_hives_by_type.keys()),
        "plugins_run": list(all_results.keys()),
        "results": all_results,
    }


def get_key(key_path: str, hive_type: str | None = None) -> dict[str, Any]:
    """Read a specific registry key. Optionally specify hive type, otherwise tries all."""
    if hive_type:
        hive_type = hive_type.upper()
        if hive_type not in _hives_by_type:
            return {
                "error": f"Hive type '{hive_type}' not available",
                "available_types": list(_hives_by_type.keys()),
            }
        hives_to_try = [(hive_type, _hives_by_type[hive_type])]
    else:
        hives_to_try = list(_hives_by_type.items())

    for htype, hive in hives_to_try:
        try:
            key = hive.get_key(key_path)
            values = []
            for value in key.iter_values(as_json=True):
                values.append({
                    "name": value.name,
                    "value": value.value,
                    "value_type": value.value_type,
                })

            subkeys = [sk.name for sk in key.iter_subkeys()]

            return {
                "key_path": key_path,
                "hive_type": htype,
                "hive_path": _hive_paths[htype],
                "name": key.name,
                "subkey_count": key.header.subkey_count,
                "values_count": key.header.values_count,
                "last_modified": key.header.last_modified,
                "values": values,
                "subkeys": subkeys,
            }
        except Exception:
            continue

    return {
        "error": f"Key not found: {key_path}",
        "searched_hives": [h[0] for h in hives_to_try],
    }


def search_by_timestamp(
    start_date: str | None = None,
    end_date: str | None = None,
    hive_type: str | None = None,
    limit: int = 100,
) -> dict[str, Any]:
    """Find registry keys modified within a date range across all hives."""
    from datetime import datetime

    from regipy.utils import convert_wintime

    start_dt = datetime.fromisoformat(start_date) if start_date else None
    end_dt = datetime.fromisoformat(end_date) if end_date else None

    if hive_type:
        hive_type = hive_type.upper()
        if hive_type not in _hives_by_type:
            return {"error": f"Hive type '{hive_type}' not available"}
        hives_to_search = [(hive_type, _hives_by_type[hive_type])]
    else:
        hives_to_search = list(_hives_by_type.items())

    matches = []
    for htype, hive in hives_to_search:
        for subkey in hive.recurse_subkeys(as_json=True):
            if len(matches) >= limit:
                break

            modified = convert_wintime(subkey.timestamp)
            if modified:
                if start_dt and modified < start_dt:
                    continue
                if end_dt and modified > end_dt:
                    continue

                matches.append({
                    "hive_type": htype,
                    "path": subkey.path,
                    "last_modified": modified.isoformat(),
                    "values_count": subkey.values_count,
                })

        if len(matches) >= limit:
            break

    return {
        "start_date": start_date,
        "end_date": end_date,
        "hives_searched": [h[0] for h in hives_to_search],
        "matches": matches,
        "match_count": len(matches),
        "limit_reached": len(matches) >= limit,
    }


# Tool definitions for MCP - simplified without requiring hive_path
TOOLS = [
    Tool(
        name="list_hives",
        description="List available Windows Registry hive files and their detected types (SYSTEM, SOFTWARE, NTUSER, SAM, SECURITY, etc.)",
        inputSchema={
            "type": "object",
            "properties": {},
            "required": [],
        },
    ),
    Tool(
        name="list_plugins",
        description="List all available forensic analysis plugins grouped by hive type. Shows which plugins can run based on available hives.",
        inputSchema={
            "type": "object",
            "properties": {},
            "required": [],
        },
    ),
    Tool(
        name="run_plugin",
        description="Run a specific forensic plugin. The correct hive is automatically selected based on the plugin's requirements.",
        inputSchema={
            "type": "object",
            "properties": {
                "plugin_name": {
                    "type": "string",
                    "description": "Name of the plugin to run (e.g., 'shimcache', 'usbstor_plugin', 'timezone_data', 'typed_urls')",
                },
            },
            "required": ["plugin_name"],
        },
    ),
    Tool(
        name="run_all_plugins",
        description="Run all compatible forensic plugins on all available hives to get a complete forensic picture of the system.",
        inputSchema={
            "type": "object",
            "properties": {},
            "required": [],
        },
    ),
    Tool(
        name="get_key",
        description="Read a specific registry key path and retrieve its values and subkeys",
        inputSchema={
            "type": "object",
            "properties": {
                "key_path": {
                    "type": "string",
                    "description": "Registry key path (e.g., '\\ControlSet001\\Control\\ComputerName\\ComputerName')",
                },
                "hive_type": {
                    "type": "string",
                    "description": "Optional: specific hive type to search (SYSTEM, SOFTWARE, NTUSER, SAM, SECURITY). If not specified, searches all hives.",
                },
            },
            "required": ["key_path"],
        },
    ),
    Tool(
        name="search_by_timestamp",
        description="Find registry keys that were modified within a specific date range",
        inputSchema={
            "type": "object",
            "properties": {
                "start_date": {
                    "type": "string",
                    "description": "Start date in ISO format (e.g., '2024-01-01T00:00:00')",
                },
                "end_date": {
                    "type": "string",
                    "description": "End date in ISO format (e.g., '2024-12-31T23:59:59')",
                },
                "hive_type": {
                    "type": "string",
                    "description": "Optional: specific hive type to search (SYSTEM, SOFTWARE, NTUSER, SAM, SECURITY)",
                },
                "limit": {
                    "type": "integer",
                    "description": "Maximum number of results to return (default: 100)",
                    "default": 100,
                },
            },
            "required": [],
        },
    ),
]


async def handle_tool_call(name: str, arguments: dict[str, Any]) -> str:
    """Handle a tool call and return JSON result."""
    handlers = {
        "list_hives": lambda: list_hives(),
        "list_plugins": lambda: list_plugins(),
        "run_plugin": lambda: run_plugin(arguments["plugin_name"]),
        "run_all_plugins": lambda: run_all_plugins(),
        "get_key": lambda: get_key(arguments["key_path"], arguments.get("hive_type")),
        "search_by_timestamp": lambda: search_by_timestamp(
            arguments.get("start_date"),
            arguments.get("end_date"),
            arguments.get("hive_type"),
            arguments.get("limit", 100),
        ),
    }

    handler = handlers.get(name)
    if not handler:
        return json.dumps({"error": f"Unknown tool: {name}"})

    try:
        result = handler()
        return json.dumps(result, indent=2, default=str)
    except Exception as e:
        logger.exception(f"Error executing tool {name}")
        return json.dumps({"error": str(e)})


def create_server() -> Server:
    """Create and configure the MCP server."""
    server = Server("regipy-mcp")

    @server.list_tools()
    async def list_tools():
        return TOOLS

    @server.call_tool()
    async def call_tool(name: str, arguments: dict[str, Any]):
        result = await handle_tool_call(name, arguments)
        return [TextContent(type="text", text=result)]

    return server


async def run_stdio_server():
    """Run the MCP server with stdio transport."""
    server = create_server()
    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, server.create_initialization_options())


def run_sse_server(host: str = "0.0.0.0", port: int = 8000):
    """Run the MCP server with SSE transport."""
    import uvicorn
    from mcp.server.sse import SseServerTransport
    from starlette.applications import Starlette
    from starlette.routing import Mount, Route

    server = create_server()
    sse = SseServerTransport("/messages/")

    async def handle_sse(request):
        async with sse.connect_sse(
            request.scope, request.receive, request._send
        ) as streams:
            await server.run(
                streams[0], streams[1], server.create_initialization_options()
            )

    app = Starlette(
        debug=True,
        routes=[
            Route("/sse", endpoint=handle_sse),
            Mount("/messages/", app=sse.handle_post_message),
        ],
    )

    logger.info(f"Starting SSE server on {host}:{port}")
    uvicorn.run(app, host=host, port=port)


def main():
    """Entry point for the MCP server."""
    import asyncio

    parser = argparse.ArgumentParser(description="Regipy MCP Server")
    parser.add_argument(
        "--transport",
        choices=["stdio", "sse"],
        default="stdio",
        help="Transport type (default: stdio)",
    )
    parser.add_argument(
        "--host",
        default="0.0.0.0",
        help="Host for SSE server (default: 0.0.0.0)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8000,
        help="Port for SSE server (default: 8000)",
    )
    args = parser.parse_args()

    # Configure hive directory from environment
    global _hive_directory
    hive_dir = os.environ.get("REGIPY_HIVE_DIRECTORY")
    if hive_dir:
        _hive_directory = Path(hive_dir)
        logger.info(f"Hive directory: {_hive_directory}")
        # Pre-load hives
        result = _detect_and_load_hives()
        logger.info(f"Loaded hives: {result.get('available_types', [])}")

    if args.transport == "sse":
        run_sse_server(args.host, args.port)
    else:
        asyncio.run(run_stdio_server())


if __name__ == "__main__":
    main()
