#!/usr/bin/env python3
"""
Regipy MCP Server - Windows Registry Analysis for Claude Desktop

This server enables Claude to analyze Windows registry hives and answer
forensic questions about system configuration, user activity, and persistence.
"""

import os
import sys
from pathlib import Path
from typing import Optional
from datetime import datetime
import logging

from mcp.server.fastmcp import FastMCP
from regipy.registry import RegistryHive
from regipy.plugins.plugin import PLUGINS
from regipy.plugins.utils import run_relevant_plugins
from regipy.hive_types import (
    SYSTEM_HIVE_TYPE,
    SOFTWARE_HIVE_TYPE,
    NTUSER_HIVE_TYPE,
    SAM_HIVE_TYPE,
    SECURITY_HIVE_TYPE,
    AMCACHE_HIVE_TYPE,
    USRCLASS_HIVE_TYPE,
    BCD_HIVE_TYPE,
)

# Import all plugins so they auto-register via __init_subclass__
import regipy.plugins  # noqa

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize MCP server
mcp = FastMCP("regipy-forensics")

# Global state for loaded hives
_loaded_hives: dict[str, RegistryHive] = {}
_hive_directory: Optional[str] = None


def _load_hives_from_directory(directory: str) -> dict[str, RegistryHive]:
    """
    Auto-discover and load all registry hives from a directory.

    Skips transaction logs (.log, .log1, .log2) and only loads actual hive files.
    Returns a dict mapping file paths to RegistryHive objects.
    """
    hives = {}
    directory_path = Path(directory)

    if not directory_path.exists():
        logger.error(f"Hive directory does not exist: {directory}")
        return hives

    # Common registry hive file patterns
    skip_extensions = {'.log', '.log1', '.log2', '.sav', '.regtrans-ms', '.blf', '.tmp'}

    for file_path in directory_path.iterdir():
        if not file_path.is_file():
            continue

        # Skip transaction logs and backup files
        if file_path.suffix.lower() in skip_extensions:
            continue

        try:
            logger.info(f"Attempting to load hive: {file_path}")
            hive = RegistryHive(str(file_path))
            hives[str(file_path)] = hive
            logger.info(f"Successfully loaded {file_path.name} as {hive.hive_type}")
        except Exception as e:
            logger.warning(f"Failed to load {file_path}: {e}")
            continue

    return hives


def _initialize_hives(hive_dir: Optional[str] = None):
    """
    Initialize hives from the specified directory or environment variable.

    Priority:
    1. Command-line argument (hive_dir parameter)
    2. REGIPY_HIVE_DIRECTORY environment variable
    3. If neither is set, hives must be loaded manually via set_hive_directory tool
    """
    global _loaded_hives, _hive_directory

    # Try parameter first, then environment variable
    _hive_directory = hive_dir or os.getenv("REGIPY_HIVE_DIRECTORY")

    if not _hive_directory:
        logger.warning("No hive directory specified. Use set_hive_directory tool or pass --hives-dir argument.")
        return

    logger.info(f"Loading hives from: {_hive_directory}")
    _loaded_hives = _load_hives_from_directory(_hive_directory)
    logger.info(f"Loaded {len(_loaded_hives)} hive(s)")


def _get_hives_by_type(hive_type: str) -> list[tuple[str, RegistryHive]]:
    """Get all loaded hives of a specific type."""
    return [(path, hive) for path, hive in _loaded_hives.items()
            if hive.hive_type == hive_type]


def _serialize_datetime(obj):
    """Convert datetime objects to ISO format strings."""
    if isinstance(obj, datetime):
        return obj.isoformat()
    return obj


def _serialize_plugin_results(results):
    """Recursively serialize plugin results, converting datetimes to strings."""
    if isinstance(results, dict):
        return {k: _serialize_plugin_results(v) for k, v in results.items()}
    elif isinstance(results, list):
        return [_serialize_plugin_results(item) for item in results]
    elif isinstance(results, datetime):
        return results.isoformat()
    else:
        return results


@mcp.tool()
def set_hive_directory(directory: str) -> str:
    """
    Set the directory containing registry hives and load them.

    Args:
        directory: Path to directory containing registry hive files

    Returns:
        Summary of loaded hives
    """
    global _loaded_hives, _hive_directory

    _hive_directory = directory
    _loaded_hives = _load_hives_from_directory(directory)

    if not _loaded_hives:
        return f"No valid registry hives found in {directory}"

    # Group by hive type
    by_type = {}
    for path, hive in _loaded_hives.items():
        hive_type = hive.hive_type or "unknown"
        if hive_type not in by_type:
            by_type[hive_type] = []
        by_type[hive_type].append(Path(path).name)

    result = [f"Loaded {len(_loaded_hives)} hive(s) from {directory}:\n"]
    for hive_type, files in sorted(by_type.items()):
        result.append(f"\n{hive_type}:")
        for file in files:
            result.append(f"  - {file}")

    return "\n".join(result)


@mcp.tool()
def list_available_hives() -> str:
    """
    List all currently loaded registry hives and their types.

    Returns:
        Summary of available hives grouped by type
    """
    if not _loaded_hives:
        return "No hives loaded. Use set_hive_directory to load hives."

    by_type = {}
    for path, hive in _loaded_hives.items():
        hive_type = hive.hive_type or "unknown"
        if hive_type not in by_type:
            by_type[hive_type] = []
        by_type[hive_type].append({
            'filename': Path(path).name,
            'path': path,
            'root_key': hive.root.name if hive.root else 'N/A'
        })

    result = [f"Available hives ({len(_loaded_hives)} total):\n"]
    for hive_type, hives in sorted(by_type.items()):
        result.append(f"\n{hive_type} ({len(hives)} file(s)):")
        for hive_info in hives:
            result.append(f"  - {hive_info['filename']}")

    return "\n".join(result)


@mcp.tool()
def list_available_plugins(hive_type: Optional[str] = None) -> str:
    """
    List all available regipy plugins, optionally filtered by hive type.
    Shows which plugins can run based on currently loaded hives.

    Args:
        hive_type: Optional hive type to filter by (e.g., 'SYSTEM', 'SOFTWARE', 'NTUSER')

    Returns:
        List of plugins with descriptions and compatibility info
    """
    # Get loaded hive types
    loaded_types = set(hive.hive_type for hive in _loaded_hives.values())

    # Group plugins by hive type
    plugins_by_type = {}
    for plugin_class in PLUGINS:
        compat_hive = plugin_class.COMPATIBLE_HIVE or "unknown"

        # Filter by requested hive type if specified
        if hive_type and compat_hive != hive_type:
            continue

        if compat_hive not in plugins_by_type:
            plugins_by_type[compat_hive] = []

        can_run = compat_hive in loaded_types
        plugins_by_type[compat_hive].append({
            'name': plugin_class.NAME,
            'description': plugin_class.DESCRIPTION or 'No description',
            'can_run': can_run
        })

    # Format output
    result = []
    total_plugins = sum(len(plugins) for plugins in plugins_by_type.values())
    runnable = sum(1 for plugins in plugins_by_type.values()
                   for p in plugins if p['can_run'])

    result.append(f"Total plugins: {total_plugins} ({runnable} can run with loaded hives)\n")

    for hive_type_name, plugins in sorted(plugins_by_type.items()):
        can_run_count = sum(1 for p in plugins if p['can_run'])
        status = "✓ AVAILABLE" if can_run_count > 0 else "✗ No hive loaded"
        result.append(f"\n{hive_type_name} ({len(plugins)} plugins) - {status}:")

        for plugin in sorted(plugins, key=lambda x: x['name']):
            status_icon = "✓" if plugin['can_run'] else "✗"
            result.append(f"  {status_icon} {plugin['name']}")
            result.append(f"      {plugin['description']}")

    return "\n".join(result)


@mcp.tool()
def run_plugin(plugin_name: str) -> dict:
    """
    Run a specific regipy plugin on the appropriate hive.

    The plugin will automatically select the correct hive based on its
    COMPATIBLE_HIVE setting. For example, 'computer_name' will run on
    the SYSTEM hive, 'typed_urls' will run on NTUSER hives.

    Args:
        plugin_name: Name of the plugin to run (e.g., 'computer_name', 'timezone_data')

    Returns:
        Plugin results as a dictionary
    """
    if not _loaded_hives:
        return {"error": "No hives loaded. Use set_hive_directory first."}

    # Find the plugin class
    plugin_class = None
    for p in PLUGINS:
        if p.NAME == plugin_name:
            plugin_class = p
            break

    if not plugin_class:
        available = [p.NAME for p in PLUGINS]
        return {
            "error": f"Plugin '{plugin_name}' not found",
            "available_plugins": sorted(available)
        }

    # Get hives of the compatible type
    compatible_hives = _get_hives_by_type(plugin_class.COMPATIBLE_HIVE)

    if not compatible_hives:
        return {
            "error": f"No {plugin_class.COMPATIBLE_HIVE} hive loaded",
            "required_hive_type": plugin_class.COMPATIBLE_HIVE
        }

    # Run plugin on all compatible hives
    all_results = {}
    for path, hive in compatible_hives:
        try:
            plugin = plugin_class(hive, as_json=True)
            if plugin.can_run():
                plugin.run()
                results = _serialize_plugin_results(plugin.entries)
                all_results[Path(path).name] = results
        except Exception as e:
            logger.error(f"Error running {plugin_name} on {path}: {e}")
            all_results[Path(path).name] = {"error": str(e)}

    return {
        "plugin": plugin_name,
        "description": plugin_class.DESCRIPTION,
        "hive_type": plugin_class.COMPATIBLE_HIVE,
        "results": all_results
    }


@mcp.tool()
def run_all_plugins_for_hive(hive_type: str) -> dict:
    """
    Run all compatible plugins for a specific hive type.

    Args:
        hive_type: Type of hive (e.g., 'SYSTEM', 'SOFTWARE', 'NTUSER', 'SAM')

    Returns:
        Combined results from all plugins
    """
    if not _loaded_hives:
        return {"error": "No hives loaded. Use set_hive_directory first."}

    compatible_hives = _get_hives_by_type(hive_type)

    if not compatible_hives:
        available_types = set(h.hive_type for h in _loaded_hives.values())
        return {
            "error": f"No {hive_type} hive loaded",
            "available_types": sorted(available_types)
        }

    # Run all plugins on all compatible hives
    all_results = {}
    for path, hive in compatible_hives:
        try:
            results = run_relevant_plugins(hive, as_json=True)
            serialized_results = _serialize_plugin_results(results)
            all_results[Path(path).name] = serialized_results
        except Exception as e:
            logger.error(f"Error running plugins on {path}: {e}")
            all_results[Path(path).name] = {"error": str(e)}

    return {
        "hive_type": hive_type,
        "files_analyzed": len(all_results),
        "results": all_results
    }


@mcp.tool()
def answer_forensic_question(question: str) -> dict:
    """
    Answer common forensic questions by automatically running relevant plugins.

    This is a high-level tool that maps questions to the appropriate plugins.

    Supported questions include:
    - What is the hostname/computer name?
    - What is the timezone?
    - What are the persistence mechanisms?
    - What programs are installed?
    - What USB devices were connected?
    - What is the Windows version?
    - What services are configured?
    - What are the user accounts?

    Args:
        question: Natural language forensic question

    Returns:
        Relevant plugin results answering the question
    """
    if not _loaded_hives:
        return {"error": "No hives loaded. Use set_hive_directory first."}

    question_lower = question.lower()

    # Map questions to plugins
    plugin_mapping = {
        'hostname': ['computer_name', 'host_domain_name'],
        'computer name': ['computer_name'],
        'timezone': ['timezone_data'],
        'persistence': ['software_plugin', 'ntuser_persistence'],
        'installed': ['installed_programs_software', 'installed_programs_ntuser'],
        'usb': ['usbstor_plugin', 'usb_devices'],
        'windows version': ['winver_plugin'],
        'os version': ['winver_plugin'],
        'services': ['services'],
        'user account': ['samparse'],
        'network': ['network_data', 'networklist'],
        'shimcache': ['shimcache'],
        'execution': ['shimcache', 'amcache', 'user_assist'],
    }

    # Find matching plugins
    relevant_plugins = []
    for keyword, plugins in plugin_mapping.items():
        if keyword in question_lower:
            relevant_plugins.extend(plugins)

    if not relevant_plugins:
        return {
            "question": question,
            "suggestion": "Try asking: What is the hostname? What is the timezone? What are the persistence methods?",
            "available_categories": list(plugin_mapping.keys())
        }

    # Remove duplicates while preserving order
    relevant_plugins = list(dict.fromkeys(relevant_plugins))

    # Run all relevant plugins
    results = {}
    for plugin_name in relevant_plugins:
        plugin_result = run_plugin(plugin_name)
        if "error" not in plugin_result:
            results[plugin_name] = plugin_result

    return {
        "question": question,
        "plugins_used": relevant_plugins,
        "results": results
    }


@mcp.tool()
def get_registry_key(key_path: str, hive_type: Optional[str] = None) -> dict:
    """
    Get a specific registry key and its values.

    Args:
        key_path: Path to the registry key (e.g., 'ControlSet001\\Control\\TimeZoneInformation')
        hive_type: Optional hive type to search in. If not specified, searches all loaded hives.

    Returns:
        Key information including values and subkeys
    """
    if not _loaded_hives:
        return {"error": "No hives loaded. Use set_hive_directory first."}

    # Determine which hives to search
    if hive_type:
        hives_to_search = _get_hives_by_type(hive_type)
    else:
        hives_to_search = list(_loaded_hives.items())

    if not hives_to_search:
        return {"error": f"No hives available for search"}

    results = {}
    for path, hive in hives_to_search:
        try:
            subkey = hive.get_key(key_path)
            if subkey:
                results[Path(path).name] = {
                    "found": True,
                    "path": subkey.path,
                    "timestamp": _serialize_datetime(subkey.timestamp),
                    "values": [
                        {
                            "name": v.name,
                            "value": v.value,
                            "type": v.value_type
                        }
                        for v in (subkey.values or [])
                    ],
                    "subkey_count": len(list(subkey.iter_subkeys())) if hasattr(subkey, 'iter_subkeys') else 0
                }
        except Exception as e:
            results[Path(path).name] = {"found": False, "error": str(e)}

    if not any(r.get("found") for r in results.values()):
        return {
            "key_path": key_path,
            "found": False,
            "searched_hives": [Path(p).name for p, _ in hives_to_search]
        }

    return {
        "key_path": key_path,
        "results": results
    }


if __name__ == "__main__":
    import argparse

    # Parse command-line arguments
    parser = argparse.ArgumentParser(description="Regipy MCP Server - Windows Registry Analysis")
    parser.add_argument(
        "--hives-dir",
        type=str,
        help="Directory containing registry hive files (default: from REGIPY_HIVE_DIRECTORY env var)"
    )
    args = parser.parse_args()

    # Initialize hives with command-line argument or environment variable
    _initialize_hives(args.hives_dir)

    # Run the MCP server
    mcp.run()
else:
    # When imported as a module, initialize from environment variable
    _initialize_hives()
