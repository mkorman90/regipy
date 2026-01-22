# CLAUDE.md - regipy

> OS-independent Python library for parsing offline Windows registry hives

## Project Overview

regipy is a forensic-focused library for parsing Windows registry hive files (files with REGF header). It's designed for digital forensics and incident response (DFIR) workflows, providing both a Python API and CLI tools.

### Core Capabilities

- Parse offline registry hives without Windows dependencies
- Recursive traversal of keys and values from any path
- Transaction log recovery (dirty hive reconstruction)
- Hive comparison/diffing (like RegShot)
- Extensible plugin system for artifact extraction
- Timeline generation for forensic analysis

## Architecture

```
regipy/
├── registry.py          # Core RegistryHive class - entry point for all parsing
├── structs.py           # Binary struct definitions (REGF header, NK/VK records, etc.)
├── hive_types.py        # Hive type constants (NTUSER, SYSTEM, SOFTWARE, SAM, etc.)
├── exceptions.py        # Custom exceptions (RegistryKeyNotFoundException, etc.)
├── utils.py             # Helpers: convert_wintime, boomerang_stream, etc.
├── recovery.py          # Transaction log application logic
├── plugins/
│   ├── plugin.py        # Base Plugin class - all plugins inherit from this
│   ├── utils.py         # run_relevant_plugins() - auto-detects hive and runs matching plugins
│   ├── ntuser/          # NTUSER.DAT plugins (persistence, typed_urls, user_assist, etc.)
│   ├── system/          # SYSTEM hive plugins (computer_name, shimcache, bam, bootkey, etc.)
│   ├── software/        # SOFTWARE hive plugins (installed_programs, profilelist, etc.)
│   ├── sam/             # SAM hive plugins (local_sid, etc.)
│   ├── security/        # SECURITY hive plugins
│   ├── amcache/         # Amcache.hve plugins
│   └── usrclass/        # UsrClass.dat plugins (shellbags)
├── cli.py               # CLI entry points
regipy_tests/
├── data/                # Test hive files (often .xz compressed)
├── validation/          # ValidationCase framework for plugin testing
docs/
└── PLUGINS.md           # Plugin development guide
```

## Key Classes and Patterns

### RegistryHive

The main entry point. Handles hive parsing, key navigation, and value retrieval.

```python
from regipy.registry import RegistryHive

reg = RegistryHive('/path/to/NTUSER.DAT')

# Navigate to a key
key = reg.get_key(r'Software\Microsoft\Windows\CurrentVersion\Run')

# Get values
values = key.get_values(as_json=True)

# Iterate subkeys
for sk in key.iter_subkeys():
    print(sk.name, sk.header.last_modified)

# Recursive traversal
for entry in reg.recurse_subkeys(as_json=True):
    print(entry)

# Control sets (SYSTEM hive)
for path in reg.get_control_sets(r'Control\ComputerName\ComputerName'):
    # Yields: ControlSet001\Control\..., ControlSet002\Control\..., etc.
    pass
```

### Plugin System

Plugins inherit from `Plugin` base class and define:
- `NAME`: Snake_case identifier
- `DESCRIPTION`: Human-readable description  
- `COMPATIBLE_HIVE`: Hive type constant from `hive_types.py`
- `run()`: Extraction logic, appends results to `self.entries`

```python
from regipy.hive_types import NTUSER_HIVE_TYPE
from regipy.plugins.plugin import Plugin

class MyPlugin(Plugin):
    NAME = 'my_plugin'
    DESCRIPTION = 'Extract something useful'
    COMPATIBLE_HIVE = NTUSER_HIVE_TYPE
    
    def run(self):
        try:
            key = self.registry_hive.get_key(r'Software\MyKey')
            for value in key.get_values(as_json=self.as_json):
                self.entries.append(value)
        except RegistryKeyNotFoundException:
            pass  # Key doesn't exist in this hive
```

### Timestamp Handling

Always use `convert_wintime()` for Windows FILETIME conversion:

```python
from regipy.utils import convert_wintime

timestamp = convert_wintime(key.header.last_modified, as_json=True)
# Returns ISO format string when as_json=True, datetime object otherwise
```

### Transaction Log Recovery

```python
from regipy.recovery import apply_transaction_logs

apply_transaction_logs(
    hive_path='/path/to/NTUSER.DAT',
    transaction_log_path='/path/to/NTUSER.DAT.LOG1',
    restored_hive_path='/path/to/recovered.DAT'
)
```

## Hive Types

Defined in `hive_types.py`:

| Constant | Typical Files |
|----------|---------------|
| `NTUSER_HIVE_TYPE` | NTUSER.DAT |
| `SYSTEM_HIVE_TYPE` | SYSTEM |
| `SOFTWARE_HIVE_TYPE` | SOFTWARE |
| `SAM_HIVE_TYPE` | SAM |
| `SECURITY_HIVE_TYPE` | SECURITY |
| `USRCLASS_HIVE_TYPE` | UsrClass.dat |
| `AMCACHE_HIVE_TYPE` | Amcache.hve |
| `BCD_HIVE_TYPE` | BCD |

## CLI Tools

- `regipy-parse-header` - Display hive header, validate checksums
- `regipy-dump` - Export entire hive to JSON (or timeline with `-t`)
- `regipy-plugins-run` - Auto-detect hive type and run relevant plugins
- `regipy-diff` - Compare two hives, output differences to CSV
- `regipy-process-transaction-logs` - Apply transaction logs to recover dirty hive

## Development Guidelines

### Adding a New Plugin

1. Create file in appropriate `plugins/<hive_type>/` directory
2. Inherit from `Plugin`, set `NAME`, `DESCRIPTION`, `COMPATIBLE_HIVE`
3. Implement `run()` method - append results to `self.entries`
4. Use try/except for `RegistryKeyNotFoundException` (key may not exist)
5. Add validation case in `regipy_tests/validation/`

### Validation Cases

Required for all new plugins:

```python
from regipy_tests.validation.validation import ValidationCase
from regipy.plugins.system.my_plugin import MyPlugin

class MyPluginValidationCase(ValidationCase):
    plugin = MyPlugin
    test_hive_file_name = "SYSTEM_WIN_10.xz"  # Must be in regipy_tests/data/
    
    # Option 1: Check for presence of specific entries
    expected_entries = [
        {"field": "value", ...}
    ]
    
    # Option 2: Exact match
    exact_expected_result = [...]
    
    expected_entries_count = 5  # Optional count validation
```

### Code Style

- Use `logging` module (not `logbook` in newer code)
- Prefer `as_json=True` parameter for JSON-serializable output
- Handle corrupted values gracefully (`is_corrupted` field)
- Document Windows-specific quirks in comments

## Installation Variants

```bash
pip install regipy[full]  # All dependencies including compiled ones
pip install regipy        # Minimal dependencies
pip install -e .[full]    # Development install
```

## Testing

```bash
pytest regipy_tests/
```

Test hives are stored as `.xz` compressed files in `regipy_tests/data/`.

## Common Forensic Artifacts by Hive

**NTUSER.DAT**: User activity
- Run/RunOnce keys (persistence)
- TypedURLs (browser history)
- UserAssist (program execution)
- RecentDocs, MRU lists

**SYSTEM**: System configuration
- ComputerName
- Shimcache/AppCompatCache (execution history)
- BAM/DAM (background activity)
- Services, network interfaces

**SOFTWARE**: Installed software
- Uninstall keys
- ProfileList (user profiles)
- Installed programs

**Amcache.hve**: Application compatibility
- File execution with SHA1 hashes
- Driver information

**UsrClass.dat**: Shell data
- Shellbags (folder access history)

## MCP Server Integration

regipy includes an MCP (Model Context Protocol) server that enables natural language forensic analysis through Claude Desktop or other MCP-compatible AI assistants.

### What it Does

The MCP server bridges Claude and regipy's plugin ecosystem, allowing investigators to:
- Ask forensic questions in plain English instead of remembering CLI syntax
- Auto-detect hive types from a directory of collected registry files
- Leverage all 75+ plugins without knowing which plugin extracts which artifact
- Get correlated results across multiple hives in a single conversational query

### Example Workflow

Instead of:
```bash
regipy-plugins-run SYSTEM -o system_output.json
regipy-plugins-run NTUSER.DAT -o ntuser_output.json
# manually correlate results...
```

You can ask:
> "What persistence mechanisms exist on this machine?"

Claude will automatically run both `software_persistence` and `ntuser_persistence` plugins and synthesize the results.

### Setup

1. Install regipy with MCP support
2. Configure Claude Desktop to use the regipy MCP server
3. Point at your evidence directory
4. Start investigating conversationally

### Design Philosophy

The MCP server exposes plugin metadata (names, descriptions, compatible hives) to Claude, letting it reason about which plugins to run based on the investigator's natural language questions. This means:
- New plugins automatically become available to Claude without prompt updates
- Claude can chain multiple plugins when a question spans artifacts
- Investigators can follow their instincts with follow-up questions

For more details, see the blog post: [Regipy MCP: Natural Language Registry Forensics with Claude](https://medium.com/dfir-dudes/regipy-mcp-natural-language-registry-forensics-with-claude-984d378784d6)

## External References

### Microsoft Documentation

- [Registry Hives (Win32)](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-hives) - Official overview of hive concepts, file formats, and locations
- [Windows Registry for Advanced Users](https://learn.microsoft.com/en-us/troubleshoot/windows-server/performance/windows-registry-advanced-users) - Detailed reference on registry structure, data types, and hive files
- [Inside the Registry](https://learn.microsoft.com/en-us/previous-versions/cc750583(v=technet.10)) - Mark Russinovich's deep dive into registry internals (cells, bins, hive file format)

### Community Resources

- [Windows Registry File Format Specification](https://github.com/msuhanov/regf) - Maxim Suhanov's comprehensive REGF format documentation (the de facto standard for forensic tool authors)
- [Google Project Zero: Registry Hives](https://projectzero.google/2024/10/the-windows-registry-adventure-4-hives.html) - Deep technical analysis of hive internals and security boundaries

### Registry File Locations

| Hive | File Path |
|------|-----------|
| SYSTEM | `%SystemRoot%\System32\config\SYSTEM` |
| SOFTWARE | `%SystemRoot%\System32\config\SOFTWARE` |
| SAM | `%SystemRoot%\System32\config\SAM` |
| SECURITY | `%SystemRoot%\System32\config\SECURITY` |
| DEFAULT | `%SystemRoot%\System32\config\DEFAULT` |
| NTUSER.DAT | `%UserProfile%\NTUSER.DAT` |
| UsrClass.dat | `%LocalAppData%\Microsoft\Windows\UsrClass.dat` |
| Amcache.hve | `%SystemRoot%\AppCompat\Programs\Amcache.hve` |

### Transaction Logs

Registry hives use transaction logs (`.LOG1`, `.LOG2`) for crash recovery. When a hive's sequence numbers don't match (primary ≠ secondary), the hive is "dirty" and transaction logs should be applied before analysis. regipy handles this via:

```bash
regipy-process-transaction-logs NTUSER.DAT -p ntuser.dat.log1 -s ntuser.dat.log2 -o recovered.DAT
```

Or programmatically via `regipy.recovery.apply_transaction_logs()`.
