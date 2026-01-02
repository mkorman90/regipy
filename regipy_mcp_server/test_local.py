#!/usr/bin/env python3
"""
Local test script for Regipy MCP Server
Tests the server functions directly without Claude Desktop
"""

import io
import os
import sys

# Fix Windows console encoding
if sys.platform == 'win32':
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

# Set the hive directory
os.environ['REGIPY_HIVE_DIRECTORY'] = r'C:\Users\marti\Downloads\hives'

# Add server to path
sys.path.insert(0, os.path.dirname(__file__))

print("=" * 70)
print("Regipy MCP Server - Local Test")
print("=" * 70)

# Import after setting environment variable
from server import (  # noqa: E402
    PLUGINS,
    _initialize_hives,
    _loaded_hives,
    answer_forensic_question,
    list_available_hives,
    list_available_plugins,
    run_plugin,
)

print("\n✓ Server imported successfully")
print(f"✓ Discovered {len(PLUGINS)} plugins")

# Initialize hives
print("\n📂 Loading hives from: C:\\Users\\marti\\Downloads\\hives")
_initialize_hives()

if _loaded_hives:
    print(f"✓ Loaded {len(_loaded_hives)} hive file(s)")

    print("\n" + "=" * 70)
    print("TEST 1: List Available Hives")
    print("=" * 70)
    result = list_available_hives()
    print(result)

    print("\n" + "=" * 70)
    print("TEST 2: List Available Plugins (SYSTEM hive)")
    print("=" * 70)
    result = list_available_plugins(hive_type="SYSTEM")
    print(result[:500] + "..." if len(result) > 500 else result)

    print("\n" + "=" * 70)
    print("TEST 3: Run Computer Name Plugin")
    print("=" * 70)
    result = run_plugin("computer_name")
    print(result)

    print("\n" + "=" * 70)
    print("TEST 4: Answer Forensic Question - Hostname")
    print("=" * 70)
    result = answer_forensic_question("What is the hostname?")
    print(result)

    print("\n" + "=" * 70)
    print("TEST 5: Answer Forensic Question - Timezone")
    print("=" * 70)
    result = answer_forensic_question("What is the timezone?")
    print(result)

    print("\n" + "=" * 70)
    print("✅ All tests completed!")
    print("=" * 70)
    print("\nNext steps:")
    print("1. Configure Claude Desktop with the config from claude_desktop_config.example.json")
    print("2. Restart Claude Desktop")
    print("3. Ask Claude: 'What registry hives are available?'")

else:
    print("\n❌ No hives loaded!")
    print("\nTroubleshooting:")
    print("1. Check that C:\\Users\\marti\\Downloads\\hives exists")
    print("2. Verify it contains registry hive files (SYSTEM, SOFTWARE, NTUSER.DAT, etc.)")
    print("3. Make sure files aren't corrupted")
