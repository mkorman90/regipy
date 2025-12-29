#!/usr/bin/env python3
"""
Simple demo of regipy-mcp with Ollama.

This script demonstrates using a local LLM to perform Windows Registry
forensic analysis. It doesn't require Docker - just Ollama running locally.

Prerequisites:
    1. Install Ollama: https://ollama.com/download
    2. Pull a model: ollama pull qwen2.5:7b
    3. Install regipy-mcp: pip install -e ..

Usage:
    python simple_demo.py /path/to/hives_directory

Example:
    python simple_demo.py ../../regipy_tests/data
"""

import json
import os
import sys
from pathlib import Path

import httpx

# Configuration
OLLAMA_URL = os.environ.get("OLLAMA_URL", "http://localhost:11434")
MODEL = os.environ.get("OLLAMA_MODEL", "qwen2.5:7b")
MAX_TOOL_RESULT_SIZE = 4000  # Truncate large results to avoid LLM timeouts


def get_tools_for_ollama():
    """Define MCP tools in Ollama format."""
    return [
        {
            "type": "function",
            "function": {
                "name": "list_hives",
                "description": "List available registry hive files and their types",
                "parameters": {"type": "object", "properties": {}, "required": []},
            },
        },
        {
            "type": "function",
            "function": {
                "name": "list_plugins",
                "description": "List all available forensic plugins grouped by hive type",
                "parameters": {"type": "object", "properties": {}, "required": []},
            },
        },
        {
            "type": "function",
            "function": {
                "name": "run_plugin",
                "description": "Run a forensic plugin (correct hive is auto-selected)",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "plugin_name": {
                            "type": "string",
                            "description": "Name of the plugin (e.g., 'shimcache', 'timezone_data', 'usbstor_plugin', 'typed_urls')",
                        },
                    },
                    "required": ["plugin_name"],
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "run_all_plugins",
                "description": "Run ALL compatible plugins on all hives for complete forensic analysis",
                "parameters": {"type": "object", "properties": {}, "required": []},
            },
        },
        {
            "type": "function",
            "function": {
                "name": "get_key",
                "description": "Read a specific registry key path and its values",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "key_path": {
                            "type": "string",
                            "description": "Registry key path (e.g., '\\\\ControlSet001\\\\Control\\\\TimeZoneInformation')",
                        },
                        "hive_type": {
                            "type": "string",
                            "description": "Optional: SYSTEM, SOFTWARE, NTUSER, SAM, or SECURITY",
                        },
                    },
                    "required": ["key_path"],
                },
            },
        },
    ]


class RegistryAnalyzer:
    """Wraps regipy-mcp server to provide tool implementations."""

    def __init__(self, hive_directory: str):
        """Initialize with a directory containing hive files."""
        os.environ["REGIPY_HIVE_DIRECTORY"] = hive_directory

        # Import and initialize the server module
        from regipy_mcp import server

        server._hive_directory = server.Path(hive_directory)
        result = server._detect_and_load_hives()

        self.server = server
        self.hive_types = result.get("available_types", [])
        print(f"Loaded hives from: {hive_directory}")
        print(f"Available hive types: {', '.join(self.hive_types)}")

    def call_tool(self, name: str, args: dict):
        """Route tool calls to server functions."""
        if name == "list_hives":
            return self.server.list_hives()
        elif name == "list_plugins":
            return self.server.list_plugins()
        elif name == "run_plugin":
            return self.server.run_plugin(args["plugin_name"])
        elif name == "run_all_plugins":
            return self.server.run_all_plugins()
        elif name == "get_key":
            return self.server.get_key(args["key_path"], args.get("hive_type"))
        return {"error": f"Unknown tool: {name}"}


def chat_with_tools(analyzer: RegistryAnalyzer, question: str):
    """Send a question to Ollama and handle tool calls."""
    tools = get_tools_for_ollama()

    messages = [
        {
            "role": "system",
            "content": f"""You are a Windows Registry forensic analyst. You have access to registry hives
from a Windows system: {', '.join(analyzer.hive_types)}.

Use the available tools to analyze the registry and answer questions.
The correct hive is automatically selected when you run plugins.
Be concise and focus on forensically relevant findings.""",
        },
        {"role": "user", "content": question},
    ]

    print(f"\n{'='*60}")
    print(f"Q: {question}")
    print("=" * 60)

    with httpx.Client(timeout=180.0) as client:
        for _ in range(10):  # Max tool call iterations
            response = client.post(
                f"{OLLAMA_URL}/api/chat",
                json={"model": MODEL, "messages": messages, "stream": False, "tools": tools},
            )
            response.raise_for_status()
            result = response.json()
            message = result.get("message", {})

            tool_calls = message.get("tool_calls", [])
            if not tool_calls:
                # Final answer
                return message.get("content", "No response")

            # Process tool calls
            messages.append(message)
            for tc in tool_calls:
                func = tc.get("function", {})
                tool_name = func.get("name")
                tool_args = func.get("arguments", {})

                print(f"\n[Tool] {tool_name}({json.dumps(tool_args)})")

                result = analyzer.call_tool(tool_name, tool_args)
                result_str = json.dumps(result, indent=2, default=str)

                # Truncate large results to avoid LLM timeouts
                if len(result_str) > MAX_TOOL_RESULT_SIZE:
                    result_str = result_str[:MAX_TOOL_RESULT_SIZE] + "\n... (truncated)"

                # Show preview
                preview = result_str[:500] + "..." if len(result_str) > 500 else result_str
                print(f"[Result] {preview}")

                messages.append({"role": "tool", "content": result_str})

    return "Max iterations reached"


def check_ollama():
    """Check if Ollama is running and has the model."""
    try:
        with httpx.Client(timeout=10.0) as client:
            response = client.get(f"{OLLAMA_URL}/api/tags")
            response.raise_for_status()
            models = [m.get("name", "") for m in response.json().get("models", [])]

            if not any(MODEL.split(":")[0] in m for m in models):
                print(f"Model '{MODEL}' not found. Available: {models}")
                print(f"Pull it with: ollama pull {MODEL}")
                return False
            return True
    except Exception as e:
        print(f"Cannot connect to Ollama at {OLLAMA_URL}: {e}")
        print("Make sure Ollama is running: ollama serve")
        return False


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    hive_dir = sys.argv[1]
    hive_path = Path(hive_dir)

    # If a file was provided, use its parent directory
    if hive_path.is_file():
        hive_dir = str(hive_path.parent)
    elif not hive_path.is_dir():
        print(f"Directory not found: {hive_dir}")
        sys.exit(1)
    else:
        hive_dir = str(hive_path)

    if not check_ollama():
        sys.exit(1)

    analyzer = RegistryAnalyzer(hive_dir)

    if not analyzer.hive_types:
        print("No registry hives found in directory!")
        sys.exit(1)

    # Demo questions
    questions = [
        "What registry hives are available and what can we analyze?",
        "What timezone was this Windows system configured to use?",
        "What USB storage devices were connected to this computer?",
    ]

    for q in questions:
        try:
            answer = chat_with_tools(analyzer, q)
            print(f"\n[Answer]\n{answer}")
        except Exception as e:
            print(f"\n[Error] {e}")

    print("\n" + "=" * 60)
    print("Demo complete!")


if __name__ == "__main__":
    main()
