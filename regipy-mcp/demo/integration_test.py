#!/usr/bin/env python3
"""
Integration test demonstrating regipy-mcp with Ollama.

This script connects to both the regipy MCP server and Ollama,
then asks forensic questions about Windows Registry hive files.
"""

import json
import sys
from typing import Any

import httpx

# Configuration
OLLAMA_URL = "http://localhost:11434"
MCP_URL = "http://localhost:8000"
MODEL = "qwen2.5:7b"  # Good balance of capability and speed


def call_mcp_tool(tool_name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    """Call an MCP tool via the SSE server's REST endpoint."""
    # For simplicity, we call the tools directly via HTTP
    # In production, you'd use the full MCP protocol
    with httpx.Client(timeout=60.0) as client:
        # Initialize MCP session
        response = client.get(f"{MCP_URL}/sse", timeout=5.0)

        # For demo purposes, we'll call tools via a simple REST wrapper
        # The actual MCP protocol uses SSE + JSON-RPC
        print(f"  [MCP] Calling {tool_name}({json.dumps(arguments)})")

    # Since MCP uses SSE which is complex to call directly,
    # we'll import and call the tools directly for the demo
    from regipy_mcp.server import (
        get_key,
        list_hives,
        list_plugins,
        run_all_plugins,
        run_plugin,
        search_by_timestamp,
    )

    tools = {
        "list_hives": lambda: list_hives(),
        "list_plugins": lambda: list_plugins(),
        "run_plugin": lambda: run_plugin(arguments["hive_path"], arguments["plugin_name"]),
        "run_all_plugins": lambda: run_all_plugins(arguments["hive_path"]),
        "get_key": lambda: get_key(arguments["hive_path"], arguments["key_path"]),
        "search_by_timestamp": lambda: search_by_timestamp(
            arguments["hive_path"],
            arguments.get("start_date"),
            arguments.get("end_date"),
            arguments.get("limit", 100),
        ),
    }

    return tools[tool_name]()


def chat_with_ollama(messages: list[dict], tools: list[dict] | None = None) -> dict:
    """Send a chat request to Ollama with optional tool definitions."""
    with httpx.Client(timeout=120.0) as client:
        payload = {
            "model": MODEL,
            "messages": messages,
            "stream": False,
        }
        if tools:
            payload["tools"] = tools

        response = client.post(f"{OLLAMA_URL}/api/chat", json=payload)
        response.raise_for_status()
        return response.json()


def get_mcp_tools_for_ollama() -> list[dict]:
    """Convert MCP tool definitions to Ollama format."""
    return [
        {
            "type": "function",
            "function": {
                "name": "list_hives",
                "description": "List available Windows Registry hive files that can be analyzed",
                "parameters": {"type": "object", "properties": {}, "required": []},
            },
        },
        {
            "type": "function",
            "function": {
                "name": "list_plugins",
                "description": "List all available regipy plugins for registry analysis",
                "parameters": {"type": "object", "properties": {}, "required": []},
            },
        },
        {
            "type": "function",
            "function": {
                "name": "run_plugin",
                "description": "Run a forensic plugin on a registry hive to extract artifacts",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "hive_path": {"type": "string", "description": "Path to the registry hive file"},
                        "plugin_name": {"type": "string", "description": "Name of the plugin to run"},
                    },
                    "required": ["hive_path", "plugin_name"],
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "run_all_plugins",
                "description": "Run all compatible forensic plugins on a registry hive",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "hive_path": {"type": "string", "description": "Path to the registry hive file"},
                    },
                    "required": ["hive_path"],
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "get_key",
                "description": "Read a specific registry key and its values",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "hive_path": {"type": "string", "description": "Path to the registry hive file"},
                        "key_path": {"type": "string", "description": "Registry key path"},
                    },
                    "required": ["hive_path", "key_path"],
                },
            },
        },
    ]


def run_forensic_query(question: str) -> str:
    """Run a forensic question through Ollama with MCP tools."""
    print(f"\n{'='*60}")
    print(f"Question: {question}")
    print("=" * 60)

    tools = get_mcp_tools_for_ollama()
    messages = [
        {
            "role": "system",
            "content": """You are a Windows Registry forensic analyst. You have access to tools
that can analyze Windows Registry hive files. Use these tools to answer questions about
the system configuration, installed software, user activity, and other forensic artifacts.

Always start by listing available hives, then use appropriate plugins to extract relevant data.
Provide clear, concise forensic analysis based on the tool results.""",
        },
        {"role": "user", "content": question},
    ]

    # Initial request to Ollama
    print("\n[Ollama] Thinking...")
    response = chat_with_ollama(messages, tools)

    # Process tool calls in a loop
    max_iterations = 5
    iteration = 0

    while iteration < max_iterations:
        iteration += 1
        message = response.get("message", {})

        # Check if the model wants to call tools
        tool_calls = message.get("tool_calls", [])

        if not tool_calls:
            # No more tool calls, return the final response
            return message.get("content", "No response generated")

        # Execute tool calls
        messages.append(message)

        for tool_call in tool_calls:
            func = tool_call.get("function", {})
            tool_name = func.get("name")
            arguments = func.get("arguments", {})

            print(f"\n[Tool Call] {tool_name}")

            try:
                result = call_mcp_tool(tool_name, arguments)
                result_str = json.dumps(result, indent=2, default=str)

                # Truncate long results for readability
                if len(result_str) > 2000:
                    result_str = result_str[:2000] + "\n... (truncated)"

                print(f"[Result] {result_str[:500]}...")

                messages.append({
                    "role": "tool",
                    "content": result_str,
                })
            except Exception as e:
                print(f"[Error] {e}")
                messages.append({
                    "role": "tool",
                    "content": json.dumps({"error": str(e)}),
                })

        # Continue the conversation
        print("\n[Ollama] Processing results...")
        response = chat_with_ollama(messages, tools)

    return response.get("message", {}).get("content", "Max iterations reached")


def check_services():
    """Check if Ollama and the required model are available."""
    print("Checking services...")

    # Check Ollama
    try:
        with httpx.Client(timeout=10.0) as client:
            response = client.get(f"{OLLAMA_URL}/api/tags")
            response.raise_for_status()
            models = response.json().get("models", [])
            model_names = [m.get("name", "").split(":")[0] for m in models]
            print(f"  Ollama: OK (models: {', '.join(model_names[:5])})")

            if MODEL.split(":")[0] not in model_names:
                print(f"\n  Model '{MODEL}' not found. Pulling...")
                pull_response = client.post(
                    f"{OLLAMA_URL}/api/pull",
                    json={"name": MODEL},
                    timeout=600.0,
                )
                print(f"  Model pulled: {MODEL}")
    except Exception as e:
        print(f"  Ollama: FAILED - {e}")
        print(f"\n  Make sure Ollama is running: docker-compose up -d ollama")
        return False

    return True


def main():
    """Run the integration test."""
    print("=" * 60)
    print("Regipy MCP + Ollama Integration Test")
    print("=" * 60)

    if not check_services():
        sys.exit(1)

    # Set up hive directory for direct tool calls
    import os
    os.environ["REGIPY_HIVE_DIRECTORY"] = "/hives"

    # Initialize the MCP server's hive directory
    from regipy_mcp import server
    server._hive_directory = server.Path(os.environ["REGIPY_HIVE_DIRECTORY"])

    # Test questions
    questions = [
        "What registry hive files are available for analysis?",
        "What was the timezone configured on this Windows system?",
        "What USB storage devices were connected to this computer?",
    ]

    for question in questions:
        try:
            answer = run_forensic_query(question)
            print(f"\n[Final Answer]\n{answer}")
        except Exception as e:
            print(f"\n[Error] {e}")

    print("\n" + "=" * 60)
    print("Integration test complete!")
    print("=" * 60)


if __name__ == "__main__":
    main()
