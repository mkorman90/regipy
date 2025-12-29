# regipy-mcp

MCP (Model Context Protocol) server for [regipy](https://github.com/mkorman90/regipy) - enabling LLM-powered Windows Registry forensic analysis.

## Installation

```bash
pip install regipy-mcp
```

## Usage

### With Claude Desktop

Add to your Claude Desktop configuration (`~/.config/claude/claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "regipy": {
      "command": "regipy-mcp",
      "env": {
        "REGIPY_HIVE_DIRECTORY": "/path/to/your/hive/files"
      }
    }
  }
}
```

### Environment Variables

- `REGIPY_HIVE_DIRECTORY`: Directory containing registry hive files to analyze

## Available Tools

| Tool | Description |
|------|-------------|
| `list_hives` | List available registry hive files and their detected types |
| `list_plugins` | List all forensic analysis plugins grouped by hive type |
| `run_plugin` | Run a specific plugin (correct hive auto-selected) |
| `run_all_plugins` | Run all compatible plugins on all available hives |
| `get_key` | Read a specific registry key path |
| `search_by_timestamp` | Find keys modified in a date range |

The server automatically detects hive types (SYSTEM, SOFTWARE, NTUSER, SAM, SECURITY) and selects the correct hive when running plugins.

## Example Questions

Once configured, you can ask Claude questions like:

- "What timezone was this computer set to?"
- "What USB devices were connected to this system?"
- "Show me all programs that run at startup"
- "What registry keys were modified after March 15, 2024?"
- "List all network connections this computer has made"

## Demo with Ollama

Try regipy-mcp with a local LLM (no API keys needed):

```bash
# Install Ollama: https://ollama.com/download
ollama pull qwen2.5:7b

# Run the demo (pass a directory containing hive files)
cd demo
python simple_demo.py /path/to/hives_directory
```

For a Docker-based demo with sample hive files, see [demo/README.md](demo/README.md).

## Development

```bash
# Install in development mode
cd regipy-mcp
pip install -e ".[dev]"

# Run tests
pytest

# Run with SSE transport (for HTTP-based clients)
regipy-mcp --transport sse --port 8000
```

## License

MIT
