# Regipy MCP + Ollama Demo

This demo shows how to use **regipy-mcp** with a local LLM (Ollama) to perform Windows Registry forensic analysis using natural language queries.

## Prerequisites

- Docker and Docker Compose
- ~8GB RAM (for running the LLM)
- ~5GB disk space (for the Ollama model)

## Quick Start

```bash
# 1. Clone the repository
git clone https://github.com/mkorman90/regipy.git
cd regipy/regipy-mcp/demo

# 2. Run the demo
./run_demo.sh
```

This will:
1. Decompress test registry hive files
2. Start Ollama and the regipy-mcp server in Docker
3. Pull the `qwen2.5:7b` model (first run only)
4. Run sample forensic queries

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Docker Compose                            │
│                                                              │
│  ┌─────────────────┐         ┌─────────────────────────┐    │
│  │     Ollama      │         │    regipy-mcp server    │    │
│  │   (qwen2.5:7b)  │◄───────►│                         │    │
│  │                 │  tools  │   ┌─────────────────┐   │    │
│  │  localhost:11434│         │   │  Registry Hives │   │    │
│  └─────────────────┘         │   │  /hives/SYSTEM  │   │    │
│                              │   │  /hives/NTUSER  │   │    │
│                              │   │  /hives/SOFTWARE│   │    │
│                              │   └─────────────────┘   │    │
│                              │     localhost:8000      │    │
│                              └─────────────────────────┘    │
└─────────────────────────────────────────────────────────────┘
```

## Manual Setup

If you prefer to run things manually:

```bash
# Prepare hive files
./prepare_hives.sh

# Start services
docker-compose up -d

# Wait for Ollama and pull model
docker exec regipy-ollama ollama pull qwen2.5:7b

# Run the integration test
docker exec -e REGIPY_HIVE_DIRECTORY=/hives regipy-mcp-server \
    python /app/demo/integration_test.py
```

## Available MCP Tools

| Tool | Description |
|------|-------------|
| `list_hives` | List available registry hive files |
| `list_plugins` | List all forensic analysis plugins |
| `run_plugin` | Run a specific plugin on a hive |
| `run_all_plugins` | Run all compatible plugins on a hive |
| `get_key` | Read a specific registry key path |
| `search_by_timestamp` | Find keys modified in a date range |

## Example Queries

Once running, you can ask questions like:

- "What registry hive files are available for analysis?"
- "What was the timezone configured on this Windows system?"
- "What USB storage devices were connected to this computer?"
- "What programs are configured to run at startup?"
- "Show me the computer name and domain information"

## Using Different Models

You can change the model by editing `integration_test.py`:

```python
MODEL = "qwen2.5:7b"      # Default - good balance
MODEL = "llama3.2:3b"     # Faster, less capable
MODEL = "qwen2.5:14b"     # More capable, needs more RAM
```

## Cleanup

```bash
# Stop services
docker-compose down

# Remove volumes (including downloaded models)
docker-compose down -v

# Remove decompressed hive files
rm -rf hives/
```

## Troubleshooting

### Ollama is slow

The first request may be slow as the model loads into memory. Subsequent requests will be faster.

### Out of memory

Try using a smaller model like `llama3.2:3b` or `qwen2.5:3b`.

### Connection refused

Make sure Docker services are running:
```bash
docker-compose ps
docker-compose logs
```
