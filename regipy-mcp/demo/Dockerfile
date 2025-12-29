FROM python:3.12-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install regipy-mcp
COPY pyproject.toml .
COPY regipy_mcp/ regipy_mcp/
COPY demo/ demo/

RUN pip install --no-cache-dir ".[dev]" httpx

# Expose SSE port for MCP
EXPOSE 8000

# Run MCP server with SSE transport
CMD ["python", "-m", "regipy_mcp.server", "--transport", "sse", "--port", "8000"]
