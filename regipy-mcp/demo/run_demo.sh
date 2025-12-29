#!/bin/bash
# Run the complete regipy-mcp + Ollama demo

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "=============================================="
echo "  Regipy MCP + Ollama Demo"
echo "=============================================="
echo

# Step 1: Prepare hive files
echo "[1/4] Preparing test hive files..."
./prepare_hives.sh
echo

# Step 2: Start services
echo "[2/4] Starting Docker services..."
docker-compose up -d
echo

# Wait for Ollama to be ready
echo "[3/4] Waiting for Ollama to be ready..."
for i in {1..30}; do
    if curl -s http://localhost:11434/api/tags > /dev/null 2>&1; then
        echo "  Ollama is ready!"
        break
    fi
    echo "  Waiting... ($i/30)"
    sleep 2
done

# Pull the model if needed
echo "  Checking for qwen2.5:7b model..."
if ! curl -s http://localhost:11434/api/tags | grep -q "qwen2.5"; then
    echo "  Pulling qwen2.5:7b (this may take a few minutes)..."
    docker exec regipy-ollama ollama pull qwen2.5:7b
fi
echo

# Step 4: Run integration test
echo "[4/4] Running integration test..."
echo
docker exec -e REGIPY_HIVE_DIRECTORY=/hives regipy-mcp-server \
    python /app/demo/integration_test.py

echo
echo "=============================================="
echo "  Demo complete!"
echo "=============================================="
echo
echo "To stop services: docker-compose down"
echo "To view logs: docker-compose logs -f"
