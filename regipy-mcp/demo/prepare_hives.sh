#!/bin/bash
# Prepare test hive files for the demo by decompressing them

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HIVE_DIR="$SCRIPT_DIR/hives"
TEST_DATA_DIR="$SCRIPT_DIR/../../regipy_tests/data"

mkdir -p "$HIVE_DIR"

echo "Preparing test hive files..."

# Decompress a selection of test hives
for hive in SYSTEM NTUSER.DAT SOFTWARE SAM; do
    src="$TEST_DATA_DIR/${hive}.xz"
    dst="$HIVE_DIR/$hive"

    if [ -f "$src" ] && [ ! -f "$dst" ]; then
        echo "  Decompressing $hive..."
        xz -dk "$src" -c > "$dst"
    elif [ -f "$dst" ]; then
        echo "  $hive already exists"
    else
        echo "  Warning: $src not found"
    fi
done

echo "Done! Hives are in: $HIVE_DIR"
ls -la "$HIVE_DIR"
