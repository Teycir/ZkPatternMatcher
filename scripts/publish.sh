#!/usr/bin/env bash
# Publish workspace crates to crates.io in dependency order

set -e

echo "=== Publishing ZkPatternMatcher to crates.io ==="
echo ""
echo "⚠️  Make sure you have:"
echo "  1. Run 'cargo login' with your crates.io token"
echo "  2. Committed all changes"
echo "  3. Tagged the release: git tag v0.1.0"
echo ""
read -p "Continue? (y/N) " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    exit 1
fi

# Step 1: Publish pattern-types (no dependencies)
echo ""
echo "[1/3] Publishing pattern-types..."
cd crates/pattern-types
cargo publish
cd ../..
sleep 10  # Wait for crates.io to index

# Step 2: Publish pattern-loader (depends on pattern-types)
echo ""
echo "[2/3] Publishing pattern-loader..."
cd crates/pattern-loader
cargo publish
cd ../..
sleep 10

# Step 3: Publish pattern-matcher (depends on pattern-types)
echo ""
echo "[3/3] Publishing pattern-matcher..."
cd crates/pattern-matcher
cargo publish
cd ../..
sleep 10

# Step 4: Publish main crate (depends on all)
echo ""
echo "[4/4] Publishing zk-pattern-matcher..."
cargo publish

echo ""
echo "✅ All crates published successfully!"
echo ""
echo "Verify at:"
echo "  - https://crates.io/crates/zk-pattern-matcher"
echo "  - https://crates.io/crates/pattern-types"
echo "  - https://crates.io/crates/pattern-loader"
echo "  - https://crates.io/crates/pattern-matcher"
