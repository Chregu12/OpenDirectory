#!/bin/bash
set -e

# Build Rust agent for Linux (native)
cargo build --release
cp target/release/od-agent-service ../agent/dist/od-agent-service-linux-amd64

echo "Built: od-agent-service-linux-amd64 ($(du -sh target/release/od-agent-service | cut -f1))"
echo ""
echo "For cross-compilation to Windows (requires mingw-w64 + cross toolchain):"
echo "  cargo build --release --target x86_64-pc-windows-gnu"
echo ""
echo "For macOS (requires osxcross):"
echo "  cargo build --release --target x86_64-apple-darwin"
