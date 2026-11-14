#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
target="${1:-$(rustc -vV | sed -n 's/^host: //p')}"
cargo build --locked --release --target "$target"
name=od-agent-service
if [[ "$target" == *windows* ]]; then name=od-agent-service.exe; fi
python3 scripts/package.py --binary "target/$target/release/$name" --target "$target" --commit "$(git rev-parse HEAD)" --epoch "$(git show -s --format=%ct HEAD)"
