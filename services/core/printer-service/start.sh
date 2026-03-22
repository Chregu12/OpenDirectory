#!/bin/sh
# Start CUPS in background (optional — may not be available on all platforms)
cupsd 2>/dev/null || true

# Start Avahi for mDNS discovery (optional)
avahi-daemon --no-drop-root --no-rlimits -D 2>/dev/null || true

# Wait for services to settle
sleep 2

# Start Node.js application
exec node src/index.js
