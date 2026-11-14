#!/bin/bash
cd "$(dirname "$0")"
echo ""
echo "  🛡️  RedactShield — Zero-Upload Sensitive Data Detection"
echo "  ======================================================="
echo ""
echo "  Starting local server..."
echo "  Open in browser: http://localhost:8080"
echo ""
echo "  Press Ctrl+C to stop."
echo ""
python3 -m http.server 8080
