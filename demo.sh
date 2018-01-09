#!/bin/bash

echo "=== Network Monitoring Suite Demo ==="
echo ""
echo "This demo shows how to use the unified main.py script"
echo ""

# Check if main.py exists
if [ ! -f "main.py" ]; then
    echo "[!] main.py not found. Run setup.sh first."
    exit 1
fi

echo "Available commands:"
echo "  python3 main.py discover  - Network device discovery"
echo "  python3 main.py monitor   - Real-time packet capture"
echo "  python3 main.py analyze   - Data analysis and reporting"
echo ""

# Show help for each command
echo "1. DISCOVER MODE - Find and profile network devices"
echo "   Usage examples:"
echo "     python3 main.py discover --fast --summary"
echo "     python3 main.py discover --username admin --password pass"
echo ""

echo "2. MONITOR MODE - Capture and analyze network traffic"
echo "   Usage examples:"
echo "     sudo python3 main.py monitor"
echo "     sudo python3 main.py monitor --interface en0"
echo ""

echo "3. ANALYZE MODE - Generate insights and reports"
echo "   Usage examples:"
echo "     python3 main.py analyze"
echo "     python3 main.py analyze --security --export"
echo ""

echo "=== Complete Workflow Example ==="
echo ""
echo "# Step 1: Discover devices on your network"
echo "python3 main.py discover --fast --summary"
echo ""
echo "# Step 2: Monitor traffic for analysis (run in background)"
echo "sudo python3 main.py monitor &"
echo ""
echo "# Step 3: After some time, stop monitoring and analyze"
echo "# Press Ctrl+C to stop monitoring, then:"
echo "python3 main.py analyze --security --export"
echo ""

echo "=== Quick Test (no sudo required) ==="
echo ""
echo "To test device discovery (no elevated privileges needed):"
echo "python3 main.py discover --fast"
echo ""

read -p "Press Enter to run a quick device discovery test..."
echo ""
echo "Running: python3 main.py discover --fast"
python3 main.py discover --fast

echo ""
echo "Demo complete! Check the logs/ directory for output files."
echo "For packet monitoring, you'll need to run: sudo python3 main.py monitor" 