#!/bin/bash

echo "=== Network Monitoring Suite Setup ==="
echo ""

# Check if running as root
if [[ $EUID -eq 0 ]]; then
   echo "Warning: Running as root. Consider running as regular user for initial setup."
   echo ""
fi

# Create logs directory
echo "[*] Creating logs directory..."
mkdir -p logs
chmod 755 logs

# Install Python dependencies
echo "[*] Installing Python dependencies..."
if command -v pip3 &> /dev/null; then
    pip3 install -r requirements.txt
elif command -v pip &> /dev/null; then
    pip install -r requirements.txt
else
    echo "[!] pip or pip3 not found. Please install Python package manager."
    exit 1
fi

# Check for nmap installation
echo "[*] Checking for nmap..."
if ! command -v nmap &> /dev/null; then
    echo "[!] nmap not found. Installing..."
    
    # Detect OS and install nmap
    if [[ "$OSTYPE" == "darwin"* ]]; then
        # macOS
        if command -v brew &> /dev/null; then
            brew install nmap
        else
            echo "[!] Homebrew not found. Please install nmap manually:"
            echo "    Visit: https://nmap.org/download.html"
        fi
    elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
        # Linux
        if command -v apt-get &> /dev/null; then
            sudo apt-get update && sudo apt-get install -y nmap
        elif command -v yum &> /dev/null; then
            sudo yum install -y nmap
        elif command -v dnf &> /dev/null; then
            sudo dnf install -y nmap
        else
            echo "[!] Package manager not detected. Please install nmap manually."
        fi
    else
        echo "[!] OS not supported for auto-installation. Please install nmap manually."
    fi
else
    echo "[+] nmap found: $(nmap --version | head -1)"
fi

# Set executable permissions
echo "[*] Setting executable permissions..."
chmod +x main.py

# Test Python imports
echo "[*] Testing Python dependencies..."
python3 -c "
import sys
missing = []

try:
    import netifaces
    print('[+] netifaces: OK')
except ImportError:
    missing.append('netifaces')
    print('[!] netifaces: MISSING')

try:
    import nmap
    print('[+] python-nmap: OK')
except ImportError:
    missing.append('python-nmap')
    print('[!] python-nmap: MISSING')

try:
    import psutil
    print('[+] psutil: OK')
except ImportError:
    missing.append('psutil')
    print('[!] psutil: MISSING')

try:
    import paramiko
    print('[+] paramiko: OK')
except ImportError:
    missing.append('paramiko')
    print('[!] paramiko: MISSING')

try:
    from scapy.all import sniff
    print('[+] scapy: OK')
except ImportError:
    missing.append('scapy')
    print('[!] scapy: MISSING (required for packet capture)')

if missing:
    print(f'[!] Missing packages: {missing}')
    print('[!] Try: pip3 install ' + ' '.join(missing))
    sys.exit(1)
else:
    print('[+] All Python dependencies satisfied!')
"

if [ $? -ne 0 ]; then
    echo "[!] Some dependencies are missing. Please install them before proceeding."
    exit 1
fi

echo ""
echo "=== Setup Complete! ==="
echo ""
echo "Quick Start Guide:"
echo ""
echo "1. Discover network devices:"
echo "   python3 main.py discover --summary"
echo ""
echo "2. Start packet monitoring (requires sudo):"
echo "   sudo python3 main.py monitor"
echo ""
echo "3. Analyze combined data:"
echo "   python3 main.py analyze --security"
echo ""
echo "For detailed usage instructions, see README.md"
echo ""

# Check if running on macOS and warn about packet capture permissions
if [[ "$OSTYPE" == "darwin"* ]]; then
    echo "Note for macOS users:"
    echo "- Packet capture requires administrator privileges"
    echo "- You may need to disable System Integrity Protection for full functionality"
    echo "- Consider running packet capture in a VM for security"
    echo ""
fi

echo "Setup completed successfully!" 