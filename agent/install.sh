#!/bin/bash
set -e
TOKEN="$1"
SERVER_URL="$2"
if [ -z "$TOKEN" ] || [ -z "$SERVER_URL" ]; then
    echo "Usage: $0 <TOKEN> <SERVER_URL>"
    exit 1
fi
if [ "$EUID" -ne 0 ]; then
    echo "Please run as root (sudo)"
    exit 1
fi

INSTALL_DIR="/opt/xmartguard-agent"
mkdir -p "$INSTALL_DIR"

echo "Installing XMartGuard Agent..."

# Install dependencies
if command -v apt-get &> /dev/null; then
    apt-get update -qq && apt-get install -y -qq python3 python3-pip curl
elif command -v yum &> /dev/null; then
    yum install -y -q python3 python3-pip curl
fi

pip3 install psutil requests --quiet 2>/dev/null || pip install psutil requests --quiet

# Download agent
curl -sSL "${SERVER_URL}/downloads/agent.py" -o "$INSTALL_DIR/agent.py"
chmod +x "$INSTALL_DIR/agent.py"

# Create systemd service
cat > /etc/systemd/system/xmartguard-agent.service << EOF
[Unit]
Description=XMartGuard Monitoring Agent
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 ${INSTALL_DIR}/agent.py --server ${SERVER_URL} --token ${TOKEN} --interval 60
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable xmartguard-agent
systemctl start xmartguard-agent

echo ""
echo "✓ XMartGuard Agent installed successfully!"
echo "  Status: $(systemctl is-active xmartguard-agent)"
echo ""
