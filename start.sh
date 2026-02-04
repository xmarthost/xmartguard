#!/bin/bash
# XMartGuard Startup Script

# Set Node.js path (adjust based on your system)
if [ -d "/opt/alt/alt-nodejs22/root/usr/bin" ]; then
    export PATH="/opt/alt/alt-nodejs22/root/usr/bin:$PATH"
elif [ -d "/opt/cpanel/ea-nodejs22/bin" ]; then
    export PATH="/opt/cpanel/ea-nodejs22/bin:$PATH"
elif [ -d "/opt/cpanel/ea-nodejs20/bin" ]; then
    export PATH="/opt/cpanel/ea-nodejs20/bin:$PATH"
elif [ -d "/opt/cpanel/ea-nodejs18/bin" ]; then
    export PATH="/opt/cpanel/ea-nodejs18/bin:$PATH"
fi

cd /opt/xmartguard
exec node server.js
