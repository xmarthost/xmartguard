#!/usr/bin/env python3
import os
import sys
import time
import json
import socket
import argparse
import requests
import psutil

VERSION = "2.0.0"

def get_metrics():
    cpu = psutil.cpu_percent(interval=1)
    mem = psutil.virtual_memory()
    disk = psutil.disk_usage('/')
    load = os.getloadavg()
    net = psutil.net_io_counters()
    
    return {
        "cpu": cpu,
        "memory": mem.percent,
        "disk": disk.percent,
        "load_avg": list(load),
        "uptime": time.time() - psutil.boot_time(),
        "network": {"rx": net.bytes_recv, "tx": net.bytes_sent},
        "system_info": {
            "hostname": socket.gethostname(),
            "os": f"{os.uname().sysname} {os.uname().release}",
            "kernel": os.uname().release,
            "arch": os.uname().machine,
            "cpu_model": open('/proc/cpuinfo').read().split('model name')[1].split(':')[1].split('\n')[0].strip() if os.path.exists('/proc/cpuinfo') else "Unknown",
            "cpu_count": psutil.cpu_count()
        }
    }

def send_metrics(server_url, token):
    try:
        metrics = get_metrics()
        response = requests.post(
            f"{server_url}/api/agent/metrics",
            json=metrics,
            headers={
                "X-Agent-Token": token,
                "X-Agent-Version": VERSION,
                "Content-Type": "application/json"
            },
            timeout=30
        )
        data = response.json()
        if data.get("problems"):
            print(f"Problems detected: {len(data['problems'])}")
        return True
    except Exception as e:
        print(f"Error: {e}")
        return False

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--server", required=True)
    parser.add_argument("--token", required=True)
    parser.add_argument("--interval", type=int, default=60)
    args = parser.parse_args()
    
    print(f"XMartGuard Agent v{VERSION}")
    print(f"Server: {args.server}")
    print(f"Interval: {args.interval}s")
    
    while True:
        send_metrics(args.server, args.token)
        time.sleep(args.interval)

if __name__ == "__main__":
    main()
