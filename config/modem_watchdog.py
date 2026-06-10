#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""
Modem Watchdog Daemon — config/modem_watchdog.py
Periodically checks the health of dial-up modems by querying them with AT commands.
If a modem hangs or locks up, it kills the associated mgetty and resets the USB port.
Part of Bounty D11.
"""

import os
import sys
import time
import subprocess
import logging
import serial
from typing import List, Dict

# Configuration
MODEM_PORTS = ["/dev/ttyModem0", "/dev/ttyModem1"]
CHECK_INTERVAL_SECONDS = 60
AT_TIMEOUT_SECONDS = 5
MAX_FAILURES_BEFORE_RESET = 3

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler("/var/log/modem_watchdog.log")
    ]
)

def reset_usb_device(port_path: str):
    """Reset the USB device node using the usbreset utility."""
    try:
        # Find physical USB sysfs path from tty node
        real_path = os.path.realpath(port_path)
        sys_path = f"/sys/class/tty/{os.path.basename(real_path)}/device"
        if os.path.exists(sys_path):
            usb_dir = os.path.dirname(os.path.realpath(sys_path))
            usb_bus_dev = os.path.basename(usb_dir) # e.g. "1-1.3" or "usb1"
            
            # Find USB bus and device numbers
            bus_file = os.path.join(usb_dir, "busnum")
            dev_file = os.path.join(usb_dir, "devnum")
            
            if os.path.exists(bus_file) and os.path.exists(dev_file):
                with open(bus_file, "r") as f:
                    bus = f.read().strip().zfill(3)
                with open(dev_file, "r") as f:
                    dev = f.read().strip().zfill(3)
                
                dev_path = f"/dev/bus/usb/{bus}/{dev}"
                logging.warning(f"🔄 Resetting USB device {dev_path} for port {port_path}...")
                
                # Execute usbreset
                subprocess.run(["usbreset", dev_path], check=True, stdout=subprocess.DEVNULL)
                return True
    except Exception as e:
        logging.error(f"❌ Failed to reset USB device: {e}")
    return False

def check_modem_health(port: str) -> bool:
    """Send AT query and verify OK response."""
    try:
        # Open serial port with timeout
        with serial.Serial(port, baudrate=115200, timeout=AT_TIMEOUT_SECONDS) as ser:
            # Clear input buffer
            ser.reset_input_buffer()
            # Send AT attention command
            ser.write(b"AT\r\n")
            # Read response
            response = ser.read_until(b"OK").decode("utf-8", errors="ignore")
            if "OK" in response:
                return True
    except (serial.SerialException, OSError) as e:
        logging.warning(f"⚠️ Serial exception on {port}: {e}")
    return False

def restart_mgetty_service(port: str):
    """Kill any running mgetty process on this port so init/systemd respawns it."""
    try:
        port_name = os.path.basename(port)
        logging.info(f"⚙️ Restarting mgetty for port {port_name}...")
        # Find mgetty processes matching this port
        subprocess.run(["pkill", "-f", f"mgetty.*{port_name}"], check=False)
    except Exception as e:
        logging.error(f"❌ Failed to restart mgetty service: {e}")

def main():
    logging.info("=== Starting RustChain Modem Watchdog Daemon ===")
    failures: Dict[str, int] = {port: 0 for port in MODEM_PORTS}
    
    while True:
        for port in MODEM_PORTS:
            if not os.path.exists(port):
                logging.error(f"❌ Modem port {port} does not exist. udev rules misconfigured?")
                continue
                
            is_healthy = check_modem_health(port)
            if is_healthy:
                if failures[port] > 0:
                    logging.info(f"🟢 Modem on {port} recovered after {failures[port]} failures.")
                failures[port] = 0
            else:
                failures[port] += 1
                logging.warning(f"⚠️ Modem on {port} failed check ({failures[port]}/{MAX_FAILURES_BEFORE_RESET}).")
                
                if failures[port] >= MAX_FAILURES_BEFORE_RESET:
                    logging.error(f"🚨 Modem on {port} is unresponsive! Initiating recovery...")
                    restart_mgetty_service(port)
                    reset_usb_device(port)
                    failures[port] = 0 # Reset counter after recovery attempt
                    
        time.sleep(CHECK_INTERVAL_SECONDS)

if __name__ == "__main__":
    # Ensure run as root for usbreset and pkill
    if os.geteuid() != 0:
        print("Error: Watchdog daemon must run as root.", file=sys.stderr)
        sys.exit(1)
    main()
