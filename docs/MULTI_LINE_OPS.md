# Multi-Line Operations & Watchdog Setup (Bounty D11)

This document details the configuration for stable multi-line modem operations, including persistent udev naming, automated health monitoring, and usbreset recovery.

---

## 1. Persistent Modem Naming via udev

USB modems are assigned names like `/dev/ttyACM0` or `/dev/ttyACM1` dynamically by the kernel at boot. If modems are unplugged, re-ordered, or rebooted, these names can swap. This breaks `mgetty` and `pppd` configurations which rely on fixed paths.

### udev Rules
To fix this, we bind modems to stable symlinks (`/dev/ttyModem0` and `/dev/ttyModem1`) based on their physical USB port routing paths (`ID_PATH` attributes).

Deploy `/etc/udev/rules.d/99-modems.rules`:
```udev
# Line 1 - Physical USB Port 1.3
SUBSYSTEM=="tty", ENV{ID_PATH}=="*-usb-0:1.3:1.0", SYMLINK+="ttyModem0", MODE="0660", GROUP="dialout"

# Line 2 - Physical USB Port 1.4
SUBSYSTEM=="tty", ENV{ID_PATH}=="*-usb-0:1.4:1.0", SYMLINK+="ttyModem1", MODE="0660", GROUP="dialout"
```

To find your device's exact `ID_PATH` attribute, run:
```bash
udevadm info --query=property --name=/dev/ttyACM0 | grep ID_PATH=
```

Apply the rules without rebooting:
```bash
sudo udevadm control --reload-rules
sudo udevadm trigger
```

---

## 2. Watchdog & Recovery Daemon

Modems operating 24/7 on simulated lines can lock up due to line noise, buffer overflow, or firmware hangs. When this happens, they stop answering incoming calls.

The `modem_watchdog.py` daemon monitors these lines:
1. Opens `/dev/ttyModemX` and sends an `AT` query.
2. Expects a decoded `OK` response within 5 seconds.
3. If it fails 3 consecutive checks (3 minutes):
   - Kills the corresponding `mgetty` process on that port.
   - Resets the underlying USB device node via `usbreset` (which power cycles the Conexant chip).
   - `init` or `systemd` automatically respawns `mgetty` on the reset port.

---

## 3. Installation

1. Copy the udev rules to the system directory:
   ```bash
   sudo cp config/99-modems.rules /etc/udev/rules.d/
   sudo udevadm control --reload-rules && sudo udevadm trigger
   ```

2. Copy the watchdog daemon script:
   ```bash
   sudo mkdir -p /etc/rustchain
   sudo cp config/modem_watchdog.py /etc/rustchain/
   sudo chmod +x /etc/rustchain/modem_watchdog.py
   ```

3. Enable the systemd service:
   ```bash
   sudo cp config/modem-watchdog.service /etc/systemd/system/
   sudo systemctl daemon-reload
   sudo systemctl enable --now modem-watchdog.service
   ```
