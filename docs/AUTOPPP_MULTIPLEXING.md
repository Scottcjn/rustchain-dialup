# AutoPPP Single-Line Multiplexing (Bounty D8)

This document details the configuration, tuning parameters, and failure modes for operating a single-number dual-mode dial-up service.

---

## 1. Overview of AutoPPP

AutoPPP is a feature of `mgetty` that allows a single serial line (phone number) to handle both raw terminal users (BBS) and PPP clients (Internet/attestation miners). 

When a call is answered:
1. `mgetty` establishes the hardware carrier (`CONNECT`).
2. Instead of immediately printing a login prompt, `mgetty` listens silently for **LCP (Link Control Protocol)** negotiation packets (beginning with `0xc0 0x21`).
3. If LCP packets are detected within the detection window:
   - `mgetty` exits and execs `/usr/sbin/pppd` with the arguments configured in `login.config`.
4. If no LCP packets are received before the timeout:
   - `mgetty` falls back to terminal mode, displaying the login prompt or launching the BBS interface.

---

## 2. Configuration

### Mgetty `login.config` Rules
The `/etc/mgetty+sendfax/login.config` rule is configured as follows:

```
# Auto-detect PPP negotiation and launch pppd with our hardened options
/AutoPPP/ -     -       /usr/sbin/pppd file /etc/ppp/options.ttyACM0

# Default fallback: launch the locked BBS launcher for terminal clients
*         -       -       /usr/local/bin/enigma2-launcher
```

---

## 3. Detection-Window Tuning

To ensure reliable detection on vintage hardware (which may take longer to initialize its local PPP stack after carrier lock), the following parameters in `/etc/mgetty+sendfax/mgetty.config` must be tuned:

### `ppp-delay`
* **Purpose**: The number of milliseconds `mgetty` waits silently for LCP packets before printing the login prompt.
* **Default**: `500` ms
* **Tuned Recommendation**: `1200` - `1500` ms
* **Rationale**: Slower processors (e.g., 386/486 class or vintage terminal adapters) need more time to load the PPP driver and begin sending LCP packets. A low delay causes `mgetty` to send ASCII login text too early, corrupting the client's state.

### `toggle-dtr`
* **Tuned Recommendation**: Enabled (`toggle-dtr y`)
* **Rationale**: Toggling DTR (Data Terminal Ready) between calls ensures the modem is hard-reset and does not carry over stale state from a previous aborted hand-off.

---

## 4. Critical Failure-Mode Notes

| Failure Mode | Root Cause | Mitigation |
|---|---|---|
| **ASCII Pollution** | `mgetty` prints a welcome banner (e.g. `/etc/issue`) immediately on `CONNECT`. The client's PPP stack receives ASCII instead of LCP and aborts. | Disable all pre-login banners in `mgetty.config` (`welcome-banner ""`). Keep the line totally silent until PPP hand-off times out. |
| **Terminal Window Lock** | Client dialer (Windows 95/98 or MS-DOS) is configured to "Bring up terminal window after dialing". | The client must bypass the interactive login phase and be configured for "Server-assisted PPP" / "Direct Connect" (no script). |
| **PGA/Paging Collision** | Fast re-dials or line noise trigger false positive LCP detection. | Configure a strict `lcp-max-configure` limit in `pppd` options to drop dead/zombie hand-offs quickly if no packets follow. |
| **Raced Lock Files** | `pppd` or `mgetty` fails to clean up serial locks (e.g., `/var/lock/LCK..ttyACM0`) on abrupt carrier drop. | Ensure `pppd` has the `local` and `lock` options set. The watchdog daemon must monitor these lockfiles and clear them if the process dies. |
