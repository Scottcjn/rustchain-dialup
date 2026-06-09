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
