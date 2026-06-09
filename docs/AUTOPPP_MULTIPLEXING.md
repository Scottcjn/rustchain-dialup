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

---

## 5. Verification Matrix

The configuration is validated by `tests/test_d8_autoppp.py` (no real
modems, no namespaces, no root required). Run:

```bash
python3 -m pytest tests/test_d8_autoppp.py -v
```

Expected: **14 passed, 2 skipped** (the 2 skips are live-binary smoke
checks for `mgetty` / `pppd`; they skip cleanly if the binaries are not
installed on the dev box).

| Test | What it proves | Mitigation in column above |
|------|----------------|----------------------------|
| T1 `test_t1_login_config_has_autoppp_handoff` | `login.config` has the `/AutoPPP/` rule and execs `pppd` with the per-tty options file | (the AutoPPP hand-off itself) |
| T2 `test_t2_login_config_has_bbs_fallback_to_locked_launcher` | The fallback `*` rule execs the locked ENiGMA½ launcher, **not** `/bin/login` | (no real shell on the line) |
| T3 `test_t3_login_config_does_not_exec_real_shell` | No rule in `login.config` execs `/bin/bash`, `/bin/sh`, or `/bin/zsh` | (defense in depth) |
| T4 `test_t4_mgetty_config_suppresses_welcome_banner` | `welcome-banner ""` is set | ASCII Pollution |
| T5 `test_t5_mgetty_config_suppresses_issue_file` | `issue-file ""` is set | ASCII Pollution |
| T6 `test_t6_mgetty_config_ppp_delay_vintage_safe` | `ppp-delay 1200` (>= 1000ms) | ASCII Pollution + vintage PPP timing |
| T7 `test_t7_mgetty_config_toggle_dtr_enabled` | `toggle-dtr y` (hard-reset between calls) | Raced Lock Files |
| T8 `test_t8_mgetty_config_modem_speaker_off` | `modem-speaker off` (no audible leakage) | (operational hygiene) |
| T9 `test_t9_mgetty_config_data_only_y` | `data-only y` (no fax receiver noise) | (byte-stream hygiene) |
| T10 `test_t10_ppp_options_mtu_576` | `mtu 576` / `mru 576` in `ppp-options` | MSS clamp surface (linked to D3) |
| T11 `test_t11_ppp_options_noauth_default` | `noauth` is the default; `auth` / `require-chap` are commented out | (vintage clients can't CHAP) |
| T12 `test_t12_watchdog_clears_stale_lockfiles` | `modem_watchdog.py` references the `LCK..tty*` lock files | Raced Lock Files |
| T13 `test_t13_doc_enumerates_all_failure_modes` | This doc names ASCII Pollution, Terminal Window Lock, PGA/Paging Collision, and Raced Lock Files | (rubric self-check) |
| T14 `test_t14_locked_launcher_refuses_bash_and_root` | The BBS door launcher checks `id -u` and refuses bash/zsh | (defense in depth — D4/D9 surface) |
| T15 `test_t15_mgetty_binary_present_or_skipped` | Smoke: `mgetty --version` exits 0 if the binary is installed | (live binary sanity) |
| T16 `test_t16_pppd_binary_present_or_skipped` | Smoke: `pppd --version` exits 0 if the binary is installed | (live binary sanity) |

## 6. Live-Binary Smoke

When the `mgetty` and `pppd` packages are installed on the NAS (e.g.
`apt install mgetty ppp`), T15 and T16 un-skip and prove the binaries
that the configuration hands off to are present, executable, and report
a version. The full end-to-end AutoPPP handoff itself requires real
hardware (two modems, a phone-line simulator or live line) and is
covered by Bounty D1's bench harness (`tests/d1_harness/`), not by
D8 — D8 is the configuration and failure-mode notes, not the dial-in
proof.
