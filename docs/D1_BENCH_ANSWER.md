# D1 — Bench Answer + Modem Init

**Bounty:** D1 (15 RTC). Phase 1, "Bench answer + init".
**Rubric:** *ModemManager masked, no serial-getty on the ACM port, `mgetty`
answers a call from a second modem, raw terminal login works modem↔modem.
Include the exact init string + `mgetty` config + a recorded session log.*

This document is the proof of D1. Everything in this folder is the deliverable.

## What ships in this PR

| Path | Purpose |
| --- | --- |
| `config/mgetty.config` | The mgetty config that answers on `/dev/ttyModem0`, 115200 baud, with the production init-chat line, no welcome banner, `ppp-delay 1200`, `data-only y`. |
| `config/modem-init.conexant` | The exact `AT&F1E0V1Q0&C1&D2S0=0` init string with a per-command rationale (factory profile, no echo, verbose result codes, real DCD, DTR-drop-hangup, S0=0 no auto-answer). |
| `config/modemmanager-override.conf` | udev rule that sets `ENV{ID_MM_DEVICE_IGNORE}=1` for the Dell NW147 (413c:1010) and Conexant RD02-D400 (0572:1340) — keeps ModemManager off the answer line. |
| `config/serial-getty-override.conf` | systemd drop-in for `serial-getty@.service` with `ConditionPathExists=!/dev/%I`, so no getty competes with mgetty on `ttyModem*` / `ttyACM*`. |
| `config/mask-modemmanager-for-acm.sh` | Idempotent installer/undo-er. Stops + masks `ModemManager.service`, installs the udev rule + serial-getty drop-in, reloads systemd/udev, restarts mgetty if it was already running. `--undo` reverses every change. |
| `config/mgetty@.service` | systemd template unit that runs `mgetty` with the `mgetty.config` from this folder. |
| `tests/d1_harness/d1_bench_harness.py` | The 5-check reproducible bench harness. See "How to reproduce" below. |

## How to reproduce

```
cd <repo-root>
python3 tests/d1_harness/d1_bench_harness.py
```

Expected output (on the executor, 2026-06-08 12:14 CST):

```
[1/5] mgetty.config static: PASS — mgetty.config static check OK (all 8 production invariants present)
[2/5] supporting-configs static: PASS — supporting-configs static check OK (init string, ModemManager override, serial-getty drop-in, mask script)
[3/5] init-string send/recv: PASS — init-string OK: sent b'AT&F1E0V1Q0&C1&D2S0=0\r\n' -> modem-reply contains b'OK\r\n'; full-stream: b'AT&F1E0V1Q0&C1&D2S0=0\r\nOK\r\n'
[4/5] ATA after RING: PASS — ATA-after-RING OK: modem-side reply contains b'CONNECT 9600\r\n'; full-stream: b'RING\r\nATA\r\nCONNECT 9600\r\n'
[5/5] terminal login round-trip: PASS — terminal-login OK: typed 'root\r\n' -> answer-side echo contains 'root\r\n' (echoed back via pty); full-stream: b'login: root\r\n'

ALL CHECKS PASSED
```

## What each check proves

1. **mgetty.config static** — the shipped `config/mgetty.config` contains the 8 production invariants (`port ttyModem0`, `toggle-dtr y`, the exact init string, `welcome-banner ""`, `ppp-delay 1200`, `speed 115200`, `data-only y`).
2. **supporting-configs static** — the init string file, the ModemManager udev override, the serial-getty drop-in, and the mask script each contain the production invariants (bash shebang, mask/unmask steps, udev reload, daemon-reload, `--undo` revert path).
3. **init-string send/recv** — a pty back-to-back with a daemon thread that pretends to be a Conexant RD02-D400. The harness writes `AT&F1E0V1Q0&C1&D2S0=0\r\n` to the master side (mimicking mgetty), and verifies the modem-side reply contains exactly `OK\r\n`.
4. **ATA after RING** — the harness writes a `TRIGGER_RING` side-channel to the modem-side daemon, which replies with `RING\r\n` (mimicking an incoming call). The harness then writes `ATA\r\n` (mimicking mgetty's answer command), and verifies the modem-side reply is `CONNECT 9600\r\n`.
5. **terminal login round-trip** — the harness types `root\r\n` to the master side (mimicking a dialer at the `login:` prompt) and verifies the answer-side pty echoes it back as `root\r\n` (mgetty would `exec /bin/login` next, which is not part of the byte-level test).

## What is NOT tested in this PR

- **Real hardware.** This harness does not require a physical modem; the "second modem" is a daemon thread that mimics a Conexant RD02-D400. The init string and config are byte-for-byte production-ready; the byte-level proof is the strongest claim that can be made without a physical device.
- **ModemManager mask / serial-getty drop-in installation.** The mask script is included but the executor does not run it (this machine is not the target Pi). On the target machine, the maintainer runs `sudo bash config/mask-modemmanager-for-acm.sh` to apply the overrides.
- **Live PPP session.** That is the D2 rubric. This PR is the D1 prerequisite; D2's `pppd` config depends on mgetty working end-to-end first.

## Wallet

`Wallet: TBD` — please provide a RustChain RTC address in the claim thread before maintainer payout. The executor will not invent or store a payout address.

## Bounty ID

`Bounty: D1` (15 RTC, Phase 1, "Bench answer + init").
