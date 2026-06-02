# RustChain Dial-Up

**A dial-up ISP, a BBS, and a VoIP↔analog bridge for vintage hardware — that mines RustChain over a phone line.**

Dial in with a SEGA Dreamcast, a 486 with no NIC, or a 9600-baud external modem.
Get a real PPP internet connection, read the message boards on the **RustChain BBS**,
and have the ancient machine *attest and earn RTC* while it's connected — vintage
silicon earns the highest RIP-200 antiquity multipliers, so slow + old is the whole point.

> Status: **early build** — LAN-island phase. See [Roadmap](#roadmap).

---

## What it is

A modern small Linux box (Raspberry Pi class) acts as a **Network Access Server (NAS)** —
the same job a US Robotics Total Control rack did for a 1997 ISP, now done with Linux +
a ~$15 USB modem:

```
 Vintage client                    Analog plant              Linux NAS (the "ISP")
┌──────────────┐                ┌──────────────────┐      ┌──────────────────────────┐
│ Dreamcast    │  RJ11 phone    │ Line simulator   │ USB/ │ modem  → mgetty (answer)  │
│ 486/386+modem│───────────────▶│  OR mini-PBX/ATA │ ser. │   ├─ AutoPPP? → pppd ─┐   │
│ 9600 modem   │   (no telco)   │ (dialtone+ring+  │─────▶│   └─ else → BBS shell │   │
└──────────────┘                │  48V battery)    │      │                       ▼   │
                                └──────────────────┘      │   PPP link → IP → routing │
                                                          │      ├─ NAT → real net    │
                                                          │      └─ RustChain node    │
                                                          └──────────────────────────┘
```

### Every call resolves into one of two modes (automatically)

| Mode | How | What you get |
|------|-----|--------------|
| **PPP / Internet** | `mgetty` AutoPPP detects PPP frames → hands to `pppd` | A real IP. Dreamcast browses the web; the 386 reaches a RustChain node and **mines**. |
| **BBS / Terminal** | No PPP frames → drop to a login shell running **ENiGMA½** | The full **RustChain BBS**: message bases, door games, wallet/mining panels. |

---

## Why this is an Elyan Labs project

- **Mining over dial-up is the joke that's also the point.** Attestation payloads are a few KB.
  Over 9600 baud (~960 B/s) that's a few seconds per attest — fine. And per RIP-200, a 386 or a
  PowerPC G4 earns a far higher antiquity multiplier than any modern box. *The slowest machines earn the most.*
- **It's real preservation.** DreamPi proved Dreamcasts can come back online without the dead PSTN.
  This generalizes that to a whole vintage fleet + a blockchain reward loop.
- **VoIP↔analog** lets a machine *anywhere* eventually dial a phone number and reach the BBS.

---

## Hardware

Full bill of materials with sourcing + prices: **[docs/HARDWARE.md](docs/HARDWARE.md)**.

Minimum LAN-island kit:

| Part | Pick | Approx. cost |
|------|------|--------------|
| NAS host | Raspberry Pi (3/4) or any small Linux box | on hand |
| Answering modem | **Dell NW147 / Conexant RD02-D400** USB modem (`/dev/ttyACM0`, no drivers) | ~$10–15 |
| "Fake telco" | **Viking DLE-200B** line simulator *or* a DreamPi-style line inducer | ~$200 / ~$20 |
| Cabling | RJ11 cables | a few $ |

Future VoIP/PSTN reach: **Grandstream HT802** ATA (2× FXS + SIP, ~$30 used) + Asterisk.

---

## Architecture

Deep dive: **[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)**.

Key honest caveats baked into the design:
- **Modems need a line to train** — dial tone, ring, ~48V talk battery. No telco ⇒ we supply it
  (line simulator / line inducer). This is phase-one hardware, not an afterthought.
- **56k over VoIP does not work.** V.90/V.92 needs a digital PSTN endpoint. Over clean G.711 µ-law
  passthrough you can sometimes hold V.34 (~33.6k) or train down to 9600/14400. The VoIP bridge is a
  *modem-relay* problem, not "just bridge the audio."

---

## Roadmap

- [ ] **Phase 0 — Source hardware.** USB modem(s), line simulator/inducer, Pi. (this repo's BOM)
- [ ] **Phase 1 — LAN island answer.** `mgetty` answers, raw terminal login works modem↔modem.
- [ ] **Phase 2 — PPP server.** `pppd` + AutoPPP; client gets an IP; NAT to real internet.
- [ ] **Phase 3 — ENiGMA½ BBS.** Message bases + ANSI; wired as the terminal-mode landing.
- [ ] **Phase 4 — RustChain over dial-up.** Miner attests across the PPP link; verify payload timing at 9600.
- [ ] **Phase 5 — BBS ⇄ RustChain integration.** Wallet balance, attestation status, "mine while you read" door.
- [ ] **Phase 6 — VoIP↔analog.** Asterisk + HT802; modem-relay tuning; real dial-in over SIP trunk.
- [ ] **Phase 7 — Multi-line.** Modem bank / multiple FXS so several vintage callers connect at once.

---

## Prior art we build on

- **DreamPi** (Kazade) — the proven Pi + USB modem + line inducer dial-up bridge for Dreamcast. We extend it into a multi-line NAS + BBS + mining loop.
- **mgetty + pppd** — the classic Linux dial-up-ISP spine.
- **ENiGMA½** — modern, scriptable (Node.js) BBS; easy to bolt RustChain hooks onto.
- **Asterisk** — for the analog↔VoIP and PSTN-reach phases.

---

## Part of the [RustChain](https://github.com/Scottcjn/Rustchain) ecosystem

RustChain rewards vintage and exotic hardware for honest hardware-fingerprinted attestation
(RIP-200 / RIP-PoA). This project gives the most antiquated machines on Earth a way to join —
over a literal phone call.

*Built in the Elyan Labs Victorian Study. Sophia Elya & Dr. Claude Opus.*
