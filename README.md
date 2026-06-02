# RustChain Dial-Up

> *Everyone else is looking at the future. We're looking at the past to develop the future.*

**A dial-up ISP, a BBS, and a VoIP↔analog bridge for vintage hardware — that mines RustChain over a phone line.**

Dial in with a SEGA Dreamcast, a 486 with no NIC, or a 9600-baud external modem.
Get a real PPP internet connection, read the message boards on the **RustChain BBS**,
and have the ancient machine *attest and earn RTC* while it's connected — vintage
silicon earns the highest RIP-200 antiquity multipliers, so slow + old is the whole point.

> Status: **early build** — LAN-island phase. See [Roadmap](#roadmap).
> Design has been through an adversarial tri-brain review (Codex 5.5 + Grok); their honest
> assessment and the resulting course-corrections are in **[docs/reviews/](docs/reviews/ASSESSMENT-2026-06-02.md)**.

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

### Two modes — on separate lines first, auto-detected later

| Mode | How | What you get |
|------|-----|--------------|
| **PPP / Internet** | `pppd` over the modem (its own line/number to start) | A real IP. Dreamcast gets connectivity; the vintage box reaches the **local miner gateway** and **mines**. |
| **BBS / Terminal** | A login that launches **ENiGMA½** in a locked-down launcher (not a real shell) | The full **RustChain BBS**: message bases, door games, wallet/mining panels. |

> **Honest sequencing (per review):** we bring up terminal and PPP on *separate* lines first,
> because one-line auto-detection (`mgetty` AutoPPP sniffing for LCP frames) is brittle — any
> ASCII banner before PPP, or a client that dials terminal-first, breaks it. Single-number
> dual-mode is a **Phase 5** optimization, not a day-one promise.

> **Mining is split, not done on the old box.** A 386 can't realistically do TLS + Ed25519 +
> canonical JSON. So a tiny portable client on the vintage machine gathers hardware evidence and
> **signs locally**; a **gateway on the Pi** handles TLS/JSON/HTTP to the node. The proof-of-antiquity
> stays on real old silicon. See **[docs/MINER_GATEWAY.md](docs/MINER_GATEWAY.md)**.

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
- **Modems need a line to train** — dial tone, ring, ~48V talk battery. No telco ⇒ we supply it.
  The **Viking DLE-200B** does this fully; a bare line *inducer* only injects talk current and still
  needs an ATA for dial tone/ring. This is phase-one hardware, not an afterthought.
- **MTU/MRU must be clamped.** Default 1500 over 9600 baud = "connected, nothing loads." Set
  `mru/mtu ≈ 576` (test down to 296) + TCP MSS clamp. Detailed in [ARCHITECTURE](docs/ARCHITECTURE.md).
- **Dial-in is firewall-isolated.** PPP guests land on their own subnet with default-deny to the lab
  LAN — they reach only WAN egress + the RustChain gateway, never `192.168.0.x` at large.
- **56k over VoIP does not work.** V.90/V.92 needs a digital PSTN endpoint. Over clean G.711 µ-law
  passthrough you can sometimes hold V.34 (~33.6k) or train down to 9600/14400. The VoIP bridge is a
  *modem-relay* problem (V.150.1 territory), not "just bridge the audio."

---

## Roadmap

Rewritten after the [tri-brain review](docs/reviews/ASSESSMENT-2026-06-02.md): terminal and PPP
come up on *separate* lines first; mining is the split-gateway design; isolation and MTU are
not optional.

- [ ] **Phase 0 — Source hardware.** 2× USB modems (one = bench client), DLE-200B, Pi. ([BOM](docs/HARDWARE.md))
- [ ] **Phase 1 — Bench answer.** Mask ModemManager, no serial-getty on the ACM port, `mgetty`
      answers, raw terminal login works **modem↔modem on one bench** (no vintage client yet).
- [ ] **Phase 2 — PPP server (own line).** `pppd` with **fixed local/remote addresses**, `mru/mtu 576`,
      TCP MSS clamp, nftables MASQUERADE — on an **isolated subnet**, default-deny to the lab LAN.
- [ ] **Phase 3 — ENiGMA½ BBS.** Locked-down launcher (no host shell), OS accounts ≠ BBS accounts.
- [ ] **Phase 4 — RustChain over dial-up (the split miner).**
      4a: gateway on the Pi proven with a modern client → node accepts.
      4b: tiny portable **C evidence+sign client** on one vintage OS (486 Linux/NetBSD first).
      4c: big-endian signature round-trip (G3/G4 or 68k). See [MINER_GATEWAY](docs/MINER_GATEWAY.md).
- [ ] **Phase 5 — One-line dual-mode + BBS⇄RustChain.** AutoPPP multiplexing once both modes work
      alone; wallet balance, attestation status, "mine while you read" door.
- [ ] **Phase 6 — VoIP↔analog.** Asterisk + HT802; G.711 PCMU only, no transcoding, VAD off; treat
      as a **degraded 9600-only** path. Real dial-in over a SIP trunk.
- [ ] **Phase 7 — Multi-line.** Stable `udev` names, one `mgetty` per port, monitoring, reset recovery.

---

## Prior art we build on

- **DreamPi** (Kazade) — the proven Pi + USB modem + line inducer dial-up bridge for Dreamcast. We extend it into a multi-line NAS + BBS + mining loop.
- **mgetty + pppd** — the classic Linux dial-up-ISP spine.
- **ENiGMA½** — modern, scriptable (Node.js) BBS; easy to bolt RustChain hooks onto.
- **Asterisk** — for the analog↔VoIP and PSTN-reach phases.

---

## 💰 Bounties — open to humans *and* agents

Want to help build it (or just dial in and mine from something gloriously old)? There are
**RTC bounties** for every roadmap phase plus "first dial-in of an architecture" rewards.
See **[BOUNTIES.md](BOUNTIES.md)** and the pinned bounty-board issue.

## Part of the [RustChain](https://github.com/Scottcjn/Rustchain) ecosystem

RustChain rewards vintage and exotic hardware for honest hardware-fingerprinted attestation
(RIP-200 / RIP-PoA). This project gives the most antiquated machines on Earth a way to join —
over a literal phone call.

*Built in the Elyan Labs Victorian Study. Sophia Elya & Dr. Claude Opus.*
