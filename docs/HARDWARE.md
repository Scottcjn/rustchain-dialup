# Hardware — Bill of Materials

Sourcing notes for the LAN-island build (no phone company in the loop). Prices are
ballpark used/eBay figures as of June 2026 and will drift.

---

## 1. NAS host

Any small always-on Linux box. The DreamPi-proven baseline is a **Raspberry Pi 3 or 4**.
Already-owned hardware in the lab is fine — the only requirements are: free USB, Linux,
and uptime. Keep it *off* busy production boxes if possible so telephony stays isolated.

---

## 2. Answering modem(s) — the core piece

The modem that **answers** the call and talks to `mgetty`/`pppd`.

| Modem | Linux node | Notes |
|-------|-----------|-------|
| **Dell NW147 (Conexant RD02-D400)** ⭐ | `/dev/ttyACM0` | DreamPi gold standard. **No drivers** — plug and go. Cheap and plentiful. |
| Hayes Accura V.92 USB | `/dev/ttyACM0` | Works as a standard serial modem on Linux. |
| Zoom 3095 (Conexant CX930xx) | `/dev/ttyACM0` | Conexant chipset, GPL source exists. |
| USR Sportster / Courier (external serial) | `/dev/ttyUSB0` via USB-serial | Best for *authentic* AT-command tuning; physical DIP switches. |

**Recommendation:** buy **2× Dell NW147 / Conexant RD02-D400** with **explicit roles**:
one is the **NAS answer modem**, the other is a **bench dial-in client** so you can prove the whole
chain modem↔modem *before* a Dreamcast or 486 is ever involved. Treat USB Conexant units as
*candidates, not assumed-good* — `/dev/ttyACM0` appearing does **not** prove reliable answer-mode
data carrier; bench-validate the specific board revision. If a Conexant ACM modem fights `mgetty`,
fall back to a **USR Courier/Sportster on USB-serial** for hard RTS/CTS and DIP-switch line control.

> `ttyACM` = USB CDC-ACM class modem (most cheap USB modems). `ttyUSB` = a USB-serial
> bridge to a classic external modem. Both speak the Hayes/V.250 AT command set.

---

## 3. The "fake phone company" — line plant

Two modems can't train against each other on bare copper. Something must supply **dial tone,
ring voltage, and ~48V DC talk battery**. Pick one:

| Option | What it does | Approx. cost | When to use |
|--------|--------------|--------------|-------------|
| **Viking DLE-200B** ⭐ | Full two-way line simulator: real dial tone, talk battery, ring. One modem dials, the other rings + answers. | ~$150–200 new | Most realistic; cleanest training; supports dialing between the two ports. |
| **DreamPi line inducer** | Injects DC talk current so the answering modem holds the line. **Does NOT by itself provide dial tone, ringing, or call routing** — it must be paired with an ATA/FXS for the dialing modem. Not a $20-and-done substitute for the DLE-200B. | ~$20 + an ATA | Cheapest; the proven DreamPi trick, but only for the *answer-and-hold* case. |
| **2× Grandstream HT802 + Asterisk** | Each modem plugs into an FXS port; Asterisk bridges the call over SIP. | ~$60 (2 ATAs) | Doubles as the VoIP↔analog bridge for later phases. |

**Recommendation for fastest working demo:** **Viking DLE-200B**. It behaves the most like a
real line, so modem training "just works" and you spend time on software, not on chasing why a
modem won't pick up. If budget is tight, the **line inducer** path is proven by DreamPi.

---

## 4. Future: VoIP↔analog + real PSTN reach

| Part | Role | Approx. cost |
|------|------|--------------|
| **Grandstream HT802** (×1–2) | FXS analog ports ↔ SIP. The micro-PBX + the modem-relay bridge. | ~$30 used each |
| Asterisk (software) | PBX / call routing / G.711 passthrough for modem relay | free |
| SIP trunk (service) | A real phone number to dial into | varies |

> **Reality check:** modem relay over VoIP is hard. Force **G.711 µ-law passthrough** (no
> compression), expect to **train down to V.34 (~33.6k) or 9600/14400**, and accept that **56k
> V.90/V.92 will not negotiate** over a VoIP path. Plan the BBS + mining UX around slow links.

---

## 5. Consumables

- RJ11 phone cables (a handful)
- Possibly RJ11 splitters / line cords to match the client modems
- For Dreamcast: the standard DC modem (33.6k US / region-dependent)

---

## Suggested first order (LAN island)

1. 2× Dell NW147 / Conexant RD02-D400 USB modem
2. 1× Viking DLE-200B line simulator  *(or)*  1× line-inducer kit + 1× HT802 for dial tone
3. RJ11 cables
4. (the Pi / Linux host you already have)

Once Phase 4 (mining over dial-up) is proven, add HT802(s) + stand up Asterisk for VoIP/PSTN.
