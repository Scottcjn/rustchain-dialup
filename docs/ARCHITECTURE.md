# Architecture

## The big picture

A dial-up ISP is a **Network Access Server (NAS)**: a machine that answers modem calls,
authenticates the caller, and bridges them onto a network. We rebuild that with Linux:

```
                          ┌─────────────────────── Linux NAS (Pi class) ───────────────────────┐
 client modem  ──RJ11──▶  │  /dev/ttyACM0                                                       │
 (Dreamcast /  ◀──train── │     │                                                               │
  486 / 9600)             │     ▼                                                               │
                          │   mgetty  ──answers, runs AT init, watches the byte stream──        │
                          │     │                                                               │
                          │     ├── sees PPP LCP frames (AutoPPP) ──▶  pppd  ──┐                 │
                          │     │                                              ▼                 │
                          │     │                                   PPP iface ppp0 (10.x.x.2)    │
                          │     │                                              │                 │
                          │     │                                     ┌────────┴────────┐        │
                          │     │                                     ▼                 ▼        │
                          │     │                          NAT/route to internet   RustChain node│
                          │     │                                                  (attest/mine) │
                          │     └── no PPP ──▶  login ──▶  ENiGMA½ BBS (terminal mode)            │
                          └────────────────────────────────────────────────────────────────────┘
```

## Component responsibilities

### `mgetty`
- Owns the modem device. Initializes it (`AT&F`, answer config), waits for `RING`, answers (`ATA`).
- **AutoPPP**: inspects the first bytes after CONNECT. If they look like PPP (LCP `0x7e ... 0xff 0x03 0xc0 0x21`), it execs `pppd` directly. Otherwise it runs the normal `/bin/login` path → BBS.
- Config: `/etc/mgetty/mgetty.config`, `/etc/mgetty/login.config`.

### `pppd`
- Negotiates the PPP link, assigns the client a local IP from a small pool, sets routes/DNS.
- Server options in `/etc/ppp/options.ttyACM0`; per-user/IP in `/etc/ppp/pap-secrets` (or chap).
- The caller now has real IP connectivity.

### Routing layer
- `net.ipv4.ip_forward=1` + `iptables`/`nftables` MASQUERADE so PPP clients reach the real internet.
- A route (or the node living on-box) so PPP clients reach a **RustChain attestation node**.

### ENiGMA½ BBS (terminal mode)
- The landing experience when the call is *not* PPP. Message bases, ANSI art, door games.
- Node.js + scriptable ⇒ RustChain panels (wallet balance, attestation status, "mine while you read").
- Runs as the shell/program for the dial-in login user.

## The two-mode decision (why AutoPPP matters)

A Dreamcast dials its ISP and immediately speaks **PPP** — it wants internet, not a text BBS.
A retro terminal program (Telix, ProComm) dials and speaks **plain ASCII** — it wants the BBS.
AutoPPP lets *one phone number / one modem* serve both: the byte pattern after CONNECT decides.

## RustChain over dial-up

Once `ppp0` is up, the vintage client has an IP and can hit a RustChain node's HTTP API:

- **Attestation payload** is small JSON (device fingerprint + signals + Ed25519 signature),
  on the order of a few KB. At 9600 baud (~960 B/s) that's a handful of seconds per attest —
  acceptable, since attestation TTL is 24h, not per-second.
- The miner runs **on the vintage machine** (or a thin client of it). Big-endian / ancient
  Python builds may need the `antique-ports` patterns; the wire protocol is just HTTP + JSON.
- **Reward angle:** RIP-200 antiquity multipliers reward old silicon (G4 2.5×, retro x86 1.4×,
  POWER8 1.5×, modern x86 0.8×). A 386 dialing in is *more* valuable per attest than a modern box.
- Anti-emulation / hardware-fingerprint checks still apply — a dial-up link doesn't bypass them.

## The VoIP↔analog seam (future phases)

We keep an **Asterisk-shaped seam** in the design so the LAN island upgrades to real dial-in
without a rewrite:

```
 LAN island today:    client-modem ──RJ11──▶ line simulator ──RJ11──▶ server-modem ──▶ NAS
 SIP/PSTN later:      client-modem ──FXS HT802──▶ Asterisk ──SIP──▶ HT802 FXS──▶ server-modem ──▶ NAS
                                                     └── SIP trunk ──▶ real phone number (dial-in)
```

Modem-relay constraints (must be respected or modems won't connect):
- **G.711 µ-law passthrough only** — disable codec compression on the SIP path.
- **Train down** — expect V.34 (~33.6k) max; force 9600/14400 for reliability.
- **No 56k** — V.90/V.92 needs a digital PSTN endpoint that a VoIP path can't present.
- Consider **T.38** semantics are for fax; *data* modem relay is V.150.1 territory and is finicky.
  For the lab, prefer real copper (line simulator) for the fast/reliable links and treat VoIP
  dial-in as a slower convenience path.

## Security & isolation notes

- Telephony/PPP box should be network-isolated from production where practical.
- PPP auth (PAP/CHAP) gates who gets an IP; the BBS has its own user accounts.
- NAT egress should be firewalled — dial-in guests shouldn't roam the lab LAN freely.
- RustChain admin keys are never exposed to dial-in clients; they only reach the public node API.
