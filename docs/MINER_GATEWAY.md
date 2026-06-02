# Miner Gateway — the split client

> This document exists because the tri-brain review (Codex 5.5, Grok) both flagged the
> same thing: **"the 386 mines" is the single most underestimated claim in the project.**
> Running the full RustChain miner *on* a Dreamcast / 386 / 68k Mac means canonical JSON,
> Ed25519 signing, TLS 1.2+, NTP-grade clock, an HTTP client, and hardware-evidence
> collection — on big-endian, pre-TLS, often pre-Python silicon. That is a separate
> software project, not a footnote. So we don't do that.

## The split

Don't put modern crypto and transport on the old machine. Split the miner in two:

```
┌──────────────────────────┐        plaintext line proto       ┌──────────────────────────┐
│ VINTAGE CLIENT           │  (over PPP, or raw serial/BBS)    │ GATEWAY (on the Pi NAS)   │
│ small portable C binary  │ ────────────────────────────────▶ │ rcgateway (Python/Go)     │
│  • collect HW evidence   │                                    │  • canonical JSON         │
│  • build challenge resp. │ ◀──────────────────────────────── │  • TLS 1.2+ to the node   │
│  • Ed25519 SIGN locally  │        node challenge / result     │  • HTTP keep-alive        │
└──────────────────────────┘                                    │  • clock / retry / DNS    │
   key + evidence NEVER                                          └─────────────┬─────────────┘
   leave the old box                                                           │ HTTPS canonical JSON
                                                                               ▼
                                                                    RustChain node API
                                                                    (/attest/submit, /epoch/enroll)
```

## The security invariant (do not violate)

RustChain's anti-emulation / proof-of-antiquity guarantee is that **the hardware evidence and
the signature are produced on the real old hardware**. The gateway is a *transport*, not an
*oracle*:

- The Ed25519 **private key lives only on the vintage machine.** The gateway never sees it.
- The **hardware-fingerprint evidence is gathered and signed on the vintage machine.** The
  gateway must not, and cannot, fabricate or alter it — if it could, one Pi could mint a farm
  of fake "vintage" miners, which is exactly the VM-farm attack RIP-PoA exists to stop.
- The gateway **only relays** the signed blob and translates transport (plaintext↔TLS,
  line-proto↔HTTP, canonical-JSON framing). A tampered blob fails signature verification at the
  node, so a malicious gateway can deny service but cannot forge a miner.
- **Bind the gateway to the physically-attached line.** One gateway instance per modem/PPP peer;
  rate-limit; refuse to multiplex many miner identities through one local relay.

## Why this also fixes the slow-link problem

- TLS handshakes, cert chains, and 1500-byte frames are murder at 9600 baud. The gateway does the
  TLS on the **fast** side (Pi → node over real Ethernet). The vintage↔gateway hop carries only a
  tiny signed blob (a few hundred bytes) — fast even at 9600.
- The vintage client needs **no TLS, no DNS, no system clock discipline** — the gateway supplies
  all of that. The old box only needs: read /proc-equivalent hardware signals, hash, Ed25519-sign.

## Endianness

Ed25519 itself is byte-string defined (endian-neutral), but the **canonical serialization of the
evidence must pin byte order explicitly** so an SH-4 (Dreamcast), big-endian PPC, or 68k produces
the same bytes the node expects to verify. Define the wire format in fixed network byte order and
test the signature round-trips from at least one big-endian target before declaring Phase 4 done.

## Phasing (supersedes the old "Phase 4" hand-wave)

- **Phase 4a — Gateway first.** Stand up `rcgateway` on the Pi. Prove it with a *modern* client
  (curl on the Pi itself) end-to-end to a RustChain node: evidence → sign → relay → attest accepted.
- **Phase 4b — One vintage target.** Port the tiny C evidence+sign client to **one** OS at a time
  (e.g. Linux/NetBSD on a 486 first — easiest toolchain — then KallistiOS for Dreamcast). Verify a
  real attestation is accepted and the antiquity multiplier lands.
- **Phase 4c — Big-endian proof.** Round-trip a signature from a big-endian box (G3/G4 or 68k).

## Acceptance test for Phase 4

> One modem pair, fixed PPP addresses, 9600 baud, the vintage C client produces a signed
> attestation that the **local gateway** relays and the node **accepts**, with the correct
> RIP-200 antiquity multiplier — and the firewall isolation (see ARCHITECTURE.md) is verified.
> Public web browsing and VoIP are explicitly **out of scope** for this milestone.
