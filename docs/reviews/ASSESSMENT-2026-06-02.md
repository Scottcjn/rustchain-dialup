# Tri-brain assessment — 2026-06-02

Honest, adversarial assessment of the v1 scaffold, run through two independent reviewers
with orthogonal lanes. Both were told to suppress encouragement and find what's wrong.
Their findings drove the **v2** docs (local gateway, MTU/MRU, network isolation, separate-lines
-first roadmap, honest line-inducer wording).

| Reviewer | Lane | Score |
|----------|------|-------|
| Codex 5.5 (`gpt-5.5`) | correctness / security / under-specification | **5/10** |
| Grok (`grok-composer-2.5`) | regression / blast-radius / ops reality | **6/10** |

**Convergent BLOCKERS (both, independently):**
1. "386 mines" is a separate software project — fixed via [the split miner gateway](../MINER_GATEWAY.md).
2. MTU/MRU unaddressed — 1500 over 9600 baud silently hangs. Need ~576 + TCP MSS clamp.
3. NAT onto the lab LAN is unsafe — isolate `ppp0`, default-deny, expose only WAN egress + gateway.
4. AutoPPP single-line dual-mode oversold — separate terminal/PPP lines first; mux later.

---

## Codex 5.5 — verbatim final assessment

### 1. Feasibility Verdict
**PPP is feasible; the full `modem -> PPP -> mine` claim is not yet substantiated.**
- `mgetty -> AutoPPP -> pppd -> ppp0` is a valid Linux dial-in pattern, but it requires explicit
  `/AutoPPP/` rules in `login.config`, correct `pppd` options, authentication behavior compatible
  with each caller, and stable modem control signals.
- The Viking DLE-200B path should support modem-to-modem training. The DreamPi line inducer is
  **not** equivalent: it does not independently provide generic dialing, ringing, and call routing.
  README treats these options too interchangeably.
- `pppd` does not magically allocate "an IP from a small pool." Start with a fixed local/remote
  address pair per modem.
- "Dreamcast browses the web" is misleading — TLS, JavaScript, payload size, browser age.
- "386 mines" is the unsupported step. A 386 is unlikely to have usable Python, Ed25519 libraries,
  TLS support, or the required hardware-fingerprint implementation.

### 2. Biggest Technical Risk
**The vintage-side RustChain attestation client will eat the most days.** `antique-ports patterns`
is not a porting plan. Hard problems: canonical JSON, Ed25519 signing, key storage, clock, HTTP,
endian assumptions, hardware signal collection, preserving anti-emulation guarantees.

### 3. Underestimated / Missing
- `AT&F` is insufficient as a generic init string (DTR hangup, carrier detect, flow control, echo,
  result codes, dial-tone detection, auto-answer, modulation cap, compression, error correction).
- NW147 claim needs revision-specific bench validation; `/dev/ttyACM0` appearing ≠ reliable answer-mode.
- AutoPPP needs exact mgetty rules, timeouts, PAP/CHAP, Dreamcast testing, device locking, carrier-drop cleanup.
- Default MTU/MRU 1500 = severe serialization latency at 9600. Test 576 / 296 + TCP MSS clamp + VJ.
- ENiGMA½ must not run through a general-purpose shell — dedicated unprivileged launcher; OS accts ≠ BBS accts.
- NAT alone is unsafe — separate subnet/VLAN, default-deny to lab LAN, explicit WAN egress, narrow
  RustChain API, IPv6 handling, logging, rate limits.
- Multi-line needs stable udev names, one mgetty per port, per-line addressing, monitoring, reset recovery.
- VoIP needs ATA tuning: G.711 PCMU only, no transcoding, VAD off, echo-cancel / jitter / loss testing.

### 4. What I Would Change
- DLE-200B + two bench-validated controller modems first; treat USB Conexant as candidates, not assumed-good.
- Dial-in NAS behind a dedicated firewall interface/VLAN; expose only WAN egress, local DNS, curated
  web proxy, BBS endpoint, narrow RustChain gateway API.
- Bring up terminal login and PPP on **separate lines** first; add AutoPPP multiplexing only after both work.
- Replace "ancient Python miner" with a small portable **C client** for one target OS at a time + a
  **local gateway** for upstream TLS / protocol translation, keeping signed challenge-response and
  hardware evidence on the vintage machine.
- First measurable milestone: one modem pair, fixed PPP addresses, 9600 baud, local gateway
  attestation, firewall verified. Defer public browsing and VoIP.

### 5. Score — **5/10**
"The dial-up NAS is technically plausible, but the documents conflate basic PPP connectivity with
secure vintage-hardware mining and under-specify the analog, portability, and isolation work."

---

## Grok — verbatim final assessment

### 1. Feasibility Verdict
**Mostly feasible for a narrow slice; several claims are overstated.**
- LAN island → answer → LCP → `pppd` → IP → NAT is the standard 1990s Linux NAS pattern; DreamPi
  proves the analog plant. Extending to `mgetty` + AutoPPP + `pppd` is credible *if* the modem trains
  and nothing else owns `/dev/ttyACM0`.
- "Every call automatically splits PPP vs BBS" — AutoPPP is a short post-CONNECT sniff for raw LCP.
  Any ASCII banner, delays, login prompts, or "connecting…" text before PPP drops to terminal/login.
  Many 486 setups dial terminal-first then launch PPP manually — not AutoPPP-friendly without client
  discipline or separate access numbers / DTMF / ring-count rules (not in roadmap).
- Dreamcast ≠ generic mgetty — DreamPi is a tailored stack (init, timeouts, expectations).
- "Miner on the vintage machine" over PPP — feasible only with a working TCP/IP stack, resolver, HTTP
  client, often TLS 1.2+. A 386 may dial PPP but have no practical way to POST JSON without specifying
  HTTP vs HTTPS, clock sync, build targets.
- BBS path replacing login requires explicit `login.config` / user / chroot / no host shell — else a
  root escape waiting to happen.

### 2. Biggest Technical Risk
**Single-modem mgetty + AutoPPP + pppd on USB ACM under modern Linux** (ModemManager / getty / udev /
wrong `login.config`) — days lost on RING never seen, immediate hangup, or PPP never handed off.
Runner-up: default MRU/MTU 1500 over 9600 → "connected, nothing loads."

### 3. Underestimated / Missing
- AutoPPP: timeout window, no leading plaintext, pppd invoke line, mgetty build flags, conflict with fax mgetty.
- Modem init: per-modem `ATS0=1`, `+FCLASS=0`, rate lock (`+MS`, `+CBST`), AT&F vs preserved profile, USB reset.
- Line simulator: DLE-200B wiring/port pairing, ring vs off-hook; inducer path may still need ATA/2nd FXS.
- MTU/MRU: no doc mention — need `mru/mtu` 552 or lower, MSS clamp, possibly 576 on Dreamcast.
- RustChain client: TLS, time sync (NTP over PPP?), DNS push, endian (SH-4/m68k/PPC), emulation checks still apply.
- BBS auth: PAP users ≠ BBS users; session isolation; Node.js upgrade path; doors calling wallet APIs.
- NAT security: default-deny egress, no RFC1918 lateral movement, per-session isolation, API abuse, logging.
- Roadmap holes: disable ModemManager; no serial-getty on ACM; idle disconnect / LCP echo; IP pool + DNS;
  bench test without vintage (2nd modem); client recipes; HTTP-only attestation endpoint for lab; single-line
  SPOF; VoIP V.150.1 vs "G.711 passthrough" hand-wave (fax T.38 ≠ data modem relay).

### 4. What I'd Change
- Phase 2: mandate pppd MRU/MSS + nftables MASQUERADE + TCPMSS clamp before "NAT to internet."
- Reduce AutoPPP bet: ring-count / DTMF / second FXS for BBS vs PPP, or document a PPP-only dial script.
- Network: `ppp0` in isolated netns or VLAN, NAT only to WAN + one RustChain API IP; no full lab LAN.
- Ops: udev symlink, ModemManager masked, watchdog AT`I` script, pppd/mgetty debug logging from day one.
- BOM: keep 2× NW147 with explicit roles (NAS answer + bench client); DLE-200B for phase-1 data validation;
  HT802 double-hop as Phase-6 degraded 9600-only path, not parallel "fast" path; USR Courier + USB-serial
  fallback for hard RTS/CTS if ACM fights you.

### 5. Score — **6/10**
"Right historical building blocks (DreamPi lineage, mgetty/pppd, line plant), but single-line AutoPPP
dual-mode, silent MTU/MRU, and vintage HTTP/TLS mining are underspecified — exactly where dial-up labs
usually stall for weeks."
