# Test Matrix: D3 Network-Isolation Ruleset

This document outlines the testing scenarios and expected behaviors to verify the nftables isolation ruleset.

---

## 1. Environment Setup

* **NAS Host IP (`ppp0` local):** `10.0.0.1`
* **Vintage Client IP (`ppp0` remote):** `10.0.0.2`
* **Local Lab LAN Range:** `192.168.1.0/24` (or other RFC1918 range)
* **WAN Interface:** `eth0`

---

## 2. Test Verification Matrix

| ID | Scenario | Command / Method | Expected Result | Status |
|---|---|---|---|---|
| **T1** | Permit WAN Egress | `ping -c 3 1.1.1.1` (from client) | Success. Packets route to internet via NAT/Masquerade. | Passed |
| **T2** | Block Lab LAN Egress | `ping -c 3 192.168.1.5` (from client) | Blocked. Packet is dropped and logged with prefix `PPP_FORWARD_BLOCK`. | Passed |
| **T3** | Block PPP ⇄ PPP | `ping -c 3 10.0.0.3` (from `10.0.0.2` client to `10.0.0.3` client) | Blocked. Lateral movement between dial-in interfaces is rejected. | Passed |
| **T4** | Permit Local DNS | `dig @10.0.0.1 google.com` (from client) | Success. DNS queries are permitted to the NAS resolver. | Passed |
| **T5** | Block Other Input | `ssh root@10.0.0.1` (from client) | Blocked. General ports (e.g. 22) on the host are dropped and logged. | Passed |
| **T6** | Permit Local BBS | `telnet 10.0.0.1 23` (or port 2323/2222) | Success. Connection accepted by the locked BBS shell. | Passed |
| **T7** | Permit Miner Gateway | `curl -s http://10.0.0.1:8099/attest/challenge` | Success. Client reaches the local RustChain gateway API. | Passed |
| **T8** | TCP MSS Clamping | Capture Syn/Ack handshake on client side | Syn segment size is clamped to `536` bytes (MTU 576 - 40). | Passed |

---

## 3. Log Audit Verification

To verify that blocks are properly recorded to system logs:

```bash
# Monitor blocked forward packets (e.g. PPP -> LAN)
tail -f /var/log/syslog | grep "PPP_FORWARD_BLOCK"

# Expected output format:
# [timestamp] hostname kernel: [PPP_FORWARD_BLOCK] IN=ppp0 OUT=eth0 SRC=10.0.0.2 DST=192.168.1.5 LEN=60 TOS=0x00 ... PROTO=ICMP
```

```bash
# Monitor blocked input packets (e.g. client attempting unauthorized ports on gateway)
tail -f /var/log/syslog | grep "PPP_INPUT_BLOCK"

# Expected output format:
# [timestamp] hostname kernel: [PPP_INPUT_BLOCK] IN=ppp0 OUT= SRC=10.0.0.2 DST=10.0.0.1 LEN=60 ... PROTO=TCP DPT=22
```
