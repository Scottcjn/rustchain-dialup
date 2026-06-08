#!/usr/bin/env python3
"""
D9 Bounty Harness — BBS⇄RustChain door automated tests.
Bounty: D9  |  Wallet: klowagent
"""
from __future__ import annotations
import json, os, re, sys, unittest
from io import StringIO

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))
from bbs.rustchain_door import (
    RustChainClient, render_header, render_balance_panel,
    render_attestation_panel, render_mining_panel, render_footer,
    render_full_screen, _progress_bar, VERSION,
)

ANSI_RE = re.compile("\[[0-9;]*m")


class TestRustChainClientLive(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = RustChainClient("https://rustchain.org", timeout=15.0)
        cls.miner_id = os.environ.get("RC_TEST_MINER", "klowagent")

    def test_health(self):
        health = self.client.health()
        self.assertTrue(health.get("ok"), f"Node health not OK: {health}")
        print(f"  [1/6] Health: PASS — node v{health.get('version','?')}")

    def test_epoch(self):
        epoch = self.client.epoch()
        self.assertIn("epoch", epoch)
        self.assertGreater(epoch["epoch"], 0)
        print(f"  [2/6] Epoch: PASS — epoch #{epoch['epoch']}")

    def test_wallet_balance(self):
        balance = self.client.wallet_balance(self.miner_id)
        self.assertIn("amount_rtc", balance)
        self.assertEqual(balance["miner_id"], self.miner_id)
        print(f"  [3/6] Balance: PASS — {balance['amount_rtc']} RTC")

    def test_tokenomics(self):
        tokenomics = self.client.tokenomics()
        self.assertIn("reference_rate_usd", tokenomics)
        self.assertEqual(tokenomics["reference_rate_usd"], 0.15)
        print(f"  [4/6] Tokenomics: PASS — ${tokenomics['reference_rate_usd']}/RTC")

    def test_find_miner(self):
        miner = self.client.find_miner(self.miner_id)
        if miner:
            self.assertIn("antiquity_multiplier", miner)
            print(f"  [5/6] Find miner: PASS — {miner.get('hardware_type','?')}, {miner.get('antiquity_multiplier','?')}x")
        else:
            print(f"  [5/6] Find miner: PASS — {self.miner_id} not active (expected for VM)")

    def test_miners_list(self):
        miners = self.client.miners()
        self.assertIsInstance(miners, list)
        self.assertGreater(len(miners), 0)
        print(f"  [6/6] Miners list: PASS — {len(miners)} active")


class TestANSIRendering(unittest.TestCase):
    def test_header_renders(self):
        header = render_header()
        clean = ANSI_RE.sub("", header)
        self.assertIn("V I N T A G E", clean)
        self.assertIn("H A R D W A R E", clean)
        print("  [1/7] Header render: PASS")

    def test_balance_panel_renders(self):
        client = RustChainClient("https://rustchain.org", timeout=10.0)
        panel = render_balance_panel(client, "test-wallet")
        self.assertIn("WALLET BALANCE", panel)
        self.assertIn("test-wallet", panel)
        print("  [2/7] Balance panel render: PASS")

    def test_attestation_panel_renders(self):
        client = RustChainClient("https://rustchain.org", timeout=10.0)
        panel = render_attestation_panel(client, "nonexistent-miner")
        self.assertIn("ATTESTATION STATUS", panel)
        self.assertIn("not found", panel)
        print("  [3/7] Attestation panel render: PASS")

    def test_mining_panel_renders(self):
        client = RustChainClient("https://rustchain.org", timeout=10.0)
        panel = render_mining_panel(client)
        self.assertIn("MINE WHILE YOU READ", panel)
        self.assertIn("Epoch", panel)
        print("  [4/7] Mining panel render: PASS")

    def test_footer_renders(self):
        footer = render_footer()
        self.assertIn(VERSION, footer)
        self.assertIn("rustchain.org", footer)
        print("  [5/7] Footer render: PASS")

    def test_full_screen_renders(self):
        client = RustChainClient("https://rustchain.org", timeout=10.0)
        screen = render_full_screen(client, "test-wallet")
        clean = ANSI_RE.sub("", screen)
        self.assertIn("V I N T A G E", clean)
        self.assertIn("WALLET BALANCE", clean)
        self.assertIn("ATTESTATION STATUS", clean)
        self.assertIn("MINE WHILE YOU READ", clean)
        self.assertIn("test-wallet", clean)
        print("  [6/7] Full screen render: PASS")

    def test_progress_bar(self):
        bar = _progress_bar(50, 100, width=10)
        self.assertIn("\u2588", bar)
        self.assertIn("\u2591", bar)
        print("  [7/7] Progress bar: PASS")


class TestStdlibOnly(unittest.TestCase):
    def test_no_external_imports(self):
        door_path = os.path.join(os.path.dirname(__file__), "..", "..", "bbs", "rustchain_door.py")
        with open(door_path) as f:
            source = f.read()
        for imp in ["import requests", "import httpx", "import aiohttp"]:
            self.assertNotIn(imp, source)
        print("  [1/1] Stdlib only: PASS")


class TestENiGMAIntegration(unittest.TestCase):
    def test_launcher_exists(self):
        launcher = os.path.join(os.path.dirname(__file__), "..", "..", "bbs", "enigma2-launcher")
        self.assertTrue(os.path.exists(launcher))
        with open(launcher) as f:
            self.assertIn("rustchain_door", f.read())
        print("  [1/2] Launcher exists: PASS")

    def test_launcher_config_loading(self):
        launcher = os.path.join(os.path.dirname(__file__), "..", "..", "bbs", "enigma2-launcher")
        with open(launcher) as f:
            source = f.read()
        self.assertIn("load_config", source)
        print("  [2/2] Launcher config: PASS")


class TestJSONOutput(unittest.TestCase):
    def test_json_output(self):
        from bbs.rustchain_door import main as door_main
        captured = StringIO()
        old_stdout = sys.stdout
        sys.stdout = captured
        try:
            ret = door_main(["--miner-id", "klowagent", "--json"])
        finally:
            sys.stdout = old_stdout
        self.assertEqual(ret, 0)
        data = json.loads(captured.getvalue())
        self.assertEqual(data["miner_id"], "klowagent")
        self.assertIn("balance", data)
        self.assertIn("epoch", data)
        self.assertIn("health", data)
        print("  [1/1] JSON output: PASS")


def run_tests():
    print("=" * 60)
    print("D9 Bounty Harness — BBS-RustChain Door Tests")
    print("=" * 60)
    print()
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    for tc in [TestRustChainClientLive, TestANSIRendering, TestStdlibOnly, TestENiGMAIntegration, TestJSONOutput]:
        suite.addTests(loader.loadTestsFromTestCase(tc))
    result = unittest.TextTestRunner(verbosity=0, stream=StringIO()).run(suite)
    print()
    print("=" * 60)
    total = result.testsRun
    failures = len(result.failures)
    errors = len(result.errors)
    if failures == 0 and errors == 0:
        print(f"ALL {total} CHECKS PASSED")
    else:
        print(f"PASSED: {total - failures - errors}/{total}")
        for test, tb in result.failures:
            print(f"  FAIL: {test}\n{tb}")
        for test, tb in result.errors:
            print(f"  ERROR: {test}\n{tb}")
    print("=" * 60)
    return 0 if (failures == 0 and errors == 0) else 1

if __name__ == "__main__":
    raise SystemExit(run_tests())
