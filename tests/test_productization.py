import argparse
import unittest
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient

from config.settings import settings
from kernel import Kernel
from server.app import create_app
import aios


class TestProductization(unittest.TestCase):
    """Verify package distribution, top-level SDK exports, CLI options, and health endpoints."""

    def test_top_level_sdk_exports(self):
        """GAP-PROD: Test that aios exports core abstractions and version directly."""
        self.assertIsNotNone(aios.__version__)
        self.assertEqual(aios.__version__, settings.version)
        self.assertTrue(hasattr(aios, "Kernel"))
        self.assertTrue(hasattr(aios, "ProcessControlBlock"))
        self.assertTrue(hasattr(aios, "PriorityLevel"))
        self.assertTrue(hasattr(aios, "CheckpointManager"))
        self.assertTrue(hasattr(aios, "FlightRecorder"))
        self.assertTrue(hasattr(aios, "TraceReplayEngine"))
        self.assertTrue(hasattr(aios, "CapabilityIssuer"))
        self.assertTrue(hasattr(aios, "CapabilityToken"))

    def test_cli_open_browser_argparse(self):
        """GAP-PROD: Test that CLI parses --open-browser and --open flags cleanly."""
        from cli import main
        import sys

        # Test default (False)
        with patch.object(sys, "argv", ["aios", "start", "--web"]):
            with patch("cli.cmd_start") as mock_cmd:
                main()
                args = mock_cmd.call_args[0][0]
                self.assertFalse(args.open_browser)

        # Test explicit --open-browser (True)
        with patch.object(sys, "argv", ["aios", "start", "--web", "--open-browser"]):
            with patch("cli.cmd_start") as mock_cmd:
                main()
                args = mock_cmd.call_args[0][0]
                self.assertTrue(args.open_browser)

        # Test shorthand --open (True)
        with patch.object(sys, "argv", ["aios", "start", "--web", "--open"]):
            with patch("cli.cmd_start") as mock_cmd:
                main()
                args = mock_cmd.call_args[0][0]
                self.assertTrue(args.open_browser)

    def test_api_health_endpoint(self):
        """GAP-PROD: Test that /api/health returns 200 OK with expected schema without auth."""
        kernel = Kernel(provider_name="mock")
        app = create_app(kernel)
        client = TestClient(app)

        response = client.get("/api/health")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["status"], "healthy")
        self.assertEqual(data["version"], settings.version)
        self.assertIn("uptime_seconds", data)
        self.assertTrue(data["scheduler_active"])

    def test_api_system_info_endpoint(self):
        """GAP-PROD: Test that /api/system/info returns comprehensive subsystem metadata."""
        kernel = Kernel(provider_name="mock")
        app = create_app(kernel)
        client = TestClient(app)

        response = client.get("/api/system/info")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["version"], settings.version)
        self.assertIn("subsystems", data)
        subsystems = data["subsystems"]
        self.assertIn("scheduler", subsystems)
        self.assertIn("security", subsystems)
        self.assertIn("memory", subsystems)
        self.assertIn("ipc", subsystems)
        self.assertIn("hitl", subsystems)


if __name__ == "__main__":
    unittest.main()
