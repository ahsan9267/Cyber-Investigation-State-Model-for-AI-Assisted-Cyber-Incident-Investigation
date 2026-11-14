import base64
from copy import deepcopy
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from spine.remote_wazuh import REMOTE_PROGRAM, RemoteReadError, _request, checkpoint_from_batch
from spine.wazuh_recovery import CONTINUITY_ERRORS, _descriptor, _inventory


class MaintenanceExporterTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.active = self.root / "alerts.json"
        self.dated = self.root / "2026" / "Oct"
        self.dated.mkdir(parents=True)
        self.archive = self.dated / "ossec-alerts-11.json"
        self.active.write_bytes(b'{"id":"one"}\n{"id":"two"}\n')
        os.link(self.active, self.archive)
        self.namespace = {"__name__": "maintenance_test"}
        exec(compile(REMOTE_PROGRAM, "remote_reader", "exec"), self.namespace)

    def checkpoint(self):
        return checkpoint_from_batch(self.namespace["read_source_batch"](
            {"offset": 0, "expected": None, "max_records": 100}, root=str(self.root),
        ))

    def inspect(self, expected):
        return self.namespace["inspect_checkpoint"](
            {"expected": expected, "archive_path": str(self.archive)}, root=str(self.root),
        )

    def rotate(self):
        self.active.unlink()
        self.active.write_bytes(b'{"id":"today"}\n')
        os.link(self.active, self.dated / "ossec-alerts-12.json")

    def test_inventory_retains_dated_files_and_active_alias(self):
        self.rotate()
        inventory = self.namespace["inspect_sources"](root=str(self.root))
        self.assertEqual(len(inventory["sources"]), 2)
        self.assertEqual(inventory["active"]["archive_path"], str(self.dated / "ossec-alerts-12.json"))

    def test_normal_rotation_does_not_invalidate_old_checkpoint(self):
        checkpoint = self.checkpoint()
        self.rotate()
        response = self.inspect(checkpoint)
        self.assertEqual(response["status"], "valid")
        self.assertEqual(response["source"]["read_path"], str(self.archive))

    def test_shrunken_retained_source_is_explicitly_identified(self):
        checkpoint = self.checkpoint()
        self.rotate()
        self.archive.write_bytes(b'{"id":"one"}\n')
        response = self.inspect(checkpoint)
        self.assertEqual(response["status"], "truncation_detected")
        self.assertLess(response["source"]["size_at_open"], checkpoint["next_offset"])
        self.assertEqual(response["source"]["native_file_id"], checkpoint["native_file_id"])

    def test_first_line_rewrite_is_distinct_from_valid_rotation(self):
        checkpoint = self.checkpoint()
        self.archive.write_bytes(b'{"id":"ONE"}\n{"id":"two"}\n')
        self.assertEqual(self.inspect(checkpoint)["status"], "content_change_detected")

    def test_checkpoint_tail_rewrite_is_identified(self):
        checkpoint = self.checkpoint()
        self.archive.write_bytes(b'{"id":"one"}\n{"id":"TWO"}\n')
        response = self.inspect(checkpoint)
        self.assertEqual(response["issue"], "Checkpoint bytes changed")

    def test_changed_line_boundary_is_identified(self):
        checkpoint = self.checkpoint()
        self.archive.write_bytes(b'{"id":"one"}\n{"id":"two"} \n')
        self.assertEqual(self.inspect(checkpoint)["issue"], "Checkpoint is not at a line boundary")

    def test_compressed_source_reports_unavailability_without_reading_new_alias(self):
        checkpoint = self.checkpoint()
        self.rotate()
        self.archive.rename(str(self.archive) + ".gz")
        response = self.inspect(checkpoint)
        self.assertEqual(response["status"], "unavailable")
        self.assertIsNone(response["source"])
        self.assertTrue(response["compressed_archive_available"])

    def test_directory_access_error_does_not_report_a_missing_generation(self):
        checkpoint = self.checkpoint()
        self.rotate()
        with patch.dict(self.namespace, {"find_archive_path": lambda *a: (_ for _ in ()).throw(PermissionError("denied"))}):
            with self.assertRaises(PermissionError):
                self.inspect(checkpoint)

    def test_inspection_refuses_path_traversal(self):
        with self.assertRaises(ValueError):
            self.namespace["inspect_checkpoint"](
                {"expected": self.checkpoint(), "archive_path": str(self.dated / "../Oct/ossec-alerts-11.json")},
                root=str(self.root),
            )

    def test_ambiguous_dated_identity_is_rejected(self):
        os.link(self.archive, self.dated / "ossec-alerts-10.json")
        with self.assertRaisesRegex(RuntimeError, "Multiple dated"):
            self.namespace["inspect_sources"](root=str(self.root))

    def test_exporter_request_validation_for_new_actions(self):
        # Exercise the same entry point used in the deployed fixed exporter.
        path = Path(__file__).resolve().parents[1] / "tools" / "build_wazuh_exporter.py"
        ns = {"__name__": "builder_test", "__file__": str(path)}
        exec(compile(path.read_text(), str(path), "exec"), ns)
        entry = {**self.namespace, "__name__": "entry_test"}
        exec(compile(ns["ENTRY"], "exporter_entry", "exec"), entry)
        for request in (
            {"action": "inspect_sources", "path": "/etc/shadow"},
            {"action": "inspect_checkpoint", "expected": None, "archive_path": None},
            {"action": "read_batch", "offset": 1, "expected": None, "max_records": 1},
        ):
            with patch.object(sys, "stdin", io.TextIOWrapper(io.BytesIO(json.dumps(request).encode()))):
                with self.assertRaises(ValueError):
                    entry["serve"]()

    def test_only_structured_exporter_errors_are_eligible_for_recovery(self):
        detail = {"error": "RuntimeError", "message": "File truncated below checkpoint"}
        with patch("spine.remote_wazuh.Path.is_file", return_value=True):
            with patch("spine.remote_wazuh.subprocess.run", return_value=subprocess.CompletedProcess(
                [], 2, json.dumps(detail).encode(), b"",
            )):
                with self.assertRaises(RemoteReadError) as captured:
                    _request({"action": "read_batch"})
                self.assertIn((captured.exception.detail["error"], captured.exception.detail["message"]), CONTINUITY_ERRORS)
            with patch("spine.remote_wazuh.subprocess.run", return_value=subprocess.CompletedProcess(
                [], 255, b"", b"Connection refused",
            )):
                with self.assertRaises(RuntimeError) as captured:
                    _request({"action": "read_batch"})
                self.assertNotIsInstance(captured.exception, RemoteReadError)
        self.assertNotIn(("PermissionError", "Permission denied"), CONTINUITY_ERRORS)
        self.assertNotIn(("RuntimeError", "Batch changed during read"), CONTINUITY_ERRORS)


if __name__ == "__main__":
    unittest.main()
