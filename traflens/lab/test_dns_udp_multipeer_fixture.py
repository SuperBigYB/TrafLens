import contextlib
import importlib.util
import io
import json
from pathlib import Path
import struct
import sys
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("fixture", Path(__file__).with_name("dns-udp-multipeer-fixture.py"))
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)
MARKER = "udpmp-" + "a" * 24


class Contract(unittest.TestCase):
    def test_four_bounded_unprefixed_queries(self):
        for case in range(4):
            data = fixture.message(MARKER, case)
            self.assertLessEqual(len(data), 512)
            self.assertEqual(struct.unpack("!6H", data[:12]), (fixture.IDS[case], 0x100, 1, 0, 0, 0))
            self.assertTrue(data.endswith(b"\0\1\0\1"))

    def test_response_identity_and_errors(self):
        for case in range(4):
            header = struct.unpack("!6H", fixture.message(MARKER, case, True)[:12])
            self.assertEqual(header[0], fixture.IDS[case])
            self.assertEqual(header[1] & 15, 3 if case in (1, 3) else 0)
            self.assertEqual(header[3], 0 if case in (1, 3) else 1)

    def test_repeated_txid_different_actual_questions(self):
        self.assertEqual(fixture.message(MARKER, 2)[:2], fixture.message(MARKER, 3)[:2])
        self.assertNotEqual(fixture.message(MARKER, 2)[12:], fixture.message(MARKER, 3)[12:])

    def test_invalid_scope(self):
        for marker, case in [("other", 0), (MARKER, -1), (MARKER, 4)]:
            with self.assertRaises(ValueError):
                fixture.message(marker, case)

    def test_plan_never_opens_socket_or_output(self):
        output = io.StringIO()
        with patch.object(sys, "argv", ["fixture"]), patch.object(fixture.socket, "socket", side_effect=AssertionError("network")), patch.object(Path, "mkdir", side_effect=AssertionError("write")), contextlib.redirect_stdout(output):
            self.assertEqual(fixture.main(), 0)
        plan = json.loads(output.getvalue())
        self.assertFalse(plan["starts_agent"])
        self.assertFalse(plan["native_source3_verified"])
        self.assertEqual(plan["queries"], 4)

    def test_execute_requires_explicit_identity(self):
        with patch.object(sys, "argv", ["fixture", "--execute"]), contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit):
                fixture.main()


if __name__ == "__main__":
    unittest.main()
