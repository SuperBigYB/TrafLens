import argparse
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

LAB = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('http_trace', LAB / 'http-trace.py')
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)


class HTTPTraceTests(unittest.TestCase):
    def config(self, output=None):
        return argparse.Namespace(trace_id='a' * 32, other_trace_id='b' * 32, count=5,
            marker='trace-example', mode='front', interface='test0', bind='fe80::1',
            peer='fe80::2', front_port=18080, back_port=18081, seconds=60, output=output)

    def test_default_is_offline_and_creates_no_files(self):
        with tempfile.TemporaryDirectory() as root:
            result = subprocess.run([sys.executable, str(LAB / 'http-trace.py')], cwd=root,
                                    capture_output=True, text=True, timeout=5, check=True)
            self.assertFalse(json.loads(result.stdout)['starts_network'])
            self.assertEqual(list(Path(root).iterdir()), [])

    def test_distinct_leg_context_and_unrelated_trace(self):
        c = self.config()
        front, back = fixture.context(c, 0, 'front'), fixture.context(c, 0, 'back')
        self.assertEqual(front[0], back[0])
        self.assertNotEqual(front[1], back[1])
        self.assertEqual(fixture.context(c, c.count, 'front')[0], c.other_trace_id)
        for value in ['0' * 32, 'A' * 32, 'a' * 31, "a' OR 1=1"]:
            with self.assertRaises(ValueError):
                fixture.trace_id(value)

    def test_front_checks_and_propagates_actual_context(self):
        c = self.config()
        calls = []
        def relay(config, sequence, leg):
            calls.append((sequence, leg, fixture.context(config, sequence, leg)))
            trace, span, _ = fixture.context(config, sequence, leg)
            return {'trace_id': trace, 'span_id': span, 'sequence': sequence, 'backend': True}
        record, body = fixture.request_context(c, fixture.resource(c, 0, 'front'),
            fixture.context(c, 0, 'front')[2], relay)
        self.assertEqual(calls[0][1], 'back')
        self.assertEqual(record['trace_id'], body['trace_id'])
        self.assertNotEqual(record['span_id'], body['span_id'])

    def test_wrong_trace_path_and_sequence_never_relay(self):
        c = self.config()
        def forbidden(*_args):
            self.fail('Rejected request reached downstream')
        for path, header in [(fixture.resource(c, 0, 'front'), '00-' + 'c' * 32 + '-1-01'),
                             ('/other/0', fixture.context(c, 0, 'front')[2]),
                             (fixture.resource(c, 99, 'front'), fixture.context(c, 0, 'front')[2])]:
            with self.assertRaises(ValueError):
                fixture.request_context(c, path, header, forbidden)

    def test_bounded_inputs_and_existing_output_rejected(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / 'report.json'
            fixture.validate(self.config(path))
            for key, value in [('count', 21), ('seconds', 91), ('back_port', 18080),
                               ('peer', 'fe80::1'), ('bind', '::1'), ('peer', 'fe80::2%test0')]:
                c = self.config(path)
                setattr(c, key, value)
                with self.assertRaises(ValueError):
                    fixture.validate(c)
            path.write_text('keep')
            with self.assertRaises(ValueError):
                fixture.validate(self.config(path))
            self.assertEqual(path.read_text(), 'keep')


if __name__ == '__main__':
    unittest.main()
