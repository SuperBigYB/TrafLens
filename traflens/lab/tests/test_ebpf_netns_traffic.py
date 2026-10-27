"""Compile the stdlib fixture and exercise only offline paths, without libtrace."""
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
import unittest


@unittest.skipUnless(sys.platform.startswith('linux'), 'fixture targets Linux')
class TrafficFixtureTests(unittest.TestCase):
    def test_wire_selftest_and_traffic_binary_cannot_trace(self):
        source=Path(__file__).resolve().parents[1]/'ebpf-netns-gate.c'
        with tempfile.TemporaryDirectory(prefix='netns-wire-') as directory:
            root=Path(directory)
            binary=root/'traffic'
            command=shlex.split(os.environ.get('CC','cc'))
            built=subprocess.run(command+['-DGATE_TRAFFIC_ONLY','-std=gnu11','-O2',
                '-Wall','-Wextra','-Werror',str(source),'-pthread','-o',str(binary)],
                capture_output=True,text=True,timeout=40)
            self.assertEqual(built.returncode,0,built.stderr)
            check=subprocess.run([str(binary),'self-test'],capture_output=True,text=True,timeout=10)
            self.assertEqual(check.returncode,0,check.stderr)
            reports=[json.loads(line) for line in check.stdout.splitlines() if line.startswith('{')]
            report=next(item for item in reports if 'equal_length_http_vectors' in item)
            self.assertTrue(report['pass'])
            self.assertEqual(report['equal_length_http_vectors'],40)
            self.assertFalse(report['network_or_tracer_started'])
            control=root/'control';control.mkdir(mode=0o700)
            evidence=root/'evidence';evidence.mkdir(mode=0o700)
            reject=subprocess.run([str(binary),'trace','--mode','legacy','--marker',
                'scopeunit01234567','--positive-tgid','42','--seconds','30',
                '--control',str(control),'--evidence',str(evidence)],
                capture_output=True,text=True,timeout=10)
            self.assertEqual(reject.returncode,77,reject.stderr)
            self.assertIn('cannot start a tracer',(evidence/'sdk-console.log').read_text())


if __name__=='__main__':
    unittest.main()
