import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest

LAB = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('managed_http_prepare', LAB / 'managed-http.py')
prepare = importlib.util.module_from_spec(spec)
spec.loader.exec_module(prepare)


class ManagedHTTPPrepareTests(unittest.TestCase):
    def options(self):
        return {'controller_ip': '203.0.113.1', 'group_id': 'g-example'}

    def test_scope_and_collection_contract(self):
        profile, bootstrap = prepare.documents(**self.options())
        inputs = profile['inputs']
        self.assertEqual(inputs['cbpf']['af_packet']['interface_regex'], '')
        self.assertFalse(inputs['cbpf']['af_packet']['inner_interface_capture_enabled'])
        self.assertFalse(inputs['ebpf']['disabled'])
        self.assertFalse(inputs['ebpf']['socket']['kprobe']['disabled'])
        self.assertFalse(inputs['ebpf']['socket']['uprobe']['golang']['enabled'])
        self.assertFalse(inputs['ebpf']['socket']['uprobe']['tls']['enabled'])
        self.assertEqual(inputs['ebpf']['file']['io_event']['collect_mode'], 0)
        self.assertTrue(inputs['ebpf']['profile']['on_cpu']['disabled'])
        self.assertFalse(inputs['proc']['enabled'])
        self.assertFalse(inputs['integration']['enabled'])
        self.assertEqual(inputs['integration']['feature_control'],
                         {kind + '_integration_disabled': True for kind in ('profile', 'trace', 'metric', 'log')})
        self.assertEqual(bootstrap['ebpf-socket-netns-scope'], '/run/traflens/target.netns')
        self.assertEqual(profile['processors']['request_log']['application_protocol_inference']['enabled_protocols'], ['HTTP'])
        self.assertEqual(profile['global']['limits']['max_millicpus'], 2000)
        self.assertEqual(profile['global']['limits']['max_memory'], 1024)

    def test_custom_endpoints_ports_and_group(self):
        profile, boot = prepare.documents('2001:db8::1', 'g-other', 20035,
                                           '2001:db8::2', 20033, 19080)
        self.assertEqual(boot['controller-ips'], ['2001:db8::1'])
        self.assertEqual(boot['vtap-group-id-request'], 'g-other')
        self.assertEqual(boot['controller-port'], 20035)
        communication = profile['global']['communication']
        self.assertEqual(communication['ingester_ip'], '2001:db8::2')
        self.assertEqual(communication['ingester_port'], 20033)
        self.assertEqual(profile['processors']['request_log']['filters']['port_number_prefilters'], {'HTTP': '19080'})
        self.assertEqual(profile['inputs']['cbpf']['af_packet']['extra_bpf_filter'], 'tcp port 19080')
        default, _ = prepare.documents(**self.options())
        self.assertEqual(default['processors']['request_log']['filters']['port_number_prefilters'], {'HTTP': '18080'})

    def test_controller_generated_mixed_case_group_identity_is_preserved(self):
        profile, boot = prepare.documents('203.0.113.1', 'g-aB9Z0CdEf1')
        self.assertEqual(boot['vtap-group-id-request'], 'g-aB9Z0CdEf1')
        self.assertEqual(profile['processors']['request_log']['filters']['port_number_prefilters'], {'HTTP': '18080'})
        for value in ['g-../other', 'g-abc/def', 'g-ab c', 'g-abc\nXYZ']:
            with self.subTest(value=value), self.assertRaises(ValueError):
                prepare.documents('203.0.113.1', value)

    def test_invalid_parameters_do_not_create_output(self):
        with tempfile.TemporaryDirectory() as root:
            target = Path(root) / 'new'
            for key, value in [('controller_ip', 'not-an-ip'), ('controller_ip', True),
                               ('group_id', 'g-a\nother: true'), ('group_id', ''),
                               ('http_port', 0), ('http_port', 65536), ('http_port', True),
                               ('controller_port', -1), ('ingester_ip', 'user:password@host')]:
                options = dict(self.options(), **{key: value})
                with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                    prepare.prepare(target, **options)
                self.assertFalse(target.exists())

    def test_private_outputs_manifest_hashes_and_no_runtime_claim(self):
        with tempfile.TemporaryDirectory() as root:
            target = Path(root) / 'prepared'
            manifest = prepare.prepare(target, **self.options())
            self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o700)
            for path in target.iterdir():
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            for name, metadata in manifest['files'].items():
                raw = (target / name).read_bytes()
                self.assertEqual(hashlib.sha256(raw).hexdigest(), metadata['sha256'])
                self.assertEqual(len(raw), metadata['bytes'])
                self.assertIsInstance(json.loads(raw), dict)
            self.assertFalse(manifest['runtime_qualified'])
            self.assertFalse(manifest['starts_agent'])
            self.assertFalse(manifest['changes_controller'])
            self.assertFalse(manifest['attaches_bpf'])

    def test_existing_output_is_preserved(self):
        with tempfile.TemporaryDirectory() as root:
            target = Path(root) / 'prepared'
            target.mkdir()
            (target / 'keep').write_text('original')
            with self.assertRaises(FileExistsError):
                prepare.prepare(target, **self.options())
            self.assertEqual(list(target.iterdir()), [target / 'keep'])
            self.assertEqual((target / 'keep').read_text(), 'original')

    def test_symlink_parent_rejected(self):
        with tempfile.TemporaryDirectory() as root:
            parent = Path(root)
            real = parent / 'real'
            real.mkdir(mode=0o700)
            (parent / 'link').symlink_to(real, target_is_directory=True)
            with self.assertRaises(ValueError):
                prepare.prepare(parent / 'link' / 'new', **self.options())
            self.assertFalse((real / 'new').exists())

    def test_public_parent_and_relative_output_rejected(self):
        with tempfile.TemporaryDirectory() as root:
            parent = Path(root)
            parent.chmod(0o755)
            with self.assertRaises(ValueError):
                prepare.prepare(parent / 'new', **self.options())
            parent.chmod(0o700)
        with self.assertRaises(ValueError):
            prepare.prepare(Path('relative'), **self.options())

    def test_cli_default_is_read_only_plan(self):
        with tempfile.TemporaryDirectory() as root:
            result = subprocess.run([sys.executable, str(LAB / 'managed-http.py')],
                                    cwd=root, capture_output=True, text=True, check=True, timeout=10)
            self.assertFalse(json.loads(result.stdout)['writes_files'])
            self.assertEqual(list(Path(root).iterdir()), [])


if __name__ == '__main__':
    unittest.main()
