"""Normal TRACE_APP license and strict trace-only Controller lease guards."""
import contextlib
import copy
import io
from pathlib import Path
import sys
import tempfile
import types
import unittest

HERE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(HERE))
import cpu_profile_common as common
import cpu_profile_controller as controller
from test_cpu_profile import FakeAPI


class OTelControllerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.work = Path(self.tmp.name)
        self.work.chmod(0o700)
        (self.work / 'controller-events').mkdir(mode=0o700)
        controller.WORK = self.work
        self.api = FakeAPI()
        self.config = types.SimpleNamespace(check_keys=lambda value, template: None)
        self.metadata = {'integration_mode': 'otel_trace', 'run': 'span-' + '1' * 24,
                         'ctrl_ip': '172.29.0.2', 'ctrl_mac': '02:00:00:00:00:02',
                         'controller_ip': '192.0.2.24', 'controller_port': 20035, 'ingester_port': 20033,
                         'profile': controller.trace_only_profile('192.0.2.24', 20035, 20033)}

    def tearDown(self):
        self.tmp.cleanup()

    def test_real_normal_trace_app_license_and_exact_restoration(self):
        # A caller cannot grant profiling by adding a top-level license hint.
        self.metadata['LICENSE_FUNCTIONS'] = [11]
        with contextlib.redirect_stdout(io.StringIO()):
            controller.prepare(self.api, self.config, self.metadata)
        self.assertEqual(self.api.agents[0]['LICENSE_FUNCTIONS'], [6])
        ebpf = self.metadata['profile']['inputs']['ebpf']
        self.assertIs(ebpf['disabled'], True)
        self.assertNotIn('off_cpu', ebpf['profile'])
        self.assertNotIn('memory', ebpf['profile'])
        self.assertEqual(self.api.agents[0]['NAME'], 'traflens-' + self.metadata['run'])
        for path in self.work.rglob('*.json'):
            self.assertNotIn('never-persist-this-test-secret', path.read_text())
        with contextlib.redirect_stdout(io.StringIO()):
            controller.cleanup(self.api, {'run': self.metadata['run'], 'agent_stopped': True, 'owned_agent_removed': True})
        self.assertEqual(self.api.agents, [])
        self.assertEqual([g['LCUUID'] for g in self.api.groups], ['old-group'])

    def test_mode_and_run_prefix_must_match(self):
        for mode, prefix in (('otel_trace', 'cpu-'), ('profile', 'span-'), ('unknown', 'span-')):
            value = copy.deepcopy(self.metadata)
            value.update(integration_mode=mode, run=prefix + '1' * 24)
            with self.assertRaises(RuntimeError):
                controller.prepare(self.api, self.config, value)
        value = copy.deepcopy(self.metadata)
        del value['integration_mode']
        with self.assertRaises(RuntimeError):
            controller.prepare(self.api, self.config, value)
        self.assertEqual(self.api.mutations, [])

    def test_no_profile_other_integration_or_host_collection_can_be_enabled(self):
        changes = [
            ('inputs', 'integration', 'feature_control', 'profile_integration_disabled'),
            ('inputs', 'integration', 'feature_control', 'trace_integration_disabled'),
            ('inputs', 'integration', 'feature_control', 'metric_integration_disabled'),
            ('inputs', 'integration', 'feature_control', 'log_integration_disabled'),
            ('inputs', 'proc', 'enabled'), ('inputs', 'ebpf', 'disabled'),
            ('inputs', 'ebpf', 'profile', 'on_cpu', 'disabled'),
            ('inputs', 'ebpf', 'profile', 'unwinding', 'dwarf_disabled'),
            ('global', 'self_monitoring', 'profile', 'enabled'),
            ('processors', 'request_log', 'filters', 'cbpf_disabled'),
            ('outputs', 'flow_metrics', 'enabled'),
        ]
        for keys in changes:
            value = copy.deepcopy(self.metadata)
            leaf = value['profile']
            for key in keys[:-1]:
                leaf = leaf[key]
            leaf[keys[-1]] = not leaf[keys[-1]]
            with self.assertRaises(RuntimeError):
                controller.prepare(self.api, self.config, value)
        self.assertEqual(self.api.mutations, [])

    def test_profile_default_contract_is_preserved(self):
        value = copy.deepcopy(self.metadata)
        del value['integration_mode']
        value['run'] = 'cpu-' + '2' * 24
        value['profile'] = common.profile_only(HERE, '192.0.2.24', 20035, 20033)
        self.assertEqual(controller.validate_metadata(value), value)
        self.assertEqual(controller.license_functions(value), [11])
        value['profile'] = self.metadata['profile']
        with self.assertRaises(RuntimeError):
            controller.validate_metadata(value)


if __name__ == '__main__':
    unittest.main()
