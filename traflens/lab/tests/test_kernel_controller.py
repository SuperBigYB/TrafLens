"""Offline normal-license and exact qualified-profile guards for kernel HTTP."""
import contextlib
import copy
import importlib.util
import io
import json
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

SPEC = importlib.util.spec_from_file_location('kernel_managed_documents', HERE / 'managed-http.py')
managed = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(managed)


class KernelControllerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.work = Path(self.tmp.name)
        self.work.chmod(0o700)
        (self.work / 'controller-events').mkdir(mode=0o700)
        controller.WORK = self.work
        self.api = FakeAPI()
        self.config = types.SimpleNamespace(check_keys=lambda value, template: None)
        self.metadata = {'integration_mode': 'kernel_http', 'run': 'nh-' + '1' * 24,
                         'ctrl_ip': '172.29.0.2', 'ctrl_mac': '02:00:00:00:00:02',
                         'controller_ip': '192.0.2.24', 'controller_port': 20035, 'ingester_port': 20033,
                         'profile': controller.kernel_http_profile('192.0.2.24', 20035, 20033)}

    def tearDown(self):
        self.tmp.cleanup()

    def test_profile_is_exactly_qualified_documents_and_only_endpoints_change(self):
        actual = self.metadata['profile']
        expected, _ = managed.documents('192.0.2.24', 'g-kerneltest', 20035, ingester_port=20033, http_port=18080)
        self.assertEqual(actual, expected)
        original = json.loads((HERE / 'managed-http-profile.json').read_text())
        unchanged = copy.deepcopy(actual)
        unchanged['global']['communication'] = original['global']['communication']
        self.assertEqual(unchanged, original)
        inputs = actual['inputs']
        self.assertIs(inputs['proc']['enabled'], False)
        self.assertIs(inputs['integration']['enabled'], False)
        self.assertTrue(all(inputs['integration']['feature_control'].values()))
        self.assertIs(inputs['ebpf']['disabled'], False)
        self.assertIs(inputs['ebpf']['profile']['on_cpu']['disabled'], True)
        self.assertIs(inputs['ebpf']['profile']['unwinding']['dwarf_disabled'], True)
        self.assertNotIn('off_cpu', inputs['ebpf']['profile'])
        self.assertNotIn('memory', inputs['ebpf']['profile'])
        self.assertEqual(actual['processors']['request_log']['filters']['port_number_prefilters'], {'HTTP': '18080'})

    def test_new_normal_feature_lease_restores_original_group_without_reusing_agent(self):
        self.assertEqual(self.api.agents, [])
        with contextlib.redirect_stdout(io.StringIO()):
            controller.prepare(self.api, self.config, self.metadata)
        self.assertEqual(self.api.agents[0]['LICENSE_FUNCTIONS'], [2, 4, 5])
        self.assertEqual(self.api.agents[0]['NAME'], 'traflens-' + self.metadata['run'])
        baseline = json.loads((self.work / 'controller-baseline.json').read_text())
        self.assertEqual(baseline['agents'], [])
        self.assertEqual([group['LCUUID'] for group in baseline['groups']], ['old-group'])
        with contextlib.redirect_stdout(io.StringIO()):
            controller.cleanup(self.api, {'run': self.metadata['run'], 'agent_stopped': True, 'owned_agent_removed': True})
        self.assertEqual(self.api.agents, [])
        self.assertEqual([group['LCUUID'] for group in self.api.groups], ['old-group'])

    def test_kernel_mode_requires_exact_nh_dash_prefix_and_no_license_override(self):
        for prefix in ['nh', 'cpu-', 'span-', 'NH-']:
            value = copy.deepcopy(self.metadata)
            value['run'] = prefix + '1' * 24
            with self.assertRaises(RuntimeError):
                controller.prepare(self.api, self.config, value)
        for key in ['LICENSE_FUNCTIONS', 'license_functions', 'license_override']:
            value = copy.deepcopy(self.metadata)
            value[key] = [11]
            with self.assertRaises(RuntimeError):
                controller.prepare(self.api, self.config, value)
        self.assertEqual(self.api.mutations, [])

    def test_wider_collection_or_different_port_cannot_be_applied(self):
        changes = [('inputs', 'proc', 'enabled'), ('inputs', 'integration', 'enabled'),
                   ('inputs', 'ebpf', 'disabled'), ('inputs', 'ebpf', 'profile', 'on_cpu', 'disabled'),
                   ('inputs', 'ebpf', 'profile', 'unwinding', 'dwarf_disabled')]
        for keys in changes:
            value = copy.deepcopy(self.metadata)
            leaf = value['profile']
            for key in keys[:-1]:
                leaf = leaf[key]
            leaf[keys[-1]] = not leaf[keys[-1]]
            with self.assertRaises(RuntimeError):
                controller.prepare(self.api, self.config, value)
        value = copy.deepcopy(self.metadata)
        value['profile']['processors']['request_log']['filters']['port_number_prefilters']['HTTP'] = '18081'
        with self.assertRaises(RuntimeError):
            controller.prepare(self.api, self.config, value)
        self.assertEqual(self.api.mutations, [])

    def test_communication_endpoint_validation_and_profile_instances_are_independent(self):
        for address, controller_port, ingester_port in [('0.0.0.0', 20035, 20033), ('224.0.0.1', 20035, 20033),
                                                       ('::1', 20035, 20033), ('192.0.2.24', 0, 20033),
                                                       ('192.0.2.24', True, 20033), ('192.0.2.24', 20035, 65536)]:
            with self.assertRaises((RuntimeError, ValueError)):
                controller.kernel_http_profile(address, controller_port, ingester_port)
        altered = controller.kernel_http_profile('192.0.2.24', 20035, 20033)
        altered['inputs']['integration']['enabled'] = True
        self.assertIs(controller.kernel_http_profile('192.0.2.24', 20035, 20033)['inputs']['integration']['enabled'], False)

    def test_profile_and_otel_modes_keep_their_exact_original_contract(self):
        for mode, prefix, profile, functions in [
                ('profile', 'cpu-', common.profile_only(HERE, '192.0.2.24', 20035, 20033), [11]),
                ('otel_trace', 'span-', controller.trace_only_profile('192.0.2.24', 20035, 20033), [6])]:
            value = copy.deepcopy(self.metadata)
            value.update(integration_mode=mode, run=prefix + '2' * 24, profile=profile)
            self.assertEqual(controller.validate_metadata(value), value)
            self.assertEqual(controller.license_functions(value), functions)
        value = copy.deepcopy(self.metadata)
        del value['integration_mode']
        with self.assertRaises(RuntimeError):
            controller.validate_metadata(value)


if __name__ == '__main__':
    unittest.main()
