import argparse
import copy
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

LAB = Path(__file__).resolve().parents[1]


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, LAB / filename)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


endpoint = module('link_endpoint', 'link-endpoint.py')
verify = module('verify_link', 'verify-link-baseline.py')


class LinkEndpointTests(unittest.TestCase):
    def test_missing_interface_retains_cleanup_receipt_and_failure_report(self):
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            result = dict(process_passed=True, owned_container_removed=True, error=None, cleanup_errors=[])
            with mock.patch.object(endpoint, 'interface_snapshot', side_effect=OSError('device disappeared')), \
                    mock.patch.object(endpoint, 'call', return_value=argparse.Namespace(stdout='existing\n')):
                endpoint.finish_environment(argparse.Namespace(interface='ethA', bind='fe80::1', peer='fe80::2'),
                                            {}, {'existing'}, work, result)
            report = json.loads((work / 'result.json').read_text())
            self.assertIs(report['pass'], False)
            self.assertIs(report['owned_container_removed'], True)
            self.assertIs(report['network_configuration_preserved'], False)
            self.assertIs(report['preexisting_containers_preserved'], True)
            self.assertIn('device disappeared', report['cleanup_errors'][0])

    def test_unavailable_docker_postcheck_retains_network_proof_and_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            snapshot = dict(configuration={'mtu': 1500}, counters={'rx_bytes': 10})
            result = dict(process_passed=True, owned_container_removed=True, error=None, cleanup_errors=[])
            with mock.patch.object(endpoint, 'interface_snapshot', return_value=snapshot), \
                    mock.patch.object(endpoint, 'call', side_effect=OSError('daemon unavailable')):
                endpoint.finish_environment(argparse.Namespace(interface='ethA', bind='fe80::1', peer='fe80::2'),
                                            snapshot, {'existing'}, work, result)
            report = json.loads((work / 'result.json').read_text())
            self.assertIs(report['pass'], False)
            self.assertIs(report['network_configuration_preserved'], True)
            self.assertIs(report['preexisting_containers_preserved'], False)
            self.assertIn('daemon unavailable', report['cleanup_errors'][0])

    def test_default_plan_does_not_access_host_or_create_workers(self):
        with mock.patch('sys.argv', ['link-endpoint']), mock.patch.object(endpoint, 'call') as call, \
                mock.patch.object(endpoint, 'interface_snapshot') as snapshot, \
                mock.patch('sys.stdout', new_callable=io.StringIO) as output:
            endpoint.main()
        self.assertFalse(json.loads(output.getvalue())['executes'])
        call.assert_not_called()
        snapshot.assert_not_called()

    def test_input_rejects_non_link_local_injected_interfaces_and_unbounded_runs(self):
        good = dict(interface='ethA', bind='fe80::1', peer='fe80::2', port=55201, streams=1,
                    seconds=10, omit=2, run_id='a' * 32, sha256=verify.SHA)
        endpoint.validate_input(argparse.Namespace(**good))
        for key, value in (('interface', '../ethA'), ('interface', 'x;id'), ('bind', '2001:db8::1'),
                           ('peer', 'fe80::1'), ('peer', 'fe80::2%ethA'), ('port', 80), ('streams', 9),
                           ('seconds', 3600), ('omit', 60), ('run_id', 'shared'), ('sha256', 'latest')):
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                endpoint.validate_input(argparse.Namespace(**{**good, key: value}))

    def test_listener_accepts_both_scope_formats_only_for_owned_process(self):
        with tempfile.TemporaryDirectory() as directory:
            args = argparse.Namespace(work=Path(directory), interface='ethA', bind='fe80::1', port=55201)
            for address in ('[fe80::1%ethA]:55201', '[fe80::1]%ethA:55201'):
                for pid, valid in ((101, True), (999, False)):
                    outputs = ['PID COMMAND\n100 timeout\n101 iperf3\n',
                               'LISTEN 0 32768 ' + address + ' [::]:* users:(("iperf3",pid=' + str(pid) + ',fd=3))\n']
                    with mock.patch.object(endpoint, 'call', side_effect=[argparse.Namespace(stdout=x) for x in outputs]):
                        self.assertEqual(endpoint.listener('owned', args) is not None, valid)

    def test_cleanup_ownership_rejects_each_resource_or_identity_change(self):
        receipt = dict(id='owned', name='owned', image=endpoint.IMAGE, command=['bounded'],
                       run_id='a' * 32, binary='/private/iperf3')
        info = {'Id': 'owned', 'Name': '/owned', 'Config': {'Image': endpoint.IMAGE,
                'Entrypoint': ['/usr/bin/timeout'], 'Cmd': ['bounded'], 'Labels': {
                    'io.traflens.purpose': endpoint.PURPOSE, 'io.traflens.run': 'a' * 32}},
                'HostConfig': dict(NetworkMode='host', PidMode='', Privileged=False, ReadonlyRootfs=True,
                    Memory=268435456, MemorySwap=268435456, NanoCpus=2000000000, PidsLimit=64,
                    CapAdd=None, CapDrop=['ALL'], SecurityOpt=['no-new-privileges']),
                'Mounts': [dict(Type='bind', Source='/private/iperf3', Destination='/iperf3', RW=False)]}
        self.assertTrue(endpoint.owned(info, receipt))
        for key, value in (('NetworkMode', 'bridge'), ('PidMode', 'host'), ('Privileged', True),
                           ('ReadonlyRootfs', False), ('Memory', 0), ('MemorySwap', -1), ('NanoCpus', 0),
                           ('PidsLimit', 0), ('CapAdd', ['SYS_ADMIN']), ('CapDrop', []), ('SecurityOpt', [])):
            changed = copy.deepcopy(info); changed['HostConfig'][key] = value
            with self.subTest(key=key):
                self.assertFalse(endpoint.owned(changed, receipt))
        changed = copy.deepcopy(info); changed['Id'] = 'foreign'
        self.assertFalse(endpoint.owned(changed, receipt))
        changed = copy.deepcopy(info); changed['Mounts'][0]['RW'] = True
        self.assertFalse(endpoint.owned(changed, receipt))


class LinkEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.expected = dict(link=1, reverse=False, streams=1, run_id='a' * 32)

    def fixture(self, reverse=False, streams=1):
        self.expected.update(reverse=reverse, streams=streams)
        docs = {}
        count = 11_000_000_000
        for role, local, peer in (('client', 'fe80::1', 'fe80::2'), ('server', 'fe80::2', 'fe80::1')):
            directory = self.root / role; directory.mkdir(exist_ok=True)
            sender = (role == 'server') == reverse
            summary = dict(bytes=count, seconds=10, bits_per_second=count * 8 / 10)
            zero = dict(bytes=0, seconds=10, bits_per_second=0)
            tx = dict(summary if sender or role == 'client' else zero, retransmits=streams)
            rx = dict(summary if not sender or role == 'client' else zero)
            connections = [dict(socket=i, local_host=local, remote_host=peer,
                                local_port=44000 + i if role == 'client' else 55201,
                                remote_port=55201 if role == 'client' else 44000 + i) for i in range(streams)]
            parts = [dict(sender=dict(socket=i, bytes=tx['bytes'] // streams, retransmits=1),
                          receiver=dict(socket=i, bytes=rx['bytes'] // streams)) for i in range(streams)]
            raw = dict(start=dict(version='iperf 3.22', cookie='synthetic-cookie', connected=connections,
                                  test_start=dict(protocol='TCP', num_streams=streams, duration=10, omit=2,
                                                  reverse=int(reverse), bidir=0, bytes=0, blocks=0)),
                       intervals=[dict(streams=[dict(socket=i, omitted=n < 2, bytes=100) for i in range(streams)],
                                       sum=dict(omitted=n < 2, seconds=1, bytes=100 * streams)) for n in range(12)],
                       end=dict(streams=parts, sum_sent=tx, sum_received=rx, cpu_utilization_percent=dict(host_total=45)),
                       extra_data=self.expected['run_id'])
            config = dict(mtu=1500, operstate='UP', route_device='ethA', ifname='ethA', route_source=local)
            counters = dict(rx_bytes=0, tx_bytes=0, rx_errors=0, tx_errors=0, rx_dropped=0, tx_dropped=0)
            delta = {**counters, 'rx_bytes': count * 2, 'tx_bytes': count * 2}
            command = ['--signal=TERM', '--kill-after=5s', '37', '/iperf3', '-6', '-J', '-B', local + '%ethA', '-p', '55201']
            command += ['-s', '-1'] if role == 'server' else ['-t', '10', '-O', '2', '-P', str(streams),
                       '--extra-data', self.expected['run_id'], '--get-server-output'] + (['-R'] if reverse else [])
            receipt = dict(role=role, run_id=self.expected['run_id'], binary_sha256=verify.SHA,
                           image=endpoint.IMAGE, rootfs_layer=verify.LAYER, command=command, id=role)
            result = dict(pass_=True, process_passed=True, owned_container_removed=True,
                          network_configuration_preserved=True, preexisting_containers_preserved=True,
                          capture_enabled=False, error=None, cleanup_errors=[], exit_code=0, oom_killed=False,
                          interface_counter_delta=delta)
            result['pass'] = result.pop('pass_')
            docs[role] = {'stdout': raw, 'created': receipt, 'result': result,
                          'before': dict(configuration=config, counters=counters),
                          'after': dict(configuration=copy.deepcopy(config), counters=delta),
                          'exit-state': dict(Running=False, ExitCode=0, OOMKilled=False),
                          'ready': dict(owned_listener=True, id=role, run_id=self.expected['run_id'])}
        docs['client']['stdout']['server_output_json'] = copy.deepcopy({
            k: docs['server']['stdout'][k] for k in ('start', 'intervals', 'end')})
        return docs

    def write(self, docs):
        for role, files in docs.items():
            for name, value in files.items():
                (self.root / role / (name + '.json')).write_text(json.dumps(value))

    def qualify(self, docs):
        self.write(docs)
        return verify.qualify(self.root / 'client', self.root / 'server', self.expected)

    def test_forward_reverse_and_parallel_measured_receiver(self):
        for reverse in (False, True):
            for streams in (1, 4):
                result = self.qualify(self.fixture(reverse, streams))
                self.assertEqual(result['receiver_gbps'], 8.8)
                self.assertEqual(result['sender_tcp_retransmits'], streams)

    def test_rejects_worker_failure_unclean_exit_or_configuration_change(self):
        for key, value in (('pass', False), ('owned_container_removed', False), ('process_passed', False),
                           ('preexisting_containers_preserved', False), ('error', 'failed'), ('capture_enabled', True)):
            docs = self.fixture(); docs['server']['result'][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):self.qualify(docs)
        docs = self.fixture(); docs['client']['after']['configuration']['mtu'] = 9000
        with self.assertRaises(ValueError):self.qualify(docs)

    def test_rejects_unrelated_transcripts_and_changed_protocol_contract(self):
        for key, value in (('protocol', 'UDP'), ('duration', 1), ('omit', 0), ('num_streams', 4),
                           ('reverse', True), ('bidir', 1)):
            docs = self.fixture(); docs['client']['stdout']['start']['test_start'][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):self.qualify(docs)
        for key, value in (('extra_data', 'b' * 32), ('error', 'interrupted')):
            docs = self.fixture(); docs['client']['stdout'][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):self.qualify(docs)

    def test_rejects_missing_or_duplicate_streams_and_endpoint_mismatch(self):
        for action in ('missing', 'duplicate', 'address', 'port', 'nested'):
            docs = self.fixture(streams=4); raw = docs['client']['stdout']
            if action == 'missing':raw['end']['streams'].pop()
            if action == 'duplicate':raw['start']['connected'][1] = copy.deepcopy(raw['start']['connected'][0])
            if action == 'address':raw['start']['connected'][0]['remote_host'] = 'fe80::3'
            if action == 'port':raw['start']['connected'][0]['remote_port'] = 55202
            if action == 'nested':raw['server_output_json']['end']['sum_received']['bytes'] += 1
            with self.subTest(action=action), self.assertRaises(ValueError):self.qualify(docs)

    def test_rejects_counter_reset_errors_and_wrong_nic(self):
        for key, value in (('rx_errors', 1), ('tx_dropped', 1), ('tx_bytes', 1), ('rx_bytes', -1)):
            docs = self.fixture(); docs['client']['after']['counters'][key] = value
            docs['client']['result']['interface_counter_delta'][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):self.qualify(docs)

    def test_rejects_partial_intervals_and_warmup_only_records(self):
        for action in ('short', 'warmup', 'socket', 'sum'):
            docs = self.fixture(); rows = docs['client']['stdout']['intervals']
            if action == 'short':rows.pop()
            if action == 'warmup':
                for row in rows:
                    row['sum']['omitted'] = True
                    row['streams'][0]['omitted'] = True
            if action == 'socket':rows[-1]['streams'][0]['socket'] = 99
            if action == 'sum':rows[-1]['sum']['bytes'] += 1
            with self.subTest(action=action), self.assertRaises(ValueError):self.qualify(docs)

    def test_accepts_iperf_omit_transition_merge_and_short_final_tail(self):
        docs = self.fixture()
        for role in ('client', 'server'):
            rows = docs[role]['stdout']['intervals']
            rows.pop(1)
            rows[1]['sum']['seconds'] = 2
            rows[-1]['sum']['seconds'] -= .0005
            rows.append(dict(streams=[dict(socket=0, omitted=False, bytes=0)],
                             sum=dict(omitted=False, seconds=.0005, bytes=0)))
        docs['client']['stdout']['server_output_json'] = copy.deepcopy({
            k: docs['server']['stdout'][k] for k in ('start', 'intervals', 'end')})
        self.assertEqual(self.qualify(docs)['receiver_gbps'], 8.8)

    def test_rejects_invalid_numbers_rate_duration_and_byte_sums(self):
        for key, value in (('bytes', True), ('bytes', 0), ('seconds', 1), ('bits_per_second', float('nan')),
                           ('bits_per_second', 99_000_000_000), ('bits_per_second', 1)):
            docs = self.fixture(); docs['client']['stdout']['end']['sum_sent'][key] = value
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):self.qualify(docs)

    def test_strict_json_rejects_duplicate_keys_and_nonfinite(self):
        path = self.root / 'bad.json'
        for value in ('{"a":1,"a":2}', '{"a":NaN}', '{"a":Infinity}'):
            path.write_text(value)
            with self.assertRaises(ValueError):verify.load(path)

    def test_aggregate_requires_full_matrix_and_does_not_export_private_identifiers(self):
        sample = self.qualify(self.fixture())
        samples = [dict(sample, link=link, reverse=reverse, streams=streams)
                   for link in (1, 2) for reverse in (False, True) for streams in (1, 4) for _ in range(3)]
        result = verify.aggregate(samples)
        self.assertEqual(len(result['groups']), 8)
        for key in ('capture_enabled', 'agent_ingestion_performance_measured', 'deepflow_performance_parity_proven'):
            self.assertIs(result[key], False)
        text = json.dumps(result)
        for value in ('fe80::', 'ethA', self.expected['run_id'], 'synthetic-cookie'):
            self.assertNotIn(value, text)
        with self.assertRaises(ValueError):verify.aggregate(samples[:-1])
        with self.assertRaises(ValueError):verify.aggregate(samples + [sample])


if __name__ == '__main__':
    unittest.main()
