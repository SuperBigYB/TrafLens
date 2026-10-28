"""Pure socket/native/API oracle guards; these tests never open a socket."""
import contextlib
import copy
import errno
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

HERE = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('tcp_acceptance', HERE / 'verify-tcp-connections.py')
V = importlib.util.module_from_spec(spec)
spec.loader.exec_module(V)


def fixture(folder):
    run = 'tcp-' + 'a' * 24
    identity = {'pid': 12345, 'tid': 12345, 'start_ticks': '98', 'netns': 'net:[9001]', 'pidns': 'pid:[9002]'}
    start = 1700000000 * 10**9
    events = []
    def add(kind, operation, local=None, peer=None, data=None, tid=12345, **values):
        value = dict(identity, run=run, scenario=kind, operation=operation, sequence=len(events)+1,
                     finished_unix_ns=start+len(events)*1000)
        value['tid'] = tid
        if local:
            value.update(local={'ip': local[0], 'port': local[1]}, peer={'ip': peer[0], 'port': peer[1]} if peer else None,
                         peer_is_actual=peer is not None)
        if data is not None:
            value.update(wire_ascii=data.decode('ascii'), bytes=len(data), sha256=hashlib.sha256(data).hexdigest())
        value.update(values)
        events.append(value)
    client_ip, server_ip = '127.77.0.1', '127.77.0.2'
    for i, kind in enumerate(V.KINDS):
        client, server = (client_ip, 30001+i), (server_ip, 18081+i)
        add(kind, 'bound_endpoint', server, accepting=kind != 'refused', exclusive_bind=True)
        add(kind, 'connect', client, server if kind != 'refused' else None,
            requested_target={'ip': server[0], 'port': server[1]}, connected=kind != 'refused', errno=0 if kind != 'refused' else errno.ECONNREFUSED)
        if kind != 'refused':
            add(kind, 'accept', server, client, tid=12346+i)
    normal_client, normal_server = (client_ip, 30001), (server_ip, 18081)
    resource = '/traflens-tcp/'+run+'/normal'
    request = ('GET '+resource+' HTTP/1.1\r\nHost: local\r\n\r\n').encode()
    body = json.dumps({'run': run, 'scenario': 'normal', 'pid': 12345, 'tid': 12346}).encode()
    response = b'HTTP/1.1 200 OK\r\n\r\n' + body
    for local, peer, data in ((normal_client, normal_server, request), (normal_server, normal_client, response)):
        add('normal', 'send', local, peer, data)
        add('normal', 'shutdown_write', local, peer, errno=0)
    add('normal', 'recv', normal_server, normal_client, request, eof_observed=True)
    add('normal', 'recv', normal_client, normal_server, response, eof_observed=True)
    reset_client, reset_server = (client_ip, 30002), (server_ip, 18082)
    reset = ('traflens-tcp/'+run+'/reset/request\n').encode()
    add('reset', 'send', reset_client, reset_server, reset)
    add('reset', 'recv', reset_server, reset_client, reset)
    add('reset', 'close_intent', reset_server, reset_client, abortive=True, linger_onoff=1, linger_seconds=0)
    add('reset', 'recv_error', reset_client, reset_server, errno=errno.ECONNRESET)
    raw = b'\n'.join(json.dumps(e).encode() for e in events) + b'\n'
    (folder/'events.jsonl').write_bytes(raw)
    receipt = dict(identity, run=run, source=V.SOURCE, **{'pass': True}, expected_connections=3,
                   thread_errors=[], owned_sockets_closed=True, owned_threads_exited=True, collector_started=False,
                   synthetic_tcp_packets=False, stored_l4_verified=False, started_unix_ns=start,
                   finished_unix_ns=start+10**9, completed={key: True for key in ('server_normal', 'server_reset', 'client_normal', 'client_reset', 'client_refused')},
                   events=len(events), events_sha256=hashlib.sha256(raw).hexdigest(), http_resource=resource,
                   server_identities={'normal': dict(identity, tid=12346), 'reset': dict(identity, tid=12347)})
    (folder/'receipt.json').write_text(json.dumps(receipt))
    (folder/'process.json').write_text(json.dumps(dict(identity, run=run, source=V.SOURCE, sdk=False)))
    return events, receipt


def native_rows(oracle):
    values = []
    for i, kind in enumerate(V.KINDS):
        case = oracle['cases'][kind]
        row = {key: 0 for key in V.COLUMNS}
        row.update(id=str(18446744073709551610+i), flow_id=str(9007199254740993+i), start_us=1700000000000001,
                   end_us=1700000000000101, time_epoch=1700000000, duration=100, agent_id=14, signal_source=0, tap_side='local', protocol=6,
                   l3_epc_id_0=0, l3_epc_id_1=-2, ip_0=case['client'][0], client_port=case['client'][1],
                   ip_1=case['server'][0], server_port=case['server'][1], close_type=V.CLOSE[kind],
                   packet_tx=2, packet_rx=2, byte_tx=1000, byte_rx=1000, total_packet_tx=2, total_packet_rx=2,
                   total_byte_tx=1000, total_byte_rx=1000, rtt=0, rtt_client=10, rtt_server=20, l7_protocol=20 if kind=='normal' else 0)
        values.append(row)
    return values


def table(rows, columns=V.COLUMNS):
    return {'OPT_STATUS': 'SUCCESS', 'result': {'columns': columns, 'values': [[r[c] for c in columns] for r in rows]}}


def packet_runtime(folder, oracle):
    folder.mkdir(mode=0o700)
    binary = folder/'native-core'
    binary.write_bytes(b'bounded offline native core fixture')
    sha = hashlib.sha256(binary.read_bytes()).hexdigest()
    current = {'schema':'traflens.packet-tcp-agent.v1','output':str(folder),'agent_id':14,'run':oracle['run'],
               'id':'b'*64,'source_commit':'c'*40,'binary_sha256':sha,'artifact_manifest_sha256':'d'*64,
               'requires_packet_bpf_ready_before_traffic':True,'baseline':{},
               'spec':{'image':'sha256:'+'9'*64,'network':'host','pid_mode':'','readonly':True,'privileged':False,'cap_add':['NET_RAW'],
                       'cap_drop':['ALL'],'ports':{},'publish_all':False,'mounts':[[str(binary),'/opt/traflens/deepflow-agent',False]],
                       'labels':{'io.traflens.purpose':'traflens.packet-tcp-agent','io.traflens.run':oracle['run'],'io.traflens.output':str(folder)}}}
    prefix = [[0x15, 1, 0, 1], [6, 0, 0, 0]]
    words = prefix+[[0x20,0,0,0xfffff008],[0x15,1,0,1],[6,0,0,0],[6,0,0,65535],[6,0,0,65535]]
    digest = lambda v: hashlib.sha256(json.dumps(v,separators=(',',':')).encode()).hexdigest()
    proof = {'schema':'traflens.packet-tcp-ready.v1','agent_id':14,'agent_container_id':current['id'],'binary_sha256':sha,
             'native_dispatcher_started':True,'fresh_three_listener_sync':True,'safe_profile_verified':True,
             'outside_custom_filter_returns_zero_before_default_policy':True,'on_cpu_enabled':False,
             'actual_agent':{'pid':20002,'container_pid':20001,'start_ticks':'100','netns':'net:[9001]','pidns':'pid:[9003]'},
             'observed_at_unix':oracle['started_unix_ns']/10**9-1,'custom_prefix':prefix,'custom_prefix_sha256':digest(prefix),
             'af_packet_socket_count':1,'lo_ifindex':1,'sockets':[{'inode':555,'fd':7,'ifindex':0,'exact_custom_prefix':True,
                     'instructions':words,'instruction_count':len(words),'filter_sha256':digest(words)}]}
    stopped = dict.fromkeys(('agent_stopped','container_removed','bpf_inventory_restored','tracefs_restored','lo_identity_and_flags_restored'),True)
    stopped['observed_at_unix'] = oracle['finished_unix_ns']/10**9+1
    exit_state = {'schema':'traflens.packet-tcp-agent.exit.v1','container_id':current['id'],'image_id':current['spec']['image'],
                  'exit_code':0,'oom_killed':False,'finished_at':'2023-11-14T22:13:22.000000123Z','observed_unix_ns':1700000002000000223}
    stopped['exit'] = exit_state
    for name, value in [('current.json',current),('packet-bpf-proof.json',proof),('stopped.json',stopped),('exit-state.json',exit_state)]:
        (folder/name).write_text(json.dumps(value))
    runtime = SimpleNamespace(tcp_packet_filter=SimpleNamespace(compile_prefix=Mock(return_value=prefix)),
                              PACKET_TCP_FILTER='fixed offline filter',inspect=Mock(return_value=None),restored=Mock(return_value=True))
    return current, proof, stopped, runtime


class TCPAcceptanceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.folder = Path(self.tmp.name)
        self.folder.chmod(0o700)
        self.events, self.receipt = fixture(self.folder)
        self.oracle = V.fixture_oracle(self.folder)

    def tearDown(self):
        self.tmp.cleanup()

    def snapshot(self, values, end=1700000002):
        return V.population(table([{'records': len(values)}], ['records']), table(values), self.oracle, 14, 1700000000, end)

    def test_default_plan_has_no_files_or_network(self):
        out = io.StringIO()
        with patch.object(V, 'fixture_oracle', side_effect=AssertionError('No reads')), patch.object(V, 'Client', side_effect=AssertionError('No HTTP')), contextlib.redirect_stdout(out):
            self.assertEqual(V.main([]), 0)
        self.assertFalse(json.loads(out.getvalue())['execute'])

    def test_actual_socket_oracle_preserves_kernel_selected_tuples(self):
        self.assertEqual(self.oracle['cases']['normal']['client'], ('127.77.0.1', 30001))
        self.assertEqual(self.oracle['cases']['refused']['server'], ('127.77.0.2', 18083))
        self.assertEqual(self.oracle['run'], 'tcp-'+'a'*24)

    def test_socket_hash_and_observed_errno_are_not_replaceable(self):
        path = self.folder/'events.jsonl'
        original = path.read_bytes()
        path.write_bytes(original+b'changed')
        with self.assertRaises(ValueError):
            V.fixture_oracle(self.folder)
        changed = copy.deepcopy(self.events)
        for event in changed:
            if event['operation'] == 'recv_error':
                event['errno'] = errno.ETIMEDOUT
        raw = b'\n'.join(json.dumps(e).encode() for e in changed)+b'\n'
        path.write_bytes(raw)
        receipt = dict(self.receipt, events_sha256=hashlib.sha256(raw).hexdigest())
        (self.folder/'receipt.json').write_text(json.dumps(receipt))
        with self.assertRaises(ValueError):
            V.fixture_oracle(self.folder)

    def test_refused_requested_target_is_not_invented_actual_peer(self):
        changed = copy.deepcopy(self.events)
        for event in changed:
            if event['scenario']=='refused' and event['operation']=='connect':
                event.update(peer=event['requested_target'], peer_is_actual=True)
        raw = b'\n'.join(json.dumps(e).encode() for e in changed)+b'\n'
        (self.folder/'events.jsonl').write_bytes(raw)
        (self.folder/'receipt.json').write_text(json.dumps(dict(self.receipt, events_sha256=hashlib.sha256(raw).hexdigest())))
        with self.assertRaises(ValueError):
            V.fixture_oracle(self.folder)

    def test_native_report_population_has_exact_uint64_and_zero_rtt_is_allowed(self):
        actual, finals, fingerprint = self.snapshot(native_rows(self.oracle))
        self.assertEqual(finals['normal']['flow_id'], '9007199254740993')
        self.assertEqual(actual[0]['id'], '18446744073709551610')
        self.assertEqual(finals['normal']['rtt'], 0)
        self.assertEqual(len(fingerprint), 64)

    def test_raw_json_uint64_flow_above_float_precision_is_exact_and_fingerprint_stays_raw(self):
        values = native_rows(self.oracle)
        for index,row in enumerate(values):
            row['flow_id'] = 2**64-1-index
        raw = json.dumps(table(values)).encode()
        decoded = V.document(raw)
        original = copy.deepcopy(decoded)
        actual, finals, digest = V.population(table([{'records':3}],['records']),decoded,self.oracle,14,1700000000,1700000002)
        self.assertEqual(decoded,original)
        self.assertEqual(finals['normal']['flow_id'],2**64-1)
        self.assertIs(type(actual[0]['flow_id']),int)
        expected = hashlib.sha256(json.dumps(actual,sort_keys=True,separators=(',',':')).encode()).hexdigest()
        self.assertEqual(digest,expected)
        strings = copy.deepcopy(actual)
        for row in strings:row['flow_id']=str(row['flow_id'])
        self.assertNotEqual(digest,hashlib.sha256(json.dumps(strings,sort_keys=True,separators=(',',':')).encode()).hexdigest())
        for invalid in (float(2**64-1),True,-1,2**64):
            broken=copy.deepcopy(values);broken[0]['flow_id']=invalid
            with self.assertRaises(ValueError,msg=repr(invalid)):
                self.snapshot(broken)

    def test_periodic_report_is_not_counted_as_another_closed_connection(self):
        values = native_rows(self.oracle)
        interim = copy.deepcopy(values[0])
        interim.update(id='3', close_type=5, end_us=1700000060000000, time_epoch=1700000060)
        for suffix in ('tx','rx'):
            values[0]['packet_'+suffix] = interim['packet_'+suffix] = interim['total_packet_'+suffix] = 1
            values[0]['byte_'+suffix] = interim['byte_'+suffix] = interim['total_byte_'+suffix] = 500
        values.append(interim)
        actual, finals, _ = self.snapshot(values,1700000063)
        self.assertEqual(len(actual), 4)
        self.assertEqual(set(finals), set(V.KINDS))
        interim['packet_tx'] = interim['total_packet_tx'] = 2
        with self.assertRaisesRegex(ValueError, 'report counters'):
            self.snapshot(values,1700000063)
        interim['packet_tx'] = interim['total_packet_tx'] = 1
        values.append(dict(values[0], id='4'))
        with self.assertRaises(ValueError):
            self.snapshot(values,1700000063)

    def test_bad_source_close_code_counter_or_identity_never_becomes_success(self):
        for key, value in [('signal_source', 3), ('agent_id', 9), ('close_type', 20), ('packet_tx', 1.5), ('id', 12), ('total_byte_tx', 0), ('time_epoch',1700000001)]:
            values = native_rows(self.oracle)
            values[0][key] = value
            with self.assertRaises(ValueError, msg=key):
                self.snapshot(values)

    def test_api_preserves_original_values_as_strings(self):
        actual, _, _ = self.snapshot(native_rows(self.oracle))
        connections = [{key: str(row[key]) if key in V.TEXT else row[key] for key in V.COLUMNS} for row in actual]
        for row in connections:
            row.update(close_type_name='recorded native classification', rtt_available=False,
                       rtt_client_available=True, rtt_server_available=True)
        response = {'from':1700000000,'to':1700000002,'agent_id':14,'signal_source':0,'limit':64,
                    'records':'3','connections':connections,'semantics':{'unit':'microseconds'}}
        V.api_connections(response, actual, 14, 1700000000, 1700000002)
        response['connections'][0]['flow_id'] = 9007199254740993
        with self.assertRaises(ValueError):
            V.api_connections(response, actual, 14, 1700000000, 1700000002)

    def test_schema_malformed_empty_cannot_become_empty_success(self):
        for values in ({}, False, 'invalid'):
            with self.assertRaises(ValueError):
                V.rows({'OPT_STATUS':'SUCCESS','result':{'columns':['id'],'values':values}}, ['id'])
        self.assertEqual(V.rows({'OPT_STATUS':'SUCCESS','result':{'columns':['id'],'values':None}}, ['id']), [])

    def test_complete_agent_population_cannot_hide_outside_filter_or_other_source(self):
        calls = []
        values = native_rows(self.oracle)
        class Client:
            def request(inner, name, base, path, fields, *rest):
                calls.append((name, fields))
                if name == 'first-count':
                    return table([{'records': len(values)}], ['records'])
                if name == 'first-rows':
                    return table(values)
                raise RuntimeError('Stop before mocked API access')
        args = SimpleNamespace(agent=14, time_from=1700000000, time_to=1700000002,
                               query_base='http://127.0.0.1:20416', console_base='http://127.0.0.1:22880')
        with self.assertRaisesRegex(RuntimeError, 'mocked API'):
            V.acceptance(Client(), args, self.oracle, {}, self.oracle)
        for _, fields in calls[:2]:
            where = fields['sql'].split(' WHERE ', 1)[1].split(' ORDER BY ', 1)[0]
            self.assertEqual(where, 'agent_id=14 AND time>=1700000000 AND time<=1700000002')
        outside = copy.deepcopy(values[0])
        outside.update(id='77', flow_id='991', server_port=18084)
        with self.assertRaisesRegex(ValueError, 'Unexpected Agent/source/protocol/endpoint'):
            self.snapshot(values+[outside])

    def test_packet_provenance_binds_actual_core_ready_filter_and_present_restoration(self):
        folder = self.folder/'packet-agent'
        current, proof, stopped, runtime = packet_runtime(folder, self.oracle)
        value = V.runtime_provenance(folder, 14, self.oracle, self.oracle, runtime)
        self.assertTrue(value['agent_runtime_provenance_verified'])
        self.assertEqual(value['native_binary_sha256'], current['binary_sha256'])
        self.assertTrue(value['kernel_accepts_only_lo'])
        self.assertEqual(value['actual_all_interface_bound_socket_count'], 1)
        self.assertEqual(value['actual_agent_finished_unix_ns'], '1700000002000000123')
        runtime.inspect.assert_called_once_with('container', current['id'])
        runtime.restored.assert_called_once_with(current)
        runtime.inspect.return_value = {'State':{'Running':False}}
        with self.assertRaisesRegex(ValueError, 'Present packet container'):
            V.runtime_provenance(folder, 14, self.oracle, self.oracle, runtime)

    def test_packet_text_configuration_or_ready_boolean_cannot_replace_actual_evidence(self):
        folder = self.folder/'packet-agent'
        current, proof, stopped, runtime = packet_runtime(folder, self.oracle)
        for name, key, value in [('current.json','agent_id',15),('packet-bpf-proof.json','binary_sha256','e'*64),
                                 ('packet-bpf-proof.json','fresh_three_listener_sync',False),
                                 ('packet-bpf-proof.json','custom_prefix',[[6,0,0,65535]]),
                                 ('packet-bpf-proof.json','observed_at_unix',self.oracle['to']+1),
                                 ('stopped.json','bpf_inventory_restored',False)]:
            originals = {'current.json':current,'packet-bpf-proof.json':proof,'stopped.json':stopped}
            changed = copy.deepcopy(originals[name])
            changed[key] = value
            (folder/name).write_text(json.dumps(changed))
            with self.assertRaises(ValueError, msg=name+'/'+key):
                V.runtime_provenance(folder, 14, self.oracle, self.oracle, runtime)
            (folder/name).write_text(json.dumps(originals[name]))
        runtime.restored.return_value = False
        with self.assertRaisesRegex(ValueError, 'Present packet container'):
            V.runtime_provenance(folder, 14, self.oracle, self.oracle, runtime)

    def test_installed_cfg_rejects_interface_bypass_or_dynamic_return(self):
        words = [[0x15,1,0,1],[6,0,0,0],[0x20,0,0,0xfffff008],[0x15,1,0,1],
                 [6,0,0,0],[6,0,0,128],[6,0,0,65535]]
        self.assertTrue(V.installed_ifindex_guard(words, 1)['kernel_accepts_only_lo'])
        whitelist = copy.deepcopy(words)
        whitelist[-4][1] = 2
        self.assertTrue(V.installed_ifindex_guard(whitelist, 1)['kernel_accepts_only_lo'])
        for pc, replacement in [(0,[5,0,0,5]), (0,[5,0,0,2]), (0,[0x16,0,0,0]), (0,[0x1ff,0,0,0]),
                                (0,[5,0,0,999]), (2,[0x20,0,0,0xfffff004]), (3,[0x15,1,1,1]),
                                (3,[0x15,1,0,2]), (4,[6,0,0,1])]:
            changed = copy.deepcopy(words)
            changed[pc] = replacement
            with self.assertRaises(ValueError, msg=str(replacement)):
                V.installed_ifindex_guard(changed, 1)

    def test_actual_exit_preserves_utc_nanoseconds_not_restoration_completion(self):
        self.assertEqual(V.docker_finished_ns('2023-11-14T22:13:22.123456789Z'),1700000002123456789)
        self.assertEqual(V.docker_finished_ns('2023-11-14T22:13:22Z'),1700000002000000000)
        self.assertEqual(V.report_window_end(1700000002123456789),1700000063)
        self.assertEqual(V.report_window_end(1700000002000000000),1700000062)
        for value in ('2023-11-14 22:13:22','2023-11-14T22:13:22+08:00','2023-11-14T22:13:22.1234567890Z'):
            with self.assertRaises(ValueError):
                V.docker_finished_ns(value)

    def test_only_explicit_credential_free_loopback_bases(self):
        self.assertEqual(V.base_url('http://127.0.0.1:20416'), 'http://127.0.0.1:20416')
        for value in ('http://u:secret@127.0.0.1:20416', 'http://127.0.0.1:20416?token=x', 'http://example.com:80', 'http://127.0.0.1:20416/path'):
            with self.assertRaises(ValueError):
                V.base_url(value)


if __name__ == '__main__':
    unittest.main()
