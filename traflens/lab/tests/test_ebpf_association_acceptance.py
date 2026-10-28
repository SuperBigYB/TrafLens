"""Offline acceptance-oracle adversarial checks; no capture/query/container."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / 'verify-ebpf-association.py'
if not SCRIPT.is_file():
    SCRIPT = Path(__file__).with_name('verify-ebpf-association.py')
spec = importlib.util.spec_from_file_location('ebpf_acceptance', SCRIPT)
v = importlib.util.module_from_spec(spec)
spec.loader.exec_module(v)
RUN = 'nh-' + 'a' * 24


def example():
    expected, rows, counter = [], [], 100
    for ci, chain in enumerate(('main', 'control')):
        for role, stage, side, client_ip, client_port, server_ip, pid in [
                ('generate', 'root-request', 'c-p', '127.0.0.1', 30000+ci, '127.0.0.2', 101),
                ('frontend', 'incoming-request', 's-p', '127.0.0.1', 30000+ci, '127.0.0.2', 102),
                ('frontend', 'outgoing-request', 'c-p', '127.0.0.2', 40000+ci, '127.0.0.3', 102),
                ('backend', 'incoming-request', 's-p', '127.0.0.2', 40000+ci, '127.0.0.3', 103)]:
            downstream = stage == 'outgoing-request' or role == 'backend'
            expected.append(dict(chain=chain, role=role, stage=stage, side=side,
                tuple=(client_ip, client_port, server_ip, 18080), pid=pid, tid=pid))
            row = dict.fromkeys(v.COLUMNS, 0)
            counter += 1
            row.update(id=str(counter), start_us='100000000', end_us='100100000', agent_id=22, signal_source=3,
                type=2, protocol=6, l7_protocol=20, tap_side=side, l3_epc_id_0=-1, l3_epc_id_1=-1,
                ip_0=client_ip, ip_1=server_ip, client_port=client_port, server_port=18080,
                req_tcp_seq=1000+ci*10+int(downstream), resp_tcp_seq=2000+ci*10+int(downstream),
                syscall_trace_id_request=str(3000+ci*10+(0 if role=='frontend' else pid)),
                syscall_trace_id_response=str(4000+ci*10+(0 if role=='frontend' else pid)),
                process_id_0=pid if side=='c-p' else 0, process_id_1=pid if side=='s-p' else 0,
                syscall_thread_0=pid, syscall_thread_1=pid, flow_id=str(5000+ci*10+int(downstream)),
                request_resource='/traflens-no-header/%s/%s' % (RUN, chain), trace_id='', span_id='', parent_span_id='')
            rows.append(row)
    document = {'columns': v.COLUMNS, 'values': [[row[k] for k in v.COLUMNS] for row in rows]}
    count = {'columns': ['records'], 'values': [[8]]}
    return expected, rows, document, count


def runtime_example(folder=Path('/private/capture'), role='frontend', pid=102, worker_id='d'*64):
    process = dict(pid=pid, start_ticks='4242', netns='net:[123]', pidns='pid:[456]')
    scope = dict(agent_container_id='a'*64, positive={'container_id':'b'*64})
    image = 'sha256:'+'c'*64
    labels = {'io.traflens.purpose':'traflens.no-header-http', 'io.traflens.run':RUN,
              'io.traflens.role':role, 'io.traflens.output':str(folder)}
    command = ['--execute','--role',role,'--run',RUN,'--output','/output','--seconds','90','--requests','2']
    mounts = [['/private/no-header-http','/workload',False],[str(folder/role),'/output',True]]
    normalized = dict(image=image,pid_mode='host',network_mode='container:'+'b'*64,read_only=True,
        cap_drop=['ALL'],nano_cpus=500000000,memory_bytes=67108864,memory_swap_bytes=67108864,pids_limit=16,
        labels=labels,entrypoint=['/workload'],command=command,mounts=mounts,privileged=False,
        cap_add=[],port_bindings={},publish_all_ports=False,security_opt=['no-new-privileges'],restart_policy='no')
    argv = ['docker','create','--pid','host','--network',normalized['network_mode'],'--read-only',
        '--cpus','0.5','--memory','67108864','--memory-swap','67108864','--pids-limit','16','--cap-drop','ALL',
        '--security-opt','no-new-privileges','--entrypoint','/workload']
    for key,value in labels.items():
        argv.extend(['--label',key+'='+value])
    argv.extend([image,*command])
    actual = dict(normalized, **process, id=worker_id,running=True,started_at='2026-10-28T08:00:00Z',
                  security_opt_raw=['no-new-privileges:true'])
    document = dict(schema='traflens.ebpf-association.worker-runtime.v1',role=role,run=RUN,
        scope_receipt='scope-runtime.json',agent_container_id=scope['agent_container_id'],
        create={'argv':argv,'argv_sha256':v.digest(v.canonical(argv)),'normalized':normalized},inspect=actual)
    created = dict(id=worker_id,command=command,mounts=mounts)
    return document,created,process,folder,scope


class AcceptanceTests(unittest.TestCase):
    def test_default_plan_has_no_file_or_network_side_effect(self):
        with tempfile.TemporaryDirectory() as directory:
            completed = subprocess.run([sys.executable, str(SCRIPT), '--capture-dir', '/does-not-exist',
                '--query-base', 'http://example.invalid', '--output', directory+'/unused'], cwd=directory,
                check=True, capture_output=True, text=True, timeout=3)
            plan = json.loads(completed.stdout)
            self.assertFalse(plan['reads_files'])
            self.assertFalse(plan['starts_network'])
            self.assertEqual(list(Path(directory).iterdir()), [])

    def test_actual_header_bytes_hashes_and_whitelist(self):
        header = 'GET /traflens-no-header/%s/main HTTP/1.1\r\nHost: 127.0.0.2:18080\r\nConnection: close\r\n\r\n' % RUN
        raw = header.encode()
        event = dict(header=header, body='', header_bytes=len(raw), bytes=len(raw),
            header_sha256=hashlib.sha256(raw).hexdigest(), message_sha256=hashlib.sha256(raw).hexdigest(),
            complete_http_message=True, tracing_and_custom_headers_absent=True)
        self.assertEqual(v.header_oracle(event, RUN, 'main', True), raw)
        traced = dict(event, header=header.replace('Connection:', 'traceparent: hidden\r\nConnection:'))
        with self.assertRaisesRegex(ValueError, 'whitelist'):
            v.header_oracle(traced, RUN, 'main', True)
        event['header_sha256'] = '0'*64
        with self.assertRaisesRegex(ValueError, 'hash'):
            v.header_oracle(event, RUN, 'main', True)

    def test_two_chains_map_by_actual_tuple_pid_and_side(self):
        expected, _, document, count = example()
        rows, mapping, fingerprint = v.snapshot(count, document, expected, RUN, 22, 100, 101)
        self.assertEqual(len(mapping), 8)
        self.assertEqual(len(fingerprint), 64)
        main, edges = v.expected_edges(mapping, 'main')
        control, _ = v.expected_edges(mapping, 'control')
        self.assertEqual([e['kind'] for e in edges], ['network_pair', 'network_pair', 'syscall_handoff'])
        self.assertTrue({n['id'] for n in main}.isdisjoint(n['id'] for n in control))
        # Permuting the response preserves the canonical complete raw fingerprint.
        document['values'].reverse()
        self.assertEqual(v.snapshot(count, document, expected, RUN, 22, 100, 101)[2], fingerprint)
        self.assertEqual(len(rows), 8)

    def test_population_filter_never_hides_wrong_source_agent_or_trace(self):
        expected, _, document, count = example()
        for key, value in [('signal_source', 4), ('agent_id', 1), ('trace_id', 'b'*32),
                           ('end_us', '102000000'), ('process_id_0', 999), ('syscall_thread_1', 999)]:
            bad = copy.deepcopy(document)
            bad['values'][0][v.COLUMNS.index(key)] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                v.snapshot(count, bad, expected, RUN, 22, 100, 101)
        incomplete = copy.deepcopy(document)
        incomplete['values'].pop()
        with self.assertRaises(ValueError):
            v.snapshot(count, incomplete, expected, RUN, 22, 100, 101)

    def test_url_and_time_alone_cannot_make_a_handoff(self):
        expected, _, document, count = example()
        _, mapping, _ = v.snapshot(count, document, expected, RUN, 22, 100, 101)
        outgoing = mapping[('main', 'frontend', 'outgoing-request')]
        outgoing['syscall_trace_id_response'] = '99999'
        with self.assertRaisesRegex(ValueError, 'handoff'):
            v.expected_edges(mapping, 'main')

    def test_missing_endpoint_syscall_id_is_retained_and_never_weakens_handoff(self):
        expected, _, document, count = example()
        document['values'][0][v.COLUMNS.index('syscall_trace_id_request')] = '0'
        rows, mapping, _ = v.snapshot(count, document, expected, RUN, 22, 100, 101)
        self.assertEqual(rows[0]['syscall_trace_id_request'], '0')
        self.assertEqual(len(v.expected_edges(mapping, 'main')[1]), 3)
        # A missing frontend identifier must still refuse the causal handoff.
        mapping[('main', 'frontend', 'incoming-request')]['syscall_trace_id_request'] = '0'
        mapping[('main', 'frontend', 'outgoing-request')]['syscall_trace_id_request'] = '0'
        with self.assertRaises(ValueError):
            v.expected_edges(mapping, 'main')

    def test_component_checks_exact_edges_all_original_fields_and_unrelated_nodes(self):
        expected, _, document, count = example()
        _, mapping, _ = v.snapshot(count, document, expected, RUN, 22, 100, 101)
        nodes, edges = v.expected_edges(mapping, 'main')
        value = dict(seed_id=nodes[0]['id'], **{'from':100, 'to':101}, agent_id=22, signal_source=3,
            limit=64, records='4', window_records='8', scope={'org_id':1, 'user_id':1},
            nodes=[dict({k:x for k,x in n.items() if k not in ('trace_id','span_id','parent_span_id')}, in_seed_component=True) for n in nodes],
            edges=edges, candidates=[dict(kind='syscall_handoff',record_ids=[n['id']],reason='missing_counterpart',
                evidence=dict({key:str(n[key]) for key in v.HANDOFF},process_id=str(n['process_id_0' if n['tap_side']=='c-p' else 'process_id_1'])))
                for n in (nodes[0],nodes[3])], diagnostics={'seed_found':True,'ambiguous_groups':0,'missing_fields':[]})
        v.validate_component(value, nodes[0]['id'], nodes, edges, 100, 101, 22)
        for mutate in ('edge', 'pid', 'scope', 'ambiguity'):
            bad = copy.deepcopy(value)
            if mutate == 'edge':
                bad['edges'][0]['evidence']['resp_tcp_seq'] = '0'
            elif mutate == 'pid':
                bad['nodes'][0]['process_id_0'] = 999
            elif mutate == 'scope':
                bad['agent_id'] = 1
            else:
                bad['diagnostics']['ambiguous_groups'] = 1
            with self.subTest(mutate=mutate), self.assertRaises(ValueError):
                v.validate_component(bad, nodes[0]['id'], nodes, edges, 100, 101, 22)

    def test_schema_null_duplicates_and_proxyable_urls_fail(self):
        for value in [None, {}, {'columns':['records','records'], 'values':[[8,8]]},
                      {'columns':['records'], 'values':None}]:
            with self.assertRaises(ValueError):
                v.table(value, ['records'])
        self.assertEqual(v.loopback('http://127.0.0.1:20819'), 'http://127.0.0.1:20819')
        for value in ['http://localhost:20819', 'http://127.0.0.1', 'https://127.0.0.1:20819',
                      'http://127.0.0.1:20819/other', 'http://user@127.0.0.1:20819']:
            with self.assertRaises(ValueError):
                v.loopback(value)

    def test_recorded_docker_identity_matches_create_proc_and_owned_scope(self):
        document,created,process,folder,scope = runtime_example()
        result = v.worker_runtime_receipt(document,created,process,RUN,'frontend',folder,scope)
        self.assertEqual(result['container_id'],created['id'])
        self.assertEqual(result['argv_sha256'],document['create']['argv_sha256'])
        for field,value in [('pid',999),('start_ticks','4243'),('netns','net:[124]'),('pid_mode','private'),
                            ('network_mode','host'),('running',False),('memory_bytes',134217728),
                            ('cap_add',['SYS_ADMIN']),('privileged',True),('port_bindings',{'80/tcp':[]})]:
            mutated = copy.deepcopy(document)
            mutated['inspect'][field] = value
            with self.subTest(field=field),self.assertRaises(ValueError):
                v.worker_runtime_receipt(mutated,created,process,RUN,'frontend',folder,scope)

    def test_create_argv_hash_does_not_replace_real_safety_and_identity_checks(self):
        document,created,process,folder,scope = runtime_example()
        for change in ('hash','pid','network','duplicate','port','label','command','image'):
            mutated = copy.deepcopy(document)
            argv = mutated['create']['argv']
            if change == 'hash':
                mutated['create']['argv_sha256'] = '0'*64
            elif change == 'pid':
                argv[argv.index('--pid')+1] = 'private'
            elif change == 'network':
                argv[argv.index('--network')+1] = 'host'
            elif change == 'duplicate':
                argv[2:2] = ['--pid','private']
            elif change == 'port':
                argv[2:2] = ['--publish','18080:18080']
            elif change == 'label':
                argv[argv.index('--label')+1] = 'io.traflens.purpose=other'
            elif change == 'command':
                argv[-1] = '4'
            else:
                argv[argv.index('sha256:'+'c'*64)] = 'mutable:latest'
            if change != 'hash':
                mutated['create']['argv_sha256'] = v.digest(v.canonical(argv))
            with self.subTest(change=change),self.assertRaises(ValueError):
                v.worker_runtime_receipt(mutated,created,process,RUN,'frontend',folder,scope)

    def test_only_proven_selinux_unavailable_daemon_label_option_is_normalized(self):
        normalization = dict(selinux_enabled=False,host_selinux_fs_present=False,host_selinux_enforce_present=False,
            daemon_security_options=['name=seccomp,profile=builtin','name=cgroupns'],
            ignored_daemon_options=['label=disable'],reason='SELinux unavailable; Docker hostPID label disable')
        actual = dict(security_opt_raw=['no-new-privileges','label=disable'],security_opt_normalization=normalization)
        self.assertTrue(v.security_option_receipt(actual))
        self.assertTrue(v.security_option_receipt(dict(actual,security_opt_raw=['label=disable','no-new-privileges:true'])))
        self.assertFalse(v.security_option_receipt({'security_opt_raw':['no-new-privileges']}))
        for field,value in [('selinux_enabled',True),('host_selinux_fs_present',True),('host_selinux_enforce_present',True),
                            ('daemon_security_options',['name=selinux']),('daemon_security_options',[]),
                            ('ignored_daemon_options',[]),('reason','unknown')]:
            bad = copy.deepcopy(actual)
            bad['security_opt_normalization'][field] = value
            with self.subTest(field=field,value=value),self.assertRaises(ValueError):
                v.security_option_receipt(bad)
        for raw in [['label=disable'],['no-new-privileges','label=disable','seccomp=unconfined'],
                    ['no-new-privileges','label=disable','label=disable'],['no-new-privileges','label=other']]:
            with self.subTest(raw=raw),self.assertRaises(ValueError):
                v.security_option_receipt(dict(actual,security_opt_raw=raw))
        with self.assertRaises(ValueError):
            v.security_option_receipt({'security_opt_raw':['no-new-privileges','label=disable']})

    def test_legacy_receipts_are_explicit_retrospective_and_new_receipts_cannot_fall_back(self):
        processes = dict.fromkeys(('frontend','backend','generate'),{})
        with tempfile.TemporaryDirectory() as directory:
            folder,report = Path(directory),{}
            v.runtime_receipts(folder,{'integration_mode':'kernel_http'},RUN,processes,{},report)
            self.assertFalse(report['docker_runtime_receipts_passed'])
            self.assertEqual(report['runtime_receipt_mode'],'legacy_retrospective')
            for metadata in [dict(schema='traflens.ebpf-association.capture.v1',runtime_receipts_required=True),
                             dict(schema='traflens.ebpf-association.capture.v1'),dict(runtime_receipts_required=False)]:
                with self.assertRaises(ValueError):
                    v.runtime_receipts(folder,metadata,RUN,processes,{}, {})
            (folder/'frontend-runtime.json').write_text('{}')
            with self.assertRaises(ValueError):
                v.runtime_receipts(folder,{'integration_mode':'kernel_http'},RUN,processes,{}, {})

    def test_complete_new_runtime_scope_binds_all_three_real_identity_receipts(self):
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory)
            (folder/'agent').mkdir()
            scope = dict(schema='traflens.ebpf-association.scope.v1',lease_path=str(folder/'lease'),
                supervisor_pid=20,supervisor_start_ticks='200',agent_container_id='a'*64,
                positive=dict(container_id='b'*64,pid=21,start_ticks='210',inode=123,netns='net:[123]',pidns='pid:[789]',source='/proc/20/fd/10'),
                negative=dict(container_id='e'*64,pid=22,start_ticks='220',inode=124,netns='net:[124]',pidns='pid:[790]',source='/proc/20/fd/11'))
            (folder/'scope-runtime.json').write_text(json.dumps(scope))
            (folder/'agent/current.json').write_text(json.dumps({'id':'a'*64,'lease_path':str(folder/'lease')}))
            processes = {}
            for index,role in enumerate(('frontend','backend','generate')):
                document,created,process,_,_ = runtime_example(folder,role,102+index,('d','f','1')[index]*64)
                (folder/(role+'-runtime.json')).write_text(json.dumps(document))
                (folder/(role+'-created.json')).write_text(json.dumps(created))
                processes[role] = process
            proof = {'agent_container_id':'a'*64,'scope_map':{'netns_id':123}}
            metadata = {'schema':'traflens.ebpf-association.capture.v1','runtime_receipts_required':True}
            report = {}
            v.runtime_receipts(folder,metadata,RUN,processes,proof,report)
            self.assertTrue(report['docker_runtime_receipts_passed'])
            self.assertEqual(report['runtime_receipt_mode'],'recorded_actual_docker_inspect')
            self.assertEqual(len(report['actual_runtime_receipt_sha256']),4)
            scope['negative']['inode'] = 123
            scope['negative']['netns'] = 'net:[123]'
            (folder/'scope-runtime.json').write_text(json.dumps(scope))
            with self.assertRaises(ValueError):
                v.runtime_receipts(folder,metadata,RUN,processes,proof,{})


if __name__ == '__main__':
    unittest.main()
