#!/usr/bin/env python3
"""Read-only acceptance of a finite no-header HTTP kernel-evidence capture.

Default is an offline plan. Execute after capture/restoration, with an unchanged
capture directory, an explicit <=60-second window, numeric loopback forwards,
and a fresh private output. URL markers select the population only; socket
tuples, actual local PID/TID, TCP sequence and dual-phase syscall IDs prove the
two finite associations. This does not prove complete headerless AutoTracing.
"""
import argparse
from collections import Counter
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import signal
import time
import urllib.error
import urllib.parse
import urllib.request

MAX_BODY = 4 << 20
MAX_ROWS = 64
MAX_REQUESTS = 32
COLUMNS = ('id,start_us,end_us,agent_id,signal_source,type,protocol,l7_protocol,tap_side,'
           'l3_epc_id_0,l3_epc_id_1,ip_0,ip_1,client_port,server_port,req_tcp_seq,resp_tcp_seq,'
           'syscall_trace_id_request,syscall_trace_id_response,syscall_cap_seq_0,syscall_cap_seq_1,'
           'process_id_0,process_id_1,syscall_thread_0,syscall_thread_1,flow_id,request_resource,'
           'trace_id,span_id,parent_span_id').split(',')
TEXT = {'id', 'start_us', 'end_us', 'syscall_trace_id_request', 'syscall_trace_id_response', 'flow_id'}
STRINGS = {'tap_side', 'ip_0', 'ip_1', 'request_resource', 'trace_id', 'span_id', 'parent_span_id'}
NETWORK = ('agent_id,l3_epc_id_0,l3_epc_id_1,ip_0,ip_1,client_port,server_port,'
           'protocol,l7_protocol,req_tcp_seq,resp_tcp_seq').split(',')
HANDOFF = ['agent_id', 'syscall_trace_id_request', 'syscall_trace_id_response', 'syscall_thread_0', 'syscall_thread_1']


def require(condition, message):
    if not condition:
        raise ValueError(message)


def number(value, low=0, high=2**64 - 1):
    require(type(value) is int or isinstance(value, str) and re.fullmatch(r'-?[0-9]+', value), 'Invalid exact integer')
    result = int(value)
    require(low <= result <= high, 'Integer outside finite contract')
    return result


def digest(data):
    return hashlib.sha256(data).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()


def read_file(path, cap=MAX_BODY):
    require(path.is_file() and not path.is_symlink(), 'Regular immutable input file required')
    with path.open('rb') as stream:
        data = stream.read(cap + 1)
    require(len(data) <= cap, 'Input exceeds byte budget')
    return data


def read_json(path):
    return json.loads(read_file(path))


def save(path, document):
    with path.open('xb') as stream:
        stream.write(canonical(document) + b'\n')


def loopback(value):
    parsed = urllib.parse.urlsplit(value)
    require(parsed.scheme == 'http' and parsed.hostname and ipaddress.ip_address(parsed.hostname).is_loopback
            and parsed.port and not parsed.username and not parsed.password and parsed.path in ('', '/')
            and not parsed.query and not parsed.fragment, 'Explicit numeric loopback HTTP base with port required')
    return value.rstrip('/')


def table(value, columns):
    require(isinstance(value, dict) and isinstance(value.get('columns'), list) and isinstance(value.get('values'), list),
            'Missing complete successful query schema')
    names, values = value['columns'], value['values']
    require(len(set(names)) == len(names) and set(columns) <= set(names), 'Missing or duplicate query columns')
    require(len(values) <= MAX_ROWS + 1, 'Response row budget exceeded')
    require(all(isinstance(row, list) and len(row) == len(names) for row in values), 'Incomplete query row')
    return [dict(zip(names, row)) for row in values]


def header_oracle(event, run, chain, request):
    header, body = event.get('header'), event.get('body')
    require(isinstance(header, str) and isinstance(body, str), 'Missing complete actual HTTP bytes')
    raw = header.encode('ascii')
    payload = body.encode('utf-8')
    require(len(raw) <= 4096 and len(payload) <= 16384 and raw.endswith(b'\r\n\r\n'), 'Incomplete/excessive HTTP header')
    lines = header[:-4].split('\r\n')
    fields = {}
    for line in lines[1:]:
        key, separator, value = line.partition(':')
        key = key.lower()
        require(separator and key not in fields, 'Malformed/duplicate actual HTTP header')
        fields[key] = value.strip()
    if request:
        require(lines[0] == 'GET /traflens-no-header/%s/%s HTTP/1.1' % (run, chain)
                and set(fields) == {'host', 'connection'} and body == '', 'Request header whitelist failed')
        require(fields['host'] in ('127.0.0.2:18080', '127.0.0.3:18080'), 'Unexpected actual Host')
    else:
        require(lines[0] == 'HTTP/1.1 200 OK' and set(fields) == {'content-length', 'content-type', 'connection'}
                and fields['content-type'] == 'application/json' and fields['content-length'] == str(len(payload)),
                'Response header whitelist/actual length failed')
    require(fields['connection'] == 'close', 'Expected finite connection')
    require(event.get('header_bytes') == len(raw) and event.get('bytes') == len(raw) + len(payload)
            and event.get('header_sha256') == digest(raw) and event.get('message_sha256') == digest(raw + payload),
            'Actual HTTP header/message hash or byte count differs')
    require(event.get('complete_http_message') is True and event.get('tracing_and_custom_headers_absent') is True,
            'Application did not prove complete no-custom-header bytes')
    return raw + payload


def socket_tuple(event, side):
    local, peer = event['local'], event['peer']
    for endpoint in (local, peer):
        require(endpoint['ip'] in ('127.0.0.1', '127.0.0.2', '127.0.0.3'), 'Socket escaped owned loopback endpoints')
        number(endpoint['port'], 1, 65535)
    client, server = (local, peer) if side == 'c-p' else (peer, local)
    require(server['port'] == 18080, 'Unexpected actual HTTP server port')
    return client['ip'], client['port'], server['ip'], server['port']


def application_oracle(folder, report):
    meta, result = read_json(folder / 'ingestion-metadata.json'), read_json(folder / 'result.json')
    run = meta.get('run')
    require(isinstance(run, str) and re.fullmatch(r'nh-[0-9a-f]{24}', run), 'Invalid unchanged capture marker')
    agent = number(meta.get('agent_id'), 1, 65535)
    require(result.get('run') == run and result.get('agent_id') == agent and result.get('pass_execution') is True
            and result.get('pass') is True and result.get('error') in ('', None) and not result.get('cleanup_errors')
            and result.get('actual_root_requests') == 2 and result.get('actual_http_exchanges') == 4
            and result.get('expected_observations') == 8 and result.get('collector_stopped') is True,
            'Finite capture execution/restoration receipt failed')
    # Lease evidence proves scope/readiness, not the separately executed app or storage.
    restoration = read_json(folder / 'scope-restoration.json')
    for key in ('pass', 'scope_only', 'external_agent_exit_and_inventory_restored', 'tracer_exit_confirmed_before_namespace_release',
                'namespace_pins_released', 'original_host_bpf_inventory_restored', 'original_tracefs_restored',
                'preexisting_containers_still_running', 'released_by_coordinator', 'scope_proof_approved'):
        require(restoration.get(key) is True, 'Scope/restoration receipt failed: ' + key)
    proofs = list(folder.glob('agent/*/coordinator-scope-proof.json'))
    require(len(proofs) == 1, 'Exactly one actual coordinator readiness proof required')
    proof = read_json(proofs[0])
    for key in ('scope_fd_pinned', 'safe_profile_verified', 'native_collector_started', 'fresh_three_listener_sync'):
        require(proof.get(key) is True, 'Actual collector readiness proof failed: ' + key)
    require(number(proof.get('scope_map', {}).get('validated'), 1, 1) == 1 and proof.get('af_packet_socket_count') == 0,
            'Native namespace map/packet-socket scope failed')
    events, processes = {}, {}
    file_hashes = {}
    stage_orders = {'frontend': [('incoming-request', 'recv'), ('outgoing-request', 'send'), ('outgoing-response', 'recv'), ('incoming-response', 'send')],
                    'backend': [('incoming-request', 'recv'), ('incoming-response', 'send')],
                    'generate': [('root-request', 'send'), ('root-response', 'recv')]}
    netns = None
    for role, stages in stage_orders.items():
        process = read_json(folder / role / 'process.json')
        receipt = read_json(folder / role / 'receipt.json')
        require(process.get('role') == role and process.get('run') == run and process.get('single_threaded') is True
                and process.get('tracing_headers') is False and process.get('sdk') is False, 'Actual single-process identity missing')
        pid, tid = number(process['pid'], 1, 2**32-1), number(process['tid'], 1, 2**32-1)
        require(pid == tid and re.fullmatch(r'[1-9][0-9]*', process['start_ticks']), 'Expected actual single-threaded PID/start identity')
        require(re.fullmatch(r'net:\[[0-9]+\]', process['netns']) is not None, 'Missing actual network namespace identity')
        netns = process['netns'] if netns is None else netns
        require(process['netns'] == netns and number(re.search(r'[0-9]+', netns)[0]) == number(proof['scope_map']['netns_id']),
                'Application was outside approved actual kernel namespace')
        require(all(receipt.get(k) == process[k] for k in ('role', 'run', 'pid', 'tid', 'start_ticks', 'netns', 'pidns'))
                and receipt.get('pass') is True and receipt.get('completed_requests') == 2 and receipt.get('expected_requests') == 2
                and receipt.get('wire_events') == 2*len(stages) and receipt.get('url_is_only_population_marker') is True
                and receipt.get('same_service_thread') is True and receipt.get('tracing_headers') is False
                and receipt.get('sdk') is False and receipt.get('error') == '', 'Application completion identity/receipt differs')
        raw = read_file(folder / role / 'wire.jsonl')
        role_events = [json.loads(line) for line in raw.splitlines()]
        require(len(role_events) == 2*len(stages), 'Missing actual HTTP wire events')
        calls = receipt.get('application_calls')
        expected_calls = [{'chain': chain, 'first_event': i*len(stages)+1, 'last_event': (i+1)*len(stages), 'complete': True}
                          for i, chain in enumerate(('main', 'control'))]
        require(calls == expected_calls, 'Independent application call execution does not prove two separate chains')
        previous_mono = 0
        for i, event in enumerate(role_events):
            chain = ('main', 'control')[i // len(stages)]
            stage, operation = stages[i % len(stages)]
            require(event.get('sequence') == i+1 and event.get('chain') == chain and event.get('stage') == stage
                    and event.get('operation') == operation
                    and all(event.get(k) == process[k] for k in ('role', 'run', 'pid', 'tid', 'start_ticks', 'netns', 'pidns')),
                    'Actual ordered wire/process identity differs')
            begin, end = number(event['started_monotonic_ns'], 1), number(event['finished_monotonic_ns'], 1)
            require(previous_mono <= begin <= end and number(event['started_unix_ns'], 1) <= number(event['finished_unix_ns'], 1),
                    'Actual synchronous application call order differs')
            previous_mono = end
            number(event['syscalls'], 1, 128)
            header_oracle(event, run, chain, stage.endswith('request'))
            events[(role, chain, stage)] = event
        processes[role] = process
        file_hashes[role + '/wire.jsonl'] = digest(raw)
    require(len({p['pid'] for p in processes.values()}) == 3, 'Three independent actual processes required')
    require(all(p['pidns'] == os.readlink('/proc/1/ns/pid') for p in processes.values()),
            'Recorded worker PID namespaces differ from this verifier host PID namespace')
    for chain in ('main', 'control'):
        for a, b in [(('generate', 'root-request'), ('frontend', 'incoming-request')),
                     (('frontend', 'outgoing-request'), ('backend', 'incoming-request')),
                     (('backend', 'incoming-response'), ('frontend', 'outgoing-response')),
                     (('frontend', 'incoming-response'), ('generate', 'root-response'))]:
            left, right = events[(a[0], chain, a[1])], events[(b[0], chain, b[1])]
            require(left['message_sha256'] == right['message_sha256'] and left['header_sha256'] == right['header_sha256']
                    and left['bytes'] == right['bytes'] and left['local'] == right['peer'] and left['peer'] == right['local'],
                    'Actual peer wire bytes or socket tuples differ')
        backend_body = json.loads(events[('backend', chain, 'incoming-response')]['body'])
        frontend_body = json.loads(events[('frontend', chain, 'incoming-response')]['body'])
        for role, body in [('frontend', frontend_body), ('backend', backend_body)]:
            require(body.get('run') == run and body.get('chain') == chain and body.get('role') == role
                    and body.get('pid') == processes[role]['pid'] and body.get('tid') == processes[role]['tid'],
                    'Actual nested response execution identity differs')
        require(frontend_body.get('backend') == backend_body, 'Actual frontend did not return the observed backend result')
    expected = []
    for chain in ('main', 'control'):
        for role, stage, side in [('generate', 'root-request', 'c-p'), ('frontend', 'incoming-request', 's-p'),
                                  ('frontend', 'outgoing-request', 'c-p'), ('backend', 'incoming-request', 's-p')]:
            event = events[(role, chain, stage)]
            expected.append({'chain': chain, 'role': role, 'stage': stage, 'side': side,
                             'tuple': socket_tuple(event, side), 'pid': processes[role]['pid'], 'tid': processes[role]['tid']})
    report.update(scope_receipt_passed=True, readiness_receipt_passed=True, application_receipts_passed=True,
                  original_wire_sha256=file_hashes, application_root_requests=2, actual_http_exchanges=4,
                  scope_proof_is_not_application_or_storage_acceptance=True,
                  recorded_pid_namespace_matches_current_verifier_host=True,
                  host_pid_proof='Recorded self PID namespace plus exact stored local PID/TID; current-host namespace comparison is retrospective, not a historical Docker inspect.')
    return run, agent, expected


def snapshot(count_document, document, expected, run, agent, start, end):
    counts = table(count_document, ['records'])
    require(len(counts) == 1 and number(counts[0]['records']) == 8, 'Unfiltered whole-marker count is not exactly eight')
    raw = table(document, COLUMNS)
    require(len(raw) == 8, 'Incomplete whole-marker observations')
    normalized, mapping, identities = [], {}, set()
    for row in raw:
        item = {}
        for key in COLUMNS:
            value = row[key]
            if key in STRINGS:
                require(isinstance(value, str), 'Invalid original text column')
                item[key] = value
            else:
                n = number(value, -(2**31) if key.startswith('l3_epc') else 0)
                item[key] = str(n) if key in TEXT else n
        require(item['id'] != '0' and item['id'] not in identities, 'Duplicate/missing original observation ID')
        identities.add(item['id'])
        require(item['agent_id'] == agent and item['signal_source'] == 3 and item['type'] == 2
                and item['protocol'] == 6 and item['l7_protocol'] == 20 and item['tap_side'] in ('c-p', 's-p'),
                'Whole marker hides no wrong Agent/source/record/protocol')
        require(start <= int(item['end_us'])//1000000 <= end and 0 < int(item['start_us']) <= int(item['end_us']),
                'Original microsecond interval outside explicit scope')
        require(all(item[k] == '' for k in ('trace_id', 'span_id', 'parent_span_id')), 'No-header population contains explicit trace context')
        require(all(number(item[k], 1) for k in ('req_tcp_seq', 'resp_tcp_seq', 'flow_id', 'syscall_thread_0', 'syscall_thread_1')),
                'Missing real kernel identifiers')
        actual_tuple = item['ip_0'], item['client_port'], item['ip_1'], item['server_port']
        local_pid = item['process_id_0' if item['tap_side'] == 'c-p' else 'process_id_1']
        candidates = [e for e in expected if e['side'] == item['tap_side'] and e['tuple'] == actual_tuple and e['pid'] == local_pid]
        require(len(candidates) == 1, 'Observation cannot map uniquely by real tuple/local PID/side')
        app = candidates[0]
        key = app['chain'], app['role'], app['stage']
        require(key not in mapping and item['syscall_thread_0'] == item['syscall_thread_1'] == app['tid'],
                'Actual host PID/TID mapping is not exact')
        require(item['request_resource'] == '/traflens-no-header/%s/%s' % (run, app['chain']), 'Population URL differs after independent tuple/PID mapping')
        mapping[key] = item
        normalized.append(item)
    require(len(mapping) == len(expected) == 8, 'Missing independently identified application observation')
    normalized.sort(key=lambda row: int(row['id']))
    return normalized, mapping, digest(canonical(normalized))


def expected_edges(mapping, chain):
    generator = mapping[(chain, 'generate', 'root-request')]
    incoming = mapping[(chain, 'frontend', 'incoming-request')]
    outgoing = mapping[(chain, 'frontend', 'outgoing-request')]
    backend = mapping[(chain, 'backend', 'incoming-request')]
    edges = []
    for client, server in ((generator, incoming), (outgoing, backend)):
        require(all(client[k] == server[k] for k in NETWORK), 'Actual network peers disagree on dual TCP evidence')
        edges.append({'kind': 'network_pair', 'from_id': client['id'], 'to_id': server['id'],
                      'evidence': {key: str(client[key]) for key in NETWORK}})
    require(incoming['process_id_1'] == outgoing['process_id_0'] != 0
            and all(number(incoming[k], 1) for k in ('syscall_trace_id_request', 'syscall_trace_id_response'))
            and all(incoming[k] == outgoing[k] for k in HANDOFF)
            and incoming['flow_id'] != outgoing['flow_id'], 'Actual frontend dual-phase syscall handoff differs')
    evidence = {key: str(incoming[key]) for key in HANDOFF}
    evidence.update(process_id=str(incoming['process_id_1']), upstream_flow_id=incoming['flow_id'], downstream_flow_id=outgoing['flow_id'])
    edges.append({'kind': 'syscall_handoff', 'from_id': incoming['id'], 'to_id': outgoing['id'], 'evidence': evidence})
    return [generator, incoming, outgoing, backend], edges


def validate_component(value, seed, nodes, edges, start, end, agent):
    require(value.get('seed_id') == seed and value.get('from') == start and value.get('to') == end
            and value.get('agent_id') == agent and value.get('signal_source') == 3 and value.get('limit') == 64
            and value.get('scope') == {'org_id': 1, 'user_id': 1}, 'Association exact scope differs')
    diagnostics = value.get('diagnostics', {})
    missing = [{'record_id': node['id'], 'fields': sorted(key for key in ('syscall_trace_id_request', 'syscall_trace_id_response')
                if node[key] == '0')} for node in nodes]
    missing = [item for item in missing if item['fields']]
    require(diagnostics.get('seed_found') is True and diagnostics.get('ambiguous_groups') == 0
            and sorted(diagnostics.get('missing_fields', []), key=canonical) == sorted(missing, key=canonical),
            'Kernel missing-field diagnostics differ from original evidence')
    require(value.get('records') == '4' and value.get('window_records') == '8', 'Association component/window cardinality differs')
    actual = value.get('nodes')
    require(isinstance(actual, list) and len(actual) == 4 and len({n.get('id') for n in actual}) == 4, 'Partial/duplicate kernel component nodes')
    wanted = {n['id']: {k: v for k, v in n.items() if k not in ('trace_id', 'span_id', 'parent_span_id')} for n in nodes}
    for node in actual:
        node = dict(node)
        require(node.pop('in_seed_component', None) is True and node.get('id') in wanted and node == wanted[node['id']],
                'Association node differs from exact original stored evidence')
    require(sorted(value.get('edges', []), key=canonical) == sorted(edges, key=canonical), 'Association edges/evidence differ from independently proved calls')
    endpoints = [nodes[0], nodes[3]]
    candidates = []
    for node in endpoints:
        evidence = {key: str(node[key]) for key in HANDOFF}
        evidence['process_id'] = str(node['process_id_0' if node['tap_side'] == 'c-p' else 'process_id_1'])
        candidates.append({'kind': 'syscall_handoff', 'record_ids': [node['id']],
            'reason': 'insufficient_nonzero_identifiers' if node['syscall_trace_id_request'] == '0' or node['syscall_trace_id_response'] == '0' else 'missing_counterpart',
            'evidence': evidence})
    require(sorted(value.get('candidates', []), key=canonical) == sorted(candidates, key=canonical),
            'Endpoint candidates do not preserve exact missing/counterpart evidence')


class Client:
    def __init__(self, output, deadline):
        self.output, self.deadline, self.requests = output, deadline, 0
        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, *_args, **_kwargs):
                return None
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())

    def request(self, name, base, path, fields, post=False):
        self.requests += 1
        remaining = self.deadline - time.monotonic()
        require(self.requests <= MAX_REQUESTS and remaining > 0, 'Finite request/deadline exhausted')
        encoded = urllib.parse.urlencode(fields)
        url = base + path + ('' if post else '?' + encoded)
        request = urllib.request.Request(url, data=encoded.encode() if post else None,
            headers={'Content-Type': 'application/x-www-form-urlencoded', 'X-Org-Id': '1', 'X-User-Id': '1'})
        prefix = '%02d-%s' % (self.requests, name)
        save(self.output / (prefix + '.request.json'), {'base': base, 'path': path, 'fields': fields})
        try:
            response = self.opener.open(request, timeout=min(12, remaining))
        except urllib.error.HTTPError as error:
            response = error
        with response:
            code, raw = response.code, response.read(MAX_BODY + 1)
        with (self.output / (prefix + '.body')).open('xb') as stream:
            stream.write(raw)
        save(self.output / (prefix + '.http.json'), {'http': code, 'bytes': len(raw), 'sha256': digest(raw)})
        require(code == 200 and len(raw) <= MAX_BODY, 'HTTP failure/excess response; original evidence retained')
        return json.loads(raw)

    def query(self, name, base, sql):
        document = self.request(name, base, '/v1/query/', {'db': 'flow_log', 'sql': sql}, True)
        require(document.get('OPT_STATUS') == 'SUCCESS', 'Native query did not succeed')
        return document.get('result')


def accept(client, args, run, agent, expected, report):
    where = "request_resource LIKE '%%%s%%'" % run
    projection = 'toString(_id) AS id,toUnixTimestamp64Micro(start_time) AS start_us,toUnixTimestamp64Micro(end_time) AS end_us,' + ','.join(COLUMNS[3:])
    def read_snapshot(label):
        count = client.query(label+'-count', args.query_base, 'SELECT Count(row) AS records FROM l7_flow_log WHERE '+where)
        rows = client.query(label+'-all', args.query_base, 'SELECT '+projection+' FROM l7_flow_log WHERE '+where+' ORDER BY _id ASC LIMIT 65')
        return snapshot(count, rows, expected, run, agent, args.time_from, args.time_to)
    original, mapping, fingerprint = read_snapshot('first')
    for source, expected_count in ((3, 8), (0, 0), (4, 0)):
        control = client.query('source-'+str(source), args.query_base,
            'SELECT Count(row) AS records FROM l7_flow_log WHERE '+where+' AND signal_source = '+str(source))
        rows = table(control, ['records'])
        require(len(rows) == 1 and number(rows[0]['records']) == expected_count, 'Whole-marker source control differs')
    components = {}
    for chain in ('main', 'control'):
        nodes, edges = expected_edges(mapping, chain)
        components[chain] = {n['id'] for n in nodes}
        for node in nodes:
            params = {'id': node['id'], 'from': args.time_from, 'to': args.time_to, 'agent': agent}
            response = client.request('component-'+node['id'], args.console_base, '/api/associations', params)
            validate_component(response, node['id'], nodes, edges, args.time_from, args.time_to, agent)
            detail = client.request('detail-'+node['id'], args.console_base, '/api/requests',
                dict(params, source=3, session=1, proto=20, q=run, limit=2))
            records = table(detail, ['id', 'agent_id', 'signal_source', 'type', 'protocol', 'l7_protocol', 'request_resource',
                                     'tap_side', 'trace_id', 'span_id', 'parent_span_id', 'response_code', 'response_status'])
            require(len(records) == 1, 'Exact observation detail absent/duplicate')
            row = records[0]
            for key in ('id', 'agent_id', 'signal_source', 'type', 'protocol', 'l7_protocol', 'request_resource', 'tap_side', 'trace_id', 'span_id', 'parent_span_id'):
                require(row.get(key) == node[key], 'Exact detail differs from original evidence: '+key)
            require(number(row['response_code']) == 200 and number(row['response_status']) == 0, 'Actual successful HTTP detail differs')
    require(components['main'].isdisjoint(components['control']), 'Unrelated executed control chain merged')
    front_main = mapping[('main', 'frontend', 'incoming-request')]
    front_control = mapping[('control', 'frontend', 'incoming-request')]
    require(all(front_main[k] != front_control[k] for k in ('syscall_trace_id_request', 'syscall_trace_id_response')),
            'Unrelated dual-phase syscall identities reused across chains')
    seed = original[0]['id']
    unknown = str(next(i for i in range(1, 100) if str(i) not in {n['id'] for n in original}))
    for label, changed in [('wrong-agent', {'agent': 65535 if agent != 65535 else 65534}),
                           ('wrong-time', {'from': args.time_to+1, 'to': args.time_to+1}), ('unknown-id', {'id': unknown})]:
        params = dict(id=seed, agent=agent, **{'from': args.time_from, 'to': args.time_to})
        params.update(changed)
        negative = client.request(label, args.console_base, '/api/associations', params)
        require(negative.get('seed_id') == params['id'] and negative.get('agent_id') == params['agent']
                and negative.get('from') == params['from'] and negative.get('to') == params['to']
                and negative.get('records') == '0' and negative.get('nodes') == [] and negative.get('edges') == []
                and negative.get('candidates') == [] and negative.get('diagnostics', {}).get('seed_found') is False,
                'Negative exact scope leaked a component')
    final, _, final_fingerprint = read_snapshot('second')
    require(final == original and final_fingerprint == fingerprint, 'Complete original evidence changed across non-atomic API verification')
    report.update(storage_acceptance_passed=True, whole_marker_reads=2, observations=8, source_counts={'3': 8, '0': 0, '4': 0},
        original_projection_sha256=fingerprint, original_ids=[n['id'] for n in original], exact_detail_reads=8,
        exact_seed_components=8, network_edges_per_component=2, syscall_handoffs_per_component=1,
        disjoint_main_control=True, negative_scopes_passed=3, original_trace_context_empty=True,
        exact_actual_host_pid_tid_mapping=True, request_count=client.requests)
    report['zero_request_syscall_ids_not_hidden'] = sum(row['syscall_trace_id_request'] == '0' for row in original)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--execute', action='store_true')
    parser.add_argument('--capture-dir', type=Path)
    parser.add_argument('--query-base')
    parser.add_argument('--console-base')
    parser.add_argument('--from', dest='time_from', type=int)
    parser.add_argument('--to', dest='time_to', type=int)
    parser.add_argument('--agent', type=int, help='optional assertion; actual Agent derives from unchanged capture metadata')
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    if not args.execute:
        print(json.dumps({'execute': False, 'reads_files': False, 'starts_network': False, 'starts_capture': False,
                          'creates_files': False, 'max_rows': 64, 'max_requests': MAX_REQUESTS, 'total_seconds': 60,
                          'per_request_seconds': 12, 'legacy_fallback': False}))
        return
    try:
        args.query_base, args.console_base = loopback(args.query_base), loopback(args.console_base)
        require(args.capture_dir and args.capture_dir.is_absolute() and args.capture_dir.resolve() == args.capture_dir
                and args.capture_dir.is_dir() and args.output and args.output.is_absolute() and not args.output.exists()
                and args.output.resolve() == args.output and args.output.parent.stat().st_uid == os.geteuid()
                and not args.output.parent.stat().st_mode & 0o077, 'Canonical capture and fresh output under owned private parent required')
        require(type(args.time_from) is int and type(args.time_to) is int and 0 < args.time_from <= args.time_to
                and args.time_to-args.time_from < 60, 'Explicit at most60 inclusive seconds required')
    except (ValueError, TypeError, OSError) as error:
        parser.error(str(error))
    os.umask(0o077)
    args.output.mkdir(mode=0o700)
    started = time.monotonic()
    report = {'passed': False, 'scope_receipt_passed': False, 'readiness_receipt_passed': False,
        'application_receipts_passed': False, 'storage_acceptance_passed': False, 'new_sampling': False, 'new_ingestion': False,
        'source': 'native eBPF source3; finite synchronous owned HTTP processes without trace/custom headers',
        'limitations': 'Exact finite kernel evidence associations; no synthetic Span IDs, inferred Span parents, full AutoTracing, or unobserved causality. URL only selects population; no URL/time-based edges.',
        'query_atomicity': 'Two complete same-ID/projection reads bracket independent API requests; no database snapshot transaction.'}
    def expired(*_):
        raise TimeoutError('Finite60second acceptance deadline exceeded')
    signal.signal(signal.SIGALRM, expired)
    signal.setitimer(signal.ITIMER_REAL, 60)
    try:
        run, agent, expected = application_oracle(args.capture_dir, report)
        require(args.agent is None or args.agent == agent, 'Explicit Agent assertion differs from capture')
        report.update(run=run, agent_id=agent, time_from=args.time_from, time_to=args.time_to)
        accept(Client(args.output, started+60), args, run, agent, expected, report)
        report['passed'] = True
    except Exception as error:
        report['error'] = type(error).__name__ + ': ' + str(error)
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        report['elapsed_seconds'] = round(time.monotonic()-started, 3)
        save(args.output / 'result.json', report)
    print(json.dumps({k: v for k, v in report.items() if k not in ('original_ids', 'original_wire_sha256')}))
    raise SystemExit(0 if report['passed'] else 1)


if __name__ == '__main__':
    main()
