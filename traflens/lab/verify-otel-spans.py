#!/usr/bin/env python3
"""Read-only acceptance of real SDK HTTP spans; default plan has no side effects."""
import argparse
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
MAX_SPANS = 16
SOURCE = 'OpenTelemetry SDK explicit instrumentation; native OTLP integration, not eBPF'
FIELDS = ['id', 'trace_id', 'span_id', 'parent_span_id', 'app_service', 'app_instance',
          'span_kind', 'endpoint', 'start_us', 'end_us', 'response_duration', 'agent_id', 'signal_source', 'type']


def require(condition, message):
    if not condition:
        raise ValueError(message)


def integer(value, low=0, high=2**64-1):
    require(type(value) is int or isinstance(value, str) and re.fullmatch('[0-9]+', value), 'Expected exact integer')
    result = int(value)
    require(low <= result <= high, 'Integer outside finite acceptance bounds')
    return result


def identifier(value, width):
    require(isinstance(value, str) and re.fullmatch('[0-9a-f]{%d}' % width, value)
            and value != '0' * width, 'Missing or malformed actual SDK identity')
    return value


def save(path, value):
    with path.open('x', encoding='utf-8') as stream:
        json.dump(value, stream, indent=2, ensure_ascii=False)
        stream.write('\n')


def read(path, cap=MAX_BODY):
    require(path.is_absolute() and path == path.resolve() and path.is_file() and not path.is_symlink(),
            'Input must be a canonical regular artifact')
    with path.open('rb') as stream:
        data = stream.read(cap + 1)
    require(len(data) <= cap, 'Artifact exceeds finite byte budget')
    return data


def document(raw):
    value = json.loads(raw, parse_constant=lambda _: (_ for _ in ()).throw(ValueError('Nonfinite JSON')))
    require(isinstance(value, dict), 'Expected JSON object')
    return value


def jsonl(path, limit):
    lines = read(path).splitlines()
    require(0 < len(lines) <= limit and all(lines), 'SDK artifact population exceeds budget or is empty')
    return [document(line) for line in lines]


def base_url(value):
    parsed = urllib.parse.urlsplit(value)
    require(parsed.scheme == 'http' and parsed.username is None and parsed.password is None
            and parsed.path in ('', '/') and not parsed.query and not parsed.fragment,
            'Use an explicit numeric loopback HTTP base without credentials')
    try:
        require(ipaddress.ip_address(parsed.hostname).is_loopback and 1 <= parsed.port <= 65535,
                'Use a numeric loopback address and explicit port')
    except (TypeError, ValueError):
        raise ValueError('Use a numeric loopback address and explicit port') from None
    return value.rstrip('/')


def expected_artifacts(work):
    meta = document(read(work / 'ingestion-metadata.json', 1 << 20))
    run = meta.get('run', '')
    require(re.fullmatch('span-[0-9a-f]{24}', run) and meta.get('integration_mode') == 'otel_trace',
            'Expected an actual public SDK trace lifecycle')
    agent = integer(meta.get('agent_id'), 1, 65535)
    lifecycle = document(read(work / 'result.json', 1 << 20))
    require(lifecycle.get('run') == run and lifecycle.get('pass') is True and lifecycle.get('cleaned') is True,
            'Owned lifecycle did not complete and restore successfully')
    expected, receipts = {}, {}
    for role, suffix in [('frontend', 'front'), ('backend', 'back')]:
        directory = work / role
        receipt = document(read(directory / 'receipt.json', 65536))
        require(receipt.get('run') == run and receipt.get('source') == SOURCE and receipt.get('role') == role
                and receipt.get('mode') == 'serve' and receipt.get('pass') is True
                and receipt.get('stop_reason') == 'requests_completed'
                and receipt.get('request_contract_completed') is True and receipt.get('completed_requests') == 2
                and receipt.get('sdk_exported_spans') == 4 and receipt.get('wire_batches') == 4
                and receipt.get('http_acknowledged_batches') == 4
                and receipt.get('export_errors') == [] and receipt.get('request_errors') == [],
                'Finite SDK service receipt did not pass its actual request/export contract')
        receipts[role] = receipt
        spans = jsonl(directory / 'spans.jsonl', MAX_SPANS)
        require(len(spans) == 4, 'Each real service must export four measured spans')
        for span in spans:
            trace, span_id = identifier(span.get('trace_id'), 32), identifier(span.get('span_id'), 16)
            parent = span.get('parent_span_id')
            if parent != '':
                identifier(parent, 16)
            start, end = integer(span.get('start_unix_ns'), 1, 2**63-1), integer(span.get('end_unix_ns'), 1, 2**63-1)
            resource, attributes = span.get('resource'), span.get('attributes')
            require(end >= start and span.get('source') == SOURCE and span.get('status_code') == 'Ok'
                    and isinstance(resource, dict) and resource.get('service.name') == run + '-' + suffix
                    and resource.get('service.instance.id') == run + '-' + role and resource.get('traflens.run') == run
                    and isinstance(attributes, dict) and attributes.get('traflens.run') == run
                    and attributes.get('http.method') == 'GET' and attributes.get('http.status_code') == 200
                    and attributes.get('http.target') in ['/traflens-span/' + run + '/main', '/traflens-span/' + run + '/control'],
                    'Actual SDK span metadata or measured interval differs from the finite workload')
            require((trace, span_id) not in expected, 'SDK exported duplicate span identities')
            expected[trace, span_id] = {'trace_id': trace, 'span_id': span_id, 'parent_span_id': parent,
                'app_service': resource['service.name'], 'app_instance': resource['service.instance.id'],
                'span_kind': integer(span.get('span_kind'), 1, 3), 'endpoint': span.get('name'),
                'start_us': start // 1000, 'end_us': end // 1000,
                'response_duration': end // 1000 - start // 1000, 'agent_id': agent, 'signal_source': 4, 'type': 2,
                'path': attributes['http.target'], 'parent_remote': span.get('parent_remote')}
        wires = jsonl(directory / 'wire.jsonl', 8)
        require(len(wires) == 4, 'Every real SDK export must have its own finite wire receipt')
        for index, wire in enumerate(wires, 1):
            name = 'exports/%04d.pb' % index
            payload = read(directory / name, 256 << 10)
            require(wire.get('batch') == index and wire.get('file') == name and wire.get('http_acknowledged') is True
                    and wire.get('http_status') == 200 and wire.get('bytes') == len(payload)
                    and wire.get('sha256') == hashlib.sha256(payload).hexdigest(),
                    'Saved official SDK OTLP bytes differ from their actual upload receipt')
    require(len(expected) == 8, 'Expected exactly eight real SDK spans')
    generator = document(read(work / 'generate' / 'receipt.json', 65536))
    requests = jsonl(work / 'generate' / 'requests.jsonl', 4)
    require(generator.get('pass') is True and generator.get('source') == SOURCE and generator.get('mode') == 'generate'
            and generator.get('run') == run and generator.get('completed_requests') == 2
            and len(requests) == 2 and {r.get('kind') for r in requests} == {'main', 'control'},
            'Generator did not complete main and independent control HTTP requests')
    traces = []
    for request in requests:
        response = request.get('actual_response', {})
        back = response.get('backend', {})
        trace = identifier(response.get('trace_id'), 32)
        require(trace not in traces and request.get('http_status') == 200
                and response.get('run') == run and back.get('run') == run
                and response.get('kind') == request['kind'] and back.get('kind') == request['kind']
                and back.get('trace_id') == trace, 'Actual HTTP responses do not prove two independent traces')
        traces.append(trace)
        chain = [(response.get('server_span_id'), '', 'frontend.server', 2, False),
                 (response.get('client_span_id'), response.get('server_span_id'), 'frontend.client', 3, False),
                 (back.get('server_span_id'), response.get('client_span_id'), 'backend.server', 2, True),
                 (back.get('internal_span_id'), back.get('server_span_id'), 'backend.work', 1, False)]
        require(back.get('received_parent_span_id') == response.get('client_span_id'), 'Backend did not receive the actual client parent')
        require(len({item[0] for item in chain}) == 4, 'Actual response reused a Span ID')
        for span_id, parent, endpoint, kind, remote in chain:
            identifier(span_id, 16)
            span = expected.get((trace, span_id))
            require(span is not None and span['parent_span_id'] == parent and span['endpoint'] == endpoint
                    and span['span_kind'] == kind and span['parent_remote'] is remote
                    and span['path'] == '/traflens-span/' + run + '/' + request['kind'],
                    'SDK parent graph differs from the actual HTTP response identities')
    require(generator.get('trace_ids') == traces and {key[0] for key in expected} == set(traces),
            'Generator and actual SDK trace populations differ')
    return {'run': run, 'agent': agent, 'traces': traces, 'spans': expected,
            'from': min(r['start_us'] for r in expected.values()) // 1000000,
            'to': max(r['end_us'] for r in expected.values()) // 1000000}


def rows(value, required):
    require(value.get('OPT_STATUS') == 'SUCCESS' and isinstance(value.get('result'), dict), 'Native query did not succeed completely')
    result = value['result']
    columns, values = result.get('columns'), result.get('values')
    require(isinstance(columns, list) and all(isinstance(c, str) for c in columns)
            and len(columns) == len(set(columns)) and set(required) <= set(columns), 'Native schema is missing or duplicated')
    if values is None:
        values = []
    require(isinstance(values, list) and len(values) <= MAX_ROWS
            and all(isinstance(r, list) and len(r) == len(columns) for r in values), 'Native result exceeds row budget or is malformed')
    return [dict(zip(columns, r)) for r in values]


class PendingPopulation(ValueError):
    pass


def snapshot(summary, value, expected):
    aggregate = rows(summary, ['records'])
    require(len(aggregate) == 1, 'Expected exactly one whole-marker Count')
    count = integer(aggregate[0]['records'], 0, MAX_ROWS)
    actual = rows(value, FIELDS)
    require(count <= 8 and len(actual) <= 8, 'Whole marker contains unexpected extra observations')
    identities, seen = set(), set()
    for row in actual:
        identity = row.get('id')
        require(isinstance(identity, str), 'Record ID must preserve exact UInt64 string precision')
        integer(identity, 1)
        key = row['trace_id'], row['span_id']
        require(identity not in identities and key not in seen and key in expected['spans'], 'Unexpected/duplicate native record or Span identity')
        identities.add(identity)
        seen.add(key)
        span = expected['spans'][key]
        for field in FIELDS[1:]:
            if field in ['span_kind', 'start_us', 'end_us', 'response_duration', 'agent_id', 'signal_source', 'type']:
                require(integer(row[field]) == span[field], 'Stored measured field differs from SDK: ' + field)
            else:
                require(type(row[field]) is str and row[field] == span[field], 'Stored metadata differs from unfiltered SDK: ' + field)
    if count != 8 or len(actual) != 8:
        raise PendingPopulation('Complete eight-span population is not visible yet')
    require(seen == set(expected['spans']), 'Native population does not match all SDK spans')
    ordered = sorted(actual, key=lambda row: integer(row['id'], 1))
    return {'records': 8, 'ids': sorted(identities, key=int), 'rows': ordered,
            'fingerprint': hashlib.sha256(json.dumps(ordered, sort_keys=True, separators=(',', ':')).encode()).hexdigest()}


def validate_graph(value, trace, expected, stored, empty=False):
    require(value.get('trace') == trace and value.get('signal_source') == 4
            and value.get('time_unit') == 'microseconds' and value.get('limit') == 256
            and value.get('scope') == {'org_id': 1, 'user_id': 1}, 'Console Span graph fixed scope differs')
    nodes, edges, diagnostics = value.get('nodes'), value.get('edges'), value.get('diagnostics')
    require(isinstance(nodes, list) and isinstance(edges, list) and isinstance(diagnostics, dict)
            and all(isinstance(v, list) and not v for v in diagnostics.values())
            and set(diagnostics) == {'duplicate_span_ids', 'conflicting_span_ids', 'missing_parent_records',
                                    'ambiguous_parent_records', 'cycle_records', 'invalid_span_records'},
            'Console diagnostics or complete arrays are absent or nonempty')
    if empty:
        require(value.get('records') == '0' and nodes == [] and edges == [], 'Negative scope did not return an explicit successful empty graph')
        return
    require(value.get('records') == '4' and len(nodes) == 4 and len(edges) == 3, 'Console must return every real Span and explicit parent edge')
    by_key = {(r['trace_id'], r['span_id']): r for r in stored}
    expected_edges, seen = set(), set()
    for node in nodes:
        key = trace, node.get('span_id')
        require(key in expected['spans'] and key not in seen, 'Console invented, duplicated or mixed a Span')
        seen.add(key)
        original, row = expected['spans'][key], by_key[key]
        for field in ['id', 'parent_span_id', 'app_service', 'app_instance', 'span_kind', 'endpoint', 'agent_id']:
            require(node.get(field) == row[field], 'Console observation metadata differs: ' + field)
        for field, column in [('start_us', 'start_us'), ('end_us', 'end_us'), ('duration_us', 'response_duration')]:
            require(type(node.get(field)) is str and integer(node[field]) == original[column], 'Console lost precise measured microseconds')
        if original['parent_span_id']:
            parent_id = by_key[trace, original['parent_span_id']]['id']
            require(node.get('parent_record_id') == parent_id and node.get('states') == ['linked'], 'Console parent is not the actual stored parent')
            expected_edges.add((parent_id, row['id']))
        else:
            require(node.get('parent_record_id') is None and node.get('states') == ['root'], 'Console fabricated a root parent')
    require(seen == {key for key in expected['spans'] if key[0] == trace}, 'Console omitted a real Span')
    actual_edges = [(edge.get('parent_record_id'), edge.get('child_record_id')) for edge in edges]
    require(len(set(actual_edges)) == len(actual_edges) and set(actual_edges) == expected_edges, 'Console edges do not match every explicit SDK parent')


class Client:
    def __init__(self, output, deadline):
        self.output, self.deadline, self.index = output, deadline, 0
        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, *args, **kwargs):
                return None
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())

    def request(self, base, name, path, fields=None):
        self.index += 1
        remaining = self.deadline - time.monotonic()
        require(self.index <= 32 and remaining > 0, 'Finite request/deadline budget exhausted')
        body = urllib.parse.urlencode(fields).encode() if fields is not None else None
        request = urllib.request.Request(base + path, data=body,
            headers={'Content-Type': 'application/x-www-form-urlencoded', 'X-Org-Id': '1', 'X-User-Id': '1', 'X-User-Type': '1'})
        prefix = '%03d-%s' % (self.index, name)
        save(self.output / (prefix + '.request.json'), {'path': path, 'fields': fields})
        try:
            response = self.opener.open(request, timeout=min(12, remaining))
        except urllib.error.HTTPError as error:
            response = error
        except Exception as error:
            save(self.output / (prefix + '.error.json'), {'error_type': type(error).__name__})
            raise
        with response:
            status, raw = response.code, response.read(MAX_BODY + 1)
        with (self.output / (prefix + '.body')).open('xb') as stream:
            stream.write(raw)
        save(self.output / (prefix + '.response.json'), {'http': status, 'bytes': len(raw)})
        require(len(raw) <= MAX_BODY and status == 200, 'Read-only request failed or exceeded4MiB; no expression fallback')
        return document(raw)


def accept(client, query, console, expected, report):
    marker = "app_service LIKE '%s%%'" % expected['run']
    count_sql = 'SELECT Count(row) AS records FROM l7_flow_log WHERE ' + marker
    sql = ('SELECT toString(_id) AS id,trace_id,span_id,parent_span_id,app_service,app_instance,span_kind,endpoint,'
           'toUnixTimestamp64Micro(start_time) AS start_us,toUnixTimestamp64Micro(end_time) AS end_us,'
           'response_duration,agent_id,signal_source,type FROM l7_flow_log WHERE ' + marker + ' ORDER BY _id ASC LIMIT 65')
    def query_sql(name, statement):
        return client.request(query, name, '/v1/query/', {'db': 'flow_log', 'sql': statement})
    previous, stable = None, None
    for attempt in range(6):
        try:
            current = snapshot(query_sql('whole-marker-count', count_sql), query_sql('whole-marker', sql), expected)
            report['attempts'].append({'passed': True, 'fingerprint': current['fingerprint'], 'ids': current['ids']})
            if previous is not None:
                require(current == previous, 'Complete whole-marker IDs or measured values changed')
                stable = current
                break
            previous = current
        except PendingPopulation as error:
            previous = None
            report['attempts'].append({'passed': False, 'pending': str(error)})
        if attempt < 5:
            time.sleep(min(1, max(0, client.deadline - time.monotonic())))
    require(stable is not None, 'Two complete identical eight-span reads did not pass')
    for source, wanted in [(4, 8), (0, 0), (3, 0)]:
        value = rows(query_sql('source-%d-control' % source, count_sql + ' AND signal_source = %d' % source), ['records'])
        require(len(value) == 1 and integer(value[0]['records']) == wanted, 'Actual source count/control differs')
    scope = {'from': expected['from'], 'to': expected['to'], 'agent': expected['agent']}
    for trace in expected['traces']:
        fields = dict(scope, trace=trace)
        value = client.request(console, 'console-spans', '/api/spans?' + urllib.parse.urlencode(fields))
        validate_graph(value, trace, expected, stable['rows'])
    trace = expected['traces'][0]
    wrong_trace = 'f' * 32 if 'f' * 32 not in expected['traces'] else 'e' * 32
    for name, changes in [('agent', {'agent': 65535 if expected['agent'] != 65535 else 65534}),
                          ('time', {'from': expected['to'] + 1, 'to': expected['to'] + 1}),
                          ('trace', {'trace': wrong_trace})]:
        fields = dict(scope, trace=trace, **changes) if 'trace' not in changes else dict(scope, **changes)
        value = client.request(console, 'empty-' + name, '/api/spans?' + urllib.parse.urlencode(fields))
        validate_graph(value, fields['trace'], expected, stable['rows'], True)
    for row in stable['rows']:
        fields = dict(scope, trace=row['trace_id'], id=row['id'])
        value = client.request(console, 'record-detail', '/api/requests?' + urllib.parse.urlencode(fields))
        actual = rows({'OPT_STATUS': 'SUCCESS', 'result': value}, ['id', 'trace_id', 'span_id', 'parent_span_id', 'agent_id', 'signal_source', 'type', 'response_duration'])
        require(len(actual) == 1, 'Actual record detail is missing or duplicated')
        for key in ['id', 'trace_id', 'span_id', 'parent_span_id', 'agent_id', 'signal_source', 'type']:
            require(actual[0][key] == row[key], 'Actual record detail differs from the whole-marker population')
        require(integer(actual[0]['response_duration']) == integer(row['response_duration']), 'Record detail measured duration differs')
    final = snapshot(query_sql('final-whole-marker-count', count_sql), query_sql('final-whole-marker', sql), expected)
    require(final == stable, 'Native population changed during non-atomic graph/detail acceptance')
    report.update(records=8, traces=expected['traces'], exact_ids=stable['ids'], row_fingerprint=stable['fingerprint'],
        consecutive_complete_reads=2, source4_records=8, source0_records=0, source3_records=0,
        all_sdk_fields_and_microseconds_match=True, both_actual_parent_graphs_match=True,
        wrong_agent_time_trace_empty=True, all_actual_record_details_match=True)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--execute', action='store_true')
    parser.add_argument('--work', type=Path)
    parser.add_argument('--query-base', default='http://127.0.0.1:20416')
    parser.add_argument('--console-base', default='http://127.0.0.1:20880')
    parser.add_argument('--output', type=Path)
    args = parser.parse_args(argv)
    if not args.execute:
        print(json.dumps({'execute': False, 'reads_files': False, 'starts_network': False, 'new_ingestion': False,
                          'max_rows': MAX_ROWS, 'max_sdk_spans': MAX_SPANS, 'timeout_seconds': 60}))
        return 0
    query, console = base_url(args.query_base), base_url(args.console_base)
    require(args.work and args.work.is_absolute() and args.work == args.work.resolve() and args.work.is_dir(), 'Canonical actual lifecycle work required')
    require(args.work.stat().st_uid == os.geteuid() and not args.work.stat().st_mode & 0o077,
            'Actual lifecycle artifacts must belong to the current user in a private directory')
    output = args.output
    require(output and output.is_absolute() and output == output.resolve() and not output.exists()
            and output.parent.stat().st_uid == os.geteuid() and not output.parent.stat().st_mode & 0o077,
            'Fresh output below an owned private parent required')
    os.umask(0o077)
    output.mkdir(mode=0o700)
    started = time.monotonic()
    report = {'passed': False, 'attempts': [], 'new_ingestion': False, 'new_sampling': False,
              'source_limit': 'Actual explicit SDK OTel spans/source4; no inferred eBPF, auto-instrumentation or absent-parent causal edges.'}
    def expired(*_):
        raise TimeoutError('Finite60-second OTel acceptance deadline exceeded')
    previous = signal.signal(signal.SIGALRM, expired)
    signal.setitimer(signal.ITIMER_REAL, 60)
    try:
        expected = expected_artifacts(args.work)
        save(output / 'expected-sdk-projection.json', {'run': expected['run'], 'agent': expected['agent'],
            'from': expected['from'], 'to': expected['to'], 'traces': expected['traces'], 'spans': list(expected['spans'].values())})
        report.update(run=expected['run'], agent_id=expected['agent'], time_from=expected['from'], time_to=expected['to'])
        accept(Client(output, started + 60), query, console, expected, report)
        report['passed'] = True
    except Exception as error:
        report['error'] = type(error).__name__ + ': ' + str(error)
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)
        report['elapsed_seconds'] = round(time.monotonic() - started, 3)
        save(output / 'result.json', report)
    print(json.dumps({key: value for key, value in report.items() if key not in ['attempts', 'exact_ids']}))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
