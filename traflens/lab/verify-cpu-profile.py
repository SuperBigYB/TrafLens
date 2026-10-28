#!/usr/bin/env python3
"""Finite read-only real Go CPU-profile acceptance; default is an offline plan.

Execute on Linux with the original pprof and its saved `go tool pprof -raw`
stdout. The tool independently reruns that decoder before trusting the raw
stack oracle. It queries only the new request-bounded native profile route.
"""
import argparse
from collections import Counter
from datetime import datetime
from decimal import Decimal
import gzip
import hashlib
import io
import ipaddress
import json
import os
from pathlib import Path
import re
import selectors
import signal
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request

MAX_BODY = 4 << 20
MAX_PPROF = 1 << 20
MAX_ROWS = 256
MAX_SAMPLES = 10000
MAX_NODES = 8192
MAX_DEPTH = 512
BUDGETS = {'compressed_bytes': 4 << 20, 'decoded_stack_bytes': 1 << 20,
           'total_decoded_stack_bytes': 8 << 20, 'nodes': MAX_NODES, 'stack_depth': MAX_DEPTH}
FIELDS = ['id', 'time', 'agent_id', 'app_service', 'profile_event_type',
          'profile_value_unit', 'profile_value', 'profile_language_type',
          'profile_create_timestamp', 'process_id', 'compression_algo']
BOUNDED_ROUTE = '/v1/profile/ProfileTracingBounded'


def integer(value, low=0, high=2**64 - 1):
    if type(value) is int:
        number = value
    elif isinstance(value, str) and re.fullmatch(r'[0-9]+', value):
        number = int(value)
    else:
        raise ValueError('Expected an exact nonnegative integer')
    if not low <= number <= high:
        raise ValueError('Integer outside acceptance budget')
    return number


def save(path, value):
    with path.open('x', encoding='utf-8') as stream:
        json.dump(value, stream, indent=2, ensure_ascii=False)
        stream.write('\n')


def read_bounded(path, limit):
    with path.open('rb') as stream:
        data = stream.read(limit + 1)
    if len(data) > limit:
        raise ValueError('Input exceeds finite byte budget')
    return data


def query_base(value):
    parsed = urllib.parse.urlsplit(value)
    if (parsed.scheme != 'http' or parsed.username is not None or parsed.password is not None
            or parsed.path not in ('', '/') or parsed.query or parsed.fragment):
        raise ValueError('Query base must be an explicit numeric loopback HTTP base')
    try:
        if not ipaddress.ip_address(parsed.hostname).is_loopback or not 1 <= parsed.port <= 65535:
            raise ValueError()
    except (TypeError, ValueError):
        raise ValueError('Use a numeric loopback address and explicit port') from None
    return value.rstrip('/')


def epoch(value):
    if type(value) is int:
        return integer(value, 1, 2**32 - 1)
    if not isinstance(value, str):
        raise ValueError('Missing explicit native timestamp')
    # Python3.10 accepts only3/6 fractional digits. Pad/truncate solely for
    # parsing an already explicit timezone, never change the recorded second.
    text = re.sub(r'\.(\d+)(?=Z|[+-]\d\d:\d\d$)',
                  lambda m: '.' + m[1].ljust(6, '0')[:6], value)
    parsed = datetime.fromisoformat(text.replace('Z', '+00:00'))
    if parsed.tzinfo is None:
        raise ValueError('Native timestamp lacks explicit timezone')
    return int(parsed.timestamp())


def parse_raw(data, app):
    """Parse the finite symbolized Go CPU `pprof -raw` layout, fail closed."""
    text = data.decode('utf-8')
    lines = text.splitlines()
    if 'PeriodType: cpu nanoseconds' not in lines:
        raise ValueError('Expected a real Go CPU/nanoseconds period')
    period_line = next((line for line in lines if line.startswith('Period: ')), '')
    period = integer(period_line.removeprefix('Period: '), 1, 10**9)
    stamp = next((line for line in lines if line.startswith('Time: ')), '')
    match = re.fullmatch(r'Time: (\d{4}-\d\d-\d\d) (\d\d:\d\d:\d\d)(?:\.(\d{1,9}))? ([+-]\d{4})(?: \S+)?', stamp)
    if not match:
        raise ValueError('Expected an explicit-offset Go raw profile time')
    start = int(datetime.strptime(match[1] + ' ' + match[2] + ' ' + match[4], '%Y-%m-%d %H:%M:%S %z').timestamp())
    duration = next((line.removeprefix('Duration: ') for line in lines if line.startswith('Duration: ')), '')
    if not re.fullmatch(r'[0-9]+(?:\.[0-9]+)?', duration) or not 0 < Decimal(duration) <= 300:
        raise ValueError('CPU profile duration outside finite bounds')
    try:
        samples_start = lines.index('Samples:') + 1
        locations_start = lines.index('Locations')
        mappings_start = lines.index('Mappings')
    except ValueError:
        raise ValueError('Missing symbolized Go raw sections') from None
    if lines[samples_start].split() != ['samples/count', 'cpu/nanoseconds']:
        raise ValueError('Storage samples must be compared to samples/count, not CPU nanoseconds')
    samples, label_seen = [], False
    for line in lines[samples_start + 1:locations_start]:
        if not line.strip():
            continue
        row = re.fullmatch(r'\s*([0-9]+)\s+([0-9]+):\s*((?:[0-9]+\s*)+)', line)
        if row:
            count = integer(row[1], 1, MAX_SAMPLES)
            cpu_ns = integer(row[2], 1, MAX_SAMPLES * 10**9)
            ids = [integer(item, 1, MAX_NODES) for item in row[3].split()]
            if cpu_ns != count * period or len(ids) > MAX_DEPTH:
                raise ValueError('CPU/count period or stack depth differs')
            samples.append((count, cpu_ns, ids))
            if len(samples) > MAX_SAMPLES:
                raise ValueError('Too many raw sample rows')
        elif re.fullmatch(r'\s+[^:\s]+:\[.*\]', line):
            if line.strip().startswith('traflens_run:'):
                if line.strip() != 'traflens_run:[' + app + ']':
                    raise ValueError('Original profile run label differs from application')
                label_seen = True
        else:
            raise ValueError('Unsupported Go raw sample layout')
    locations, current = {}, None
    for line in lines[locations_start + 1:mappings_start]:
        if not line.strip():
            continue
        location = re.fullmatch(r'\s*([0-9]+):\s+0x[0-9a-fA-F]+(?:\s+M=[0-9]+)?\s+(.+)', line)
        if location:
            current = integer(location[1], 1, MAX_NODES)
            if current in locations:
                raise ValueError('Duplicate Go raw location')
            locations[current] = []
            tail = location[2]
        elif current is not None:
            tail = line.strip()
        else:
            raise ValueError('Unsupported Go raw location layout')
        frame = re.fullmatch(r'(\S+)\s+.+:[0-9]+(?::[0-9]+)?(?:\s+s=-?[0-9]+)?', tail)
        if not frame or len(frame[1]) > 16384 or '\0' in frame[1]:
            raise ValueError('Expected resolved finite Go function names')
        locations[current].append(frame[1])
    collapsed = Counter()
    for count, _, ids in samples:
        leaf_to_root = []
        for identity in ids:
            if identity not in locations:
                raise ValueError('Raw sample references an unresolved location')
            leaf_to_root.extend(locations[identity])
        if not 1 <= len(leaf_to_root) <= MAX_DEPTH:
            raise ValueError('Expanded inline stack exceeds finite bounds')
        collapsed[tuple(reversed(leaf_to_root))] += count
    total = sum(collapsed.values())
    if not label_seen or not collapsed or total > MAX_SAMPLES or len(collapsed) > MAX_ROWS:
        raise ValueError('Missing real labeled samples or raw population exceeds budget')
    return {'stacks': collapsed, 'samples': total, 'cpu_nanoseconds': sum(r[1] for r in samples),
            'period_nanoseconds': period, 'start_epoch': start, 'raw_sample_rows': len(samples)}


def sampling_receipt(value, profile_hash, profile_bytes, time_from, time_to):
    """Bind the unchanged sampling identity separately from transport app labels."""
    run = value.get('run', '')
    if (not re.fullmatch(r'cpu-[0-9a-f]{24}', run) or value.get('profile_sha256') != profile_hash
            or value.get('profile_bytes') != profile_bytes
            or value.get('source') != 'go_runtime_pprof_self'
            or value.get('sampling_scope') != 'current process only'
            or value.get('completed_duration') is not True):
        raise ValueError('Original sampling receipt does not identify this unchanged real pprof')
    start = integer(value.get('started_unix_ns'), 1, 2**63 - 1) // 10**9
    end = integer(value.get('finished_unix_ns'), 1, 2**63 - 1) // 10**9
    if not time_from <= start <= end <= time_to:
        raise ValueError('Query interval must cover the original receipt sampling interval')
    return run, start, end


def decode_again(go, profile, output, deadline):
    """Decode only the original file; no symbol downloads or Go module downloads."""
    environment = dict(os.environ, GOTOOLCHAIN='local', GOWORK='off', GOPROXY='off', GOSUMDB='off',
                       GOMEMLIMIT='64MiB', GOMAXPROCS='1')
    process = subprocess.Popen([go, 'tool', 'pprof', '-raw', '-symbolize=none', str(profile)],
                               stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               start_new_session=True, env=environment)
    buffers = {0: bytearray(), 1: bytearray()}
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ, 0)
    selector.register(process.stderr, selectors.EVENT_READ, 1)
    limit_time = min(deadline, time.monotonic() + 15)
    success = False
    try:
        while selector.get_map():
            if time.monotonic() >= limit_time:
                raise TimeoutError('Go raw decoder exceeded finite deadline')
            for key, _ in selector.select(min(1, max(.001, limit_time - time.monotonic()))):
                chunk = os.read(key.fd, 65536)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                target = buffers[key.data]
                cap = MAX_BODY if key.data == 0 else 8192
                target.extend(chunk[:max(0, cap + 1 - len(target))])
                if len(target) > cap:
                    raise ValueError('Go raw decoder output exceeds finite budget')
        if process.wait(timeout=1) != 0:
            raise ValueError('Go tool pprof did not decode the original file')
        success = True
        return bytes(buffers[0])
    finally:
        if not success:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait(timeout=5)
        selector.close()
        process.stdout.close()
        process.stderr.close()
        (output / 'go-pprof-raw.stdout').open('xb').write(buffers[0][:MAX_BODY])
        (output / 'go-pprof-raw.stderr').open('xb').write(buffers[1][:8192])


def rows(document, required):
    if document.get('OPT_STATUS') != 'SUCCESS' or not isinstance(document.get('result'), dict):
        raise ValueError('Native query did not return a complete successful result')
    result = document['result']
    columns = result.get('columns')
    if (not isinstance(columns, list) or not all(isinstance(c, str) for c in columns)
            or len(set(columns)) != len(columns) or not set(required) <= set(columns)):
        raise ValueError('Missing/duplicate query columns')
    values = result.get('values')
    if values is None:
        values = []
    if not isinstance(values, list) or len(values) > MAX_ROWS + 1 or any(not isinstance(r, list) or len(r) != len(columns) for r in values):
        raise ValueError('Malformed or excessive query rows')
    return [dict(zip(columns, row)) for row in values]


def snapshot(summary, document, app, agent, original, max_rows):
    aggregate = rows(summary, ['records', 'samples'])
    if len(aggregate) != 1:
        raise ValueError('Expected one Count/Sum aggregate')
    count = integer(aggregate[0]['records'], 1, max_rows)
    samples = integer(aggregate[0]['samples'], 1, MAX_SAMPLES)
    actual = rows(document, FIELDS)
    if len(actual) != count or samples != original['samples']:
        raise ValueError('Whole-marker row/sample population differs from original pprof')
    identities, total = set(), 0
    for row in actual:
        identity = row['id']
        if not isinstance(identity, str) or identity in identities:
            raise ValueError('Missing/duplicate exact string record ID')
        integer(identity, 1)
        identities.add(identity)
        for key, expected in [('agent_id', agent), ('app_service', app), ('profile_event_type', 'cpu'),
                              ('profile_value_unit', 'samples'), ('profile_language_type', 'Golang'),
                              ('process_id', 0), ('compression_algo', 'zstd')]:
            if row[key] != expected or type(row[key]) is not type(expected):
                raise ValueError('Unexpected unfiltered profile metadata: ' + key)
        if epoch(row['time']) != original['start_epoch'] or epoch(row['profile_create_timestamp']) != original['start_epoch']:
            raise ValueError('Stored timestamp differs from original real CPU profile')
        total += integer(row['profile_value'], 1, MAX_SAMPLES)
    if total != samples:
        raise ValueError('Stored sample weights differ from whole-marker Sum')
    fingerprint = hashlib.sha256(json.dumps(actual, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    return {'records': count, 'samples': samples, 'ids': sorted(identities), 'fingerprint': fingerprint}


def validate_tree(document, expected, app, row_cap, input_rows):
    if document.get('OPT_STATUS') != 'SUCCESS' or not isinstance(document.get('result'), dict):
        raise ValueError('Bounded readable-tree API failed')
    tree = document['result']
    if tree.get('bounds_applied') is not True or tree.get('max_rows') != row_cap or tree.get('input_rows') != input_rows or tree.get('budgets') != BUDGETS:
        raise ValueError('Request-level native bounds absent or different')
    functions, types = tree.get('functions'), tree.get('function_types')
    function_values, node_values = tree.get('function_values', {}), tree.get('node_values', {})
    if function_values.get('columns') != ['self_value', 'total_value'] or node_values.get('columns') != ['function_id', 'parent_node_id', 'self_value', 'total_value']:
        raise ValueError('Unexpected bounded tree schema')
    nodes, fn_values = node_values.get('values'), function_values.get('values')
    if input_rows == 0:
        if functions != [] or types != [] or nodes != [] or fn_values != []:
            raise ValueError('Negative scope is not an explicit empty bounded tree')
        return Counter()
    if (not isinstance(functions, list) or not 2 <= len(functions) <= MAX_NODES or functions[0] != app
            or len(set(functions)) != len(functions) or not all(isinstance(f, str) and 0 < len(f) <= 16384 and '\0' not in f for f in functions)
            or not isinstance(types, list) or len(types) != len(functions) or not all(isinstance(t, str) for t in types)
            or not isinstance(nodes, list) or not 2 <= len(nodes) <= MAX_NODES
            or not isinstance(fn_values, list) or len(fn_values) != len(functions)):
        raise ValueError('Missing or excessive bounded function/node data')
    total_samples = sum(expected.values())
    child_totals = [0] * len(nodes)
    function_totals = [[0, 0] for _ in functions]
    paths, collapsed = {}, Counter()
    for index, row in enumerate(nodes):
        if not isinstance(row, list) or len(row) != 4 or any(type(v) is not int for v in row):
            raise ValueError('Invalid exact bounded node integers')
        function, parent, own, total = row
        if not 0 <= function < len(functions) or not 0 <= own <= total <= total_samples:
            raise ValueError('Invalid bounded node weight/function')
        if index == 0:
            if function != 0 or parent != -1 or own != 0 or total != total_samples:
                raise ValueError('Bounded root differs from original sample sum')
            paths[index] = ()
        else:
            if not 0 <= parent < index or function == 0:
                raise ValueError('Cycle, extra root or unsupported node ordering')
            paths[index] = paths[parent] + (functions[function],)
            if len(paths[index]) > MAX_DEPTH:
                raise ValueError('Bounded tree depth exceeds input contract')
            child_totals[parent] += total
            if own:
                collapsed[paths[index]] += own
        function_totals[function][0] += own
        function_totals[function][1] += total
    for index, row in enumerate(nodes):
        if row[2] + child_totals[index] != row[3]:
            raise ValueError('Node self/children do not conserve samples')
    if fn_values != function_totals or any(any(type(v) is not int for v in row) for row in fn_values):
        raise ValueError('Function values differ from complete node aggregation')
    if collapsed != expected:
        raise ValueError('Every native decoded stack/weight must match original Go CPU samples')
    return collapsed


class Client:
    def __init__(self, base, output, deadline):
        self.base, self.output, self.deadline, self.index = base, output, deadline, 0
        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, *args, **kwargs):
                return None
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())

    def request(self, name, path, fields, as_json=False):
        self.index += 1
        remaining = self.deadline - time.monotonic()
        if self.index > 20 or remaining <= 0:
            raise TimeoutError('Finite request count/deadline exhausted')
        encoded = json.dumps(fields).encode() if as_json else urllib.parse.urlencode(fields).encode()
        request = urllib.request.Request(self.base + path, data=encoded,
            headers={'Content-Type': 'application/json' if as_json else 'application/x-www-form-urlencoded', 'X-Org-Id': '1'})
        try:
            response = self.opener.open(request, timeout=min(8, remaining))
        except urllib.error.HTTPError as error:
            response = error
        with response:
            status, raw = response.code, response.read(MAX_BODY + 1)
        prefix = '%03d-%s' % (self.index, name)
        (self.output / (prefix + '.body')).open('xb').write(raw)
        save(self.output / (prefix + '.request.json'), {'path': path, 'fields': fields, 'http': status})
        if len(raw) > MAX_BODY:
            raise ValueError('Native response exceeds4MiB')
        value = json.loads(raw, parse_constant=lambda _: (_ for _ in ()).throw(ValueError('Nonfinite JSON')))
        if not isinstance(value, dict):
            raise ValueError('Native response is not an envelope')
        return status, value

    def query(self, name, sql):
        status, value = self.request(name, '/v1/query/', {'db': 'profile', 'sql': sql})
        if status != 200:
            raise ValueError('Native profile query HTTP failure')
        return value


def accept(client, args, original, report):
    marker = "app_service LIKE '%%%s%%'" % args.app
    summary_sql = 'SELECT Count(row) AS records,Sum(profile_value) AS samples FROM in_process WHERE ' + marker
    detail_sql = ('SELECT toString(_id) AS id,' + ','.join(FIELDS[1:]) + ' FROM in_process WHERE ' + marker
                  + ' ORDER BY _id ASC LIMIT ' + str(args.max_rows + 1))
    def read_snapshot():
        return snapshot(client.query('count-sum', summary_sql), client.query('whole-marker', detail_sql),
                        args.app, args.agent, original, args.max_rows)
    previous, stable = None, None
    for _ in range(args.attempts):
        try:
            current = read_snapshot()
            report['attempts'].append({'passed': True, **current})
            if previous is not None and current == previous:
                stable = current
                break
            previous = current
        except (ValueError, OSError) as error:
            previous = None
            report['attempts'].append({'passed': False, 'error': str(error)})
        time.sleep(min(1, max(0, client.deadline - time.monotonic())))
    if stable is None:
        raise ValueError('Two complete identical whole-marker reads did not pass')
    if stable['records'] < 2:
        raise ValueError('At least two stored rows are needed to exercise a valid n-1 row-cap refusal')
    fields = {'app_service': args.app, 'profile_event_type': 'cpu', 'profile_language_type': 'Golang',
              'time_start': args.time_from, 'time_end': args.time_to,
              'tag_filter': "agent_id=%d AND profile_value_unit='samples'" % args.agent}
    status, refused = client.request('bounded-n-minus-one', BOUNDED_ROUTE,
        dict(fields, max_rows=stable['records'] - 1), True)
    if status != 400 or refused.get('OPT_STATUS') != 'RESOURCE_NUM_EXCEEDED' or 'max_rows' not in str(refused.get('DESCRIPTION', '')):
        raise ValueError('Native n-1 cap must explicitly refuse excess input before a partial tree')
    status, tree = client.request('bounded-complete', BOUNDED_ROUTE, dict(fields, max_rows=stable['records']), True)
    if status != 200:
        raise ValueError('Native exact row cap did not return a complete tree')
    validate_tree(tree, original['stacks'], args.app, stable['records'], stable['records'])
    for name, changed in [('wrong-time', {'time_start': args.time_to + 1, 'time_end': args.time_to + 1}),
                          ('wrong-agent', {'tag_filter': "agent_id=%d AND profile_value_unit='samples'" % (65535 if args.agent != 65535 else 65534)})]:
        status, empty = client.request(name, BOUNDED_ROUTE, dict(fields, **changed, max_rows=stable['records']), True)
        if status != 200:
            raise ValueError('Native negative scope did not return a valid empty bounded result')
        validate_tree(empty, Counter(), args.app, stable['records'], 0)
    language = rows(client.query('different-language-control', summary_sql + " AND profile_language_type='eBPF'"), ['records', 'samples'])
    if len(language) != 1 or integer(language[0]['records']) != 0 or integer(language[0]['samples']) != 0:
        raise ValueError('Different-language control unexpectedly has marked samples')
    if read_snapshot() != stable:
        raise ValueError('Stored metadata/weight fingerprint changed during non-atomic tree verification')
    report.update(records=stable['records'], samples=stable['samples'], exact_ids=stable['ids'],
        row_fingerprint=stable['fingerprint'], fingerprint_scope='supported ID/metadata/weight projection; not compressed stack bytes',
        consecutive_exact_reads=2, bounded_n_minus_one_rejected=True, bounded_n_complete=True,
        all_decoded_stacks_and_weights_match=True, wrong_time_and_agent_empty=True,
        different_language_empty=True, language_is_not_an_authoritative_source_field=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--execute', action='store_true')
    parser.add_argument('--query-base', default='http://127.0.0.1:20416')
    parser.add_argument('--app')
    parser.add_argument('--from', dest='time_from', type=int)
    parser.add_argument('--to', dest='time_to', type=int)
    parser.add_argument('--agent', type=int)
    parser.add_argument('--pprof', type=Path)
    parser.add_argument('--pprof-raw', type=Path)
    parser.add_argument('--receipt', type=Path, help='original immutable real sampling receipt; its run may differ from the fresh transport app')
    parser.add_argument('--expected-stacks', type=Path, help='optional third independent JSON: profile_sha256 and stacks[{frames,samples}]')
    parser.add_argument('--go', default='go', help='explicit local Go decoder executable recommended; no modules/network')
    parser.add_argument('--output', type=Path)
    parser.add_argument('--max-rows', type=int, default=MAX_ROWS)
    parser.add_argument('--attempts', type=int, default=4)
    parser.add_argument('--timeout', type=int, default=90)
    args = parser.parse_args()
    if not args.execute:
        print(json.dumps({'execute': False, 'reads_files': False, 'starts_network': False, 'starts_capture': False,
            'max_rows': MAX_ROWS, 'max_samples': MAX_SAMPLES, 'route': BOUNDED_ROUTE, 'legacy_fallback': False}))
        return
    base = query_base(args.query_base)
    if (not re.fullmatch(r'cpu-[0-9a-f]{24}', args.app or '') or type(args.agent) is not int or not 1 <= args.agent <= 65535
            or type(args.time_from) is not int or type(args.time_to) is not int
            or not 0 < args.time_from <= args.time_to < 2**32 - 1 or args.time_to - args.time_from > 300
            or not args.pprof or not args.pprof_raw or not args.receipt or not args.output or not 2 <= args.max_rows <= MAX_ROWS
            or not 2 <= args.attempts <= 6 or not 15 <= args.timeout <= 120):
        parser.error('Explicit finite application/Agent/original profile/interval/new output required')
    output = args.output
    if (not output.is_absolute() or output != output.resolve() or output.exists()
            or output.parent.stat().st_uid != os.geteuid() or output.parent.stat().st_mode & 0o077):
        parser.error('Fresh canonical output with an owned private parent required')
    os.umask(0o077)
    output.mkdir(mode=0o700)
    started = time.monotonic()
    report = {'passed': False, 'attempts': [], 'source_limit': 'Real self Go CPU pprof through external integration, not eBPF. No L7 signal_source; database PID0 is not the sampled OS PID. No absolute CPU-percent inference.', 'new_sampling': False, 'new_ingestion': False, 'legacy_fallback': False}
    def expired(*_):
        raise TimeoutError('Finite CPU-profile acceptance deadline exceeded')
    signal.signal(signal.SIGALRM, expired)
    signal.setitimer(signal.ITIMER_REAL, args.timeout)
    try:
        profile = read_bounded(args.pprof, MAX_PPROF)
        if not profile.startswith(b'\x1f\x8b'):
            raise ValueError('Original runtime pprof must be an unchanged gzip artifact')
        with gzip.GzipFile(fileobj=io.BytesIO(profile)) as compressed:
            if len(compressed.read((8 << 20) + 1)) > 8 << 20:
                raise ValueError('Original protobuf exceeds8MiB decoded input budget')
        raw = read_bounded(args.pprof_raw, MAX_BODY)
        decoded = decode_again(args.go, args.pprof, output, started + args.timeout)
        if hashlib.sha256(decoded).digest() != hashlib.sha256(raw).digest():
            raise ValueError('Saved raw stdout differs from independently redecoded original pprof; use matching Go/TZ and preserve exact stdout')
        profile_hash = hashlib.sha256(profile).hexdigest()
        receipt = json.loads(read_bounded(args.receipt, 65536))
        original_run, receipt_start, receipt_end = sampling_receipt(receipt, profile_hash, len(profile), args.time_from, args.time_to)
        original = parse_raw(decoded, original_run)
        if not receipt_start <= original['start_epoch'] <= receipt_end:
            raise ValueError('Decoded profile time differs from its original sampling receipt')
        if not args.time_from <= original['start_epoch'] <= args.time_to:
            raise ValueError('Expected interval excludes the original unmodified sample time')
        if args.expected_stacks:
            other = json.loads(read_bounded(args.expected_stacks, MAX_BODY))
            expected = Counter()
            for row in other.get('stacks', []):
                frames = row.get('frames')
                if not isinstance(frames, list) or not 1 <= len(frames) <= MAX_DEPTH or not all(isinstance(f, str) and f for f in frames):
                    raise ValueError('Invalid independent collapsed stack')
                expected[tuple(frames)] += integer(row.get('samples'), 1, MAX_SAMPLES)
            if other.get('profile_sha256') != profile_hash or expected != original['stacks']:
                raise ValueError('Independent expected stacks differ from actual original pprof')
        report.update(profile_sha256=profile_hash, raw_pprof_stdout_sha256=hashlib.sha256(decoded).hexdigest(),
            original_samples=original['samples'], original_cpu_nanoseconds=original['cpu_nanoseconds'],
            original_period_nanoseconds=original['period_nanoseconds'], independent_raw_redecode_exact=True,
            original_sampling_run=original_run, transport_app_is_not_sampling_identity=True)
        accept(Client(base, output, started + args.timeout), args, original, report)
        report['passed'] = True
    except Exception as error:
        report['error'] = type(error).__name__ + ': ' + str(error)
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        report['elapsed_seconds'] = round(time.monotonic() - started, 3)
        save(output / 'result.json', report)
    print(json.dumps({k: v for k, v in report.items() if k not in ['attempts', 'exact_ids']}))
    raise SystemExit(0 if report['passed'] else 1)


if __name__ == '__main__':
    main()
