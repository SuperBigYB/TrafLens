#!/usr/bin/env python3
"""Bounded two-scan HTTP packet acceptance, with exact keyset pagination."""
import argparse
import base64
from contextlib import contextmanager
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import re
import signal
import stat
import time
import urllib.parse
import urllib.request

SPEC = importlib.util.spec_from_file_location('http_reports', Path(__file__).with_name('verify-http-load.py'))
reports = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(reports)
require, integer = reports.require, reports.integer
MAX_BODY = 2 * 1024 * 1024


def decode(raw):
    def reject(value):
        raise ValueError('Nonfinite JSON value')
    return json.loads(raw, object_pairs_hook=reports.pairs, parse_constant=reject)


def values(document, columns):
    require(type(document) is dict and document.get('OPT_STATUS') == 'SUCCESS', 'Query failed')
    result = document.get('result')
    require(type(result) is dict and result.get('columns') == columns
            and type(result.get('values')) is list, 'Query schema differs')
    return result['values']


def scan(query, marker, count, agent_id, page_size=256, *, await_count=None):
    """Query only a whole marker. No protocol, Agent or endpoint predicates."""
    integer(count, 1, 200000); integer(agent_id, 1, 65535); integer(page_size, 64, 1000)
    require(type(marker) is str and re.fullmatch('[a-z0-9-]{1,48}', marker), 'Invalid marker')
    predicate = "request_resource LIKE '%" + marker + "%'"
    count_sql = 'SELECT Count(row) AS row_count FROM l7_flow_log WHERE ' + predicate

    def row_count():
        rows = values(query(count_sql), ['row_count'])
        require(len(rows) == 1 and type(rows[0]) is list and len(rows[0]) == 1, 'Invalid count shape')
        return integer(rows[0][0], 0, 1000000000)

    counts = [row_count()]
    while counts[-1] < count and await_count is not None:
        await_count()
        counts.append(row_count())
    require(counts[-1] == count, 'Whole-marker count differs')
    prefix = '/traflens-load/' + marker + '/'
    seen, cursor, pages = set(), '', 0
    for _ in range(math.ceil(count / page_size) + 1):
        sql = 'SELECT ' + ','.join(reports.FIELDS) + ' FROM l7_flow_log WHERE ' + predicate
        if cursor:
            sql += " AND request_resource > '" + cursor + "'"
        sql += ' ORDER BY request_resource LIMIT ' + str(page_size + 1)
        rows = values(query(sql), reports.FIELDS)
        require(len(rows) <= page_size + 1, 'Page exceeds requested limit')
        previous, validated = cursor, []
        for row in rows:
            require(type(row) is list and len(row) == len(reports.FIELDS), 'Invalid row width')
            resource = row[0]
            require(type(resource) is str and resource.startswith(prefix), 'Resource marker differs')
            suffix = resource[len(prefix):]
            require(re.fullmatch('[0-9]{1,6}', suffix) is not None, 'Noncanonical request sequence')
            seq = int(suffix)
            require(str(seq) == suffix and seq < count, 'Unexpected request sequence')
            require(resource > previous, 'Duplicate, regressing or unsorted key')
            previous = resource
            require(all(type(row[i]) is int for i in (2, 3, 4, 5, 6, 8, 9)), 'Invalid numeric type')
            require(row[1:] == ['GET', 200, 0, 20, 2, 0, 'c', agent_id, 6], 'Unexpected packet Session')
            validated.append(seq)
        pages += 1
        consumed = validated[:page_size]
        require(not seen.intersection(consumed), 'Repeated request sequence')
        seen.update(consumed)
        require(len(seen) <= count, 'Too many requests')
        if len(rows) <= page_size:
            require(len(seen) == count, 'Truncated or missing request set')
            require(row_count() == count, 'Count changed after scan')
            return {'pages': pages, 'rows': len(seen), 'count_reads': len(counts) + 1}
        # The lookahead is validated but deliberately re-read on the next page.
        cursor = rows[page_size - 1][0]
    raise ValueError('Page budget exceeded')


def verify(query, client, server, agent_id, page_size=256, *, await_count=None):
    summary = reports.verify(client, server)
    scans = [scan(query, client['marker'], summary['scheduled'], agent_id, page_size,
                  await_count=await_count if i == 0 else None) for i in range(2)]
    summary.update(kind='paginated-http-packet-acceptance', packet_exact_query_reads=2,
                   expected_captured_endpoints_per_request=1, page_size=page_size, scans=scans,
                   transactional_snapshot_proven=False)
    return summary


def save(path, document):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w') as stream:
        json.dump(document, stream, indent=2, allow_nan=False)
        stream.write('\n')


def input_identity(client, server, agent_id, page_size):
    return {'client_sha256': hashlib.sha256(Path(client).read_bytes()).hexdigest(),
            'server_sha256': hashlib.sha256(Path(server).read_bytes()).hexdigest(),
            'agent_id': agent_id, 'page_size': page_size}


def check_inputs(directory, client, server, agent_id, page_size):
    require(reports.load(Path(directory) / 'inputs.json') == input_identity(client, server, agent_id, page_size),
            'Archived report or acceptance identity differs')


def replay(directory, client, server, agent_id, page_size=256):
    """Recheck every archived SQL/response in exact order, without network access."""
    directory = Path(directory)
    names = sorted(directory.glob('query-[0-9][0-9][0-9][0-9][0-9][0-9].json'))
    integer(page_size, 64, 1000)
    count = reports.verify(client, server)['scheduled']
    require(len(names) <= 2 * (math.ceil(count / page_size) + 3) + 300, 'Archive call budget exceeded')
    require([p.name for p in names] == ['query-%06d.json' % i for i in range(1, len(names) + 1)],
            'Archive query sequence differs')
    calls = iter(names)
    def query(sql):
        path = next(calls, None)
        require(path is not None, 'Incomplete archive')
        record = reports.load(path)
        require(record.get('sql') == sql, 'Archived query differs')
        return record['response']
    # Polls are replayed; finite archive exhaustion is the replay budget.
    summary = verify(query, client, server, agent_id, page_size, await_count=lambda: None)
    require(next(calls, None) is None, 'Unexpected extra archived query')
    return summary


@contextmanager
def deadline(seconds):
    # Socket timeouts measure inactivity; SIGALRM also bounds a slow-drip read.
    require(signal.getitimer(signal.ITIMER_REAL) == (0.0, 0.0), 'Existing timer must not be replaced')
    previous = signal.getsignal(signal.SIGALRM)
    def expired(signum, frame):
        raise TimeoutError('Collection deadline exceeded')
    signal.signal(signal.SIGALRM, expired)
    signal.setitimer(signal.ITIMER_REAL, seconds)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--client', required=True, type=Path)
    parser.add_argument('--server', required=True, type=Path)
    parser.add_argument('--agent-id', required=True, type=int)
    parser.add_argument('--page-size', type=int, default=256)
    parser.add_argument('--timeout', type=int, default=120)
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument('--execute', action='store_true')
    modes.add_argument('--replay', type=Path)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    client, server = reports.load(args.client), reports.load(args.server)
    plan = reports.verify(client, server)
    integer(args.agent_id, 1, 65535); integer(args.page_size, 64, 1000); integer(args.timeout, 10, 300)
    if args.replay:
        check_inputs(args.replay, args.client, args.server, args.agent_id, args.page_size)
        print(json.dumps(replay(args.replay, client, server, args.agent_id, args.page_size), allow_nan=False))
        return
    if not args.execute:
        print(json.dumps({'execute': False, 'scheduled': plan['scheduled'], 'page_size': args.page_size,
                          'exact_scans': 2, 'timeout_seconds': args.timeout}))
        return
    require(args.output is not None and args.output.is_absolute(), 'New absolute private output directory required')
    parent = args.output.parent
    require(parent.is_dir() and parent.resolve() == parent and parent.stat().st_uid == os.getuid()
            and stat.S_IMODE(parent.stat().st_mode) & 0o077 == 0, 'Output parent must be owned, private and not symlinked')
    args.output.mkdir(mode=0o700)
    save(args.output / 'inputs.json', input_identity(args.client, args.server, args.agent_id, args.page_size))
    start, calls = time.monotonic(), 0
    budget = 2 * (math.ceil(plan['scheduled'] / args.page_size) + 3) + args.timeout
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    def query(sql):
        nonlocal calls
        remaining = args.timeout - (time.monotonic() - start)
        require(remaining > 0 and calls < budget, 'Query time or call budget exhausted')
        calls += 1
        record = {'sql': sql}
        try:
            payload = urllib.parse.urlencode({'db': 'flow_log', 'sql': sql}).encode('ascii')
            request = urllib.request.Request('http://127.0.0.1:20416/v1/query/', data=payload)
            with opener.open(request, timeout=min(15, remaining)) as response:
                raw = response.read(MAX_BODY + 1)
                require(len(raw) <= MAX_BODY, 'Query response too large')
                try:
                    record['response'] = decode(raw)
                except (ValueError, UnicodeError):
                    record['invalid_response_base64'] = base64.b64encode(raw).decode('ascii')
                    raise
            require(time.monotonic() - start < args.timeout, 'Query deadline exceeded')
            return record['response']
        except Exception as exc:
            record['error_type'] = type(exc).__name__
            raise
        finally:
            save(args.output / ('query-%06d.json' % calls), record)
    def await_count():
        require(time.monotonic() - start + 1 < args.timeout, 'Ingestion deadline exceeded')
        time.sleep(1)
    try:
        with deadline(args.timeout):
            summary = verify(query, client, server, args.agent_id, args.page_size, await_count=await_count)
            check_inputs(args.output, args.client, args.server, args.agent_id, args.page_size)
            require(replay(args.output, client, server, args.agent_id, args.page_size) == summary, 'Archive replay differs')
        save(args.output / 'summary.json', summary)
        print(json.dumps(summary, allow_nan=False))
    except Exception as exc:
        save(args.output / 'failure.json', {'pass': False, 'error_type': type(exc).__name__, 'calls': calls})
        raise SystemExit('Packet acceptance failed; private output retained') from None


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        raise ValueError('Query redirects are forbidden')


if __name__ == '__main__':
    main()
