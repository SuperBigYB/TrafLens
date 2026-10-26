import argparse
import json
from pathlib import Path

root = Path('/tmp/traflens-lab-20261026')
evidence = root / 'evidence'
parser = argparse.ArgumentParser()
parser.add_argument('--dns-marker', default='dns-20261026-ingest1')
parser.add_argument('--mysql-marker', default='mysql20261026a')
args = parser.parse_args()
for protocol, marker, protocol_id in [('dns', args.dns_marker, 120), ('mysql', args.mysql_marker, 60)]:
    client = json.loads((root / f'traffic-{protocol}-client-{marker}.json').read_text())
    server = json.loads((root / f'traffic-{protocol}-server-{marker}.json').read_text())
    for document in (client, server):
        assert document['marker'] == marker
        assert len(document['records']) == 20
        assert [record['sequence'] for record in document['records']] == list(range(20))
        assert all(record['verified'] is True for record in document['records'])
    records = []
    if protocol == 'dns':
        for document in (client, server):
            assert document['complete'] is True and document['errors'] == []
        keys = ('sequence', 'id', 'name', 'address', 'rcode', 'ttl', 'query_hex', 'response_hex')
        for index, (request, response) in enumerate(zip(client['records'], server['records'])):
            assert all(request[key] == response[key] for key in keys)
            assert request['name'] == f'q{index}.{marker}.traflens.invalid'
            assert request['address'] == f'198.18.0.{index + 1}'
            assert request['rcode'] == 0 and request['ttl'] == 60
            records.append({'request_resource': request['name'], 'request_type': 'A',
                            'response_code': 0, 'response_status': 0,
                            'response_result': f"A={request['address']} TTL=60"})
    else:
        for document in (client, server):
            assert document['success'] is True and document['quit_verified'] is True
            assert document['database_execution'] is False
        keys = ('sequence', 'request_type', 'request_resource', 'column_name', 'row_value',
                'expected_response_status', 'expected_response_code')
        for request, response in zip(client['records'], server['records']):
            assert all(request[key] == response[key] for key in keys)
            assert request['request_type'] == 'COM_QUERY'
            records.append({'request_resource': request['request_resource'], 'request_type': 'COM_QUERY',
                            'response_code': None, 'response_status': 0})
    expected = {'marker': marker, 'protocol': protocol_id, 'records': records}
    path = evidence / f'expected-{protocol}-{marker}.json'
    path.write_text(json.dumps(expected, indent=2) + '\n')
    path.chmod(0o600)
    print(json.dumps({'protocol': protocol, 'client_and_server_exact_count': 20,
                      'matching_wire_and_result_records': True, 'expected': str(path)}))
