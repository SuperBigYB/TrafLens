#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Check query/config APIs in the owned isolated lab; retain raw output privately."""
import argparse
import datetime
import json
import pathlib
import re
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
import uuid


MEMBERS = ('VTAP_LCUUIDS', 'DISABLE_VTAP_LCUUIDS', 'PENDING_VTAP_LCUUIDS')


def strict_json(body):
    value = json.loads(body)
    if not isinstance(value, dict):
        raise ValueError('Expected one JSON object')
    return value


def single_count(value):
    result = value.get('result', {})
    rows = result.get('values', [])
    if result.get('columns') != ['Count(row)'] or len(rows) != 1 or len(rows[0]) != 1:
        raise ValueError('Unexpected Count(row) result shape')
    number = rows[0][0]
    if type(number) is not int or number < 0:
        raise ValueError('Count(row) must be one unsigned integer')
    return number


def require_empty_owned_group(group, identity, name):
    if not re.fullmatch(r'traflens-api-[0-9a-f]{12}', name):
        raise RuntimeError('Unexpected temporary group name')
    if not identity or group.get('LCUUID') != identity or group.get('NAME') != name:
        raise RuntimeError('Temporary group identity mismatch')
    if any(group.get(key) for key in MEMBERS):
        raise RuntimeError('Refusing to alter a populated group')


def resource_identity(info):
    # Docker can return equivalent mounts in a different order across inspect calls.
    return {'id': info['Id'], 'started': info['State']['StartedAt'],
            'mounts': sorted(info['Mounts'], key=lambda mount: mount['Destination'])}


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class Check:
    def __init__(self, lab, root, output, expected):
        self.lab, self.root, self.output = lab, root, output
        self.output.mkdir(mode=0o700, parents=True, exist_ok=False)
        self.raw, self.results = [], []
        self.version = subprocess.check_output(['docker', 'exec', 'traflens-lab-server', '/bin/deepflow-server', '-v'], text=True)
        if f'CommitID: {expected}\n' not in self.version:
            raise RuntimeError('Server binary does not match the expected source')
        self.before = self.database_identity()
        self.expected = expected

    def database_identity(self):
        values = {}
        for suffix in ('server', 'mysql', 'clickhouse'):
            info = self.lab.inspect('container', 'traflens-lab-' + suffix)
            if not info:
                raise RuntimeError('Missing owned lab container')
            self.lab.require_owned(info, self.root, 'container')
            if not info['State']['Running']:
                raise RuntimeError('Owned lab container is not running')
            values[suffix] = resource_identity(info)
        return values

    def request(self, port, path, payload=None, method='GET', form=False, raw_json=False):
        if not path.startswith('/v1/') or port not in (20416, 20417):
            raise RuntimeError('Request outside the lab API scope')
        if form and raw_json:
            raise RuntimeError('Ambiguous request encoding')
        data = payload.encode() if raw_json else urllib.parse.urlencode(payload).encode() if form else json.dumps(payload).encode() if payload is not None else None
        req = urllib.request.Request(f'http://127.0.0.1:{port}' + path, data=data, method=method,
            headers={'Content-Type': 'application/x-www-form-urlencoded' if form else 'application/json', 'X-Org-Id': '1', 'X-User-Id': '1', 'X-User-Type': '1'})
        try:
            response = urllib.request.build_opener(NoRedirect).open(req, timeout=30)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            status = response.code
            body = response.read(1048577).decode('utf-8')
        if len(body.encode()) > 1048576:
            raise RuntimeError('API response exceeds the evidence limit')
        try:
            value, single = strict_json(body), True
        except (ValueError, TypeError):
            value, single = None, False
        self.raw.append({'port': port, 'path': path, 'method': method, 'request': payload, 'status': status, 'single_json': single, 'body': body})
        return status, value, single

    def controller(self, path, payload=None, method='GET'):
        status, value, single = self.request(20417, path, payload, method)
        if not single or status != 200 or value.get('OPT_STATUS') != 'SUCCESS':
            raise RuntimeError('Controller request failed: ' + method + ' ' + path)
        return value.get('DATA')

    def queries(self, baseline):
        for sql in ('SELECT count() FROM l7_flow_log', 'SELECT Count() FROM l7_flow_log', 'SELECT Sum() FROM l7_flow_log'):
            status, value, single = self.request(20416, '/v1/query/', {'db': 'flow_log', 'sql': sql}, 'POST', form=True)
            ok = single and status == 400 and value.get('OPT_STATUS') == 'INVALID_POST_DATA'
            self.results.append({'case': sql.split()[1], 'passed': ok, 'http_status': status, 'single_json': single})
            if not baseline and not ok:
                raise RuntimeError('Empty aggregation did not return one typed client error')
        def native_count():
            return int(subprocess.check_output(['docker', 'exec', 'traflens-lab-clickhouse', 'clickhouse-client', '--query',
                'SELECT count() FROM flow_log.l7_flow_log FORMAT TabSeparatedRaw'], text=True, timeout=30).strip())
        before = native_count()
        status, value, single = self.request(20416, '/v1/query/', {'db': 'flow_log', 'sql': 'SELECT Count(row) FROM l7_flow_log'}, 'POST', form=True)
        after = native_count()
        ok = single and status == 200 and value.get('OPT_STATUS') == 'SUCCESS' and single_count(value) == before == after
        self.results.append({'case': 'Count(row)', 'passed': ok, 'http_status': status, 'single_json': single, 'native_count_matches': ok})
        if not ok:
            raise RuntimeError('Supported Count(row) control failed')

    def configurations(self):
        import yaml
        before = self.controller('/v1/vtap-groups/')
        agents_before = self.controller('/v1/vtaps/')
        name = 'traflens-api-' + uuid.uuid4().hex[:12]
        if any(g.get('NAME') == name for g in before):
            raise RuntimeError('Temporary group name already exists')
        original_configs = {g['LCUUID']: self.controller('/v1/agent-group-configuration/' + g['LCUUID'] + '/json') for g in before}
        created = self.controller('/v1/vtap-groups/', {'NAME': name, 'VTAP_LCUUIDS': [], 'TEAM_ID': 1}, 'POST')
        identity = created.get('LCUUID')
        require_empty_owned_group(created, identity, name)
        path = '/v1/agent-group-configuration/' + identity
        target = {'HTTP': '18080', 'DNS': '18053'}
        def config(leaf):
            return {'processors': {'request_log': {'filters': {'port_number_prefilters': leaf}}}}
        def read():
            value = self.controller(path + '/json')
            leaf = value['processors']['request_log']['filters']['port_number_prefilters']
            if not isinstance(leaf, str) or yaml.safe_load(leaf) != target:
                raise RuntimeError('Stored prefilter mapping differs from the synthetic input')
            return value
        try:
            self.controller(path + '/json', config(target), 'POST')
            expected = read()
            self.results.append({'case': 'nested_dict_post_and_persisted_read', 'passed': True})
            self.controller(path + '/json', config('HTTP: "18080"\nDNS: "18053"\n'), 'PUT')
            if read() != expected:
                raise RuntimeError('Equivalent legacy YAML text changed stored configuration')
            self.results.append({'case': 'yaml_string_put_and_persisted_read', 'passed': True})
            for label, leaf in (('integer_dict', 7), ('malformed_yaml_dict', 'HTTP: [')):
                status, value, single = self.request(20417, path + '/json', config(leaf), 'PUT')
                ok = single and status == 400 and value.get('OPT_STATUS') == 'INVALID_POST_DATA' and read() == expected
                self.results.append({'case': label + '_reject_without_mutation', 'passed': ok, 'http_status': status, 'single_json': single})
                if not ok:
                    raise RuntimeError('Malformed configuration was not rejected atomically')
            def raw_number(literal):
                value = config(target)
                value['global'] = {'limits': {'max_millicpus': '__EXACT_NUMBER__'}}
                return json.dumps(value).replace('"__EXACT_NUMBER__"', literal)
            for literal, number in (('9007199254740993', 9007199254740993), ('1000.0', 1000), ('1e3', 1000)):
                status, value, single = self.request(20417, path + '/json', raw_number(literal), 'PUT', raw_json=True)
                stored = read()
                ok = single and status == 200 and value.get('OPT_STATUS') == 'SUCCESS' and stored['global']['limits']['max_millicpus'] == number
                self.results.append({'case': 'raw_json_number_' + literal, 'passed': ok, 'http_status': status, 'single_json': single})
                if not ok:
                    raise RuntimeError('Raw JSON integer did not persist exactly')
                expected = stored
            status, value, single = self.request(20417, path + '/json', raw_number('1.00000000000000001'), 'PUT', raw_json=True)
            ok = single and status == 400 and value.get('OPT_STATUS') == 'INVALID_POST_DATA' and read() == expected
            self.results.append({'case': 'raw_close_fraction_rejected_without_mutation', 'passed': ok, 'http_status': status, 'single_json': single})
            if not ok:
                raise RuntimeError('A fractional raw JSON number was rounded instead of rejected')
        finally:
            matches = self.controller('/v1/vtap-groups/' + identity + '/')
            if len(matches) != 1:
                raise RuntimeError('Cannot prove temporary group ownership for cleanup')
            require_empty_owned_group(matches[0], identity, name)
            status, value, single = self.request(20417, path, method='DELETE')
            if not single or not ((status == 200 and value.get('OPT_STATUS') == 'SUCCESS') or
                    (status == 404 and value.get('OPT_STATUS') == 'RESOURCE_NOT_FOUND')):
                raise RuntimeError('Cannot safely remove the temporary configuration')
            self.controller('/v1/vtap-groups/' + identity + '/', method='DELETE')
        after = self.controller('/v1/vtap-groups/')
        def identities(rows):
            return sorted(({key: g.get(key) for key in ('LCUUID', 'NAME', 'TEAM_ID') + MEMBERS} for g in rows), key=lambda g: g['LCUUID'])
        agent_keys = ('LCUUID', 'NAME', 'TYPE', 'CTRL_IP', 'CTRL_MAC', 'VTAP_GROUP_LCUUID', 'TEAM_ID')
        def agent_identities(rows):
            return sorted(({key: a.get(key) for key in agent_keys} for a in rows), key=lambda a: a['LCUUID'])
        if identities(after) != identities(before) or agent_identities(self.controller('/v1/vtaps/')) != agent_identities(agents_before):
            raise RuntimeError('Original group/Agent inventory changed')
        for group, expected in original_configs.items():
            if self.controller('/v1/agent-group-configuration/' + group + '/json') != expected:
                raise RuntimeError('An original group configuration changed')
        self.results.append({'case': 'temporary_group_cleaned_and_original_inventory_preserved', 'passed': True})

    def save(self, error=None):
        after = self.database_identity()
        retained = after == self.before
        data = {'expected_source_commit': self.expected, 'checked_at_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(), 'cases': self.results,
            'all_cases_passed': all(r['passed'] for r in self.results) and not error, 'container_identity_unchanged_during_checks': retained, 'error': str(error) if error else None}
        self.lab.private_write(self.output / 'raw-http.json', json.dumps(self.raw, indent=2) + '\n')
        self.lab.private_write(self.output / 'resource-identity.json', json.dumps({'before': self.before, 'after': after}, indent=2) + '\n')
        self.lab.private_write(self.output / 'summary.json', json.dumps(data, indent=2) + '\n')
        print(json.dumps(data))
        if not retained:
            raise RuntimeError('A lab container changed during acceptance')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=pathlib.Path, default=pathlib.Path('/tmp/traflens-lab-20261026'))
    parser.add_argument('--lab-tools', type=pathlib.Path, default=pathlib.Path('/tmp/traflens-lab-code-20261026'))
    parser.add_argument('--output', type=pathlib.Path, required=True)
    parser.add_argument('--expected-commit', required=True)
    parser.add_argument('--baseline', action='store_true', help='Read-only query control; record known failures without requiring their rejection contract')
    args = parser.parse_args()
    if not re.fullmatch('[0-9a-f]{40}', args.expected_commit):
        parser.error('Expected a complete source commit')
    root = args.root.resolve()
    if not args.output.resolve().is_relative_to(root / 'evidence'):
        parser.error('Raw output must remain in the private lab evidence directory')
    sys.path.insert(0, str(args.lab_tools.resolve()))
    import lab
    check = Check(lab, root, args.output, args.expected_commit)
    error = None
    try:
        check.queries(args.baseline)
        if not args.baseline:
            check.configurations()
    except Exception as caught:
        error = caught
    finally:
        check.save(error)
    if error:
        raise SystemExit(1)


if __name__ == '__main__':
    main()
