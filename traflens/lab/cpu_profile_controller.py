"""Private-output Controller lease for the public profile-only lifecycle."""
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import re
import sys
import time
import uuid
import urllib.error
import urllib.parse
import urllib.request
from cpu_profile_common import digest, private_dir, profile_only, require, validate_controller_url, validate_controller_binding
WORK = None
GROUP_MEMBER_KEYS = ('VTAP_LCUUIDS', 'DISABLE_VTAP_LCUUIDS', 'PENDING_VTAP_LCUUIDS')
AGENT_IDENTITY = ('ID', 'LCUUID', 'NAME', 'CTRL_IP', 'CTRL_MAC', 'TYPE', 'TEAM_ID', 'VTAP_GROUP_LCUUID', 'ENABLE', 'LICENSE_FUNCTIONS')
GROUP_IDENTITY = ('ID', 'LCUUID', 'NAME', 'SHORT_UUID', 'TEAM_ID', 'USER_ID', 'LICENSE_FUNCTIONS')

def read_json_argument(value):
    if value.lstrip().startswith('{'):
        return json.loads(value)
    return json.loads(Path(value).read_text())

def save(name, value):
    path = WORK / name
    with path.open('x') as stream:
        json.dump(value, stream, indent=2)
        stream.write('\n')
    path.chmod(384)
    return value

def load(name):
    path = WORK / name
    return json.loads(path.read_text()) if path.exists() else None

def identity(row, keys):
    return {key: row.get(key) for key in keys}

def member_ids(group):
    return sorted({value for key in GROUP_MEMBER_KEYS for value in group.get(key, []) or []})

def get_groups(api):
    rows = api('/v1/vtap-groups/')['DATA'] or []
    require(isinstance(rows, list) and all((isinstance(r, dict) and r.get('LCUUID') for r in rows)), 'Controller identity or scope mismatch')
    require(len({r['LCUUID'] for r in rows}) == len(rows), 'Controller identity or scope mismatch')
    return rows

def get_agents(api):
    rows = api('/v1/vtaps/')['DATA'] or []
    require(isinstance(rows, list) and all((isinstance(r, dict) and r.get('LCUUID') for r in rows)), 'Controller identity or scope mismatch')
    require(len({r['LCUUID'] for r in rows}) == len(rows), 'Controller identity or scope mismatch')
    return rows

def mutate(api, action, path, body=None, method='POST'):
    event = 'controller-events/' + str(time.time_ns()) + '-' + uuid.uuid4().hex
    save(event + '-intent.json', {'action': action, 'method': method, 'path': path, 'body': body})
    response = api(path, body, method)
    save(event + '-receipt.json', response)
    return response

def verify_baseline(api, baseline):
    groups = {r['LCUUID']: r for r in get_groups(api)}
    agents = {r['LCUUID']: r for r in get_agents(api)}
    for old in baseline['groups']:
        current = groups.get(old['LCUUID'])
        require(current and identity(current, GROUP_IDENTITY) == identity(old, GROUP_IDENTITY), 'Existing group identity changed')
        for key in GROUP_MEMBER_KEYS:
            require(sorted(current.get(key) or []) == sorted(old.get(key) or []), 'Existing group membership changed')
        require(digest(api('/v1/agent-group-configuration/' + old['LCUUID'] + '/yaml')['DATA']) == baseline['yaml_hashes'][old['LCUUID']], 'Existing group YAML changed')
    for old in baseline['agents']:
        current = agents.get(old['LCUUID'])
        require(current and identity(current, AGENT_IDENTITY) == identity(old, AGENT_IDENTITY), 'Existing Agent identity/configuration changed')
    return (groups, agents)

def integration_mode(value):
    mode = value.get('integration_mode', 'profile')
    require(mode in ('profile', 'otel_trace'), 'Unknown integration mode')
    return mode


def license_functions(value):
    # Normal feature management only: TRACE_APP=6, PROFILE_INT=11.
    return [6] if integration_mode(value) == 'otel_trace' else [11]


def trace_only_profile(controller_ip, controller_port, ingester_port):
    value = profile_only(Path(__file__).resolve().parent, controller_ip, controller_port, ingester_port)
    integration = value['inputs']['integration']
    integration['feature_control'] = {'profile_integration_disabled': True, 'trace_integration_disabled': False,
                                      'metric_integration_disabled': True, 'log_integration_disabled': True}
    integration['compression'] = {'trace': False, 'profile': False}
    return value


def validate_metadata(value):
    require(isinstance(value, dict), 'Controller metadata must be an object')
    trace = integration_mode(value) == 'otel_trace'
    prefix = 'span-' if trace else 'cpu-'
    require(re.fullmatch(prefix + '[0-9a-f]{24}', value.get('run', '')), 'Run prefix differs from integration mode')
    address = ipaddress.ip_address(value['ctrl_ip'])
    require(address.version == 4 and address.is_private and (not address.is_loopback) and (not address.is_link_local) and (not address.is_unspecified), 'Controller identity or scope mismatch')
    require(re.fullmatch('(?:[0-9a-f]{2}:){5}[0-9a-f]{2}', value['ctrl_mac']), 'Controller identity or scope mismatch')
    require(not int(value['ctrl_mac'][:2], 16) & 1 and value['ctrl_mac'] != '00:00:00:00:00:00', 'Controller identity or scope mismatch')
    require(isinstance(value['profile'], dict), 'Controller identity or scope mismatch')
    if trace:
        expected = trace_only_profile(value['controller_ip'], value['controller_port'], value['ingester_port'])
    else:
        expected = profile_only(Path(__file__).resolve().parent, value['controller_ip'], value['controller_port'], value['ingester_port'])
    require(value['profile'] == expected, 'Configuration differs from the fixed integration mode')
    return value


def prepare(api, config, value):
    value = validate_metadata(value)
    functions = license_functions(value)
    require(load('controller-baseline.json') is None, 'Prepare is one-shot; retain earlier receipts')
    (groups, agents) = (get_groups(api), get_agents(api))
    name = 'traflens-' + value['run']
    require(all((r['NAME'] != name for r in groups + agents)), 'Run name already exists')
    require(all((r.get('CTRL_IP') != value['ctrl_ip'] or r.get('CTRL_MAC') != value['ctrl_mac'] for r in agents)), 'Endpoint identity already registered')
    controllers = api('/v1/controllers/')['DATA'] or []
    require(len(controllers) == 1 and len(controllers[0]['AZS']) == 1, 'Controller identity or scope mismatch')
    require(any((g['NAME'] == 'default' for g in groups)), 'Owned default group missing')
    template = api('/v1/agent-group-configuration/template/json')['DATA']
    config.check_keys(value['profile'], template)
    baseline = {'metadata': value, 'groups': [identity(g, GROUP_IDENTITY + GROUP_MEMBER_KEYS) for g in groups], 'agents': [identity(a, AGENT_IDENTITY) for a in agents], 'yaml_hashes': {g['LCUUID']: digest(api('/v1/agent-group-configuration/' + g['LCUUID'] + '/yaml')['DATA']) for g in groups}, 'controllers': [{'REGION': controllers[0]['REGION'], 'AZ': controllers[0]['AZS'][0]['AZ']}]}
    save('controller-baseline.json', baseline)
    save('controller-group-intent.json', {'NAME': name, 'TEAM_ID': 1, 'ENABLE': 1, 'STATE': 1, 'VTAP_LCUUIDS': []})
    response = mutate(api, 'create-owned-group', '/v1/vtap-groups/', load('controller-group-intent.json'))
    save('controller-group-created.json', response)
    group = response['DATA']
    require(group['NAME'] == name and group['TEAM_ID'] == 1 and (group['LCUUID'] not in {g['LCUUID'] for g in groups}) and (not member_ids(group)), 'Controller identity or scope mismatch')
    agent_body = {'NAME': name, 'TYPE': 5, 'CTRL_IP': value['ctrl_ip'], 'CTRL_MAC': value['ctrl_mac'], 'VTAP_GROUP_LCUUID': group['LCUUID'], 'TEAM_ID': 1, 'AZ': controllers[0]['AZS'][0]['AZ'], 'REGION': controllers[0]['REGION']}
    save('controller-agent-intent.json', agent_body)
    response = mutate(api, 'create-owned-agent', '/v1/vtaps/', agent_body)
    save('controller-agent-created.json', response)
    agent = response['DATA']
    require(all((agent.get(k) == v for (k, v) in agent_body.items())) and agent['LCUUID'] not in {r['LCUUID'] for r in agents}, 'Controller identity or scope mismatch')
    mutate(api, 'license-owned-agent', '/v1/vtaps-license-type/' + agent['LCUUID'] + '/', {'LICENSE_FUNCTIONS': functions}, 'PATCH')
    mutate(api, 'enable-owned-agent', '/v1/vtaps/' + agent['LCUUID'] + '/', {'ENABLE': 1}, 'PATCH')
    current = next((r for r in get_agents(api) if r['LCUUID'] == agent['LCUUID']))
    require(all((current.get(k) == v for (k, v) in agent_body.items())) and current['ENABLE'] == 1 and (current['LICENSE_FUNCTIONS'] == functions), 'Controller identity or scope mismatch')
    configs = api('/v1/agent-group-configuration/json')['DATA']
    if isinstance(configs, str):
        configs = json.loads(configs)
    require(isinstance(configs, dict), 'Unexpected configuration index')
    method = 'PUT' if group['LCUUID'] in configs else 'POST'
    path = '/v1/agent-group-configuration/' + group['LCUUID'] + '/yaml'
    mutate(api, 'configure-owned-group', path, json.dumps(value['profile']), method)
    configured = api(path)['DATA']
    if isinstance(configured, str):
        configured = json.loads(configured)
    require(configured == value['profile'], 'Applied profile differs')
    verify_baseline(api, baseline)
    result = {'prepared': True, 'run': value['run'], 'agent_id': agent['ID'], 'agent_lcuuid': agent['LCUUID'], 'group_lcuuid': group['LCUUID'], 'group_short_uuid': group['SHORT_UUID']}
    save('controller-prepared.json', result)
    print(json.dumps({'prepared': True, 'created': True, 'agent_id': agent['ID'], 'group_short_uuid': group['SHORT_UUID']}))

def recover_created(api, baseline, kind):
    receipt = load('controller-' + kind + '-created.json')
    if receipt:
        return receipt['DATA']
    intent = load('controller-' + kind + '-intent.json')
    if not intent:
        return None
    rows = get_groups(api) if kind == 'group' else get_agents(api)
    matches = [r for r in rows if r.get('NAME') == intent['NAME']]
    if not matches:
        return None
    require(len(matches) == 1 and matches[0]['LCUUID'] not in {r['LCUUID'] for r in baseline[kind + 's']}, 'Controller identity or scope mismatch')
    row = matches[0]
    if kind == 'group':
        require(row['TEAM_ID'] == 1, 'Controller identity or scope mismatch')
    else:
        require(all((row.get(k) == intent[k] for k in ('NAME', 'TYPE', 'CTRL_IP', 'CTRL_MAC', 'VTAP_GROUP_LCUUID', 'TEAM_ID'))), 'Controller identity or scope mismatch')
    save('controller-' + kind + '-created.json', {'OPT_STATUS': 'SUCCESS', 'DATA': row, 'recovered_after_uncertain_create': True})
    return row

def cleanup(api, proof_argument):
    baseline = load('controller-baseline.json')
    require(baseline, 'No prepare baseline; no mutation authorized')
    value = validate_metadata(baseline['metadata'])
    group = recover_created(api, baseline, 'group')
    agent = recover_created(api, baseline, 'agent')
    if agent:
        raw_proof = proof_argument or value.get('stopped_proof') or value.get('stoppedproof')
        require(raw_proof, 'Explicit owned collector stopped proof required')
        proof = read_json_argument(raw_proof) if isinstance(raw_proof, str) else raw_proof
        require(proof.get('run') == value['run'], 'Controller identity or scope mismatch')
        require(proof.get('collector_never_started') is True or (proof.get('agent_stopped') is True and proof.get('owned_agent_removed') is True), 'Controller identity or scope mismatch')
        save('controller-events/' + str(time.time_ns()) + '-stopped-proof.json', proof)
        matches = [r for r in get_agents(api) if r['LCUUID'] == agent['LCUUID']]
        if matches:
            current = matches[0]
            require(current['ID'] == agent['ID'] and current['LCUUID'] == agent['LCUUID'], 'Controller identity or scope mismatch')
            require(current['NAME'] == 'traflens-' + value['run'] and current['CTRL_IP'] == value['ctrl_ip'] and (current['CTRL_MAC'] == value['ctrl_mac']), 'Controller identity or scope mismatch')
            require(group and current['VTAP_GROUP_LCUUID'] == group['LCUUID'] and (current['TEAM_ID'] == 1) and (current['TYPE'] == 5), 'Controller identity or scope mismatch')
            mutate(api, 'delete-owned-stopped-agent', '/v1/vtaps/' + agent['LCUUID'] + '/', method='DELETE')
        require(not any((r['LCUUID'] == agent['LCUUID'] for r in get_agents(api))), 'Owned Agent remains')
    if group:
        matches = [r for r in get_groups(api) if r['LCUUID'] == group['LCUUID']]
        if matches:
            current = matches[0]
            require(current['ID'] == group['ID'] and current['SHORT_UUID'] == group['SHORT_UUID'], 'Controller identity or scope mismatch')
            require(current['NAME'] == 'traflens-' + value['run'] and current['TEAM_ID'] == 1 and (not member_ids(current)), 'Controller identity or scope mismatch')
            require(not any((r['VTAP_GROUP_LCUUID'] == group['LCUUID'] for r in get_agents(api))), 'Refusing group delete with remaining members')
            mutate(api, 'delete-owned-empty-group', '/v1/vtap-groups/' + group['LCUUID'] + '/', method='DELETE')
        require(not any((r['LCUUID'] == group['LCUUID'] for r in get_groups(api))), 'Owned group remains')
    (groups, agents) = verify_baseline(api, baseline)
    require(set(groups) == {r['LCUUID'] for r in baseline['groups']} and set(agents) == {r['LCUUID'] for r in baseline['agents']}, 'Unexpected final inventory')
    save('controller-events/' + str(time.time_ns()) + '-cleanup-completed.json', {'owned_agent_removed': True, 'owned_group_removed': True, 'baseline_identities_and_yaml_preserved': True})
    print(json.dumps({'cleaned': True, 'baseline_identities_and_yaml_preserved': True}))


def dispatch(args):
    global WORK
    import lab
    validate_controller_url(args.controller_url)
    root = private_dir(args.backend_root)
    work = Path(args.work).absolute()
    require(work != root and work.is_relative_to(root), 'Controller work must be strictly below owned backend root')
    info = lab.inspect('container', args.server_container)
    require(info is not None, 'Owned lab Server missing')
    lab.require_owned(info, root, 'container')
    validate_controller_binding(args.controller_url, info)
    if args.action == 'prepare':
        if work.parent == root / 'cpu-profiles':
            (root / 'cpu-profiles').mkdir(mode=0o700, exist_ok=True)
            private_dir(root / 'cpu-profiles')
        private_dir(work.parent)
        private_dir(work, fresh=True)
    WORK = private_dir(work)
    (WORK / 'controller-events').mkdir(mode=0o700, exist_ok=True)
    def api(path, body=None, method='GET'):
        data = body.encode() if isinstance(body, str) else json.dumps(body).encode() if body is not None else None
        request = urllib.request.Request(args.controller_url + path, data=data, method=method,
          headers={'Content-Type': 'application/yaml' if isinstance(body, str) else 'application/json', 'X-Org-Id':'1', 'X-User-Id':'1', 'X-User-Type':'1'})
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                raw = response.read(16*1024*1024+1)
                require(len(raw) <= 16*1024*1024, 'Controller response exceeded limit')
                result = json.loads(raw)
        except urllib.error.HTTPError as error:
            raise RuntimeError('Controller HTTP request failed with status ' + str(error.code)) from None
        require(result.get('OPT_STATUS') == 'SUCCESS', 'Controller request rejected')
        return result
    spec = importlib.util.spec_from_file_location('cpu_profile_config', Path(__file__).with_name('configure-agent.py'))
    config = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(config)
    import fcntl
    with (WORK / 'controller.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        try:
            value = json.load(sys.stdin)
            if args.action == 'prepare':
                validate_metadata(value)
                prepare(api, config, value)
            elif load('controller-baseline.json') is None:
                require(not load('controller-group-intent.json') and not load('controller-agent-intent.json'), 'Missing Controller baseline')
                print(json.dumps({'cleaned':True, 'baseline_not_mutated':True}))
            else:
                cleanup(api, value)
        except Exception as error:
            save('controller-events/' + str(time.time_ns()) + '-failure.json', {'action':args.action, 'error_type':type(error).__name__})
            raise RuntimeError('Controller lifecycle failed; private receipts retained') from None
