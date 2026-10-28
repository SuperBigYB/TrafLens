#!/usr/bin/env python3
"""Run one scoped fast MySQL capture with bounded metadata gates; offline by default."""
import argparse
import re
import shlex
import stat
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import struct
import subprocess
import sys
import time

HERE = Path(__file__).resolve().parent
R = HERE.parent.parent
CONTROL_SHA = '599d82f845e2d2e36f5fca86884780b447068affe182592445a4ef39a27ddd4b'
P = W = CLIENT = OPTIONS = SERVER = None

def require(v, m):
    if not v:
        raise ValueError(m)

def sha(p):
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()

def save(p, v):
    with open(p, 'x', encoding='utf-8') as f:
        json.dump(v, f, indent=2);f.write('\n')

def load(p):
    return json.loads(Path(p).read_text())

def call(argv, timeout=8):
    out = subprocess.run(argv, cwd=R, capture_output=True, timeout=timeout)
    require(len(out.stdout) <= 65536 and len(out.stderr) <= 65536, 'Control response budget')
    require(out.returncode == 0, 'Fixed control call failed; no output exposed')
    return out.stdout

def dump_control(prefix, action):
    commands = {
        'set': (['datadump', 'set', '--pid', '0', '--comm', '', '--l7-proto', '0', '--port', '0'],
                'Set pid 0 comm  proto 0 ip  port 0\nSuccess.\n'),
        'on': (['datadump', 'on', '--only-stdout', '--timeout', '30'],
               'Set datadump on, timeout 30s Success.\n'),
        'off': (['datadump', 'off'], 'Set datadump off Success.\n'),
    }
    args, expected = commands[action]
    reply = call(prefix+args).decode('utf-8')
    require(reply.endswith(expected) and reply.count('Success.') == 1 and 'Failed.' not in reply,
            'Native control did not acknowledge the fixed requested parameters')
    return hashlib.sha256(reply.encode()).hexdigest()

def checked_server():
    probe = """import json,subprocess,sys
from pathlib import Path
import hashlib
v=json.loads(subprocess.check_output(['docker','inspect',sys.argv[1]],timeout=8))[0]
m=[m for m in v['Mounts'] if m['Type']=='bind' and m['Destination']=='/etc/server.yaml']
assert len(m)==1 and m[0]['RW'] is False
config=Path(m[0]['Source']);assert config.is_absolute() and config.is_file()
config_sha=hashlib.sha256(config.read_bytes()).hexdigest()
print(json.dumps({'config_sha256':config_sha,'config_destination':m[0]['Destination'],'config_readonly':not m[0]['RW'],'id':v['Id'],'image':v['Image'],'running':v['State']['Running'],
 'readonly_rootfs':v['HostConfig']['ReadonlyRootfs'],'network_mode':v['HostConfig']['NetworkMode'],
 'lab':v['Config']['Labels'].get('io.traflens.lab')}))"""
    value = json.loads(call(['ssh', '-o', 'BatchMode=yes', OPTIONS['--backend-host'],
                            shlex.join(['python3', '-c', probe, OPTIONS.get('--server-container', 'traflens-lab-server')])], 15))
    require(value.get('running') is True and value.get('readonly_rootfs') is True
            and value.get('lab') == OPTIONS['--backend-root']
            and value.get('config_destination') == '/etc/server.yaml' and value.get('config_readonly') is True
            and re.fullmatch('[0-9a-f]{64}', value.get('config_sha256', ''))
            and re.fullmatch('[0-9a-f]{64}', value.get('id', ''))
            and re.fullmatch('sha256:[0-9a-f]{64}', value.get('image', '')),
            'Explicit owned read-only Server identity required')
    require(SERVER is None or value == SERVER, 'Owned Server identity changed')
    return {'pass': True, 'identity': value}


def effective_preprocess(current, binding):
    path=Path(current['folder'])/'logs/deepflow-agent_rCURRENT.log'
    require(path == path.resolve() and not path.is_symlink(), 'Exact owned current Agent log required')
    meta=path.stat()
    require(stat.S_ISREG(meta.st_mode) and meta.st_uid == os.geteuid() and not meta.st_mode & 0o022
            and 0 < meta.st_size <= 8<<20, 'Agent config log ownership/size differs')
    raw=path.read_bytes()
    require(len(raw)<=8<<20, 'Agent config log budget exceeded')
    text=raw.decode('utf-8')
    blocks=re.findall(r'preprocess: EbpfSocketPreprocess \{([^{}]+)\}',text)
    require(len(blocks)==1, 'Exactly one actual merged socket preprocess configuration required')
    block=blocks[0]
    wanted={'out_of_order_reassembly_cache_size':'256','out_of_order_reassembly_timeout':'100ms',
            'out_of_order_reassembly_protocols':'["MySQL",]', 'segmentation_reassembly_protocols':'[]'}
    found={}
    for key, expected in wanted.items():
        match=re.findall(r'\b'+key+r':\s*(\[[^\]]*\]|[^,\n]+),',block)
        require(len(match)==1, 'Merged preprocess field missing/ambiguous')
        compact=re.sub(r'\s+','',match[0])
        require(compact==expected, 'Actual merged socket preprocess differs from fixed MySQL sorting qualification')
        found[key]=compact
    return {'pass':True,'source':'actual native INFO merged UserConfig, not Controller raw YAML',
            'matched_blocks':1,'fields':found,'log_sha256':hashlib.sha256(raw).hexdigest(),
            'log_bytes':len(raw),'agent':binding,'observed_unix_ns':time.time_ns()}


def capture_options(values):
    require(values[:2] == ['run', '--execute'], 'Exactly one explicit run required after --')
    fields = ('work backend-host backend-root backend-work backend-code controller-ip ctrl-ip ctrl-mac '
              'artifacts workload-bin workload-sha256 workload-source image server-container controller-url '
              'controller-port ingester-port forward-port observer-timeout-seconds').split()
    allowed = {'--'+v for v in fields}; selected = {}
    require(len(values[2:]) % 2 == 0, 'Capture options require distinct key/value pairs')
    for key, value in zip(values[2::2], values[3::2]):
        require(key in allowed and key not in selected and value and not value.startswith('--')
                and not any(c in value for c in '\r\n\0'), 'Unknown/duplicate capture option')
        selected[key] = value
    require(all('--'+v in selected for v in fields[:14]), 'Explicit owned capture parameters required')
    require(re.fullmatch('[A-Za-z0-9][A-Za-z0-9_.@-]{0,127}', selected['--backend-host'])
            and re.fullmatch('[A-Za-z0-9][A-Za-z0-9_.-]{0,127}', selected.get('--server-container','traflens-lab-server')),
            'Explicit SSH alias and container name required')
    module = import_diagnostic()
    module.CORE.validate_controller_url(selected.get('--controller-url', 'http://127.0.0.1:20417'))
    return selected


def fresh_output(path):
    require(path and path.is_absolute() and path == path.resolve() and not path.exists(), 'Fresh canonical directory required')
    parent = path.parent.stat()
    require(stat.S_ISDIR(parent.st_mode) and parent.st_uid == os.geteuid() and not parent.st_mode & 0o077,
            'Owned private parent required')
    return path


def import_diagnostic():
    sys.path.insert(0, str(HERE))
    s = importlib.util.spec_from_file_location('public_fast_diagnostic', HERE/'ebpf-mysql-diagnostic.py')
    m = importlib.util.module_from_spec(s);s.loader.exec_module(m)
    return m

def binding_and_peer(request):
    module = import_diagnostic()
    binding, current = module.live_agent_binding(W)
    require(binding == request['agent'], 'Live Agent identity differs from requested gate')
    pid = binding['pid']
    root = Path(f'/proc/{pid}/root')
    require(os.readlink(root/'var/run') == '/run', 'Actual image var/run link differs from fixed verified contract')
    endpoint = str(root/'run/deepflow_bpf_ctrl')
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as ctl:
        ctl.settimeout(2);ctl.connect(endpoint)
        peer = struct.unpack('3i', ctl.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
    require(peer[0] == pid and peer[1:] == (0, 0), 'Control socket is not the exact owned native Agent')
    require(module.live_agent_binding(W)[0] == binding, 'Agent generation changed during socket binding')
    return current, {'pass': True, 'socket_endpoint': 'exact-native-pid-root/run/deepflow_bpf_ctrl',
                     'var_run_link_rebased_under_exact_native_root': True,
                     'peer_pid_matches_native_pid': True, 'peer_uid': peer[1], 'peer_gid': peer[2],
                     'binding': binding, 'observed_unix_ns': time.time_ns()}

def ack(stage, request, artifacts):
    d = W/'observer'/stage
    require(time.time_ns() < request['deadline_unix_ns'], 'Observer gate expired')
    save(d/'manifest.json', {
        'schema': 'traflens.scoped-observer-manifest.v1', 'stage': stage,
        'run': request['run'], 'nonce': request['nonce'], 'agent': request['agent'],
        'completed': True, 'scope_profile_unchanged': True, 'old_server_unchanged': True,
        'captured_at_unix_ns': time.time_ns(),
        'artifacts': [{'name': f.name, 'bytes': f.stat().st_size, 'sha256': sha(f)} for f in artifacts],
    })
    call(['python3', str(HERE/'ebpf-mysql-fast.py'), 'ack', '--execute', '--work', str(W), '--stage', stage])

def clean_auxiliary(process, label, errors):
    if process is None:
        return
    try:
        if process.poll() is not None:
            return
        process.terminate()
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=3)
    except Exception as error:
        errors.append({'process':label,'error_type':type(error).__name__})


def main(argv=None):
    global P, W, CLIENT, OPTIONS, SERVER
    args = argparse.ArgumentParser(description=__doc__)
    args.add_argument('--execute', action='store_true')
    args.add_argument('--observer-output', type=Path)
    args.add_argument('--control-client', type=Path)
    args.add_argument('capture', nargs=argparse.REMAINDER)
    parsed = args.parse_args(argv)
    if not parsed.execute:
        print(json.dumps({'execute':False,'starts_network':False,'writes_files':False,
                          'observer_seconds':30,'max_records':256,'max_stdout_bytes':8<<20,
                          'storage_verified':False,'native_qualified':False}))
        return 0
    os.umask(0o077)
    require(os.geteuid() == 0 and os.uname().machine == 'x86_64', 'Linux x86_64 root required')
    values = parsed.capture[1:] if parsed.capture[:1] == ['--'] else parsed.capture
    OPTIONS = capture_options(values)
    W = fresh_output(Path(OPTIONS['--work']))
    P = fresh_output(parsed.observer_output)
    require(W != P and not W.is_relative_to(P) and not P.is_relative_to(W), 'Separate fresh outputs required')
    CLIENT = parsed.control_client
    require(CLIENT and CLIENT.is_absolute() and CLIENT == CLIENT.resolve(), 'Canonical control client required')
    meta = CLIENT.stat()
    require(stat.S_ISREG(meta.st_mode) and meta.st_uid == os.geteuid() and not meta.st_mode & 0o077
            and 0 < meta.st_size <= 8<<20 and sha(CLIENT) == CONTROL_SHA, 'Exact owned control client required')
    command = [sys.executable, str(HERE/'ebpf-mysql-fast.py')] + values
    SERVER = checked_server()['identity']
    P.mkdir(mode=0o700)
    save(P/'observer-server-pre.json', {'pass':True,'identity':SERVER})
    def interrupted(*_):
        raise InterruptedError('Bounded fast capture interrupted; cleaning owned resources')
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    supervisor = None;follower = None;parser = None;ctl_prefix = None
    log_file = open(P/'capture-supervisor.log', 'xb')
    observer_log = None
    result = {'schema': 'traflens.mysql-fast-observed.v1', 'pass': False,
              'diagnostic_only': True, 'storage_verified': False, 'observer_payload_saved': False,
              'native_agent_console_may_include_owned_fixture_payload': True,
              'error': '', 'started_unix_ns': time.time_ns(), 'stages': []}
    try:
        supervisor = subprocess.Popen(command, cwd=R, stdout=log_file, stderr=subprocess.STDOUT)
        save(P/'capture-supervisor-process.json', {'pid': supervisor.pid, 'argv': command,
             'start_ticks': Path(f'/proc/{supervisor.pid}/stat').read_text().rsplit(')',1)[1].split()[19]})
        deadline = time.monotonic()+350
        dump_started = None;parser_started = None
        seen = set()
        while time.monotonic() < deadline:
            for stage in ['before-first-wire', 'after-final-wire']:
                d = W/'observer'/stage
                if stage in seen or not (d/'request.json').exists():
                    continue
                request = load(d/'request.json')
                current, peer = binding_and_peer(request)
                save(d/'socket-binding.json', peer)
                save(d/'effective-preprocess.json', effective_preprocess(current,request['agent']))
                save(d/'old-server-check.json', checked_server())
                if stage == 'before-first-wire':
                    logs_mount = [a for a,b,c in current['mounts'] if b == '/var/log/traflens' and c is True]
                    require(len(logs_mount) == 1 and Path(logs_mount[0]).is_relative_to(Path(current['folder'])), 'Exact owned writable logs mount required')
                    target = Path(logs_mount[0])/'fast-ebpfctl'
                    require(not target.exists(), 'Do not replace existing Agent file')
                    shutil.copyfile(CLIENT, target);target.chmod(0o700)
                    require(sha(target) == sha(CLIENT), 'Bound control-client copy differs')
                    ctl_prefix = ['docker', 'exec', request['agent']['container_id'], '/var/log/traflens/fast-ebpfctl']
                    pre = d/'tracer-pre.txt';pre.write_bytes(call(ctl_prefix+['tracer', 'show']))
                    dump_control(ctl_prefix, 'set')
                    observer_log = open(P/'observer-parser-summary.json', 'xb')
                    follower = subprocess.Popen(['docker', 'logs', '--follow', '--since', str(request['requested_at_unix_ns']//1_000_000_000), request['agent']['container_id']],
                                                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
                    parser = subprocess.Popen(['python3', str(HERE/'native-mysql-observer.py'), '--execute', '--stream',
                          '--container-id', request['agent']['container_id'], '--capture-dir', str(W), '--tracer-pre', str(pre),
                          '--tracer-post', str(P/'tracer-post.txt'), '--output', str(P/'metadata-1'), '--duration', '30'],
                          cwd=R, stdin=follower.stdout, stdout=observer_log, stderr=subprocess.DEVNULL)
                    parser_started = time.monotonic()
                    follower.stdout.close()
                    save(P/'observer-stream-processes.json', {'follower_pid': follower.pid, 'parser_pid': parser.pid,
                         'container_id': request['agent']['container_id'], 'bounded_seconds': 30,
                         'only_stdout_header_metadata_retained': True})
                    start_ack = dump_control(ctl_prefix, 'on')
                    dump_started = time.monotonic()
                    save(d/'control-start.json', {'pass': True, 'duration_seconds':30, 'stdout_only': True,
                         'ctl_sha256': sha(target), 'exact_scope_bound': True,
                         'control_ack_sha256': start_ack, 'started_unix_ns': time.time_ns(), 'actual_agent_binding_preserved': True})
                    ack(stage, request, [d/'socket-binding.json', d/'old-server-check.json', d/'effective-preprocess.json', pre, d/'control-start.json'])
                else:
                    require(ctl_prefix and dump_started and parser.poll() is None, 'Metadata parser died before tail gate')
                    # Allow a bounded post-wire statistics tail. Actual emitted
                    # intervals are independently queried; waiting proves none.
                    target = min(dump_started+22, parser_started+27)
                    remaining = max(0, target-time.monotonic())
                    require(remaining < 25 and time.time_ns()+int((remaining+8)*1e9) < request['deadline_unix_ns'], 'Bounded tail exceeds gate')
                    require(time.monotonic()+remaining+5 < parser_started+35, 'Insufficient metadata parser wall time')
                    time.sleep(remaining)
                    stop_ack = dump_control(ctl_prefix, 'off')
                    (P/'tracer-post.txt').write_bytes(call(ctl_prefix+['tracer', 'show']))
                    follower.terminate();follower.wait(timeout=3)
                    parser.wait(timeout=5)
                    parsed = load(P/'metadata-1/result.json')
                    require(parser.returncode == 0 and parsed.get('pass') is True, 'Streaming metadata validation failed; retain failure')
                    for source, name in [(P/'metadata-1/result.json','metadata-result.json'),
                                         (P/'metadata-1/events.json','metadata-events.json'),
                                         (P/'metadata-1/tracer-snapshots.json','tracer-snapshots.json')]:
                        shutil.copyfile(source, d/name);os.chmod(d/name,0o600)
                    save(d/'control-stop.json', {'pass': True, 'explicit_off_completed': True,
                         'control_ack_sha256': stop_ack, 'tail_is_after_all_wire_not_phase_wait': True, 'finished_unix_ns': time.time_ns()})
                    ack(stage, request, [d/'socket-binding.json', d/'old-server-check.json', d/'effective-preprocess.json', d/'metadata-result.json',
                        d/'metadata-events.json', d/'tracer-snapshots.json', d/'control-stop.json'])
                seen.add(stage);result['stages'].append(stage)
            if supervisor.poll() is not None:
                break
            time.sleep(.08)
        require(supervisor.poll() is not None, 'Finite lifecycle supervisor exceeded350seconds')
        capture_result = load(W/'result.json')
        require(supervisor.returncode == 0 and capture_result.get('pass') is True and len(seen)==2,
                'Diagnostic lifecycle or restoration failed; preserve receipts')
        result['pass'] = True
    except Exception as error:
        result['error'] = str(error) if type(error) is ValueError else type(error).__name__
        if isinstance(error, FileNotFoundError):result['missing_fixed_path'] = str(error.filename)
    finally:
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        signal.signal(signal.SIGINT, signal.SIG_IGN)
        if ctl_prefix:
            try:
                dump_control(ctl_prefix, 'off')
                result['finally_explicit_off'] = True
            except Exception:
                result['finally_explicit_off'] = False # exited Agent is proved by public cleanup
        auxiliary_errors = []
        clean_auxiliary(follower, 'metadata-follower', auxiliary_errors)
        clean_auxiliary(parser, 'metadata-parser', auxiliary_errors)
        result['auxiliary_cleanup_errors'] = auxiliary_errors
        try:
            if supervisor and supervisor.poll() is None:
                supervisor.terminate()
                try:
                    supervisor.wait(timeout=150)
                except subprocess.TimeoutExpired:
                    result['supervisor_still_live'] = True
        except Exception as error:
            result['supervisor_cleanup_error'] = type(error).__name__
        if (W/'state.json').exists():
            try:
                stopped = call(['python3',str(HERE/'ebpf-mysql-fast.py'),'stop','--execute','--work',str(W)], 160)
                save(P/'public-stop.json',json.loads(stopped));result['public_stop_pass'] = True
            except Exception as error:
                result['public_stop_pass'] = False;result['public_stop_error'] = type(error).__name__
        try:save(P/'observer-server-post.json',checked_server());result['old_server_unchanged'] = True
        except Exception:result['old_server_unchanged'] = False
        log_file.close()
        if observer_log:observer_log.close()
        result['finished_unix_ns'] = time.time_ns()
        result['pass'] = bool(result['pass'] and result.get('public_stop_pass') and result.get('old_server_unchanged') and not auxiliary_errors
                              and not result.get('supervisor_cleanup_error') and not result.get('supervisor_still_live'))
        save(P/'observer-supervisor-result.json',result)
    print(json.dumps(result))
    return 0 if result['pass'] else 1

if __name__ == '__main__':
    try:
        sys.exit(main())
    except Exception as error:
        print(json.dumps({'pass':False,'error_type':type(error).__name__,'private_receipts_retained':True}))
        sys.exit(1)

