"""Desktop SSH/scp coordinator. Runs traffic/restart only with --execute.

The remote run must already be prepared. Root owns Agent start and final stop.
Use --phase before/during/after to retain control between phases, or all.
"""
import argparse
import datetime
import json
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import time

ROOT = '/tmp/traflens-lab-20261026'
CODE = '/tmp/traflens-lab-code-20261026'
REPO = '/root/yb/git/TrafLens'
HOST = 'fe80::5a47:caff:fe7c:7859'
PROTOCOLS = {'http': (18080, 'traffic.py'), 'dns': (18053, 'dns-traffic.py'), 'mysql': (18060, 'mysql-traffic.py')}
SSH_OPTIONS = ['-o', 'BatchMode=yes', '-o', 'ConnectTimeout=10', '-o', 'ServerAliveInterval=5', '-o', 'ServerAliveCountMax=2']
CREATE_FLAGS = getattr(subprocess, 'CREATE_NO_WINDOW', 0)


def utc():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def expected_command(run, phase, protocol, side):
    port, script = PROTOCOLS[protocol]
    marker = run + phase[0] + protocol
    directory = ROOT + '/fault-tests/' + run if side == 'server' else REPO + '/.traflens/work/fault-tests/' + run
    path = CODE + '/' + script if side == 'server' else REPO + '/traflens/lab/' + script
    return (['timeout', '--signal=TERM', '--kill-after=5s', '75s', 'python3', path,
             'serve' if side == 'server' else 'client', '--address', HOST, '--marker', marker,
             '--port', str(port), '--count', '20', '--timeout', '75', '--interval-ms',
             '1000' if phase == 'during' else '100', '--interface',
             'enp2s0f0' if side == 'server' else 'enp1s0f0', '--output',
             directory + '/traffic-%s-%s-%s.json' % (protocol, side, marker)])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run-id', required=True)
    parser.add_argument('--phase', choices=('before', 'during', 'after', 'all'), default='before')
    parser.add_argument('--execute', action='store_true')
    args = parser.parse_args()
    if not re.fullmatch('[a-z][a-z0-9]{4,24}', args.run_id):
        parser.error('Invalid prepared run-id')
    local = Path(__file__).resolve().parent / 'fault-runs' / args.run_id
    plan = json.loads((local / 'plan.json').read_text())
    if plan['run_id'] != args.run_id:
        raise RuntimeError('Plan run-id mismatch')
    phases = ('before', 'during', 'after') if args.phase == 'all' else (args.phase,)
    for phase in phases:
        for protocol in PROTOCOLS:
            item = plan['phases'][phase][protocol]
            for side in ('server', 'client'):
                if item[side + '_command'] != expected_command(args.run_id, phase, protocol, side):
                    raise RuntimeError('Plan command differs from the approved fixture scope')
            expected_destination = ROOT + '/fault-tests/' + args.run_id + '/traffic-%s-client-%s.json' % (protocol, args.run_id + phase[0] + protocol)
            if item['client_json_destination_on_dev240'] != expected_destination:
                raise RuntimeError('Unexpected client evidence destination')
    if not args.execute:
        print(json.dumps({'dry_run': True, 'run_id': args.run_id, 'phases': phases,
                          'ports': [18053, 18060, 18080], 'agent_actions': False,
                          'clickhouse_restarts': 1 if 'during' in phases else 0}, indent=2))
        return
    for program in ('ssh', 'scp'):
        if not shutil.which(program):
            raise RuntimeError(program + ' is unavailable')
    label = args.phase + '-driver'
    logs = local / label
    logs.mkdir()  # refuse a second execution under the same stage/marker
    jobs, outcomes = [], []
    deadline = time.monotonic() + 900

    def start(argv, name):
        stdout = (logs / (name + '.stdout')).open('wb')
        stderr = (logs / (name + '.stderr')).open('wb')
        process = subprocess.Popen(argv, stdout=stdout, stderr=stderr, creationflags=CREATE_FLAGS)
        job = {'process': process, 'name': name, 'argv': argv, 'stdout': stdout, 'stderr': stderr,
               'started_at_utc': utc(), 'started': time.monotonic()}
        jobs.append(job)
        return job

    def ssh(host, command, name):
        return start(['ssh'] + SSH_OPTIONS + [host, shlex.join(command)], name)

    def wait(job, seconds=100, check=True):
        limit = min(seconds, deadline - time.monotonic())
        if limit <= 0:
            raise TimeoutError('Coordinator deadline expired')
        rc = job['process'].wait(timeout=limit)
        job['stdout'].close()
        job['stderr'].close()
        result = {'name': job['name'], 'rc': rc, 'started_at_utc': job['started_at_utc'],
                  'finished_at_utc': utc(), 'elapsed_seconds': round(time.monotonic() - job['started'], 3)}
        outcomes.append(result)
        (logs / (job['name'] + '.result.json')).write_text(json.dumps(result, indent=2) + '\n')
        print(json.dumps(result), flush=True)
        if check and rc:
            raise RuntimeError('Command failed: ' + job['name'])
        return rc

    def helper(action, phase=None, check=True):
        command = ['python3', CODE + '/fault-test.py', action, '--run-id', args.run_id]
        if phase:
            command += ['--phase', phase, '--verify-seconds', '120' if phase == 'during' else '60']
        return wait(ssh('dev-240', command, (phase or 'run') + '-' + action), seconds=150, check=check)

    def agent_ready():
        code = '''import json,pathlib,re,time,urllib.request
work=pathlib.Path("/root/yb/git/TrafLens/.traflens/work/agent-run")
end=time.monotonic()+90
while time.monotonic()<end:
 try:
  p=json.loads((work/"provenance.json").read_text())
  with (work/"console.log").open("rb") as f:
   f.seek(p["console_start_offset"]); text=f.read().decode(errors="replace")
  starts=list(re.finditer(r"Start dispatcher \\(0\\)",text))
  assert starts and re.search(r"Grpc finish update[^\\n]*on 3 listener",text[starts[-1].end():])
  with urllib.request.urlopen("http://127.0.0.1:39091/livez",timeout=3) as response: h=json.load(response)
  assert h["status"]=="ok" and any(c["module"]=="dispatcher" and c["running"] for c in h["components"])
  pid=int((work/"deepflow-agent.pid").read_text())
  assert pathlib.Path("/proc",str(pid),"exe").resolve()==pathlib.Path("/root/yb/git/TrafLens/agent/target/debug/deepflow-agent")
  print(json.dumps({"agent_pid":pid,"fresh_dispatcher_and_three_listener_sync":True,"liveness":h,"binary_sha256":p["binary_sha256"]})); break
 except (OSError,ValueError,KeyError,AssertionError): time.sleep(1)
else: raise SystemExit("Owned Agent dispatcher/three-listener readiness timeout")
'''
        wait(ssh('dev-79', ['timeout', '--kill-after=5s', '95s', 'python3', '-c', code], 'agent-readiness'), seconds=105)

    def ready(servers):
        end = time.monotonic() + 20
        while time.monotonic() < end:
            all_ready = True
            for job in servers:
                text = ''.join((logs / (job['name'] + suffix)).read_text(errors='replace') for suffix in ('.stdout', '.stderr'))
                if not re.search(r'(?m)^ready |"event"\s*:\s*"ready"', text):
                    all_ready = False
                    if job['process'].poll() is not None:
                        wait(job)
                        raise RuntimeError('Fixture exited without ready: ' + job['name'])
            if all_ready:
                return
            time.sleep(0.1)
        raise TimeoutError('Fixture ready deadline expired')

    try:
        # Read-only state fetch also binds this local process to the remote total deadline.
        state_job = ssh('dev-240', ['cat', ROOT + '/fault-tests/' + args.run_id + '/state.json'], 'state-before')
        wait(state_job)
        state = json.loads((logs / 'state-before.stdout').read_text())
        if state['run_id'] != args.run_id or state['root'] != ROOT or state['owner'] != 'traflens-lab':
            raise RuntimeError('Prepared state ownership mismatch')
        seconds_left = state['deadline_epoch'] - time.time()
        if seconds_left < 120:
            raise RuntimeError('Prepared run has insufficient deadline remaining')
        deadline = time.monotonic() + min(900, seconds_left)
        agent_ready()
        for phase in phases:
            print(json.dumps({'phase': phase, 'event': 'starting', 'at_utc': utc()}), flush=True)
            servers = [ssh('dev-240', plan['phases'][phase][protocol]['server_command'], phase + '-' + protocol + '-server') for protocol in PROTOCOLS]
            ready(servers)
            if phase == 'during':
                helper('arm-during')
            clients = [ssh('dev-79', plan['phases'][phase][protocol]['client_command'], phase + '-' + protocol + '-client') for protocol in PROTOCOLS]
            if phase == 'during':
                time.sleep(2)
                if helper('restart', check=False):
                    helper('recover', check=False)  # start-only; never a second restart
            for job in clients + servers:
                wait(job, seconds=85)
            for protocol in PROTOCOLS:
                item = plan['phases'][phase][protocol]
                source = item['client_command'][-1]
                destination = item['client_json_destination_on_dev240']
                wait(start(['scp', '-3'] + SSH_OPTIONS + ['dev-79:' + source, 'dev-240:' + destination],
                           phase + '-' + protocol + '-copy'), seconds=30)
            rc = helper('verify', phase, check=False)
            if phase == 'before' and rc:
                raise RuntimeError('Before failed; no fault may be injected')
        if 'after' in phases:
            helper('finalize', check=False)
        summary = {'run_id': args.run_id, 'phases': phases, 'finished_at_utc': utc(), 'commands': outcomes,
                   'all_commands_passed': all(result['rc'] == 0 for result in outcomes),
                   'note': 'Baseline failure is preserved; the coordinator never edits remote acceptance state.'}
        (logs / 'run-summary.json').write_text(json.dumps(summary, indent=2) + '\n')
        return 0 if summary['all_commands_passed'] else 1
    finally:
        for job in jobs:
            if job['process'].poll() is None:
                job['process'].terminate()
                try:
                    job['process'].wait(timeout=3)
                except subprocess.TimeoutExpired:
                    job['process'].kill()
            for stream in (job['stdout'], job['stderr']):
                if not stream.closed:
                    stream.close()


if __name__ == '__main__':
    raise SystemExit(main())
