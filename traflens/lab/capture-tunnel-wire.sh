#!/usr/bin/env bash
set -euo pipefail
umask 077
marker=${1:?marker}
[[ "$marker" =~ ^[a-z0-9-]{1,24}$ ]]
repo=/root/yb/git/TrafLens
work="$repo/.traflens/work/tunnel-wire/$marker"
mkdir -p "$work"
cd "$repo"
python3 - "$marker" "$work" <<'PY'
import json,pathlib,re,sys,time,urllib.request
marker, output = sys.argv[1], pathlib.Path(sys.argv[2])
lease=json.loads(pathlib.Path('/tmp/traflens-tunnel-link-'+marker+'/lease.json').read_text())
assert lease['role']=='dev-79' and lease['status']=='ready'
assert lease['deadline_monotonic']-time.monotonic() > 110
work=pathlib.Path('.traflens/work/agent-run')
provenance=json.loads((work/'provenance.json').read_text())
with (work/'console.log').open() as source:
    source.seek(provenance['console_start_offset'])
    text=source.read()
start=text.rfind('Start mirror dispatcher')
assert start>=0 and re.search(r'Grpc finish update .* on 3 listener', text[start:])
live=json.load(urllib.request.urlopen('http://127.0.0.1:39091/livez', timeout=5))
assert live['status']=='ok' and any(c['module']=='dispatcher' and c['running'] for c in live['components'])
(output/'liveness.json').write_text(json.dumps(live,indent=2)+'\n')
(output/'agent-provenance.json').write_text(json.dumps(provenance,indent=2)+'\n')
(output/'agent-readiness.log').write_text('\n'.join(line for line in text.splitlines() if 'Start mirror dispatcher' in line or 'on 3 listener' in line)+'\n')
PY
rm -f "$repo/.traflens/work/agent-run/queues-ready.json"
(
  date --iso-8601=ns > "$work/capture-start.txt"
  set +e
  timeout --preserve-status --signal=INT 100 tcpdump -i enp1s0f0 -n -s 0 -U \
    -w "$work/received.pcap" \
    'ether src 58:47:ca:7c:78:59 and ether dst 58:47:ca:77:66:e2 and ip src 198.18.0.240 and ip dst 198.18.0.79 and (ip proto 47 or udp dst port 4790)' \
    > "$work/capture.log" 2>&1
  printf '%s\n' "$?" > "$work/capture-exit.txt"
  date --iso-8601=ns > "$work/capture-end.txt"
) &
capture_pid=$!
(
  set +e
  python3 traflens/lab/watch-queues.py --seconds 90 > "$work/queues-console.log" 2>&1
  printf '%s\n' "$?" > "$work/queues-exit.txt"
  cp .traflens/work/agent-run/queue-observations.json \
    .traflens/work/agent-run/observed-1-tagged-flow-to-app-protocol-logs.log \
    .traflens/work/agent-run/observed-1-tagged-flow-to-quadruple-generator.log \
    .traflens/work/agent-run/observed-2-protolog-to-collector-sender.log "$work/"
) &
queue_pid=$!
ready=0
for attempt in $(seq 1 40); do
  if grep -q 'listening on enp1s0f0' "$work/capture.log" 2>/dev/null \
     && test -s .traflens/work/agent-run/queues-ready.json; then
    ready=1
    python3 - "$work" "$capture_pid" "$queue_pid" <<'PY'
import datetime,json,pathlib,sys
path=pathlib.Path(sys.argv[1])/'capture-ready.json'
path.write_text(json.dumps({'ready':True,'at_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),
                          'capture_pid':int(sys.argv[2]),'queue_pid':int(sys.argv[3]),
                          'capture_seconds':100,'queue_seconds':90})+'\n')
PY
    break
  fi
  sleep 0.25
done
test "$ready" = 1
wait "$capture_pid"
wait "$queue_pid"
