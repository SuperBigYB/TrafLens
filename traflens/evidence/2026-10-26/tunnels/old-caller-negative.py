#!/usr/bin/env python3
"""Compare old caller with new decoders; restore source even on failure."""
import hashlib
import json
from pathlib import Path
import os
import subprocess

repo = Path('/root/yb/git/TrafLens')
source = repo / 'agent/src/common/decapsulate.rs'
work = repo / '.traflens/work'
candidate = source.read_bytes()
baseline = subprocess.check_output(['git', 'show', '52fa57a8b:agent/src/common/decapsulate.rs'], cwd=repo)
hook = b'\n#[cfg(test)]\n#[path = "decapsulate_regression.rs"]\nmod regression;\n'
env = os.environ.copy()
env.update(PATH='/root/.rustup/toolchains/stable-x86_64-unknown-linux-gnu/bin:' + env['PATH'],
           CARGO_BUILD_JOBS='4', CARGO_PROFILE_TEST_DEBUG='0', CARGO_PROFILE_DEV_DEBUG='0',
           CARGO_NET_OFFLINE='true', CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER='cc')
command = ['cargo', 'test', '--locked', '--no-default-features', '--lib',
           'common::decapsulate::regression', '--', '--test-threads=1']
try:
    source.write_bytes(baseline + hook)
    with (work / 'tunnel-old-caller-negative.log').open('wb') as output:
        result = subprocess.run(command, cwd=repo / 'agent', env=env, stdout=output, stderr=subprocess.STDOUT)
finally:
    source.write_bytes(candidate)
assert source.read_bytes() == candidate
record = {'baseline_caller': '52fa57a8b48fb54cb290364fe7d7c7f60d6aa077',
          'scope': 'old caller plus current new decoder modules and new regression tests; not pristine upstream',
          'argv': command, 'exit_code': result.returncode,
          'candidate_caller_sha256': hashlib.sha256(candidate).hexdigest(),
          'source_restored': True}
(work / 'tunnel-old-caller-negative.json').write_text(json.dumps(record, indent=2) + '\n')
print(json.dumps(record))
if result.returncode == 0:
    raise SystemExit('negative control unexpectedly passed')
