import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile

repo = Path('/root/yb/git/TrafLens')
out = repo / '.traflens/work/git-metadata-probe'
out.mkdir(exist_ok=True)
source = (repo / 'agent/build.rs').read_text()
body = source.split('fn set_build_info() -> Result<()> {', 1)[1].split('    println!("cargo:rerun-if-env-changed=GITHUB_REF_NAME");', 1)[0]
probe = out / 'probe.rs'
probe.write_text('use std::{path::PathBuf, process::Command, str};\nfn main() -> anyhow::Result<()> {' + body + '\nOk(())\n}\n')
rust = '/root/.rustup/toolchains/stable-x86_64-unknown-linux-gnu/bin/rustc'
anyhow = next((repo / 'agent/target/debug/deps').glob('libanyhow-*.rlib'))
subprocess.run([rust, '--edition=2021', '-C', 'panic=abort', str(probe), '--extern', 'anyhow=' + str(anyhow), '-L',
                'dependency=' + str(repo / 'agent/target/debug/deps'), '-o', str(out / 'probe')], check=True)
env = os.environ.copy()
env.update(GIT_CONFIG_GLOBAL='/dev/null', GIT_CONFIG_NOSYSTEM='1')

def git(cwd, *args):
    return subprocess.check_output(['git', '-c', 'core.hooksPath=/dev/null', *args], cwd=cwd, env=env, stderr=subprocess.STDOUT, text=True)

def check(label, cwd, expected):
    result = subprocess.check_output([str(out / 'probe')], cwd=cwd, env=env, text=True)
    paths = {Path(line.split('=', 1)[1]).resolve() for line in result.splitlines()}
    assert paths == {p.resolve() for p in expected}, (label, result, expected)
    assert all(path.exists() for path in paths)
    return {'case': label, 'passed': True, 'paths': sorted(str(p) for p in paths)}

with tempfile.TemporaryDirectory(prefix='repos-', dir=out) as temp:
    primary = Path(temp) / 'primary'
    primary.mkdir()
    git(primary, 'init', '--initial-branch=main')
    git(primary, '-c', 'user.name=TrafLens Test', '-c', 'user.email=test@example.invalid', 'commit', '--allow-empty', '-m', 'metadata fixture')
    common = primary / '.git'
    results = [check('ordinary repository', primary, [common / 'HEAD', common / 'refs/heads'])]
    git(primary, 'pack-refs', '--all')
    results.append(check('packed branch refs', primary, [common / 'HEAD', common / 'refs/heads', common / 'packed-refs']))
    linked = Path(temp) / 'linked'
    git(primary, 'worktree', 'add', '--detach', str(linked), 'HEAD')
    gitdir = Path(git(linked, 'rev-parse', '--git-dir').strip())
    results.append(check('linked detached worktree', linked, [gitdir / 'HEAD', gitdir / 'commondir', common / 'refs/heads', common / 'packed-refs']))
manifest = {'source_commit': git(repo, 'rev-parse', 'HEAD').strip(),
            'source_sha256': hashlib.sha256(source.encode()).hexdigest(),
            'scope': 'verbatim production set_build_info path-watcher prefix, actual ordinary/packed/linked Git repositories',
            'cases': results}
(out / 'results.json').write_text(json.dumps(manifest, indent=2) + '\n')
print(json.dumps(manifest, indent=2))
