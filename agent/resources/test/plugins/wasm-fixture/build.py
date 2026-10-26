#!/usr/bin/env python3
"""Build the two pinned regression guests in an isolated TinyGo container."""
# SPDX-License-Identifier: Apache-2.0
import argparse
import gzip
import hashlib
import io
import json
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import urllib.request

IMAGE = "ghcr.io/tinygo-org/tinygo@sha256:52907162ca3ba807c3c0914e07daffc1fe0c50ce91445ec43a0428337dc1b901"
COMMIT = "3ac5fba17db6cc03ae6ed82254e2a0a9f39a5e9d"
ROOT = Path(__file__).resolve().parent


def sha(data):
    return hashlib.sha256(data).hexdigest()


def run_container(work, command, *, offline):
    args = ["docker", "run", "--rm", "--user", "0:0", "--cpus", "4",
            "--memory", "8g", "--pids-limit", "4096", "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges"]
    if offline:
        args += ["--network", "none"]
    args += ["--mount", f"type=bind,src={work},dst=/work", "-w", "/work/fixture",
             "-e", "HOME=/work/home", "-e", "GOPATH=/work/gopath",
             "-e", "GOCACHE=/work/gocache", "-e", "GOTOOLCHAIN=local",
             "-e", "GOPROXY=off" if offline else "GOPROXY=https://goproxy.cn,direct",
             "-e", "GOFLAGS=-mod=readonly", IMAGE, "sh", "-ec", command]
    subprocess.run(args, check=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--work", type=Path, help="new isolated directory (must not exist)")
    args = parser.parse_args()
    if args.work:
        work = args.work.resolve()
        work.mkdir(parents=False, exist_ok=False)
    else:
        work = Path(tempfile.mkdtemp(prefix="traflens-wasm-fixture-"))
    print(f"Retained isolated build directory: {work}", flush=True)
    provenance = json.loads((ROOT / "sdk-provenance.json").read_text())
    with urllib.request.urlopen(
        f"https://codeload.github.com/deepflowio/deepflow-wasm-go-sdk/tar.gz/{COMMIT}",
        timeout=90,
    ) as response:
        archive = response.read()
    if sha(archive) != provenance["archive_sha256"]:
        raise ValueError("SDK archive checksum mismatch")
    sdk = work / "sdk"
    sdk.mkdir()
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as tar:
        for entry in tar.getmembers():
            parts = Path(entry.name).parts[1:]
            if not parts:
                continue
            if entry.name.startswith("/") or any(p in ("..", "") for p in parts) or entry.issym() or entry.islnk():
                raise ValueError("Unsafe SDK archive member")
            target = sdk.joinpath(*parts)
            if entry.isdir():
                target.mkdir(parents=True, exist_ok=True)
            elif entry.isfile():
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(tar.extractfile(entry).read())
            else:
                raise ValueError("Unsupported SDK archive member")
    serde = sdk / "sdk/serde.go"
    before = serde.read_bytes()
    patch = (ROOT / "sdk-is-end.patch").read_bytes()
    if sha(before) != provenance["serde_before_sha256"] or sha(patch) != provenance["patch_sha256"]:
        raise ValueError("SDK patch precondition mismatch")
    if "IsEnd   *bool" not in (sdk / "sdk/pb/WasmPluginApi.pb.go").read_text():
        raise ValueError("SDK no longer exposes AppInfo.IsEnd")
    marker = b"\t\tif info.IsAsync != nil {"
    if before.count(marker) != 1:
        raise ValueError("SDK patch location mismatch")
    after = before.replace(marker, b"\t\t// Preserve the current AppInfo field 21 merge/end contract.\n\t\tif info.ProtocolMerge {\n\t\t\tmsg.IsEnd = proto.Bool(info.IsEnd)\n\t\t}\n\n" + marker)
    if sha(after) != provenance["serde_after_sha256"]:
        raise ValueError("SDK patch output checksum mismatch")
    serde.write_bytes(after)
    fixture = work / "fixture"
    fixture.mkdir()
    names = [p.name for p in ROOT.glob("*.go")] + ["go.mod", "go.sum"]
    for name in names:
        shutil.copyfile(ROOT / name, fixture / name)
    run_container(work, "go mod edit -replace github.com/deepflowio/deepflow-wasm-go-sdk=/work/sdk; go mod download all; go test decode.go decode_test.go; tinygo version", offline=False)
    # Dependency preparation may only add checksums if the pinned manifest is incomplete.
    if (fixture / "go.sum").read_bytes() != (ROOT / "go.sum").read_bytes():
        raise ValueError("Dependency checksums changed; review go.sum before building")
    run_container(work, "mkdir -p /work/out; for pass in 1 2; do for flavor in packet native; do tags=''; if [ \"$flavor\" = native ]; then tags='-tags=nativefixture'; fi; tinygo build -target=wasi -scheduler=asyncify -panic=trap -no-debug -opt=z $tags -o /work/out/wasm_test_${flavor}_${pass}.wasm .; done; done", offline=True)
    outputs = {}
    for flavor in ("packet", "native"):
        first = (work / f"out/wasm_test_{flavor}_1.wasm").read_bytes()
        second = (work / f"out/wasm_test_{flavor}_2.wasm").read_bytes()
        if first != second:
            raise ValueError(f"{flavor} repeated builds differ")
        buffer = io.BytesIO()
        with gzip.GzipFile(filename="", mode="wb", compresslevel=9, mtime=0, fileobj=buffer) as stream:
            stream.write(first)
        compressed = buffer.getvalue()
        repeat_buffer = io.BytesIO()
        with gzip.GzipFile(filename="", mode="wb", compresslevel=9, mtime=0, fileobj=repeat_buffer) as stream:
            stream.write(second)
        if compressed != repeat_buffer.getvalue():
            raise ValueError(f"{flavor} repeated gzip output differs")
        name = f"wasm_test_{flavor}.wasm.gz"
        (ROOT / name).write_bytes(compressed)
        outputs[name] = {"wasm_sha256": sha(first), "wasm_bytes": len(first),
                         "gzip_sha256": sha(compressed), "gzip_bytes": len(compressed)}
    manifest = {"image": IMAGE, "sdk_commit": COMMIT, "sdk_patched": True,
                "repeat_builds": 2, "gzip_mtime": 0, "outputs": outputs,
                "inputs": {n: sha((ROOT / n).read_bytes()) for n in sorted(names + ["build.py", "verify.py", "sdk-is-end.patch", "sdk-provenance.json", "README.md", "NOTICE"])}}
    (ROOT / "build-manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(json.dumps(outputs, indent=2))


if __name__ == "__main__":
    main()
