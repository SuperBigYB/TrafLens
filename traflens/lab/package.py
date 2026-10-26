#!/usr/bin/env python3
"""Package the locally built server and its matching runtime resources."""

import argparse
import hashlib
import json
import pathlib
import subprocess
import tarfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=pathlib.Path)
    parser.add_argument("--zoneinfo", type=pathlib.Path, help="Go toolchain lib/time/zoneinfo.zip; defaults to go env GOROOT")
    args = parser.parse_args()
    repo = pathlib.Path(__file__).resolve().parents[2]
    binary = repo / "server/bin/deepflow-server"
    if not binary.is_file():
        parser.error("Build the server with its owning Makefile first.")
    zoneinfo = args.zoneinfo
    if zoneinfo is None:
        goroot = subprocess.check_output(["go", "env", "GOROOT"], text=True).strip()
        zoneinfo = pathlib.Path(goroot) / "lib/time/zoneinfo.zip"
    if not zoneinfo.is_file():
        parser.error("Provide the build toolchain's IANA archive with --zoneinfo")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    sha = subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=repo, text=True
    ).strip()
    mappings = {
        "server/bin/deepflow-server": "bin/deepflow-server",
        "server/controller/db/metadb/migrator/schema": "etc/metadb/schema",
        "server/querier/db_descriptions": "etc/db_descriptions",
        "server/controller/cloud/filereader/manual_data_samples.yaml":
            "etc/manual_data_samples.yaml",
    }
    with tarfile.open(args.output, "w:gz") as archive:
        for source, target in mappings.items():
            archive.add(repo / source, arcname=target)
        lua_dir = repo / "server/controller/cloud/kubernetes_gather/lua"
        for source in sorted(lua_dir.iterdir()):
            archive.add(source, arcname="bin/" + source.name)
        archive.add(zoneinfo, arcname="share/zoneinfo.zip")
    digest = hashlib.sha256(args.output.read_bytes()).hexdigest()
    info = {
        "source_head": sha,
        "server_version": subprocess.check_output([str(binary), "-v"], text=True),
        "archive_sha256": digest,
        "archive_bytes": args.output.stat().st_size,
        "timezone_archive_sha256": hashlib.sha256(zoneinfo.read_bytes()).hexdigest(),
        "note": "Source HEAD and binary build revision are recorded separately.",
    }
    args.output.with_suffix(args.output.suffix + ".json").write_text(
        json.dumps(info, indent=2) + "\n", encoding="utf-8"
    )
    print(json.dumps(info, indent=2))


if __name__ == "__main__":
    main()
