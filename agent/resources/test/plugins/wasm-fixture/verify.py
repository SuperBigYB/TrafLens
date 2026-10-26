#!/usr/bin/env python3
"""Verify committed fixture inputs and gzip/WASM outputs without downloading tools."""
# SPDX-License-Identifier: Apache-2.0
import gzip
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def digest(data):
    return hashlib.sha256(data).hexdigest()


def main():
    manifest = json.loads((ROOT / "build-manifest.json").read_text())
    inputs = {p.name for p in ROOT.glob("*.go")} | {"go.mod", "go.sum", "build.py", "verify.py", "sdk-is-end.patch", "sdk-provenance.json", "README.md", "NOTICE"}
    if set(manifest["inputs"]) != inputs:
        raise ValueError("fixture input inventory changed; regenerate fixtures")
    for name, expected in manifest["inputs"].items():
        if Path(name).name != name or digest((ROOT / name).read_bytes()) != expected:
            raise ValueError(f"fixture input mismatch: {name}; regenerate fixtures")
    expected_names = {f"wasm_test_{flavor}.wasm.gz" for flavor in ("packet", "native")}
    if set(manifest["outputs"]) != expected_names or manifest["repeat_builds"] != 2:
        raise ValueError("unexpected fixture manifest outputs")
    for name, expected in manifest["outputs"].items():
        compressed = (ROOT / name).read_bytes()
        raw = gzip.decompress(compressed)
        if compressed[4:8] != bytes(4) or raw[:8] != b"\0asm\x01\0\0\0":
            raise ValueError(f"invalid deterministic gzip/WASM header: {name}")
        actual = {"wasm_sha256": digest(raw), "wasm_bytes": len(raw),
                  "gzip_sha256": digest(compressed), "gzip_bytes": len(compressed)}
        if actual != expected:
            raise ValueError(f"fixture output mismatch: {name}")
    print("WASM fixture integrity: 2 variants, pinned inputs and outputs verified")


if __name__ == "__main__":
    main()
