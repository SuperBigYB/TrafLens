#!/usr/bin/env python3
"""Sample the owned Server's read-only debug status without exposing its port."""

import argparse
import datetime
import json
import pathlib
import subprocess
import time

import lab


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seconds", type=int, default=60)
    parser.add_argument("--root", type=pathlib.Path, default=pathlib.Path("/tmp/traflens-lab-20261026"))
    args = parser.parse_args()
    if not 1 <= args.seconds <= 90:
        parser.error("Sample for at most 90 seconds")
    root = args.root.resolve()
    info = lab.inspect("container", "traflens-lab-server")
    lab.require_owned(info, root, "container")
    pid = int(info["State"]["Pid"])
    if pid <= 0:
        raise RuntimeError("Owned Server is not running")
    deadline = time.monotonic() + args.seconds
    output = root / "evidence/backend-samples.jsonl"
    with output.open("w") as target:
        output.chmod(0o600)
        while time.monotonic() < deadline:
            result = subprocess.run(["nsenter", "-t", str(pid), "-n", "/tmp/traflens-backend-probe"],
                                    text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=35)
            if result.returncode:
                raise RuntimeError("Read-only backend probe failed")
            record = {"sampled_at_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                      "counters": json.loads(result.stdout)}
            target.write(json.dumps(record) + "\n")
            target.flush()
            time.sleep(min(2, max(0, deadline - time.monotonic())))
    print(str(output))


if __name__ == "__main__":
    main()
