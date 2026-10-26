#!/usr/bin/env python3
"""Observe debug copies of lab queues using ephemeral local UDP ports.

Wire format matches the pinned public bincode-standard QueueMessage protocol.
Unlike the upstream CLI's fixed local port, this permits concurrent observers.
Only the three smoke-test queues are addressed, on the owned loopback debugger.
"""

import argparse
import json
import os
import pathlib
import re
import select
import socket
import time

QUEUES = ["1-tagged-flow-to-app-protocol-logs", "1-tagged-flow-to-quadruple-generator",
          "2-protolog-to-collector-sender"]


def uint(value):
    if value < 251:
        return bytes([value])
    for marker, width in ((251, 2), (252, 4), (253, 8), (254, 16)):
        if value < 1 << (width * 8):
            return bytes([marker]) + value.to_bytes(width, "little")
    raise ValueError("Integer too large")


def decode_uint(payload, offset=0):
    marker = payload[offset]
    if marker < 251:
        return marker, offset + 1
    width = {251: 2, 252: 4, 253: 8, 254: 16}[marker]
    end = offset + 1 + width
    return int.from_bytes(payload[offset + 1:end], "little"), end


def message(variant, name, seconds=None):
    encoded = name.encode()
    result = uint(4) + uint(variant) + uint(len(encoded)) + encoded
    if seconds is not None:
        result += uint(seconds) + uint(0)  # Duration seconds, nanoseconds
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=pathlib.Path, default=pathlib.Path("/root/yb/git/TrafLens"))
    parser.add_argument("--seconds", type=int, default=45)
    args = parser.parse_args()
    if not 1 <= args.seconds <= 90:
        parser.error("Observe for at most 90 seconds")
    os.umask(0o077)
    work = args.repo.resolve() / ".traflens/work/agent-run"
    (work / "queues-ready.json").unlink(missing_ok=True)
    provenance = json.loads((work / "provenance.json").read_text())
    with (work / "console.log").open() as source:
        source.seek(provenance["console_start_offset"])
        ports = re.findall(r"debugger listening on: \[::\]:(\d+)", source.read())
    if not ports:
        raise RuntimeError("Current owned Agent has no debugger startup evidence")
    endpoint = ("127.0.0.1", int(ports[-1]))
    sockets = {}
    counts = {name: {"debug_items": 0, "debug_bytes": 0, "acknowledged": False, "errors": []} for name in QUEUES}
    outputs = {}
    deadline = time.monotonic() + args.seconds
    try:
        for name in QUEUES:
            connection = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            connection.bind(("127.0.0.1", 0))
            sockets[connection] = name
            outputs[name] = (work / ("observed-" + name + ".log")).open("w")
            connection.sendto(message(3, name, args.seconds + 5), endpoint)
        while time.monotonic() < deadline:
            ready, _, _ = select.select(list(sockets), [], [], min(1, max(0, deadline - time.monotonic())))
            for connection in ready:
                payload, sender = connection.recvfrom(65535)
                if sender[0] != "127.0.0.1":
                    continue
                name = sockets[connection]
                variant, offset = decode_uint(payload)
                if variant == 7:
                    counts[name]["acknowledged"] = True
                elif variant in (2, 8):
                    length, offset = decode_uint(payload, offset)
                    text = payload[offset:offset + length].decode("utf-8", errors="replace")
                    if variant == 8:
                        counts[name]["errors"].append(text)
                    else:
                        counts[name]["debug_items"] += 1
                        counts[name]["debug_bytes"] += length
                        if outputs[name].tell() < 2 * 1024 * 1024:
                            outputs[name].write(text + "\n")
                            outputs[name].flush()
            if all(value["acknowledged"] for value in counts.values()):
                (work / "queues-ready.json").write_text(json.dumps({"endpoint": endpoint, "seconds": args.seconds}) + "\n")
    finally:
        for connection, name in sockets.items():
            connection.sendto(message(4, name), endpoint)
            connection.close()
        for output in outputs.values():
            output.close()
    (work / "queue-observations.json").write_text(json.dumps(counts, indent=2) + "\n")
    print(json.dumps(counts, indent=2))


if __name__ == "__main__":
    main()
