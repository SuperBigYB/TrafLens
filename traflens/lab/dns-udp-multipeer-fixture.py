#!/usr/bin/env python3
"""Finite real UDP wire fixture; never starts an Agent or claims ingestion."""
import argparse
import hashlib
import json
import multiprocessing as mp
import os
from pathlib import Path
import re
import socket
import struct
import threading
import time

SERVER = ("127.0.0.2", 18080)
IDS = (0x4101, 0x4102, 0x4141, 0x4141)


def message(marker, case, response=False):
    if not re.fullmatch(r"udpmp-[0-9a-f]{24}", marker) or case not in range(4):
        raise ValueError("invalid finite fixture identity")
    name = f"case{case}.{marker}.test"
    question = b"".join(bytes([len(x)]) + x.encode("ascii") for x in name.split(".")) + b"\0\0\1\0\1"
    error = case in (1, 3)
    answer = b"\xc0\x0c\0\1\0\1\0\0\0\x3c\0\4\xc6\x12\0\x29" if response and not error else b""
    flags = (0x8183 if error else 0x8180) if response else 0x0100
    data = struct.pack("!6H", IDS[case], flags, 1, bool(answer), 0, 0) + question + answer
    assert 12 <= len(data) <= 512
    return data


def identity():
    # Own-process identity only; no host inventory or business metadata.
    stat = Path("/proc/self/stat").read_text().rsplit(")", 1)[1].split()
    return {"pid": os.getpid(), "tid": threading.get_native_id(), "startticks": int(stat[19]),
            "netns_inode": os.stat("/proc/self/ns/net").st_ino}


def io(sock, events, operation, data=None, peer=None):
    start = time.time_ns()
    if operation == "send":
        assert data is not None and 12 <= len(data) <= 512
        n = sock.sendto(data, peer)
        assert n == len(data)
    else:
        data, peer = sock.recvfrom(513)
        assert 12 <= len(data) <= 512
    end = time.time_ns()
    local = sock.getsockname()
    assert local[0] in ("127.0.0.1", "127.0.0.2") and peer[0] in ("127.0.0.1", "127.0.0.2")
    events.append({"operation": operation, "fd": sock.fileno(), "local": local, "peer": peer,
                   "started_unix_ns": start, "finished_unix_ns": end,
                   "wire_hex": data.hex(), "wire_sha256": hashlib.sha256(data).hexdigest()})
    assert len(events) <= 8
    return data, peer


def worker(role, marker, pipe):
    events = []
    sock = None
    try:
        process = identity()
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(2)
        # No reuse flags, no external addresses, exactly one bound socket per worker.
        sock.bind(SERVER if role == "server" else ("127.0.0.1", 0))
        pipe.send({"ready": True, "identity": process, "local": sock.getsockname()})
        seen = set()
        while True:
            if not pipe.poll(4):
                raise TimeoutError("finite control deadline")
            cmd = pipe.recv()
            if cmd[0] == "stop":
                break
            if role == "server":
                assert cmd[0] == "batch" and cmd[1] in (1, 2)
                pending = []
                for _ in range(cmd[1]):
                    data, peer = io(sock, events, "recv")
                    matches = [i for i in range(4) if data == message(marker, i)]
                    assert len(matches) == 1 and matches[0] not in seen
                    case = matches[0]
                    seen.add(case)
                    pending.append((case, peer))
                # Both repeated-TXID requests are received before either reply.
                for case, peer in reversed(pending):
                    io(sock, events, "send", message(marker, case, True), peer)
            else:
                assert cmd[0] == "exchange"
                case = cmd[1]
                assert case in ((0, 2) if role == "client-a" else (1, 3)) and case not in seen
                seen.add(case)
                io(sock, events, "send", message(marker, case), SERVER)
                data, peer = io(sock, events, "recv")
                assert peer == SERVER and data == message(marker, case, True)
            pipe.send({"done": True})
        expected = 4 if role == "server" else 2
        assert len(seen) == expected and len(events) == expected * 2
        sock.close()
        sock = None
        pipe.send({"pass": True, "role": role, "identity": process, "wire": events,
                   "owned_socket_closed": True, "native_source3_verified": False})
    except BaseException as error:
        pipe.send({"pass": False, "role": role, "error_category": type(error).__name__, "wire": events})
        raise
    finally:
        if sock is not None:
            sock.close()
        pipe.close()


def receive(pipe):
    if not pipe.poll(4):
        raise TimeoutError("finite child reply deadline")
    value = pipe.recv()
    if value.get("pass") is False:
        raise RuntimeError("owned worker failed")
    return value


def execute(marker, output, required_ns):
    if os.stat("/proc/self/ns/net").st_ino != required_ns:
        raise ValueError("explicit namespace identity differs")
    output.mkdir(mode=0o700, parents=False, exist_ok=False)
    os.chmod(output, 0o700)
    context = mp.get_context("spawn")
    workers = {}
    result = {"schema": "traflens.udp-multipeer-wire.v1", "pass": False,
              "native_source3_verified": False, "workers": {}, "processes_stopped": False}
    try:
        for role in ("server", "client-a", "client-b"):
            parent, child = context.Pipe()
            process = context.Process(target=worker, args=(role, marker, child))
            process.start()
            child.close()
            workers[role] = process, parent
            result["workers"][role] = receive(parent)
        assert len({result["workers"][r]["local"][1] for r in ("client-a", "client-b")}) == 2
        assert all(v["identity"]["netns_inode"] == required_ns for v in result["workers"].values())
        for case, client in ((0, "client-a"), (1, "client-b")):
            workers["server"][1].send(("batch", 1))
            workers[client][1].send(("exchange", case))
            assert receive(workers[client][1])["done"] and receive(workers["server"][1])["done"]
        workers["server"][1].send(("batch", 2))
        for case, client in ((2, "client-a"), (3, "client-b")):
            workers[client][1].send(("exchange", case))
        for role in ("server", "client-a", "client-b"):
            assert receive(workers[role][1])["done"]
        for role, (_, pipe) in workers.items():
            pipe.send(("stop",))
            result["workers"][role] = receive(pipe)
        result["pass"] = True
    except BaseException as error:
        result["error_category"] = type(error).__name__
    finally:
        for process, pipe in workers.values():
            process.join(1)
            if process.is_alive():
                process.terminate()
                process.join(2)
            if process.is_alive():
                process.kill()
                process.join(1)
            pipe.close()
        result["processes_stopped"] = all(not p.is_alive() for p, _ in workers.values())
        result["pass"] = result["pass"] and result["processes_stopped"] and all(p.exitcode == 0 for p, _ in workers.values())
        receipt = output / "wire-receipt.json"
        fd = os.open(receipt, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(fd, "w") as target:
            json.dump(result, target, indent=2)
            target.write("\n")
    # Never print private wire/identity or claim database acceptance.
    return 0 if result["pass"] else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--run")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--require-netns-inode", type=int)
    args = parser.parse_args()
    if not args.execute:
        print(json.dumps({"execute": False, "starts_network": False, "starts_agent": False,
                          "creates_files": False, "queries": 4, "server_sockets": 1,
                          "client_sockets": 2, "repeated_txid_overlap": True,
                          "native_source3_verified": False}))
        return 0
    if not args.run or not args.output or not args.require_netns_inode:
        parser.error("execute requires run, fresh output and exact network namespace inode")
    message(args.run, 0)
    return execute(args.run, args.output, args.require_netns_inode)


if __name__ == "__main__":
    raise SystemExit(main())
