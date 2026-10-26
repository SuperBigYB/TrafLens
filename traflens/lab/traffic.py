#!/usr/bin/env python3
"""Small, uniquely marked HTTP workload over an explicitly scoped IPv6 link."""
import argparse
import datetime
import http.client
import http.server
import json
from pathlib import Path
import re
import socket
import socketserver
import time


def utc():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def save(path, value):
    document = json.dumps(value, indent=2) + "\n"
    if path:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(document, encoding="utf-8")
    print(document, end="", flush=True)


def serve(args):
    records = []
    prefix = "/traflens-e2e/" + args.marker + "/"

    class Server(http.server.HTTPServer):
        address_family = socket.AF_INET6

        def server_bind(self):
            socketserver.TCPServer.server_bind(self)
            self.server_name = "traflens-lab.invalid"
            self.server_port = self.server_address[1]

    class Handler(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_GET(self):
            if not self.path.startswith(prefix) or not self.path[len(prefix):].isdigit():
                self.send_error(404)
                return
            sequence = int(self.path[len(prefix):])
            body = json.dumps({"marker": args.marker, "sequence": sequence, "path": self.path}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body)
            records.append({"time": utc(), "path": self.path, "sequence": sequence, "status": 200})
            self.close_connection = True

        def log_message(self, *unused):
            pass

    address = (args.address, args.port, 0, socket.if_nametoindex(args.interface))
    with Server(address, Handler) as server:
        server.timeout = 1
        print("ready " + json.dumps({"address": args.address, "interface": args.interface, "port": args.port}), flush=True)
        deadline = time.monotonic() + args.timeout
        while len(records) < args.count and time.monotonic() < deadline:
            server.handle_request()
    save(args.output, {"kind": "marked-http-server", "marker": args.marker, "records": records})
    if len(records) != args.count:
        raise SystemExit("HTTP server did not receive the expected request count")


def client(args):
    records = []
    destination = (args.address, args.port, 0, socket.if_nametoindex(args.interface))
    for sequence in range(args.count):
        path = "/traflens-e2e/%s/%s" % (args.marker, sequence)
        started = time.monotonic()
        with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as connection:
            connection.settimeout(args.timeout)
            connection.connect(destination)
            request = "GET %s HTTP/1.1\r\nHost: traflens-lab.invalid\r\nConnection: close\r\n\r\n" % path
            connection.sendall(request.encode("ascii"))
            response = http.client.HTTPResponse(connection)
            response.begin()
            payload = json.loads(response.read())
            if response.status != 200 or payload != {"marker": args.marker, "sequence": sequence, "path": path}:
                raise RuntimeError("HTTP response failed status/body verification")
            records.append({"time": utc(), "path": path, "status": response.status, "duration_ms": round((time.monotonic() - started) * 1000, 3)})
            response.close()
        time.sleep(args.interval_ms / 1000)
    save(args.output, {"kind": "marked-http-client", "marker": args.marker, "destination": args.address, "interface": args.interface, "records": records})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=["serve", "client"])
    parser.add_argument("--address", required=True)
    parser.add_argument("--interface", required=True)
    parser.add_argument("--marker", required=True)
    parser.add_argument("--port", type=int, default=18080)
    parser.add_argument("--count", type=int, default=20)
    parser.add_argument("--timeout", type=int, default=90)
    parser.add_argument("--interval-ms", type=int, default=100)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if not re.fullmatch(r"[a-z0-9-]{1,64}", args.marker):
        parser.error("marker must contain 1-64 lowercase letters, digits or hyphens")
    if not 1 <= args.count <= 1000 or not 1 <= args.timeout <= 300 or not 1 <= args.port <= 65535 or not 0 <= args.interval_ms <= 10000:
        parser.error("count, timeout, port or interval is out of range")
    socket.inet_pton(socket.AF_INET6, args.address)
    (serve if args.mode == "serve" else client)(args)


if __name__ == "__main__":
    main()
