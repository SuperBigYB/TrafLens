#!/usr/bin/env python3
"""Start or stop an isolated, resource-limited native-server test stack."""

import argparse
import hashlib
import ipaddress
import json
import os
import pathlib
import secrets
import shutil
import subprocess
import tarfile
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

PREFIX = "traflens-lab"
LABEL = "io.traflens.lab"
HERE = pathlib.Path(__file__).resolve().parent


def run(args, capture=False, check=True, timeout=600):
    result = subprocess.run(
        args, text=True, stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.PIPE if capture else None, timeout=timeout,
    )
    if check and result.returncode:
        detail = result.stderr.strip() if capture else "see command output"
        raise RuntimeError("{} failed: {}".format(args[0:3], detail))
    return result


def inspect(kind, name):
    result = run(["docker", kind, "inspect", name], capture=True, check=False)
    return json.loads(result.stdout)[0] if result.returncode == 0 else None


def require_owned(info, root, kind):
    labels = info.get("Config", {}).get("Labels", {}) if kind == "container" else info.get("Labels", {})
    if labels.get(LABEL) != str(root):
        raise RuntimeError("Refusing to change an existing resource owned elsewhere")


def container(root, name, options, image, command, recreate):
    full_name = PREFIX + "-" + name
    info = inspect("container", full_name)
    if info:
        require_owned(info, root, "container")
        if recreate:
            run(["docker", "rm", "-f", full_name], capture=True)
            info = None
        elif name == "server":
            requested = inspect("image", image)
            if not requested or info["Image"] != requested["Id"]:
                raise RuntimeError("Requested Server runtime differs from the running image; use --recreate-server")
    if info is None:
        run([
            "docker", "create", "--name", full_name, "--network", PREFIX,
            "--label", LABEL + "=" + str(root), "--restart", "no",
            "--log-opt", "max-size=10m", "--log-opt", "max-file=2",
        ] + options + [image] + command, capture=True)
    run(["docker", "start", full_name], capture=True)
    print("started " + full_name, flush=True)


def volume(root, name):
    full_name = PREFIX + "-" + name
    info = inspect("volume", full_name)
    if info:
        require_owned(info, root, "volume")
    else:
        run(["docker", "volume", "create", "--label", LABEL + "=" + str(root), full_name], capture=True)
    return full_name


def wait_for(label, callback, timeout):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            result = callback()
            if result:
                print(label + " ready", flush=True)
                return result
        except (OSError, ValueError, urllib.error.URLError):
            pass
        time.sleep(2)
    raise RuntimeError(label + " did not become ready before timeout")


def health():
    with urllib.request.urlopen("http://127.0.0.1:20417/v1/health/", timeout=3) as response:
        value = json.load(response)
    return value if value.get("OPT_STATUS") == "SUCCESS" else None


def query(sql, database="flow_log"):
    data = urllib.parse.urlencode({"db": database, "sql": sql}).encode()
    request = urllib.request.Request("http://127.0.0.1:20416/v1/query/", data=data)
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return json.load(response)
    except urllib.error.HTTPError as error:
        body = error.read().decode("utf-8", errors="replace")
        try:
            return json.loads(body)
        except ValueError:
            return {"OPT_STATUS": "INVALID_RESPONSE", "HTTP_STATUS": error.code, "RAW_BODY": body}


def extract_runtime(package, target):
    digest = hashlib.sha256(package.read_bytes()).hexdigest()
    target.mkdir(mode=0o700, parents=True, exist_ok=True)
    destination_root = target / digest
    marker = destination_root / ".archive-sha256"
    if marker.is_file() and marker.read_text().strip() == digest:
        return destination_root
    if destination_root.exists():
        destination_root = pathlib.Path(tempfile.mkdtemp(prefix=digest + "-", dir=target))
        marker = destination_root / ".archive-sha256"
    else:
        destination_root.mkdir(mode=0o700)
    with tarfile.open(package, "r:gz") as archive:
        for member in archive.getmembers():
            destination = (destination_root / member.name).resolve()
            if destination_root.resolve() not in destination.parents or member.issym() or member.islnk() or member.isdev():
                raise RuntimeError("Unsafe runtime archive entry")
        archive.extractall(destination_root)
    marker.write_text(digest + "\n")
    marker.chmod(0o600)
    return destination_root


def private_write(path, content):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as output:
        output.write(content)
    path.chmod(0o600)


def prepare_root(root):
    if root == pathlib.Path("/") or not root.is_absolute():
        raise RuntimeError("Use a dedicated absolute lab root")
    marker = root / "owner.json"
    if root.exists() and any(root.iterdir()) and not marker.is_file():
        raise RuntimeError("Existing lab root has no ownership marker")
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    root.chmod(0o700)
    if marker.is_file():
        value = json.loads(marker.read_text())
        if value != {"owner": PREFIX, "root": str(root)}:
            raise RuntimeError("Lab root ownership marker mismatch")
    else:
        private_write(marker, json.dumps({"owner": PREFIX, "root": str(root)}) + "\n")


def start(args):
    root = args.root.resolve()
    prepare_root(root)
    images = json.loads((HERE / "images.json").read_text())
    secret = root / "mysql-password"
    if not secret.exists():
        private_write(secret, secrets.token_hex(24) + "\n")
    password = secret.read_text().strip()
    if len(password) != 48 or any(c not in "0123456789abcdef" for c in password):
        raise RuntimeError("Invalid private lab password file")
    secret.chmod(0o600)
    private_write(root / "mysql.env", "MYSQL_ROOT_PASSWORD=" + password + "\nMYSQL_ROOT_HOST=%\n")
    private_write(root / "server.yaml", (HERE / "server.yaml.in").read_text().replace("{{MYSQL_PASSWORD}}", password))
    shutil.copyfile(HERE / "clickhouse.xml", root / "clickhouse.xml")
    shutil.copyfile(HERE / "clickhouse-users.xml", root / "clickhouse-users.xml")
    # ClickHouse drops privileges; its public bind-mounted XML must remain readable.
    (root / "clickhouse.xml").chmod(0o644)
    (root / "clickhouse-users.xml").chmod(0o644)
    runtime = extract_runtime(args.runtime_package, root / "runtimes")
    binary = runtime / "bin/deepflow-server"
    binary_hash = hashlib.sha256(binary.read_bytes()).hexdigest()
    dockerfile = runtime / "Dockerfile"
    dockerfile.write_text(
        "FROM " + images["runtime"] + "\n"
        "COPY bin/ /bin/\nCOPY etc/ /etc/\n"
        "COPY share/zoneinfo.zip /usr/share/zoneinfo.zip\n"
        "ENV ZONEINFO=/usr/share/zoneinfo.zip\n"
        'ENTRYPOINT ["/bin/deepflow-server"]\n'
    )
    image_hash = hashlib.sha256(dockerfile.read_bytes() + args.runtime_package.read_bytes()).hexdigest()
    server_image = PREFIX + "-server:" + image_hash[:16]
    if not inspect("image", server_image):
        run(["docker", "build", "--network", "none", "--pull=false", "-t", server_image, str(runtime)])
    info = inspect("network", PREFIX)
    if info:
        require_owned(info, root, "network")
    else:
        run(["docker", "network", "create", "--label", LABEL + "=" + str(root), PREFIX], capture=True)
    mysql_volume = volume(root, "mysql-data")
    clickhouse_volume = volume(root, "clickhouse-data")
    storage_volume = volume(root, "clickhouse-storage")
    container(root, "mysql", [
        "--network-alias", "mysql", "--cpus=1", "--memory=1g", "--memory-swap=1g", "--pids-limit=256",
        "--env-file", str(root / "mysql.env"), "-v", mysql_volume + ":/var/lib/mysql",
    ], images["mysql"], ["--default-authentication-plugin=mysql_native_password", "--innodb-buffer-pool-size=128M", "--max-connections=60"], args.recreate)
    container(root, "clickhouse", [
        "--network-alias", "clickhouse", "--cpus=2", "--memory=4g", "--memory-swap=4g", "--pids-limit=1024",
        "--ulimit", "nofile=262144:262144", "-v", clickhouse_volume + ":/var/lib/clickhouse",
        "-v", storage_volume + ":/var/lib/clickhouse_storage",
        "-v", str(root / "clickhouse.xml") + ":/etc/clickhouse-server/config.d/traflens.xml:ro",
        "-v", str(root / "clickhouse-users.xml") + ":/etc/clickhouse-server/users.d/traflens.xml:ro",
    ], images["clickhouse"], [], args.recreate)
    wait_for("MySQL", lambda: run([
        "docker", "exec", PREFIX + "-mysql", "sh", "-c",
        'MYSQL_PWD="$MYSQL_ROOT_PASSWORD" mysqladmin -h127.0.0.1 -uroot ping --silent',
    ], capture=True, check=False, timeout=10).returncode == 0, args.timeout)
    wait_for("ClickHouse", lambda: run([
        "docker", "exec", PREFIX + "-clickhouse", "clickhouse-client", "--query", "SELECT 1",
    ], capture=True, check=False, timeout=10).returncode == 0, args.timeout)
    container(root, "server", [
        "--network-alias", "server", "--network-alias", "deepflow-server",
        "--cpus=2", "--memory=4g", "--memory-swap=4g", "--pids-limit=512",
        "--read-only", "--tmpfs", "/tmp:rw,nosuid,size=256m", "--tmpfs", "/var/log:rw,nosuid,size=128m",
        "-e", "DEEPFLOW_SERVER_RUNNING_MODE=STANDALONE", "-e", "K8S_NODE_IP_FOR_DEEPFLOW=" + args.host_ip,
        "-e", "K8S_POD_IP_FOR_DEEPFLOW=127.0.0.1", "-e", "GOMAXPROCS=2", "-e", "GOMEMLIMIT=3GiB",
        "-v", str(root / "server.yaml") + ":/etc/server.yaml:ro",
        "-p", args.host_ip + ":20035:20035/tcp", "-p", args.host_ip + ":20033:20033/tcp",
        "-p", args.host_ip + ":20033:20033/udp", "-p", "127.0.0.1:20416:20416/tcp",
        "-p", "127.0.0.1:20417:20417/tcp",
    ], server_image, ["-f", "/etc/server.yaml"], args.recreate or args.recreate_server)
    value = wait_for("Controller", health, args.timeout)
    actual_server = inspect("container", PREFIX + "-server")
    report = {
        "health": value, "server_binary_sha256": binary_hash,
        "server_image": actual_server["Config"]["Image"], "server_image_id": actual_server["Image"],
        "requested_server_image": server_image,
        "images": images, "lab_root": str(root), "host_ip": args.host_ip,
        "note": "Health and database readiness do not prove Agent collection or performance parity.",
    }
    private_write(root / "readiness.json", json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))


def stop(args):
    root = args.root.resolve()
    for name in ("server", "clickhouse", "mysql"):
        full_name = PREFIX + "-" + name
        info = inspect("container", full_name)
        if info:
            require_owned(info, root, "container")
            run(["docker", "stop", "--time", "20", full_name], capture=True)
            print("stopped " + full_name)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["start", "stop"])
    parser.add_argument("--root", type=pathlib.Path, default=pathlib.Path("/tmp/traflens-lab-20261026"))
    parser.add_argument("--runtime-package", type=pathlib.Path)
    parser.add_argument("--host-ip", default="192.168.1.240", type=lambda s: str(ipaddress.IPv4Address(s)))
    parser.add_argument("--timeout", type=int, default=180)
    parser.add_argument("--recreate", action="store_true", help="Recreate only containers bearing this lab's exact ownership label; retain data volumes")
    parser.add_argument("--recreate-server", action="store_true", help="Recreate only the owned Server; keep both database containers running")
    args = parser.parse_args()
    if args.action == "start":
        if not args.runtime_package or not args.runtime_package.is_file():
            parser.error("start requires --runtime-package")
        start(args)
    else:
        stop(args)


if __name__ == "__main__":
    main()
