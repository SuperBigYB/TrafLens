"""Shared guards for the finite, profile-only lab lifecycle (stdlib only)."""
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import urllib.parse

RUN = re.compile(r"cpu-[0-9a-f]{24}\Z")
SHA = re.compile(r"[0-9a-f]{64}\Z")


def require(condition, message="CPU profile ownership or scope check failed"):
    if not condition:
        raise RuntimeError(message)



def validate_controller_url(value):
    """Pure preflight: a credential-free numeric loopback HTTP HostPort only."""
    require(isinstance(value, str) and value == value.strip()
            and not any(ord(c) < 33 for c in value), "Invalid Controller loopback URL")
    try:
        endpoint = urllib.parse.urlsplit(value)
        address = ipaddress.ip_address(endpoint.hostname)
        valid = (endpoint.scheme == 'http' and endpoint.username is None and endpoint.password is None
                 and endpoint.path == '' and not endpoint.query and not endpoint.fragment
                 and endpoint.port is not None and 1 <= endpoint.port <= 65535 and address.is_loopback)
    except (ValueError, TypeError):
        raise RuntimeError("Invalid Controller loopback URL") from None
    require(valid, "Controller URL must be a credential-free numeric loopback HTTP HostPort")
    return endpoint


def validate_controller_binding(value, server):
    """Pure check against the already ownership-verified Server's API binding."""
    endpoint = validate_controller_url(value)
    require(isinstance(server, dict) and server.get('HostConfig', {}).get('NetworkMode') != 'host',
            "Controller binding requires a published owned Server port")
    bindings = server.get('NetworkSettings', {}).get('Ports', {}).get('20417/tcp') or []
    matched = False
    for binding in bindings:
        try:
            address = ipaddress.ip_address(binding.get('HostIp', ''))
            port = int(binding.get('HostPort', ''))
            if address.is_loopback and address == ipaddress.ip_address(endpoint.hostname) and port == endpoint.port:
                matched = True
        except (ValueError, TypeError, AttributeError):
            continue
    require(matched, "Controller URL does not match the owned Server loopback API publication")
    return endpoint


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def private_dir(path, fresh=False):
    path = Path(path).absolute()
    require(path == path.resolve(), "Private directory must have no symlink components")
    if fresh:
        parent = path.parent
        require(parent.is_dir() and parent.stat().st_uid == os.geteuid() and parent.stat().st_mode & 0o077 == 0,
                "Output parent must be owned and private")
        path.mkdir(mode=0o700)
    require(path.is_dir() and path.stat().st_uid == os.geteuid() and path.stat().st_mode & 0o077 == 0,
            "Directory must be owned and private")
    return path


def save(path, value):
    with Path(path).open("x", encoding="utf-8") as stream:
        json.dump(value, stream, indent=2)
        stream.write("\n")
    Path(path).chmod(0o600)
    return value


def load(path):
    path = Path(path)
    return json.loads(path.read_text()) if path.exists() else None


def receipt(profile, receipt_path):
    profile, receipt_path = Path(profile), Path(receipt_path)
    for path in (profile, receipt_path):
        require(path.is_absolute() and path == path.resolve() and path.is_file() and not path.is_symlink(),
                "Sampling inputs must be canonical regular files")
    require(2 <= profile.stat().st_size <= 1 << 20, "Profile must be at most 1 MiB")
    raw = profile.read_bytes()
    value = json.loads(receipt_path.read_text())
    require(value.get("source") == "go_runtime_pprof_self" and value.get("sampling_scope") == "current process only",
            "Original finite self-sampling receipt required")
    require(RUN.fullmatch(value.get("run", "")) and value.get("completed_duration") is True
            and value.get("stop_reason") == "duration", "Sampling receipt is incomplete")
    start, end = value.get("started_unix_ns"), value.get("finished_unix_ns")
    require(type(start) is int and type(end) is int and 0 < start <= end
            and end - start <= 25 * 10**9, "Invalid original sample time")
    require(raw[:2] == b"\x1f\x8b" and hashlib.sha256(raw).hexdigest() == value.get("profile_sha256")
            and len(raw) == value.get("profile_bytes"), "Original profile/receipt SHA or size differs")
    require((end + 10**9 - 1) // 10**9 <= 4294967295, "Sample time exceeds native UInt32 range")
    return {"original_sampling_run": value["run"], "from": start // 10**9,
            "to": (end + 10**9 - 1) // 10**9, "profile_sha256": value["profile_sha256"],
            "profile_bytes": len(raw), "sampling_receipt_sha256": hashlib.sha256(receipt_path.read_bytes()).hexdigest()}


def profile_only(here, controller_ip, controller_port, ingester_port):
    address = ipaddress.ip_address(controller_ip)
    require(address.version == 4 and not address.is_unspecified and not address.is_multicast,
            "Explicit reachable IPv4 Controller address required")
    require(all(type(n) is int and 1 <= n <= 65535 for n in (controller_port, ingester_port)), "Invalid backend port")
    value = json.loads((Path(here) / "agent-smoke.json").read_text())
    value["global"]["limits"]["max_millicpus"] = 1000
    value["global"]["communication"].update(proxy_controller_ip=str(address), proxy_controller_port=controller_port,
                                           ingester_ip=str(address), ingester_port=ingester_port)
    value["global"]["self_monitoring"]["log"].update(log_file="/var/log/traflens/deepflow-agent.log", log_backhaul_enabled=False)
    value["global"]["self_monitoring"]["profile"]["enabled"] = False
    value["global"]["self_monitoring"]["debug"]["enabled"] = False
    value["inputs"]["proc"]["enabled"] = False
    value["inputs"]["ebpf"]["disabled"] = True
    value["inputs"]["ebpf"]["profile"]["on_cpu"]["disabled"] = True
    value["inputs"]["ebpf"]["profile"].setdefault("unwinding", {})["dwarf_disabled"] = True
    value["inputs"]["cbpf"]["af_packet"].update(interface_regex="^traflens-no-physical-interface$", extra_bpf_filter="")
    value["processors"]["request_log"]["filters"]["cbpf_disabled"] = True
    value["outputs"]["flow_metrics"]["enabled"] = False
    integration = value["inputs"]["integration"]
    integration.update(enabled=True, listen_port=39093, compression={"profile": False})
    integration["feature_control"] = {"profile_integration_disabled": False, "trace_integration_disabled": True,
                                      "metric_integration_disabled": True, "log_integration_disabled": True}
    return value
