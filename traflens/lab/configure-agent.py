#!/usr/bin/env python3
"""Apply the restricted smoke-test config to this isolated lab's empty default group."""

import argparse
import json
import pathlib
import urllib.error
import urllib.request

import lab


def api(path, body=None, method="GET"):
    data = body.encode() if isinstance(body, str) else json.dumps(body).encode() if body is not None else None
    request = urllib.request.Request(
        "http://127.0.0.1:20417" + path, data=data, method=method,
        headers={"Content-Type": "application/yaml" if isinstance(body, str) else "application/json",
                 "X-Org-Id": "1", "X-User-Id": "1", "X-User-Type": "1"},
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            value = json.load(response)
    except urllib.error.HTTPError as error:
        raise RuntimeError("Controller HTTP error: " + error.read().decode("utf-8", errors="replace")) from None
    if value.get("OPT_STATUS") != "SUCCESS":
        raise RuntimeError("Controller rejected " + path + ": " + str(value.get("DESCRIPTION")))
    return value


def check_keys(values, template, path=""):
    for key, value in values.items():
        current_path = path + "." + key if path else key
        if key not in template:
            raise RuntimeError("Unknown config key: " + current_path)
        if isinstance(value, dict):
            if template.get(key + "_comment", {}).get("type") != "dict":
                check_keys(value, template[key], current_path)
        elif isinstance(value, (int, float)) and not isinstance(value, bool):
            bounds = template.get(key + "_comment", {}).get("range", [])
            if len(bounds) == 2 and all(isinstance(v, (int, float)) for v in bounds):
                if not bounds[0] <= value <= bounds[1]:
                    raise RuntimeError("Out-of-range config: " + current_path)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=pathlib.Path, default=pathlib.Path("/tmp/traflens-lab-20261026"))
    args = parser.parse_args()
    root = args.root.resolve()
    lab.prepare_root(root)
    info = lab.inspect("container", "traflens-lab-server")
    lab.require_owned(info, root, "container")
    groups = api("/v1/vtap-groups/")["DATA"]
    if len(groups) != 1 or groups[0]["NAME"] != "default":
        raise RuntimeError("Expected this fresh isolated lab's single default group")
    group = groups[0]
    if any(group.get(field) for field in ("VTAP_LCUUIDS", "DISABLE_VTAP_LCUUIDS", "PENDING_VTAP_LCUUIDS")):
        raise RuntimeError("Apply before starting Agents; refusing to change a populated group")
    config = json.loads((lab.HERE / "agent-smoke.json").read_text())
    template = api("/v1/agent-group-configuration/template/json")["DATA"]
    check_keys(config, template)
    configurations = api("/v1/agent-group-configuration/json")["DATA"]
    group_id = group["LCUUID"]
    path = "/v1/agent-group-configuration/" + group_id + "/yaml"
    # JSON is valid YAML. The YAML endpoint accepts nested dicts directly, whereas
    # the GUI JSON endpoint represents certain dict-valued leaves as YAML strings.
    result = api(path, json.dumps(config, indent=2), "PUT" if group_id in configurations else "POST")
    actual = api(path)
    if json.loads(actual["DATA"]) != config:
        raise RuntimeError("Controller config round trip differs from requested smoke config")
    evidence = root / "evidence"
    evidence.mkdir(mode=0o700, exist_ok=True)
    lab.private_write(evidence / "agent-group.json", json.dumps(group, indent=2) + "\n")
    lab.private_write(evidence / "agent-config-applied.json", json.dumps(actual, indent=2) + "\n")
    static = (lab.HERE / "agent-static.yaml.in").read_text().replace("{{GROUP_ID}}", group["SHORT_UUID"])
    lab.private_write(root / "agent-static.yaml", static)
    print(json.dumps({"group_lcuuid": group_id, "group_short_uuid": group["SHORT_UUID"],
                      "apply_status": result["OPT_STATUS"], "round_trip_equal": True,
                      "capture_interface": "enp1s0f0", "capture_filter": "tcp port 18080",
                      "agent_started": False}, indent=2))


if __name__ == "__main__":
    main()
