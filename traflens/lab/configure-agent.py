#!/usr/bin/env python3
"""Apply a restricted packet smoke profile to the isolated lab's owned Agent group."""

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


def require_group_scope(group, agents, update_owned):
    members = [value for key in ("VTAP_LCUUIDS", "DISABLE_VTAP_LCUUIDS", "PENDING_VTAP_LCUUIDS")
               for value in group.get(key, []) or []]
    if not update_owned:
        if members:
            raise RuntimeError("Apply before starting Agents; use --update-owned-agent only after stopping the lab Agent")
        return
    expected = {"NAME": "traflens-dev79-smoke", "TYPE": 5,
                "CTRL_IP": "192.168.1.79", "CTRL_MAC": "58:47:ca:77:66:e5",
                "VTAP_GROUP_LCUUID": group["LCUUID"]}
    if len(agents) != 1 or any(agents[0].get(key) != value for key, value in expected.items()):
        raise RuntimeError("Refusing to reconfigure an unexpected Agent inventory")
    identity = agents[0].get("LCUUID")
    if not identity or not members or any(value != identity for value in members):
        raise RuntimeError("The populated group contains an unexpected Agent identity")


def profile_config(profile):
    config = json.loads((lab.HERE / "agent-smoke.json").read_text())
    if profile == "protocols":
        config["inputs"]["cbpf"]["af_packet"]["extra_bpf_filter"] = (
            "(tcp port 18080) or (udp port 18053) or (tcp port 18060)")
        request_log = config["processors"]["request_log"]
        request_log["application_protocol_inference"]["enabled_protocols"] = ["HTTP", "DNS", "MySQL"]
        request_log["filters"]["port_number_prefilters"] = {
            "HTTP": "18080", "DNS": "18053", "MySQL": "18060"}
    elif profile != "http":
        raise ValueError("Unknown packet smoke profile")
    return config


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=pathlib.Path, default=pathlib.Path("/tmp/traflens-lab-20261026"))
    parser.add_argument("--profile", choices=("http", "protocols"), default="http")
    parser.add_argument("--update-owned-agent", action="store_true",
                        help="After stopping the lab Agent, allow its exact registered dev-79 identity")
    args = parser.parse_args()
    root = args.root.resolve()
    lab.prepare_root(root)
    info = lab.inspect("container", "traflens-lab-server")
    lab.require_owned(info, root, "container")
    groups = api("/v1/vtap-groups/")["DATA"]
    if len(groups) != 1 or groups[0]["NAME"] != "default":
        raise RuntimeError("Expected this fresh isolated lab's single default group")
    group = groups[0]
    agents = (api("/v1/vtaps/")["DATA"] or []) if args.update_owned_agent else []
    require_group_scope(group, agents, args.update_owned_agent)
    config = profile_config(args.profile)
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
    suffix = "-" + args.profile if args.update_owned_agent else ""
    lab.private_write(evidence / ("agent-group" + suffix + ".json"), json.dumps(group, indent=2) + "\n")
    lab.private_write(evidence / ("agent-config-applied" + suffix + ".json"), json.dumps(actual, indent=2) + "\n")
    static = (lab.HERE / "agent-static.yaml.in").read_text().replace("{{GROUP_ID}}", group["SHORT_UUID"])
    lab.private_write(root / "agent-static.yaml", static)
    print(json.dumps({"group_lcuuid": group_id, "group_short_uuid": group["SHORT_UUID"],
                      "apply_status": result["OPT_STATUS"], "round_trip_equal": True,
                      "capture_interface": "enp1s0f0", "profile": args.profile,
                      "capture_filter": config["inputs"]["cbpf"]["af_packet"]["extra_bpf_filter"],
                      "agent_started": False}, indent=2))


if __name__ == "__main__":
    main()
