#!/usr/bin/env python3
"""Explicitly register the real dev-79 bare-metal Agent in the empty lab inventory."""

import argparse
import json
import pathlib

import lab


def main():
    # Reuse the same audited controller transport and ownership guard.
    import importlib.util
    spec = importlib.util.spec_from_file_location("configure_agent", lab.HERE / "configure-agent.py")
    configure = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(configure)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=pathlib.Path, default=pathlib.Path("/tmp/traflens-lab-20261026"))
    args = parser.parse_args()
    root = args.root.resolve()
    lab.prepare_root(root)
    lab.require_owned(lab.inspect("container", "traflens-lab-server"), root, "container")
    groups = configure.api("/v1/vtap-groups/")["DATA"]
    if len(groups) != 1 or groups[0]["NAME"] != "default":
        raise RuntimeError("Unexpected lab group inventory")
    controllers = configure.api("/v1/controllers/")["DATA"]
    if len(controllers) != 1 or controllers[0]["IP"] != "192.168.1.240":
        raise RuntimeError("Unexpected lab controller inventory")
    controller = controllers[0]
    if len(controller["AZS"]) != 1:
        raise RuntimeError("Expected one seeded lab availability zone")
    desired = {
        "NAME": "traflens-dev79-smoke", "TYPE": 5,
        "CTRL_IP": "192.168.1.79", "CTRL_MAC": "58:47:ca:77:66:e5",
        "AZ": controller["AZS"][0]["AZ"], "REGION": controller["REGION"],
        "VTAP_GROUP_LCUUID": groups[0]["LCUUID"], "TEAM_ID": 1,
    }
    agents = configure.api("/v1/vtaps/")["DATA"] or []
    if agents:
        if len(agents) != 1 or any(agents[0].get(key) != value for key, value in desired.items()):
            raise RuntimeError("Refusing to modify an unexpected existing Agent")
        agent = agents[0]
    else:
        agent = configure.api("/v1/vtaps/", desired, "POST")["DATA"]
    # Explicitly select the public CE packet metrics/request-log features. The
    # manual-create path otherwise leaves the backing feature list empty.
    configure.api("/v1/vtaps-license-type/" + agent["LCUUID"] + "/",
                  {"LICENSE_FUNCTIONS": [2, 4]}, "PATCH")
    # The official create/feature paths do not refresh the cache; an owned enable update does.
    response = configure.api("/v1/vtaps/" + agent["LCUUID"] + "/", {"ENABLE": 1}, "PATCH")
    lab.private_write(root / "evidence/agent-registration.json", json.dumps(response, indent=2) + "\n")
    print(json.dumps({"agent_id": response["DATA"]["ID"], "name": desired["NAME"],
                      "ctrl_ip": desired["CTRL_IP"], "type": "CHOST_BM (5)",
                      "enable": response["DATA"]["ENABLE"], "status": response["OPT_STATUS"]}, indent=2))


if __name__ == "__main__":
    main()
