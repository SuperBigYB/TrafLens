import copy
import importlib.util
import io
import json
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

LAB = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("tunnel_link", LAB / "tunnel-link.py")
link = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(link)


class FakeIP:
    def __init__(self, config):
        self.config = config
        self.link = {"ifindex": 26, "ifname": config["interface"], "address": config["mac"],
                     "flags": ["UP", "LOWER_UP"], "operstate": "UP"}
        self.addresses = []
        self.routes = [{"dst": "default", "dev": "management", "gateway": "192.0.2.1"}]
        self.writes = []
        self.fail_route_add = False
        self.fail_address_add = False

    def __call__(self, *arguments, read=False):
        if read:
            if arguments[:2] == ("-j", "link"):
                return [copy.deepcopy(self.link)]
            if arguments[:4] == ("-j", "-4", "address", "show"):
                return copy.deepcopy(self.addresses)
            if arguments == ("-j", "-4", "route", "show", "table", "all"):
                return copy.deepcopy(self.routes)
            raise AssertionError(arguments)
        self.writes.append(list(arguments))
        if arguments[:3] == ("-4", "address", "add"):
            if self.fail_address_add:
                raise RuntimeError("address add failed")
            self.addresses = [{"ifname": self.config["interface"], "addr_info": [
                {"family": "inet", "local": self.config["local"], "prefixlen": 32,
                 "label": self.config["interface"] + ":tlens"}]}]
        elif arguments[:3] == ("-4", "route", "add"):
            if self.fail_route_add:
                raise RuntimeError("route add failed")
            self.routes.append({"dst": self.config["peer"] + "/32", "dev": self.config["interface"],
                                "prefsrc": self.config["local"], "protocol": "static", "metric": link.METRIC})
        elif arguments[:3] == ("-4", "route", "del"):
            self.routes = [route for route in self.routes if route.get("dst") == "default"]
        elif arguments[:3] == ("-4", "address", "del"):
            self.addresses = []
        else:
            raise AssertionError(arguments)


class TunnelLinkTests(unittest.TestCase):
    def setUp(self):
        self.config = link.plan("dev-79", "case-one", 10)
        self.fake = FakeIP(self.config)

    def test_default_plan_never_reads_or_writes_network_or_creates_directory(self):
        with mock.patch.object(link, "ip") as ip, mock.patch.object(link, "execute") as execute, \
                mock.patch("sys.stdout", new_callable=io.StringIO) as output:
            self.assertEqual(link.main(["--role", "dev-79", "--marker", "case-one"]), 0)
        self.assertEqual(json.loads(output.getvalue())["event"], "plan")
        ip.assert_not_called()
        execute.assert_not_called()

    def test_roles_commands_and_duration_marker_bounds(self):
        for role in link.ROLES:
            config = link.plan(role, "a" * 48, 300)
            address, route = config["add_argv"]
            self.assertEqual(address[4], config["local"] + "/32")
            self.assertIn(config["interface"] + ":tlens", address)
            self.assertEqual(route[4], config["peer"] + "/32")
            self.assertEqual(route[-6:], ["proto", "static", "metric", "42796", "table", "main"])
        for marker in ("", "a" * 49, "../other", "UPPER", "x_y", "x y"):
            with self.subTest(marker=marker), self.assertRaises(ValueError):
                link.plan("dev-79", marker, 10)
        for seconds in (9, 301):
            with self.assertRaises(ValueError):
                link.plan("dev-79", "good", seconds)
        with self.assertRaises(ValueError):
            link.plan("foreign", "good", 10)

    def test_link_identity_and_up_guards_precede_any_write(self):
        for key, value in (("ifname", "foreign"), ("address", "00:00:00:00:00:00"),
                           ("flags", []), ("operstate", "DOWN")):
            fake = FakeIP(self.config)
            fake.link[key] = value
            with self.subTest(key=key), mock.patch.object(link, "ip", side_effect=fake):
                with self.assertRaises(RuntimeError):
                    link.Lease(self.config).add()
            self.assertEqual(fake.writes, [])

    def test_existing_bench_address_on_any_interface_or_as_peer_refused(self):
        for target in (self.config["local"], self.config["peer"]):
            for field in ("local", "peer"):
                fake = FakeIP(self.config)
                fake.addresses = [{"ifname": "foreign", "addr_info": [
                    {"family": "inet", field: target, "prefixlen": 32}]}]
                with self.subTest(target=target, field=field), mock.patch.object(link, "ip", side_effect=fake):
                    with self.assertRaises(RuntimeError):
                        link.Lease(self.config).add()
                self.assertEqual(fake.writes, [])

    def test_covering_prefix_in_any_table_refused_default_ignored(self):
        for prefix in ("198.18.0.0/24", "198.18.0.79", "198.18.0.240/32", "128.0.0.0/1"):
            fake = FakeIP(self.config)
            fake.routes.append({"dst": prefix, "table": 200, "type": "unreachable"})
            with self.subTest(prefix=prefix), mock.patch.object(link, "ip", side_effect=fake):
                with self.assertRaises(RuntimeError):
                    link.Lease(self.config).add()
            self.assertEqual(fake.writes, [])
        with mock.patch.object(link, "ip", side_effect=self.fake):
            checked = link.preflight(self.config)
        self.assertEqual(checked["bench_addresses"], [])
        self.assertEqual(checked["covering_nondefault_routes"], [])
        self.assertNotIn("management", json.dumps(checked))

    def test_partial_route_failure_rolls_back_only_successful_address(self):
        self.fake.fail_route_add = True
        lease = link.Lease(self.config)
        with mock.patch.object(link, "ip", side_effect=self.fake):
            with self.assertRaises(RuntimeError):
                lease.add()
            self.assertEqual(lease.cleanup(), [])
        self.assertEqual([argv[1:3] for argv in self.fake.writes],
                         [["address", "add"], ["route", "add"], ["address", "del"]])
        self.assertEqual(self.fake.addresses, [])

    def test_failed_address_add_never_claims_or_deletes_an_existing_item(self):
        self.fake.fail_address_add = True
        lease = link.Lease(self.config)
        with mock.patch.object(link, "ip", side_effect=self.fake):
            with self.assertRaises(RuntimeError):
                lease.add()
            self.assertEqual(lease.cleanup(), [])
        self.assertEqual(len(self.fake.writes), 1)

    def test_timed_out_add_is_uncertain_and_never_claims_cleanup_success(self):
        def timeout_route(*arguments, read=False):
            if arguments[:3] == ("-4", "route", "add"):
                raise subprocess.TimeoutExpired(["ip", *arguments], 5)
            return self.fake(*arguments, read=read)

        lease = link.Lease(self.config)
        with mock.patch.object(link, "ip", side_effect=timeout_route):
            with self.assertRaises(subprocess.TimeoutExpired):
                lease.add()
            self.assertTrue(lease.cleanup())
        self.assertTrue(lease.address_added)
        self.assertEqual(lease.uncertain_add, "route")
        self.assertEqual(len(self.fake.writes), 1)

    def test_signal_killed_ip_child_is_an_unknown_command_result(self):
        result = subprocess.CompletedProcess(["ip"], -signal.SIGTERM, stdout="", stderr="")
        with mock.patch.object(link.subprocess, "run", return_value=result):
            with self.assertRaises(link.UnknownIPResult):
                link.ip("-4", "address", "add", "198.18.0.79/32", "dev", "enp1s0f0")

    def test_applied_then_killed_add_is_unknown_and_never_destructively_cleaned(self):
        for kind in ("address", "route"):
            fake = FakeIP(self.config)

            def apply_then_die(*arguments, read=False):
                result = fake(*arguments, read=read)
                if arguments[:3] == ("-4", kind, "add"):
                    raise link.UnknownIPResult("ip child killed after kernel applied request")
                return result

            lease = link.Lease(self.config)
            with self.subTest(kind=kind), mock.patch.object(link, "ip", side_effect=apply_then_die):
                with self.assertRaises(link.UnknownIPResult):
                    lease.add()
                self.assertTrue(lease.cleanup())
            self.assertEqual(lease.uncertain_add, kind)
            self.assertEqual(len(fake.writes), 1 if kind == "address" else 2)
            self.assertTrue(fake.addresses)

    def test_expired_preflight_does_not_add_network_items(self):
        with tempfile.TemporaryDirectory(prefix="traflens-link-test-") as temporary:
            config = dict(self.config, lease_dir=str(Path(temporary) / "lease"))
            with mock.patch.object(link, "ip", side_effect=self.fake), \
                    mock.patch.object(link.os, "geteuid", return_value=0), \
                    mock.patch.object(link.signal, "signal"), \
                    mock.patch.object(link.time, "monotonic", side_effect=[100, 110, 110]), \
                    mock.patch("sys.stdout", new_callable=io.StringIO):
                self.assertEqual(link.execute(config, []), 1)
            self.assertEqual(self.fake.writes, [])
            state = json.loads((Path(config["lease_dir"]) / "lease.json").read_text())
            self.assertTrue(state["cleanup_ok"])
            self.assertIn("expired", state["error"])

    def test_exact_cleanup_route_first_and_repeated_cleanup_has_no_writes(self):
        lease = link.Lease(self.config)
        with mock.patch.object(link, "ip", side_effect=self.fake):
            lease.add()
            self.assertEqual(lease.cleanup(), [])
            count = len(self.fake.writes)
            self.assertEqual(lease.cleanup(), [])
        self.assertEqual(len(self.fake.writes), count)
        self.assertEqual([argv[1:3] for argv in self.fake.writes][-2:], [["route", "del"], ["address", "del"]])
        self.assertEqual(self.fake.routes, [{"dst": "default", "dev": "management", "gateway": "192.0.2.1"}])

    def test_changed_route_is_not_deleted_and_dependent_address_retained(self):
        for key, value in (("dst", "198.18.0.0/24"), ("dev", "foreign"), ("prefsrc", "192.0.2.1"),
                           ("metric", 1), ("protocol", "boot"), ("table", 200)):
            fake = FakeIP(self.config)
            lease = link.Lease(self.config)
            with self.subTest(key=key), mock.patch.object(link, "ip", side_effect=fake):
                lease.add()
                fake.routes[-1][key] = value
                self.assertTrue(lease.cleanup())
            self.assertEqual(len(fake.writes), 2)
            self.assertTrue(lease.address_added)

    def test_changed_address_is_never_deleted(self):
        for key, value in (("local", "198.18.0.79"), ("prefixlen", 24), ("label", "foreign"),
                           ("peer", "198.18.0.79")):
            fake = FakeIP(self.config)
            lease = link.Lease(self.config)
            with self.subTest(key=key), mock.patch.object(link, "ip", side_effect=fake):
                lease.add()
                if key == "local":
                    fake.addresses[0]["ifname"] = "foreign"
                else:
                    fake.addresses[0]["addr_info"][0][key] = value
                self.assertTrue(lease.cleanup())
            self.assertEqual(len(fake.writes), 3)  # Owned route removed; foreign address remains.
            self.assertEqual(fake.writes[-1][1:3], ["route", "del"])

    def test_replaced_interface_refuses_all_cleanup_but_down_original_can_cleanup(self):
        for key, value in (("ifindex", 999), ("address", "00:00:00:00:00:00")):
            fake = FakeIP(self.config)
            lease = link.Lease(self.config)
            with self.subTest(key=key), mock.patch.object(link, "ip", side_effect=fake):
                lease.add()
                fake.link[key] = value
                self.assertTrue(lease.cleanup())
            self.assertEqual(len(fake.writes), 2)
        with mock.patch.object(link, "ip", side_effect=self.fake):
            lease = link.Lease(self.config)
            lease.add()
            self.fake.link.update(flags=[], operstate="DOWN")
            self.assertEqual(lease.cleanup(), [])

    def test_existing_owner_directory_refused_before_network(self):
        with tempfile.TemporaryDirectory(prefix="traflens-link-test-") as temporary:
            config = dict(self.config, lease_dir=temporary)
            with mock.patch.object(link.os, "geteuid", return_value=0), mock.patch.object(link, "ip") as ip:
                with self.assertRaises(FileExistsError):
                    link.execute(config, [])
            ip.assert_not_called()

    def test_signal_uses_finally_cleanup_and_private_filtered_state(self):
        handlers = {}
        def install(number, handler):
            handlers[number] = handler
            return signal.SIG_DFL

        def wait(unused):
            handlers[signal.SIGTERM](signal.SIGTERM, None)

        with tempfile.TemporaryDirectory(prefix="traflens-link-test-") as temporary:
            directory = Path(temporary) / "lease"
            config = dict(self.config, lease_dir=str(directory))
            event = link.threading.Event()
            with mock.patch.object(link, "ip", side_effect=self.fake), \
                    mock.patch.object(link.os, "geteuid", return_value=0), \
                    mock.patch.object(link.signal, "signal", side_effect=install), \
                    mock.patch.object(link.threading, "Event", return_value=event), \
                    mock.patch.object(event, "wait", side_effect=wait), \
                    mock.patch("sys.stdout", new_callable=io.StringIO) as output:
                self.assertEqual(link.execute(config, ["--execute"]), 0)
            state = json.loads((directory / "lease.json").read_text())
            self.assertTrue(state["cleanup_ok"])
            self.assertFalse(state["address_added"])
            self.assertFalse(state["route_added"])
            self.assertEqual([json.loads(line)["event"] for line in output.getvalue().splitlines()], ["ready", "finished"])
            self.assertNotIn("management", (directory / "preflight.json").read_text())
            self.assertEqual(directory.stat().st_mode & 0o777, 0o700)
            self.assertEqual((directory / "lease.json").stat().st_mode & 0o777, 0o600)


if __name__ == "__main__":
    unittest.main()
