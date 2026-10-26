import copy
import importlib.util
import json
from pathlib import Path
import sys
import time
import unittest
from unittest import mock

LAB = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(LAB))
SPEC = importlib.util.spec_from_file_location("fault_test", LAB / "fault-test.py")
fault = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(fault)


class FaultScopeTests(unittest.TestCase):
    def setUp(self):
        self.baseline = {"owned": {
            name: {"id": name + "-id", "image_id": name + "-image", "started_at": "old", "running": True,
                   "volume_mounts": dict(fault.VOLUMES) if name == fault.CH else {}}
            for name in fault.OWNED}, "unrelated": {
                "/unrelated": {"id": "untouched", "started_at": "last-week", "running": True}}}

    def test_unchanged_scope_and_only_recorded_ch_start_are_allowed(self):
        fault.check_snapshot(self.baseline, copy.deepcopy(self.baseline))
        current = copy.deepcopy(self.baseline)
        current["owned"][fault.CH]["started_at"] = "new"
        fault.check_snapshot(self.baseline, current, True)
        with self.assertRaises(RuntimeError):
            fault.check_snapshot(self.baseline, current, False)

    def test_changed_container_image_or_volume_rejected(self):
        for name in fault.OWNED:
            for key in ("id", "image_id", "volume_mounts"):
                current = copy.deepcopy(self.baseline)
                current["owned"][name][key] = "different"
                with self.subTest(name=name, key=key), self.assertRaises(RuntimeError):
                    fault.check_snapshot(self.baseline, current, True)

    def test_non_ch_restart_or_unrelated_change_rejected(self):
        for name in ("traflens-lab-server", "traflens-lab-mysql"):
            current = copy.deepcopy(self.baseline)
            current["owned"][name]["started_at"] = "now"
            with self.subTest(name=name), self.assertRaises(RuntimeError):
                fault.check_snapshot(self.baseline, current, True)
        for key, value in (("id", "replacement"), ("started_at", "now"), ("running", False)):
            current = copy.deepcopy(self.baseline)
            current["unrelated"]["/unrelated"][key] = value
            with self.subTest(key=key), self.assertRaises(RuntimeError):
                fault.check_snapshot(self.baseline, current, True)

    def test_unrecorded_extra_ch_start_rejected(self):
        state = {"baseline": self.baseline, "helper_sha256": {}, "expected_ch_started_at": "recorded"}
        current = copy.deepcopy(self.baseline)
        current["owned"][fault.CH]["started_at"] = "another-restart"
        with mock.patch.object(fault, "helpers", return_value={}), \
                mock.patch.object(fault, "snapshot", return_value=current):
            with self.assertRaisesRegex(RuntimeError, "unrecorded"):
                fault.ensure_scope(state, Path("/tmp/owned"), True)
            fault.ensure_scope(state, Path("/tmp/owned"), True, allow_new_start=True)

    def test_restart_is_single_use_and_needs_before_arm_and_deadline(self):
        states = [
            {"restart_consumed": True},
            {"restart_consumed": False, "phases": {}},
            {"restart_consumed": False, "phases": {"before": {"passed": True}}},
            {"restart_consumed": False, "phases": {"before": {"passed": True}},
             "during_armed_at_utc": "now", "deadline_epoch": time.time() + 10},
        ]
        for state in states:
            with self.subTest(state=state), mock.patch.object(fault, "command") as command:
                with self.assertRaises(RuntimeError):
                    fault.restart(state, Path("/tmp/run"), Path("/tmp/owned"))
                command.assert_not_called()

    def test_expired_run_is_bounded(self):
        with self.assertRaisesRegex(RuntimeError, "deadline"):
            fault.remaining({"deadline_epoch": time.time() - 1})

    def test_failed_during_can_verify_after_recovery_but_not_pass_final(self):
        state = {"restart_consumed": True, "restart": {"success": True},
                 "recovery": {"healthy": True}, "deadline_epoch": time.time() + 120,
                 "phases": {"before": {"passed": True},
                            "during": {"passed": False, "acceptance_sha256": "failed-evidence"},
                            "after": {"passed": True}}}
        fault.require_phase_progress(state, "after")
        with mock.patch.object(fault, "ensure_scope", return_value=self.baseline), \
                mock.patch.object(fault, "save") as save:
            with self.assertRaisesRegex(RuntimeError, "did not pass"):
                fault.finalize(state, Path("/tmp/run"), Path("/tmp/owned"))
            self.assertIs(save.call_args.args[1]["passed"], False)

    def test_after_needs_completed_during_and_recovery(self):
        base = {"restart_consumed": True, "phases": {"before": {"passed": True}}, "recovery": {"healthy": True}}
        for during in ({}, {"passed": False}, {"passed": "false", "acceptance_sha256": "hash"}):
            state = copy.deepcopy(base)
            state["phases"]["during"] = during
            with self.subTest(during=during), self.assertRaises(RuntimeError):
                fault.require_phase_progress(state, "after")
        state = copy.deepcopy(base)
        state["phases"]["during"] = {"passed": False, "acceptance_sha256": "hash"}
        state["recovery"]["healthy"] = False
        with self.assertRaises(RuntimeError):
            fault.require_phase_progress(state, "after")

    def test_foreign_owned_label_fails_before_any_docker_mutation(self):
        info = {"Config": {"Labels": {fault.lab.LABEL: "/another/lab"}}}
        with mock.patch.object(fault, "inspect", return_value=info), mock.patch.object(fault, "command") as command:
            with self.assertRaises(RuntimeError):
                fault.snapshot(Path("/tmp/owned"))
            command.assert_not_called()

    def test_failed_restart_is_consumed_before_command_and_never_retried(self):
        state = {"restart_consumed": False, "phases": {"before": {"passed": True}},
                 "during_armed_at_utc": "now", "deadline_epoch": time.time() + 300}

        def fail_command(args, **unused):
            self.assertIs(state["restart_consumed"], True)
            self.assertEqual(args, ["docker", "restart", "--time", "10", fault.CH])
            raise RuntimeError("simulated disconnect")

        with mock.patch.object(fault, "ensure_scope", return_value=self.baseline), \
                mock.patch.object(fault, "save"), mock.patch.object(fault, "restore") as restore, \
                mock.patch.object(fault, "command", side_effect=fail_command) as command:
            with self.assertRaisesRegex(RuntimeError, "simulated"):
                fault.restart(state, Path("/tmp/run"), Path("/tmp/owned"))
            with self.assertRaisesRegex(RuntimeError, "consumed"):
                fault.restart(state, Path("/tmp/run"), Path("/tmp/owned"))
            self.assertEqual(command.call_count, 1)
            restore.assert_called_once()

    def test_recovery_starts_only_the_same_stopped_ch(self):
        before = copy.deepcopy(self.baseline)
        before["owned"][fault.CH]["running"] = False
        after = copy.deepcopy(self.baseline)
        after["owned"][fault.CH]["started_at"] = "recovered"
        state = {"deadline_epoch": time.time() + 120}
        with mock.patch.object(fault, "ensure_scope", side_effect=[before, after]), \
                mock.patch.object(fault, "command") as command, \
                mock.patch.object(fault, "healthy", return_value=True), mock.patch.object(fault, "save"):
            fault.restore(state, Path("/tmp/run"), Path("/tmp/owned"))
            self.assertEqual(command.call_count, 1)
            self.assertEqual(command.call_args.args[0], ["docker", "start", fault.CH])
            self.assertEqual(state["expected_ch_started_at"], "recovered")

    def test_timeout_may_adopt_only_the_consumed_restart_before_recovery(self):
        state = {"restart_consumed": False, "phases": {"before": {"passed": True}},
                 "during_armed_at_utc": "now", "deadline_epoch": time.time() + 300}
        after = copy.deepcopy(self.baseline)
        after["owned"][fault.CH]["started_at"] = "daemon-completed-the-restart"

        def recover(observed_state, *_unused):
            self.assertIs(observed_state["restart_consumed"], True)
            self.assertIs(observed_state["restart"]["success"], False)
            self.assertEqual(observed_state["expected_ch_started_at"], "daemon-completed-the-restart")

        with mock.patch.object(fault, "ensure_scope", side_effect=[self.baseline, after]) as scope, \
                mock.patch.object(fault, "save"), mock.patch.object(fault, "restore", side_effect=recover), \
                mock.patch.object(fault, "command", side_effect=fault.subprocess.TimeoutExpired("docker", 60)):
            with self.assertRaises(fault.subprocess.TimeoutExpired):
                fault.restart(state, Path("/tmp/run"), Path("/tmp/owned"))
            self.assertEqual(scope.call_args.kwargs, {"allow_new_start": True})

    def test_subprocess_timeout_cannot_outlive_total_deadline(self):
        with mock.patch.object(fault, "DEADLINE_EPOCH", time.time() + 0.5), \
                mock.patch.object(fault.subprocess, "run", return_value=mock.Mock(stdout="ok")) as run:
            self.assertEqual(fault.command(["docker", "ps"], timeout=600), "ok")
            self.assertLessEqual(run.call_args.kwargs["timeout"], 0.5)

    def test_prepare_plan_uses_only_three_ports_and_nine_unique_markers(self):
        plan = fault.build_plan("f20261026x", Path("/tmp/owned/run"))
        markers, ports = [], set()
        for phase in fault.PHASES:
            for protocol in fault.PROTOCOLS:
                item = plan["phases"][phase][protocol]
                markers.append(item["marker"])
                self.assertRegex(item["marker"], r"^[a-z0-9]+$")
                for side in ("server", "client"):
                    command = item[side + "_command"]
                    self.assertEqual(command[:4], ["timeout", "--signal=TERM", "--kill-after=5s", "75s"])
                    ports.add(int(command[command.index("--port") + 1]))
                    self.assertEqual(command[command.index("--count") + 1], "20")
                    self.assertEqual(command[command.index("--address") + 1], fault.HOST)
                    self.assertNotIn("ssh", command)
                    interval = command[command.index("--interval-ms") + 1]
                    self.assertEqual(interval, "1000" if phase == "during" else "100")
        self.assertEqual(len(set(markers)), 9)
        self.assertEqual(ports, {18053, 18060, 18080})


class FaultExpectedTests(unittest.TestCase):
    def test_http_duplicate_or_failed_response_cannot_be_expected(self):
        value = "f20261026bhttp"
        document = {"marker": value, "records": [
            {"path": "/traflens-e2e/%s/%d" % (value, i), "status": 200} for i in range(20)]}
        self.assertEqual(len(fault.expected_records("http", value, document, copy.deepcopy(document))), 20)
        for change in ("duplicate", "status"):
            server = copy.deepcopy(document)
            if change == "duplicate":
                server["records"][1] = server["records"][0]
            else:
                server["records"][0]["status"] = 500
            with self.subTest(change=change), self.assertRaises(ValueError):
                fault.expected_records("http", value, document, server)

    def test_dns_expected_includes_exact_a_answer_and_rejects_mismatch(self):
        value = "f20261026ddns"
        dns = fault.load_helper("test_fault_dns", "dns-traffic.py")
        document = {"marker": value, "complete": True, "errors": [], "records": []}
        for record in dns.workload(value, 20):
            query = dns.build_query(record["id"], record["name"])
            response = dns.build_response(query, record["address"])
            document["records"].append(dict(record, rcode=0, ttl=60, verified=True,
                                             query_hex=query.hex(), response_hex=response.hex()))
        expected = fault.expected_records("dns", value, document, copy.deepcopy(document))
        self.assertEqual(expected[0]["response_result"], "A=198.18.0.1 TTL=60")
        server = copy.deepcopy(document)
        server["records"][0]["address"] = "198.18.0.99"
        with self.assertRaises(ValueError):
            fault.expected_records("dns", value, document, server)

    def test_mysql_expected_keeps_null_success_code_and_fixed_selects(self):
        value = "f20261026amysql"
        mysql = fault.load_helper("test_fault_mysql", "mysql-traffic.py")
        document = {"marker": value, "success": True, "quit_verified": True,
                    "database_execution": False, "records": [
                        dict(mysql.query_record(value, i), verified=True) for i in range(20)]}
        expected = fault.expected_records("mysql", value, document, copy.deepcopy(document))
        self.assertIsNone(expected[0]["response_code"])
        self.assertEqual(expected[0]["request_type"], "COM_QUERY")
        server = copy.deepcopy(document)
        server["database_execution"] = True
        with self.assertRaises(ValueError):
            fault.expected_records("mysql", value, document, server)

    def test_restart_overlap_uses_same_host_server_timestamps(self):
        restart = {"begin_at_utc": "2026-10-26T12:00:02+00:00", "returned_at_utc": "2026-10-26T12:00:04+00:00"}
        times = ["2026-10-26T12:00:01+00:00", "2026-10-26T12:00:03+00:00", "2026-10-26T12:00:05+00:00"]
        for protocol, key in (("http", "time"), ("dns", "received_at_utc"), ("mysql", "time")):
            document = {"records": [{key: value} for value in times]}
            self.assertEqual(fault.overlap(document, protocol, restart),
                             {"before_restart": 1, "during_restart_call": 1, "after_restart_return": 1})

    def test_after_phase_cannot_reuse_pre_restart_records(self):
        restart = {"returned_at_utc": "2026-10-26T12:00:04+00:00"}
        for protocol, key in (("http", "time"), ("dns", "received_at_utc"), ("mysql", "time")):
            fault.require_after({"records": [{key: "2026-10-26T12:00:05+00:00"}]}, protocol, restart)
            with self.subTest(protocol=protocol), self.assertRaises(ValueError):
                fault.require_after({"records": [{key: "2026-10-26T12:00:03+00:00"}]}, protocol, restart)
        with self.assertRaises(ValueError):
            fault.timestamp("2026-10-26T12:00:05")


if __name__ == "__main__":
    unittest.main()
