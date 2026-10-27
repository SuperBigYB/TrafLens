import importlib.util
import io
import json
from pathlib import Path
import unittest
import tempfile
from unittest import mock

SPEC=importlib.util.spec_from_file_location('agent_resources',Path(__file__).resolve().parents[1]/'sample-agent-resources.py')
m=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(m)


class AgentResourceTests(unittest.TestCase):
    def test_single_work_process(self):
        self.assertEqual(m.work_process({101:{'ppid':100,'start_ticks':1}},101),101)

    def test_readiness_owner_defines_work_process_regardless_of_parent_or_child(self):
        rows={101:{'ppid':100,'start_ticks':1},102:{'ppid':101,'start_ticks':2}}
        self.assertEqual(m.work_process(rows,101),101)
        self.assertEqual(m.work_process(rows,102),102)
        with self.assertRaises(ValueError):m.work_process(rows,999)

    def test_rejects_parallel_agents_cycles_empty_and_extra_processes(self):
        for rows in ({},{101:{'ppid':100},102:{'ppid':100}},
                     {101:{'ppid':102},102:{'ppid':101}},
                     {101:{'ppid':100},102:{'ppid':101},103:{'ppid':102}}):
            with self.subTest(rows=rows),self.assertRaises(ValueError):m.work_process(rows,101)

    def test_readiness_socket_refuses_foreign_ambiguous_or_absent_owner(self):
        row='LISTEN 0 128 0.0.0.0:39091 0.0.0.0:* users:(("deepflow-agent",pid=101,fd=14))'
        self.assertEqual(m.listener_owner(row,{101,102},39091),101)
        for text in ('',row.replace('pid=101','pid=999'),row+'\n'+row.replace('pid=101','pid=102'),
                     'LISTEN 0 128 0.0.0.0:39091 0.0.0.0:*'):
            with self.assertRaises(ValueError):m.listener_owner(text,{101,102},39091)

    def test_memory_peak_missing_is_explicitly_unavailable_not_zero(self):
        with tempfile.TemporaryDirectory() as directory:
            p=Path(directory)/'memory.peak';self.assertIsNone(m.memory_peak(p))
            p.write_text('12345\n');self.assertEqual(m.memory_peak(p),12345)
            for value in ('-1','bad'):
                p.write_text(value)
                with self.assertRaises(ValueError):m.memory_peak(p)

    def test_rejects_pid_reuse_and_parent_change(self):
        before={101:{'ppid':100,'start_ticks':1},102:{'ppid':101,'start_ticks':2}}
        m.require_stable(before,dict(before))
        for after in ({101:{'ppid':100,'start_ticks':9},102:before[102]},
                      {101:before[101],102:{'ppid':99,'start_ticks':2}},
                      {101:before[101]}):
            with self.assertRaises(ValueError):m.require_stable(before,after)

    def test_default_plan_does_not_inspect_or_start_sampling(self):
        with mock.patch('sys.argv',['sample-agent-resources']),mock.patch.object(m,'Sample') as sample, \
             mock.patch.object(m.subprocess,'check_output') as command,mock.patch('sys.stdout',new_callable=io.StringIO) as output:
            m.main()
        self.assertFalse(json.loads(output.getvalue())['executes']);sample.assert_not_called();command.assert_not_called()


if __name__=='__main__':unittest.main()
