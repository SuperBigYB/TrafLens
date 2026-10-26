import copy
import importlib.util
from pathlib import Path
import sys
import unittest

LAB = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(LAB))
spec = importlib.util.spec_from_file_location('configure_agent', LAB / 'configure-agent.py')
configure = importlib.util.module_from_spec(spec)
spec.loader.exec_module(configure)


class GroupScopeTests(unittest.TestCase):
    def setUp(self):
        self.group = {'LCUUID': 'owned-group', 'VTAP_LCUUIDS': ['owned-agent']}
        self.agent = {'LCUUID': 'owned-agent', 'NAME': 'traflens-dev79-smoke', 'TYPE': 5,
                      'CTRL_IP': '192.168.1.79', 'CTRL_MAC': '58:47:ca:77:66:e5',
                      'VTAP_GROUP_LCUUID': 'owned-group'}

    def test_initial_empty_group(self):
        configure.require_group_scope({'LCUUID': 'owned-group'}, [], False)

    def test_populated_group_needs_explicit_update(self):
        with self.assertRaises(RuntimeError):
            configure.require_group_scope(self.group, [self.agent], False)

    def test_exact_owned_agent_can_update(self):
        configure.require_group_scope(self.group, [self.agent], True)

    def test_foreign_disabled_or_pending_member_rejected(self):
        for key in ('VTAP_LCUUIDS', 'DISABLE_VTAP_LCUUIDS', 'PENDING_VTAP_LCUUIDS'):
            group = copy.deepcopy(self.group)
            group[key] = ['foreign-agent']
            with self.subTest(key=key), self.assertRaises(RuntimeError):
                configure.require_group_scope(group, [self.agent], True)

    def test_changed_identity_or_inventory_rejected(self):
        for key in ('NAME', 'TYPE', 'CTRL_IP', 'CTRL_MAC', 'VTAP_GROUP_LCUUID', 'LCUUID'):
            agent = dict(self.agent, **{key: 'foreign'})
            with self.subTest(key=key), self.assertRaises(RuntimeError):
                configure.require_group_scope(self.group, [agent], True)
        for agents in ([], [self.agent, self.agent]):
            with self.assertRaises(RuntimeError):
                configure.require_group_scope(self.group, agents, True)


if __name__ == '__main__':
    unittest.main()
