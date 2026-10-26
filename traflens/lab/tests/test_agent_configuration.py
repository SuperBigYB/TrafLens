import copy
import importlib.util
import json
from pathlib import Path
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
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


class PacketProfileTests(unittest.TestCase):
    def test_existing_profiles_preserve_capture_and_protocol_scope(self):
        baseline = json.loads((LAB / 'agent-smoke.json').read_text())
        self.assertEqual(configure.profile_config('http'), baseline)
        protocols = configure.profile_config('protocols')
        self.assertEqual(protocols['inputs']['cbpf']['af_packet']['extra_bpf_filter'],
                         '(tcp port 18080) or (udp port 18053) or (tcp port 18060)')
        request = protocols['processors']['request_log']
        self.assertEqual(request['application_protocol_inference']['enabled_protocols'], ['HTTP', 'DNS', 'MySQL'])
        self.assertEqual(request['filters']['port_number_prefilters'],
                         {'HTTP': '18080', 'DNS': '18053', 'MySQL': '18060'})
        self.assertNotIn('preprocess', protocols['inputs']['cbpf'])

    def test_tunnels_preserve_resource_and_output_limits(self):
        baseline = configure.profile_config('http')
        tunnels = configure.profile_config('tunnels')
        self.assertEqual(tunnels['global'], baseline['global'])
        self.assertEqual(tunnels['outputs'], baseline['outputs'])
        self.assertEqual(tunnels['global']['limits']['max_millicpus'], 2000)
        self.assertEqual(tunnels['global']['limits']['max_memory'], 1024)
        inputs = tunnels['inputs']
        self.assertEqual(inputs['ebpf'], {'disabled': True})
        self.assertEqual(inputs['proc'], {'enabled': False})
        self.assertEqual(inputs['cbpf']['af_packet']['interface_regex'], '^enp1s0f0$')
        self.assertEqual(inputs['cbpf']['af_packet']['tunning'], baseline['inputs']['cbpf']['af_packet']['tunning'])
        self.assertEqual(inputs['cbpf']['af_packet']['tunning']['ring_blocks'], 8)

    def test_tunnels_enable_decoders_and_only_http_dns(self):
        config = configure.profile_config('tunnels')
        self.assertEqual(config['inputs']['cbpf']['preprocess'], {
            'tunnel_decap_protocols': [1, 2, 3, 4, 5],
            'tunnel_trim_protocols': ['ERSPAN', 'TEB']})
        request = config['processors']['request_log']
        self.assertEqual(request['application_protocol_inference']['enabled_protocols'], ['HTTP', 'DNS'])
        self.assertEqual(request['filters'], {'port_number_prefilters': {'HTTP': '18080', 'DNS': '18053'},
                                              'cbpf_disabled': False, 'tag_filters': {'HTTP': [], 'DNS': []}})
        self.assertEqual(config['outputs']['flow_log']['filters']['l7_ignored_observation_points'], [])
        self.assertEqual(config['outputs']['flow_log']['throttles']['l7_throttle'], 1000)

    def test_only_tunnels_use_mirror_capture_for_bidirectional_inner_flows(self):
        for profile, mode in (('http', 0), ('protocols', 0), ('tunnels', 1)):
            with self.subTest(profile=profile):
                config = configure.profile_config(profile)
                self.assertEqual(config['inputs']['cbpf']['common']['capture_mode'], mode)

    def test_only_tunnels_skip_npb_exclusions_while_bpf_stays_enabled(self):
        for profile in ('http', 'protocols', 'tunnels'):
            with self.subTest(profile=profile):
                af_packet = configure.profile_config(profile)['inputs']['cbpf']['af_packet']
                self.assertEqual(af_packet.get('skip_npb_bpf', False), profile == 'tunnels')
                self.assertFalse(af_packet.get('bpf_filter_disabled', False))
        af_packet = configure.profile_config('tunnels')['inputs']['cbpf']['af_packet']
        self.assertIs(af_packet['skip_npb_bpf'], True)
        self.assertIs(af_packet['bpf_filter_disabled'], False)

    def test_unknown_profile_rejected(self):
        with self.assertRaises(ValueError):
            configure.profile_config('other')

    @unittest.skipUnless(shutil.which('tcpdump'), 'offline BPF check requires tcpdump')
    def test_tunnel_bpf_admits_only_exact_outer_identity_and_protocols(self):
        def frame(src_mac='58:47:ca:7c:78:59', dst_mac='58:47:ca:77:66:e2',
                  src='198.18.0.240', dst='198.18.0.79', protocol=47, port=4790, gre_type=0x88be):
            payload = struct.pack('!HHHH', 40000, port, 8, 0) if protocol == 17 else b'\x00' * 8
            if protocol == 47:
                version, size = (2, 12) if gre_type == 0x22eb else (1, 8)
                feature = struct.pack('!I', version << 28) + b'\x00' * (size - 4)
                payload = struct.pack('!HHI', 0x1000, gre_type, 1) + feature + b'\x00' * 14
            ethernet = bytes.fromhex(dst_mac.replace(':', '') + src_mac.replace(':', '') + '0800')
            ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), 0, 0, 64,
                             protocol, 0, socket.inet_aton(src), socket.inet_aton(dst))
            return ethernet + ip + payload

        allowed = [frame(), frame(gre_type=0x22eb), frame(protocol=17)]
        rejected = []
        for protocol, gre_type in ((47, 0x88be), (47, 0x22eb), (17, 0x88be)):
            rejected.extend([frame(protocol=protocol, gre_type=gre_type, src_mac='58:47:ca:7c:78:58'),
                             frame(protocol=protocol, gre_type=gre_type, dst_mac='58:47:ca:77:66:e3'),
                             frame(protocol=protocol, gre_type=gre_type, src='198.18.0.241'),
                             frame(protocol=protocol, gre_type=gre_type, dst='198.18.0.80'),
                             frame(protocol=protocol, gre_type=gre_type, src_mac='58:47:ca:77:66:e2',
                                   dst_mac='58:47:ca:7c:78:59', src='198.18.0.79', dst='198.18.0.240')])
        rejected.extend([frame(protocol=6), frame(protocol=4), frame(protocol=17, port=4789),
                         frame(protocol=17, port=6081)])
        with tempfile.TemporaryDirectory(prefix='traflens-filter-test-') as temporary:
            source, result = Path(temporary) / 'input.pcap', Path(temporary) / 'accepted.pcap'
            data = bytearray(struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
            for packet in allowed + rejected:
                data.extend(struct.pack('<IIII', 1, 0, len(packet), len(packet)))
                data.extend(packet)
            source.write_bytes(data)
            bpf = configure.profile_config('tunnels')['inputs']['cbpf']['af_packet']['extra_bpf_filter']
            subprocess.run(['tcpdump', '-r', str(source), '-w', str(result), bpf],
                           check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
            output = result.read_bytes()
            self.assertIn(output[:4], (b'\xd4\xc3\xb2\xa1', b'\xa1\xb2\xc3\xd4'))
            endian = '<' if output[:4] == b'\xd4\xc3\xb2\xa1' else '>'
            captured, offset = [], 24
            while offset < len(output):
                _, _, length, _ = struct.unpack_from(endian + 'IIII', output, offset)
                offset += 16
                captured.append(output[offset:offset + length])
                offset += length
            self.assertEqual(captured, allowed)


if __name__ == '__main__':
    unittest.main()
