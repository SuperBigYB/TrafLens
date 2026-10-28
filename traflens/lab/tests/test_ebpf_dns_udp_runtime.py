"""Offline typed UDP lifecycle/manifest guards; no live collection."""
import contextlib
import copy
import importlib.util
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

LAB=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(LAB))
def load(name,file):
    spec=importlib.util.spec_from_file_location(name,LAB/file)
    m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m

UDP=load('udp_contract_tested','ebpf-dns-udp.py')
PREPARE=load('udp_preparation_tested','managed-dns-udp.py')
AGENT=load('udp_agent_tested','managed-http-agent.py')

class UDPGuards(unittest.TestCase):
    def receipt(self):
        return {'run':'dns-'+'1'*24,'role':'server','pass':True,'protocol':'real UDP DNS','transport':'udp',
         'completed_requests':3,'expected_requests':3,'wire_events':6,'owned_socket_count':1,
         'udp_datagrams_sent':3,'udp_datagrams_received':3,'datagram_exchanges':3,'bound_udp_sockets':1,
         'connected_udp_sockets':0,'socket_type':'SOCK_DGRAM','framing':'udp-datagram',
         'single_peer_only_qualification':True,'single_peer_per_socket':True,'separate_client_udp_sockets':False,
         'owned_sockets_closed':True,'listener_closed':True,'single_threaded':True,'error':'',
         'transactions':[{'complete':True} for _ in range(3)]}
    def test_default_is_offline_without_resources(self):
        with mock.patch.object(UDP.RUNTIME,'execute',side_effect=AssertionError),contextlib.redirect_stdout(io.StringIO()) as out:
            self.assertEqual(UDP.main([]),0)
        value=json.loads(out.getvalue());self.assertFalse(value['creates_resources']);self.assertEqual(value['protocol'],'DNS/UDP')
    def test_udp_and_tcp_contracts_remain_distinct(self):
        c=UDP.CONTRACT;UDP.RUNTIME.validate_contract(c)
        self.assertEqual((c.stem,c.schema,c.transport,c.label,c.integration_mode),('dns-udp','traflens.ebpf-dns-udp.capture.v1','udp','DNS/UDP','kernel_dns'))
        self.assertEqual((UDP.RUNTIME.DNS_CONTRACT.stem,UDP.RUNTIME.DNS_CONTRACT.transport),('dns','tcp'))
        for bad in [c._replace(udp=False),c._replace(prepare_file='managed-dns.py'),c._replace(diagnostic=True),c._replace(fast=True),c._replace(udp='true')]:
            with self.assertRaises(RuntimeError):UDP.RUNTIME.validate_contract(bad)
    def test_single_peer_receipt_refuses_tcp_and_multiple_peers(self):
        good=self.receipt();UDP.validate_receipt(good,good['run'],'server')
        for key,value in [('protocol','real TCP DNS'),('transport','tcp'),('owned_socket_count',3),('single_peer_per_socket',False),('tcp_eof_events',0),('pacing_ms',100),('transactions',[{'complete':True}])]:
            bad=copy.deepcopy(good);bad[key]=value
            with self.assertRaises(RuntimeError):UDP.validate_receipt(bad,good['run'],'server')
    def test_preparation_requires_explicit_udp_manifest(self):
        with tempfile.TemporaryDirectory() as temp:
            folder=Path(temp)/'udp';manifest=PREPARE.prepare(folder,controller_ip='192.0.2.24',group_id='g-MiXeD123')
            self.assertEqual(manifest['schema'],'traflens.managed-dns-udp-preparation.v1')
            boot,profile=AGENT.verified_preparation(folder)
            self.assertEqual(profile['processors']['request_log']['application_protocol_inference']['enabled_protocols'],['DNS'])
            self.assertEqual(profile['processors']['request_log']['filters']['port_number_prefilters'],{'DNS':'18080'})
            self.assertFalse(profile['inputs']['proc']['enabled']);self.assertFalse(profile['inputs']['integration']['enabled'])
            self.assertTrue(profile['inputs']['ebpf']['profile']['on_cpu']['disabled']);self.assertTrue(profile['inputs']['ebpf']['profile']['unwinding']['dwarf_disabled'])
            manifest['transport']='tcp';(folder/'manifest.json').write_text(json.dumps(manifest))
            with self.assertRaises(ValueError):AGENT.verified_preparation(folder)
    def test_rehashed_broader_profile_is_refused(self):
        with tempfile.TemporaryDirectory() as temp:
            folder=Path(temp)/'udp';manifest=PREPARE.prepare(folder,controller_ip='192.0.2.24',group_id='g-MiXeD123')
            profile=json.loads((folder/'group-profile.json').read_text());profile['inputs']['proc']['enabled']=True
            (folder/'group-profile.json').write_text(json.dumps(profile));manifest['files']['group-profile.json']={'sha256':AGENT.sha(folder/'group-profile.json'),'bytes':(folder/'group-profile.json').stat().st_size};(folder/'manifest.json').write_text(json.dumps(manifest))
            with self.assertRaises(ValueError):AGENT.verified_preparation(folder)
    def test_worker_keeps_exact_namespace_and_resource_limits(self):
        state={'run':'dns-'+'1'*24,'negative_run':'dns-'+'2'*24,'output':'/owned/capture',
          'args':{'image':'sha256:'+'a'*64,'workload_bin':'/owned/udp'},
          'scope':{'positive':{'container_id':'b'*64},'negative':{'container_id':'c'*64}}}
        value=UDP.RUNTIME.worker_spec(state,'positive-client',UDP.CONTRACT)
        self.assertEqual(value['labels']['io.traflens.purpose'],'traflens.ebpf-dns-udp.worker')
        self.assertEqual(value['network_mode'],'container:'+'b'*64);self.assertEqual(value['cap_drop'],['ALL'])
        self.assertEqual(value['pid_mode'],'host');self.assertTrue(value['read_only']);self.assertEqual(value['port_bindings'],{})

    def test_udp_source_extension_preserves_existing_fast_dependencies(self):
        fast=load('udp_review_existing_mysql_fast','ebpf-mysql-fast.py')
        files=set(fast.RUNTIME.capture_source_files(fast.CONTRACT))
        required={'ebpf-mysql-fast.py','ebpf-mysql-diagnostic.py','ebpf-mysql.py','verify-ebpf-mysql-fast.py',
                  'verify-ebpf-mysql.py','native-mysql-observer.py','ebpf-mysql-fast-observed.py'}
        self.assertTrue(required<=files)
        self.assertNotIn('ebpf-dns-udp.c',files)
        self.assertTrue({'ebpf-dns-udp.py','managed-dns-udp.py','verify-ebpf-dns-udp.py','ebpf-dns-udp.c'}<=set(UDP.RUNTIME.capture_source_files(UDP.CONTRACT)))


if __name__=='__main__':unittest.main()
