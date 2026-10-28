import contextlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import tempfile
import os
import unittest
from unittest.mock import patch

HERE=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('fast_observed_test',HERE/'ebpf-mysql-fast-observed.py')
M=importlib.util.module_from_spec(spec);spec.loader.exec_module(M)

class ObservedTests(unittest.TestCase):
    def options(self):
        values={'work':'/private/work','backend-host':'dev-240','backend-root':'/private/lab',
          'backend-work':'/private/lab/capture','backend-code':'/private/lab/code',
          'controller-ip':'192.0.2.1','ctrl-ip':'192.0.2.2','ctrl-mac':'02:00:00:00:00:01',
          'artifacts':'/private/artifacts','workload-bin':'/private/worker','workload-sha256':'a'*64,
          'workload-source':'/private/source.c','image':'sha256:'+'b'*64,'server-container':'owned-server'}
        return ['run','--execute']+[item for k,v in values.items() for item in ('--'+k,v)]
    def test_default_does_not_read_or_spawn(self):
        with patch.object(M,'capture_options',side_effect=AssertionError),patch.object(M.subprocess,'Popen',side_effect=AssertionError),contextlib.redirect_stdout(io.StringIO()) as out:
            self.assertEqual(M.main([]),0)
        self.assertFalse(json.loads(out.getvalue())['writes_files'])
    def test_unknown_duplicate_and_newline_options_rejected(self):
        for tail in [['--shell','anything'],['--work','/private/replaced'],['--controller-url','http://localhost/\n']]:
            with self.subTest(tail=tail),self.assertRaises(ValueError):M.capture_options(self.options()+tail)
    def test_readonly_or_plan_cannot_execute(self):
        for head in [['plan','--execute'],['stop','--execute'],['run','--shell']]:
            with self.assertRaises(ValueError):M.capture_options(head+self.options()[2:])
    def test_credential_url_is_rejected_before_receipt(self):
        with self.assertRaises(RuntimeError):M.capture_options(self.options()+['--controller-url','http://user:secret@127.0.0.1:20417'])
    def test_explicit_valid_options_remain_literal(self):
        result=M.capture_options(self.options())
        self.assertEqual(result['--backend-work'],'/private/lab/capture')
    def test_zero_exit_failed_control_is_not_ack(self):
        with patch.object(M,'call',return_value=b'Failed.\n'),self.assertRaises(ValueError):M.dump_control(['docker','exec','owned'],'set')
    def test_wrong_parameters_do_not_ack(self):
        with patch.object(M,'call',return_value=b'Set pid 1 comm  proto 0 ip  port 0\nSuccess.\n'),self.assertRaises(ValueError):M.dump_control(['docker','exec','owned'],'set')
    def test_old_server_identity_cannot_change(self):
        identity={'id':'a'*64,'image':'sha256:'+'b'*64,'running':True,'readonly_rootfs':True,'network_mode':'owned','lab':'/private/lab','config_sha256':'d'*64,'config_destination':'/etc/server.yaml','config_readonly':True}
        with patch.object(M,'OPTIONS',{'--backend-host':'dev-240','--backend-root':'/private/lab'}),patch.object(M,'SERVER',identity),patch.object(M,'call',return_value=json.dumps(dict(identity,id='c'*64)).encode()),self.assertRaises(ValueError):M.checked_server()
    def test_rootfs_unprotected_server_rejected(self):
        identity={'id':'a'*64,'image':'sha256:'+'b'*64,'running':True,'readonly_rootfs':False,'network_mode':'owned','lab':'/private/lab','config_sha256':'d'*64,'config_destination':'/etc/server.yaml','config_readonly':True}
        with patch.object(M,'OPTIONS',{'--backend-host':'dev-240','--backend-root':'/private/lab'}),patch.object(M,'SERVER',None),patch.object(M,'call',return_value=json.dumps(identity).encode()),self.assertRaises(ValueError):M.checked_server()

    def test_unresponsive_auxiliary_never_prevents_runtime_cleanup(self):
        class Unresponsive:
            def poll(self):return None
            def terminate(self):pass
            def kill(self):pass
            def wait(self,timeout):raise subprocess.TimeoutExpired('owned-child',timeout)
        errors=[]
        M.clean_auxiliary(Unresponsive(),'metadata-parser',errors)
        self.assertEqual(errors,[{'process':'metadata-parser','error_type':'TimeoutExpired'}])


    def test_actual_merged_preprocess_requires_mysql_not_raw_default(self):
        def log(protocols):
            return 'INFO effective UserConfig preprocess: EbpfSocketPreprocess {\n out_of_order_reassembly_cache_size: 256,\n out_of_order_reassembly_protocols: '+protocols+',\n out_of_order_reassembly_timeout: 100ms,\n segmentation_reassembly_protocols: [],\n }\n'
        with tempfile.TemporaryDirectory() as folder:
            logs=Path(folder)/'logs';logs.mkdir()
            p=logs/'deepflow-agent_rCURRENT.log';p.write_text(log('[\n"MySQL",\n]'));p.chmod(0o600)
            current={'folder':folder};binding={'pid':123}
            self.assertTrue(M.effective_preprocess(current,binding)['pass'])
            p.write_text(log('[]'))
            with self.assertRaises(ValueError):M.effective_preprocess(current,binding)
            p.write_text(log('["MySQL",]')+log('[]'))
            with self.assertRaises(ValueError):M.effective_preprocess(current,binding)

    def test_changed_server_config_hash_cannot_pass(self):
        identity={'id':'a'*64,'image':'sha256:'+'b'*64,'running':True,'readonly_rootfs':True,'network_mode':'owned','lab':'/private/lab','config_sha256':'d'*64,'config_destination':'/etc/server.yaml','config_readonly':True}
        with patch.object(M,'OPTIONS',{'--backend-host':'dev-240','--backend-root':'/private/lab'}),patch.object(M,'SERVER',identity),patch.object(M,'call',return_value=json.dumps(dict(identity,config_sha256='e'*64)).encode()),self.assertRaises(ValueError):M.checked_server()


if __name__=='__main__':unittest.main()
