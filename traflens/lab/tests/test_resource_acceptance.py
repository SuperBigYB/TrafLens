import importlib.util
from pathlib import Path
import unittest

SPEC=importlib.util.spec_from_file_location('resource_acceptance',Path(__file__).resolve().parents[1]/'verify-agent-resources.py')
m=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(m)


class ResourceAcceptanceTests(unittest.TestCase):
    def fixture(self):
        return {'pass':True,'errors':[],'process_identity_stable':True,'readiness_owner_verified':True,
            'cpu_scope':'all container processes including watchdog','rss_scope':'verified readiness-listener owner; watchdog excluded',
            'agent_process_count':2,'interval_seconds':.1,'observation_seconds':1,
            'samples':[{'offset_seconds':i*.4,'rss_kib':v,'cgroup_memory_current_bytes':(i+1)*100} for i,v in enumerate([10000,12000,11000])],
            'sampled_agent_rss_peak_kib':12000,'sampled_cgroup_memory_max_bytes':300,
            'cpu_delta':{'usage_usec':100000,'user_usec':40000,'system_usec':60000,'nr_throttled':0,'throttled_usec':0},
            'cpu_core_seconds':.1,'average_cpu_cores':.1,'cgroup_memory_peak_available':False,'cgroup_memory_peak_bytes':None}

    def test_valid_and_explicitly_missing_optional_peak(self):
        d=self.fixture();r=m.verify(d);self.assertEqual(r['cpu_core_seconds'],.1)
        self.assertIsNone(r['kernel_cgroup_memory_peak_mib'])
        d.update(cgroup_memory_peak_available=True,cgroup_memory_peak_bytes=400)
        self.assertTrue(m.verify(d)['kernel_cgroup_memory_peak_available'])

    def test_rejects_failed_identity_unproven_owner_and_wrong_rss_scope(self):
        for key,value in [('pass',False),('process_identity_stable',False),('readiness_owner_verified',False),
                          ('rss_scope','leaf process'),('agent_process_count',3)]:
            d=self.fixture();d[key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):m.verify(d)

    def test_rejects_units_boolean_negative_and_cpu_accounting(self):
        for key,value in [('cpu_core_seconds',100000),('average_cpu_cores',True),('observation_seconds',float('nan'))]:
            d=self.fixture();d[key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):m.verify(d)
        for value in [-1,True,999999]:
            d=self.fixture();d['cpu_delta']['system_usec']=value
            with self.assertRaises(ValueError):m.verify(d)

    def test_rejects_sample_gaps_nonmonotonic_and_false_maxima(self):
        for action in ['gap','order','rss','memory']:
            d=self.fixture()
            if action=='gap':d['samples']=d['samples'][:2]
            if action=='order':d['samples'][1]['offset_seconds']=0
            if action=='rss':d['sampled_agent_rss_peak_kib']=1
            if action=='memory':d['sampled_cgroup_memory_max_bytes']=1
            with self.subTest(action=action),self.assertRaises(ValueError):m.verify(d)

    def test_unavailable_is_not_zero_and_reported_peak_covers_samples(self):
        d=self.fixture();d['cgroup_memory_peak_bytes']=0
        with self.assertRaises(ValueError):m.verify(d)
        d=self.fixture();d.update(cgroup_memory_peak_available=True,cgroup_memory_peak_bytes=200)
        with self.assertRaises(ValueError):m.verify(d)


if __name__=='__main__':unittest.main()
