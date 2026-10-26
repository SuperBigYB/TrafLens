import importlib.util
import pathlib
import unittest

source = pathlib.Path(__file__).resolve().parents[1] / 'accept-api.py'
spec = importlib.util.spec_from_file_location('accept_api', source)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class APIAcceptanceControls(unittest.TestCase):
    def test_agent_inventory_accepts_empty_null_but_rejects_bad_shapes(self):
        self.assertEqual(module.agent_identities(None), [])
        self.assertEqual(module.agent_identities([]), [])
        for rows in (False, 0, '', {}, [None], [{}]):
            with self.subTest(rows=rows), self.assertRaises(ValueError):
                module.agent_identities(rows)

    def test_count_control_accepts_one_unsigned_result(self):
        self.assertEqual(module.single_count({'result': {'columns': ['Count(row)'], 'values': [[40]]}}), 40)

    def test_count_control_rejects_wrong_or_duplicate_results(self):
        for result in ({'columns': ['other'], 'values': [[40]]}, {'columns': ['Count(row)'], 'values': [[40], [40]]},
                       {'columns': ['Count(row)'], 'values': [[True]]}, {'columns': ['Count(row)'], 'values': [[-1]]}):
            with self.subTest(result=result), self.assertRaises(ValueError):
                module.single_count({'result': result})

    def test_resource_identity_ignores_only_mount_order(self):
        def info(mounts, identity='same', started='same'):
            return {'Id': identity, 'State': {'StartedAt': started}, 'Mounts': mounts}
        a = {'Destination': '/a', 'Source': 'owned-a', 'RW': True}
        b = {'Destination': '/b', 'Source': 'owned-b', 'RW': False}
        expected = module.resource_identity(info([a, b]))
        self.assertEqual(expected, module.resource_identity(info([b, a])))
        for changed in (info([dict(a, Source='foreign'), b]), info([dict(a, RW=False), b]),
                        info([a, b], identity='replaced'), info([a, b], started='restarted')):
            with self.subTest(changed=changed):
                self.assertNotEqual(expected, module.resource_identity(changed))

    def test_single_json_rejects_concatenated_objects(self):
        with self.assertRaises(ValueError):
            module.strict_json('{"OPT_STATUS":"SERVER_ERROR"}{}')

    def test_single_json_rejects_non_object(self):
        for body in ('[]', 'null', '1', '"ok"'):
            with self.subTest(body=body), self.assertRaises(ValueError):
                module.strict_json(body)

    def test_single_json_accepts_one_complete_response(self):
        self.assertEqual(module.strict_json(' {"OPT_STATUS":"INVALID_POST_DATA"}\n'), {'OPT_STATUS': 'INVALID_POST_DATA'})

    def test_cleanup_rejects_wrong_group_identity(self):
        for group in ({'LCUUID': 'foreign', 'NAME': 'traflens-api-0123456789ab'}, {'LCUUID': 'owned', 'NAME': 'foreign-name'}):
            with self.subTest(group=group), self.assertRaises(RuntimeError):
                module.require_empty_owned_group(group, 'owned', 'traflens-api-0123456789ab')

    def test_cleanup_rejects_populated_group(self):
        for key in module.MEMBERS:
            group = {'LCUUID': 'owned', 'NAME': 'traflens-api-0123456789ab', key: ['foreign-agent']}
            with self.subTest(key=key), self.assertRaises(RuntimeError):
                module.require_empty_owned_group(group, 'owned', 'traflens-api-0123456789ab')

    def test_cleanup_accepts_exact_empty_temporary_group(self):
        module.require_empty_owned_group({'LCUUID': 'owned', 'NAME': 'traflens-api-0123456789ab', 'VTAP_LCUUIDS': []}, 'owned', 'traflens-api-0123456789ab')
