# Copyright (c) 2020 by Farsight Security, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import re
import os
import time
from typing import Generator
import unittest

import dnsdb2


def _gen_integration_test(cases):
    def tc(self):
        for i in range(len(cases)):
            c = cases[i]
            with self.subTest(i=i, case=c):

                f = getattr(self.client, c.get('f'))

                exc = c.get('exc')
                if not exc:
                    o = f(*c.get('args', []), **c.get('kwargs', {}))
                    if isinstance(o, Generator):
                        res = list(o)
                    else:
                        res = o
                else:
                    with self.assertRaises(exc):
                        res = list()
                        for row in f(*c.get('args', []), **c.get('kwargs', {})):
                            res.append(row)

                row_check = c.get('row_check')
                if row_check:
                    for row in res:
                        self.assertTrue(row_check(row), str(row))

                check = c.get('check')
                if check:
                    check(res)
    return tc


def check_aggr(res) -> bool:
    """
    This checks for duplicate keys in the result set. The query must have some duplicates
    after aggregation.
    """
    seen = set()
    for row in res:
        k = (row['rrname'], row['rrtype'], tuple(row['rdata']))
        if k in seen:
            return True
        seen.add(k)


class TestIntegration(unittest.TestCase):
    def setUp(self):
        self.apikey = os.getenv('APIKEY')
        self.server = os.getenv('DNSDB_SERVER', dnsdb2.DEFAULT_DNSDB_SERVER)
        if not self.apikey:
            self.skipTest('apikey undefined')
        self.client = dnsdb2.Client(apikey=self.apikey, server=self.server)

    def tearDown(self) -> None:
        self.client.close()

    def test_bad_key(self):
        c = dnsdb2.Client('invalid-key', server=self.server)
        try:
            self.assertRaises(dnsdb2.AccessDenied, c.rate_limit)
        finally:
            c.close()

    test_ping = _gen_integration_test([
        {
            'f': 'ping',
            'check': lambda res: res
        }
    ])

    def test_ping_empty_key(self):
        c = dnsdb2.Client('', server=self.server)
        try:
            self.assertTrue(c.ping())
        finally:
            c.close()

    def test_ping_bad_key(self):
        c = dnsdb2.Client('invalid-key', server=self.server)
        try:
            self.assertTrue(c.ping())
        finally:
            c.close()

    test_rate_limit = _gen_integration_test([
        {
            'f': 'rate_limit',
            'check': lambda res: 'rate' in res
        }
    ])

    test_rrset = _gen_integration_test([
        {
            'f': 'lookup_rrset',
            'args': ['farsightsecurity.com'],
            'row_check': lambda row: row['rrname'] == 'farsightsecurity.com.',
            'check': lambda res: len(res) > 0,
        },
        {
            'f': 'lookup_rrset',
            'args': ['farsightsecurity.com'],
            'kwargs': {'rrtype': 'A'},
            'row_check': lambda row: row['rrtype'] == 'A',
            'check': lambda res: len(res) > 0,
        },
        {
            'f': 'lookup_rrset',
            'args': ['farsightsecurity.com'],
            'kwargs': {'bailiwick': 'com'},
            'row_check': lambda row: row['bailiwick'] == 'com.',
            'check': lambda res: len(res) > 0,
        },
        {
            'f': 'lookup_rrset',
            'args': ['farsightsecurity.com'],
            'kwargs': {'rrtype': 'NS', 'bailiwick': 'com'},
            'row_check': lambda row: row['rrtype'] == 'NS' and row['bailiwick'] == 'com.',
            'check': lambda res: len(res) > 0,
        },
        {
            'f': 'summarize_rrset',
            'args': ['farsightsecurity.com'],
            'check': lambda res: len(res) == 1 and res[0]['count'] > 0,
        },
    ])

    test_rdata_name = _gen_integration_test([
        {
            'f': 'lookup_rdata_name',
            'args': ['exch.fsi.io'],
            'row_check': lambda res: len(list(filter(lambda rdata: rdata.endswith('exch.fsi.io.'), res['rdata']))) > 0,
            'check': lambda res: len(res) > 0,
        },
        {
            'f': 'lookup_rdata_name',
            'args': ['exch.fsi.io'],
            'kwargs': {'rrtype': 'MX'},
            'row_check': lambda row: row['rrtype'] == 'MX',
            'check': lambda res: len(res) > 0,
        },
        {
            'f': 'summarize_rdata_name',
            'args': ['exch.fsi.io'],
            'check': lambda res: res[0]['count'] > 0,
        },
    ])

    test_rdata_ip = _gen_integration_test([
        {
            'f': 'lookup_rdata_ip',
            'args': ['104.244.14.95'],
            'row_check': lambda res: len(list(filter(lambda rdata: rdata == '104.244.14.95', res['rdata']))) > 0,
            'check': lambda res: len(res) > 0,
        },
        {
            'f': 'lookup_rdata_ip',
            'args': ['104.244.14.95'],
            'kwargs': {'rrtype': 'A'},
            'row_check': lambda row: row['rrtype'] == 'A',
            'check': lambda res: len(res) > 0,
        },
        {
            'f': 'lookup_rdata_ip',
            'args': ['2620:11c:f008::95'],
            'row_check': lambda res: len(list(filter(lambda rdata: rdata == '2620:11c:f008::95', res['rdata']))) > 0,
            'check': lambda res: len(res) > 0,
        },
        {
            'f': 'lookup_rdata_ip',
            'args': ['2620:11c:f008::95'],
            'kwargs': {'rrtype': 'A'},
            'row_check': lambda row: row['rrtype'] == 'AAAA',
            'check': lambda res: len(res) > 0,
        },
        {
            'f': 'lookup_rdata_ip',
            'args': ['104.244.14.95-104.244.14.96'],
            'row_check': lambda res: len(list(filter(lambda rdata: rdata in ('104.244.14.95', '104.244.14.96'),
                                                     res['rdata']))) > 0,
            'check': lambda res: len(res) > 0,
        },
        {
            'f': 'lookup_rdata_ip',
            'args': ['104.244.14.0'],
            'row_check': lambda res: len(list(filter(lambda rdata: rdata.startswith('104.244.14.'), res['rdata']))) > 0,
            'check': lambda res: len(res) > 0,
        },
        {
            'f': 'summarize_rdata_ip',
            'args': ['104.244.14.95'],
            'row_check': lambda res: res['count'] > 0,
            'check': lambda res: len(res) == 1,
        },
    ])

    test_rdata_raw = _gen_integration_test([
        {
            'f': 'lookup_rdata_raw',
            'args': ['000A04657863680366736902696F00'],
            'row_check': lambda res: len(list(filter(lambda rdata: rdata == '10 exch.fsi.io.', res['rdata']))) > 0,
            'check': lambda res: len(res) > 0,
        },
        {
            'f': 'lookup_rdata_raw',
            'args': ['000A04657863680366736902696F00'],
            'kwargs': {
                'rrtype': 'MX',
            },
            'row_check': lambda res: res['rrtype'] == 'MX',
            'check': lambda res: len(res) > 0,
        },
        {
            'f': 'summarize_rdata_raw',
            'args': ['000A04657863680366736902696F00'],
            'row_check': lambda res: res['count'] > 0,
            'check': lambda res: len(res) == 1,
        },
    ])

    test_flex = _gen_integration_test([
        {
            'f': 'flex_rrnames_regex',
            'args': [r'fa*rsight?security\.com\.$'],
            'row_check': lambda res: re.search(r'fa*rsight?security\.com\.$', res['rrname']),
            'check': lambda res: len(res) > 0,
        },
        {
            'f': 'flex_rrnames_regex',
            'args': [r'farsight?security\.com\.$'],
            'kwargs': {
                'rrtype': 'A',
            },
            'row_check': lambda res: res['rrtype'] == 'A',
            'check': lambda res: len(res) > 0,
        },
        {
            'f': 'flex_rrnames_glob',
            'args': ['*.farsigh?security.com.'],
            'row_check': lambda res: re.search(r'.+\.farsigh.security\.com\.$', res['rrname']),
            'check': lambda res: len(res) > 0,
        },
        {
            'f': 'flex_rdata_regex',
            'args': [r'exch\.fsi'],
            'row_check': lambda res: re.search(r'exch\.fsi', res['rdata']),
            'check': lambda res: len(res) > 0,
        },
        {
            'f': 'flex_rdata_glob',
            'args': ['*exch.fsi*'],
            'row_check': lambda res: re.search(r'exch\.fsi', res['rdata']),
            'check': lambda res: len(res) > 0,
        },
    ])

    test_kwargs = _gen_integration_test([
        {
            'f': 'lookup_rrset',
            'args': ['farsightsecurity.com'],
            'kwargs': {
                'time_first_before': -86400,
            },
            'row_check': lambda res: res.get('time_first', res.get('zone_time_first')) < time.time()-86340,
            'check': lambda res: len(res) > 0,
        },
        {
            'f': 'lookup_rrset',
            'args': ['farsightsecurity.com'],
            'kwargs': {
                'time_first_after': -86400,
            },
            'row_check': lambda res: res.get('time_first', res.get('zone_time_first')) >= time.time() - 86460,
        },
        {
            'f': 'lookup_rrset',
            'args': ['farsightsecurity.com'],
            'kwargs': {
                'time_last_before': -86400,
            },
            'row_check': lambda res: res.get('time_last', res.get('zone_time_last')) < time.time() - 86340,
            'check': lambda res: len(res) > 0,
        },
        {
            'f': 'lookup_rrset',
            'args': ['farsightsecurity.com'],
            'kwargs': {
                'time_last_after': -86400,
            },
            'row_check': lambda res: res.get('time_last', res.get('zone_time_last')) >= time.time() - 86460,
        },
        {
            'f': 'lookup_rrset',
            'args': ['farsightsecurity.com'],
            'kwargs': {
                'limit': 5,
            },
            'row_check': lambda row: row['rrname'] == 'farsightsecurity.com.',
            'check': lambda res: len(res) == 5,
            'exc': dnsdb2.QueryLimited,
        },
        {
            'f': 'lookup_rrset',
            'args': ['farsightsecurity.com'],
            'kwargs': {
                'aggr': False,
            },
            'check': check_aggr,
        },
        {
            'f': 'lookup_rrset',
            'args': ['farsightsecurity.com'],
            'kwargs': {
                'humantime': True,
            },
            'row_check': lambda res: isinstance(res.get('time_first', res.get('zone_time_first')), str),
            'check': lambda res: len(res) > 0,
        },
        {
            'f': 'lookup_rrset',
            'args': ['farsightsecurity.com'],
            'kwargs': {
                'offset': 1,
            },
            'check': lambda res: len(res) > 0,
        },
        {
            'f': 'summarize_rrset',
            'args': ['farsightsecurity.com'],
            'kwargs': {
                'max_count': 1,
            },
            'check': lambda res: len(res) == 1,
        }
    ])


if __name__ == '__main__':
    unittest.main()
