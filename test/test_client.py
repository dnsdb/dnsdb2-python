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

import json
from typing import List
import unittest

import requests_mock

import dnsdb2


class TestGenerators(unittest.TestCase):
    prefix = 'abc'

    def setUp(self):
        self.params = {'a': 'b'}
        self.ignore_limited = False

    rrset = dnsdb2.client._gen_rrset(prefix)

    def test_rrset(self):
        owner_name = 'def'
        self.path = f'{self.prefix}/rrset/name/{owner_name}'
        self.rrset(owner_name, **self.params)

    def test_rrset_with_rrtype(self):
        owner_name = 'def'
        rrtype = 'A'
        self.path = f'{self.prefix}/rrset/name/{owner_name}/{rrtype}'
        self.rrset(owner_name, rrtype=rrtype, **self.params)

    def test_rrset_with_bailiwick(self):
        owner_name = 'def'
        bailiwick = 'ghi'
        self.path = f'{self.prefix}/rrset/name/{owner_name}/{dnsdb2.client.RRTYPE_ANY}/{bailiwick}'
        self.rrset(owner_name, bailiwick=bailiwick, **self.params)

    def test_rrset_with_bailiwick_and_rrtype(self):
        owner_name = 'def'
        rrtype = 'A'
        bailiwick = 'ghi'
        self.path = f'{self.prefix}/rrset/name/{owner_name}/{rrtype}/{bailiwick}'
        self.rrset(owner_name, rrtype=rrtype, bailiwick=bailiwick, **self.params)

    def test_rrset_quoting(self):
        owner_name = 'de/f'
        bailiwick = 'gh,i'
        self.path = f'{self.prefix}/rrset/name/{dnsdb2.client._quote(owner_name)}/{dnsdb2.client.RRTYPE_ANY}/{dnsdb2.client._quote(bailiwick)}'  # nopep8
        self.rrset(owner_name, bailiwick=bailiwick, **self.params)

    def test_rrset_idna(self):
        owner_name = 'å∫ç'
        bailiwick = '∂éƒ'
        self.path = f'''{self.prefix}/rrset/name/{owner_name.encode('idna').decode('ascii')}/{dnsdb2.client.RRTYPE_ANY}/{bailiwick.encode('idna').decode('ascii')}'''  # nopep8
        self.rrset(owner_name, bailiwick=bailiwick, **self.params)

    def test_rrset_ignore_limited(self):
        owner_name = 'def'
        self.path = f'{self.prefix}/rrset/name/{owner_name}'
        self.ignore_limited = True
        self.rrset(owner_name, ignore_limited=True, **self.params)

    rdata_name = dnsdb2.client._gen_rdata_name(prefix)

    def test_rdata_name(self):
        name = 'def'
        self.path = f'{self.prefix}/rdata/name/{name}'
        self.rdata_name(name, **self.params)

    def test_rdata_name_rrtype(self):
        name = 'def'
        rrtype = 'A'
        self.path = f'{self.prefix}/rdata/name/{name}/{rrtype}'
        self.rdata_name(name, rrtype=rrtype, **self.params)

    def test_rdata_name_quoting(self):
        name = 'de/f'
        self.path = f'{self.prefix}/rdata/name/{dnsdb2.client._quote(name)}'
        self.rdata_name(name, **self.params)

    def test_rdata_name_idna(self):
        name = '∂éƒ'
        self.path = f'''{self.prefix}/rdata/name/{name.encode('idna').decode('ascii')}'''
        self.rdata_name(name, **self.params)

    def test_rdata_name_ignore_limited(self):
        name = 'def'
        self.path = f'{self.prefix}/rdata/name/{name}'
        self.ignore_limited = True
        self.rdata_name(name, ignore_limited=True, **self.params)

    rdata_ip = dnsdb2.client._gen_rdata_ip(prefix)

    def test_rdata_ip(self):
        ip = '1.2.3.4'
        self.path = f'{self.prefix}/rdata/ip/{ip}'
        self.rdata_ip(ip, **self.params)

    def test_rdata_ip_cidr(self):
        ip = '1.2.3.0/24'
        self.path = f'''{self.prefix}/rdata/ip/{ip.replace('/', ',')}'''
        self.rdata_ip(ip, **self.params)

    def test_rdata_range(self):
        ip = '1.2.3.4-5.6.7.8'
        self.path = f'{self.prefix}/rdata/ip/{ip}'
        self.rdata_ip(ip, **self.params)

    def test_rdata_ip_ignore_limited(self):
        ip = '1.2.3.4'
        self.path = f'{self.prefix}/rdata/ip/{ip}'
        self.ignore_limited = True
        self.rdata_ip(ip, ignore_limited=True, **self.params)

    rdata_raw = dnsdb2.client._gen_rdata_raw(prefix)

    def test_rdata_raw(self):
        raw_rdata = 'abcd'
        self.path = f'{self.prefix}/rdata/raw/{raw_rdata}'
        self.rdata_raw(raw_rdata, **self.params)

    def test_rdata_raw_rrtype(self):
        raw_rdata = 'abcd'
        rrtype = 'A'
        self.path = f'{self.prefix}/rdata/raw/{raw_rdata}/{rrtype}'
        self.rdata_raw(raw_rdata, rrtype=rrtype, **self.params)

    def test_rdata_raw_ignore_limited(self):
        raw_rdata = 'abcd'
        self.path = f'{self.prefix}/rdata/raw/{raw_rdata}'
        self.ignore_limited = True
        self.rdata_raw(raw_rdata, ignore_limited=True, **self.params)

    flexMethod = 'def'
    flex = dnsdb2.client._gen_flex(prefix, flexMethod)

    def test_flex(self):
        value = 'a+b*c?d'
        self.path = f'{self.prefix}/{self.flexMethod}/{dnsdb2.client._quote(value)}'
        self.flex(value, **self.params)

    def test_flex_rrtype(self):
        value = 'a+b*c?d'
        rrtype = 'A'
        self.path = f'{self.prefix}/{self.flexMethod}/{dnsdb2.client._quote(value)}/{rrtype}'
        self.flex(value, rrtype=rrtype, **self.params)

    def test_flex_ignore_limited(self):
        value = 'a+b*c?d'
        self.path = f'{self.prefix}/{self.flexMethod}/{dnsdb2.client._quote(value)}'
        self.ignore_limited = True
        self.flex(value, ignore_limited=True, **self.params)

    def _saf_query(self, path, ignore_limited=False, **params):
        self.assertEqual(self.path, path, 'url path')
        self.assertEqual(self.params, params, 'params')
        self.assertEqual(self.ignore_limited, ignore_limited)


@requests_mock.Mocker()
class TestDnsdbClient(unittest.TestCase):
    def setUp(self) -> None:
        self.server = 'https://unit.test'
        self.apikey = 'abcdef-ghijkl-mnopqrstuvwxyz'
        self.swclient = 'abc-client'
        self.version = 'v1.2.3.4'
        self.client = dnsdb2.Client(server=self.server, apikey=self.apikey,
                                    swclient=self.swclient, version=self.version)

    def test_headers(self, _):
        headers = self.client._headers()
        self.assertEqual(self.apikey, headers.get('X-Api-Key'), 'X-Api-Key header')
        self.assertEqual(dnsdb2.client.ACCEPT_CONTENT_TYPE, headers.get('Accept'), 'Accept header')

    def test_base_params(self, _):
        params = self.client._base_params()
        self.assertEqual(self.client.swclient, params.get('swclient'), 'swclient')
        self.assertEqual(self.client.version, params.get('version'), 'version')

    def test_ping(self, m):
        m.get(
            f'{self.server}/dnsdb/v2/ping?swclient={self.swclient}&version={self.version}',
            json={'ping': 'ok'},
            request_headers=self.client._headers(),
        )
        self.assertTrue(self.client.ping(), 'ping ok')

    def test_ping_fail(self, m):
        m.get(
            f'{self.server}/dnsdb/v2/ping?swclient={self.swclient}&version={self.version}',
            status_code=403,
            request_headers=self.client._headers(),
        )
        self.assertRaises(dnsdb2.DnsdbException, self.client.ping)

    def test_rate_limit(self, m):
        expected = {'rate': {'foo': 1}}
        m.get(f'{self.server}/dnsdb/v2/rate_limit?swclient={self.swclient}&version={self.version}',
              json=expected,
              request_headers=self.client._headers(),
              )

        self.assertEqual(expected, self.client.rate_limit())

    def test_rate_limit_404(self, m):
        m.get(f'{self.server}/dnsdb/v2/rate_limit?swclient={self.swclient}&version={self.version}',
              status_code=404,
              request_headers=self.client._headers(),
              )

        self.assertRaises(dnsdb2.DnsdbException, self.client.rate_limit)

    def test_rate_limit_403(self, m):
        m.get(f'{self.server}/dnsdb/v2/rate_limit?swclient={self.swclient}&version={self.version}',
              status_code=403,
              request_headers=self.client._headers(),
              )

        self.assertRaises(dnsdb2.AccessDenied, self.client.rate_limit)

    def test_query(self, m):
        records = [
            '{"count":1820,"zone_time_first":1374250920,"zone_time_last":1589472138,"rrname":"farsightsecurity.com.",'
            '"rrtype":"NS","bailiwick":"com.","rdata":["ns5.dnsmadeeasy.com.","ns6.dnsmadeeasy.com.","ns7.dnsmadeeasy'
            '.com."]}',
            '{"count":6350,"time_first":1380123423,"time_last":1427869045,"rrname":"farsightsecurity.com.","rrtype":"'
            'A","bailiwick":"farsightsecurity.com.","rdata":["66.160.140.81"]}',
        ]
        path = 'test/path'

        m.get(
            '{server}/dnsdb/v2/{path}?swclient={swclient}&version={version}'.format(
                server=self.client.server,
                path=path,
                swclient=self.client.swclient,
                version=self.client.version,
            ),
            text='\n'.join(saf_wrap(records)),
            request_headers=self.client._headers(),
        )

        for rrset in self.client._saf_query(path):
            self.assertEqual(json.loads(records[0]), rrset)
            records = records[1:]
        self.assertListEqual([], records, "All records consumed")

    def test_query_403(self, m):
        path = 'test/path'

        m.get(
            '{server}/dnsdb/v2/{path}?swclient={swclient}&version={version}'.format(
                server=self.client.server,
                path=path,
                swclient=self.client.swclient,
                version=self.client.version,
            ),
            status_code=403,
            request_headers=self.client._headers(),
        )

        self.assertRaises(dnsdb2.AccessDenied, self.client._saf_query, path)

    def test_query_404(self, m):
        path = 'file/not/found'

        m.get(
            '{server}/dnsdb/v2/{path}?swclient={swclient}&version={version}'.format(
                server=self.client.server,
                path=path,
                swclient=self.client.swclient,
                version=self.client.version,
            ),
            status_code=404,
            request_headers=self.client._headers(),
        )

        self.assertRaises(dnsdb2.QueryError, self.client._saf_query, path)


class TestQuote(unittest.TestCase):
    def testBasic(self):
        self._run_test('abc', 'abc')

    def testComma(self):
        self._run_test('ab,c', 'ab%2Cc')

    def testSlash(self):
        self._run_test('ab/c', 'ab%2Fc')

    def _run_test(self, test, expected):
        self.assertEqual(expected, dnsdb2.client._quote(test))


def saf_wrap(records, limited=False, failed=False, truncated=False) -> List[str]:
    header = ['{"cond": "begin"}']
    if limited:
        trailer = ['{"cond": "limited"}']
    elif failed:
        trailer = ['{"cond": "failed"}']
    elif truncated:
        trailer = []
    else:
        trailer = ['{"cond": "succeeded"}']

    return header + [f'{{"obj":{obj}}}' for obj in records] + trailer


if __name__ == '__main__':
    unittest.main()
