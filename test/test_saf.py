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
import textwrap
from typing import Iterable, Collection, Type
import unittest

import requests_mock

import dnsdb2
import dnsdb2.saf

class TestSafHandler(unittest.TestCase):
    def test_simple(self):
        self.run_test(
            textwrap.dedent('''\
                {"cond": "begin"}
                {"obj": {"count": 10392, "time_first": 138126549}}
                {"cond": "succeeded"}
            ''').split('\n'),
            ['{"count":10392,"time_first":138126549}']
        )

    def test_simple_ongoing(self):
        self.run_test(
            textwrap.dedent('''\
                {"cond": "begin"}
                {"cond": "ongoing", "obj": {"count": 10392, "time_first": 138126549}}
                {"cond": "succeeded"}
            ''').split('\n'),
            ['{"count":10392,"time_first":138126549}']
        )

    def test_limited(self):
        self.run_test(
            textwrap.dedent('''\
                {"cond": "begin"}
                {"obj":{"count":10392,"time_first":138126549}}
                {"cond": "limited", "msg": "Query limit reached", "obj":{"count":33,"time_first":19126549}}
            ''').split('\n'),
            textwrap.dedent('''\
                {"count":10392,"time_first":138126549}
                {"count":33,"time_first":19126549}
            ''').split('\n'),
            e=dnsdb2.QueryLimited
        )

    def test_ignore_limited(self):
        self.run_test(
            textwrap.dedent('''\
                {"cond": "begin"}
                {"obj":{"count":10392,"time_first":138126549}}
                {"cond": "limited", "msg": "Query limit reached", "obj":{"count":33,"time_first":19126549}}
            ''').split('\n'),
            textwrap.dedent('''\
                {"count":10392,"time_first":138126549}
                {"count":33,"time_first":19126549}
            ''').split('\n'),
            ignore_limited=True,
        )

    def test_failure(self):
        self.run_test(
            textwrap.dedent('''\
                {"cond": "begin"}
                {"cond": "failed", "msg": "Processing timeout; results may be incomplete", "obj":{"count":33,"time_first":19126549}}
            ''').split('\n'),  # nopep8
            textwrap.dedent('''\
                {"count":33,"time_first":19126549}
            ''').split('\n'),
            e=dnsdb2.QueryFailed
        )

    def test_truncated(self):
        self.run_test(
            textwrap.dedent('''\
                {"cond": "begin"}
                {"cond": "ongoing", "obj": {"count": 10392, "time_first": 138126549}}
            ''').split('\n'),
            ['{"count":10392,"time_first":138126549}'],
            e=dnsdb2.QueryTruncated
        )

    def test_invalid_cond(self):
        self.run_test(['{"cond": "invalid"}'], [], e=dnsdb2.ProtocolError)

    def test_broken_json(self):
        self.run_test(['{"cond": '], [], e=dnsdb2.ProtocolError)

    def run_test(self, msgs: Iterable[str], expected: Collection[str], e: Type[BaseException] = None,
                 ignore_limited: bool = False):
        class Response:
            def __init__(self):
                self.closed = False
            def iter_lines(_, decode_unicode: bool):
                self.assertTrue(decode_unicode)
                return msgs
            def close(self):
                self.closed = True

        res = Response()
        if not e:
            actual = list(dnsdb2.saf.handle_saf(res, ignore_limited=ignore_limited))
        else:
            actual = []

            def f():
                for msg in dnsdb2.saf.handle_saf(res, ignore_limited=ignore_limited):
                    actual.append(msg)
            self.assertRaises(e, f)
        self.assertEqual([json.loads(s) for s in filter(lambda x: x, expected)], actual)
        self.assertTrue(res.closed, "Connection was closed")

if __name__ == '__main__':
    unittest.main()
