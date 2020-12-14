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
#
# A mock DNSDB Client for unit testing. Calls are recorded as dictionaries
# to `Client.calls`. Keys are as follows:
#
# f: function name
# args: arguments
# kwargs: keyword arguments
# res: results from a successful execution
# e: exception raised
#
# `search_results` is an iterable of results to be returned by calls to the
# lookup, summarize, and flex methods. You can use the `limited` wrapper around
# a result if you need it to raise a `dnsdb2.QueryLimited` after returning results.
#
# You can make every call raise an exception by providing one through the `exception`
# argument.

from typing import Iterable

import dnsdb2


def _raises(f):
    def g(*args, **kwargs):
        self = args[0]
        if self.exception:
            raise self.exception
        return f(*args, **kwargs)
    g.__name__ = f.__name__

    return g


def _records(f):
    def g(*args, **kwargs):
        call = {
            'f': f.__name__,
            'args': args[1:],
            'kwargs': kwargs,
        }
        self = args[0]
        self.calls.append(call)

        try:
            res = f(*args, **kwargs)
            call['res'] = res
            return res
        except Exception as e:
            call['e'] = e
            raise
    g.__name__ = f.__name__

    return g


def _searches(f):
    def g(*args, **_):
        self = args[0]
        res = self.search_results[0]
        self.search_results = self.search_results[1:]
        if isinstance(res, Exception):
            raise res
        return res
    g.__name__ = f.__name__

    return g


def limited(i: Iterable):
    for res in i:
        yield res
    raise dnsdb2.QueryLimited


class Client:
    def __init__(self,
                 exception: Exception = None,
                 ping_result: bool = False,
                 rate_limit_result: dict = None,
                 search_results: Iterable = None):
        self.calls = list()
        self.exception = exception
        self.ping_result = ping_result
        self.rate_limit_result = rate_limit_result
        self.search_results = search_results

    @_records
    @_raises
    def ping(self) -> bool:
        return self.ping_result

    @_records
    @_raises
    def rate_limit(self) -> dict:
        return self.rate_limit_result

    @_records
    @_raises
    @_searches
    def lookup_rrset(self, owner_name: str, rrtype: str = None, bailiwick: str = None, ignore_limited: bool = False, **params):  # noqa
        pass

    @_records
    @_raises
    @_searches
    def summarize_rrset(self, owner_name: str, rrtype: str = None, bailiwick: str = None, ignore_limited: bool = False, **params):  # noqa
        pass

    @_records
    @_raises
    @_searches
    def lookup_rdata_name(self, name: str, rrtype: str = None, ignore_limited: bool = False, **params):  # noqa
        pass

    @_records
    @_raises
    @_searches
    def summarize_rdata_name(self, name: str, rrtype: str = None, ignore_limited: bool = False, **params):  # noqa
        pass

    @_records
    @_raises
    @_searches
    def lookup_rdata_ip(self, ip: str, ignore_limited: bool = False, **params):  # noqa
        pass

    @_records
    @_raises
    @_searches
    def summarize_rdata_ip(self, ip: str, ignore_limited: bool = False, **params):  # noqa
        pass

    @_records
    @_raises
    @_searches
    def lookup_rdata_raw(self, raw_rdata: str, rrtype: str = None, ignore_limited: bool = False, **params):  # noqa
        pass

    @_records
    @_raises
    @_searches
    def summarize_rdata_raw(self, raw_rdata: str, rrtype: str = None, ignore_limited: bool = False, **params):  # noqa
        pass

    @_records
    @_raises
    @_searches
    def flex_rrnames_regex(self, value: str, rrtype: str = None, ignore_limited: bool = False, **params):  # noqa
        pass

    @_records
    @_raises
    @_searches
    def flex_rrnames_glob(self, value: str, rrtype: str = None, ignore_limited: bool = False, **params):  # noqa
        pass

    @_records
    @_raises
    @_searches
    def flex_rdata_regex(self, value: str, rrtype: str = None, ignore_limited: bool = False, **params):  # noqa
        pass

    @_records
    @_raises
    @_searches
    def flex_rdata_glob(self, value: str, rrtype: str = None, ignore_limited: bool = False, **params):  # noqa
        pass
