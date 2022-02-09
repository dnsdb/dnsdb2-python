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
# A client for DNSDB protocol version 2 with Flex Search.
#
# Example:
#     c = dnsdb2.Client(apikey, swclient="yourappname", version="v0.0")
#     try:
#        for result in c.flex_rrnames_regex(r'\._dkim\.', limit=1):
#            # do something with result
#        except dnsdb2.QueryLimited:
#            # log that the query was limited, or re-issue with the next
#            # offset

import http
import urllib.parse
from typing import Dict

import requests

import dnsdb2
import dnsdb2.saf

ACCEPT_CONTENT_TYPE = 'application/x-ndjson'
DEFAULT_DNSDB_SERVER = 'https://api.dnsdb.info'
API_PREFIX = 'dnsdb/v2'
DEFAULT_SWCLIENT = 'dnsdb2python'
DEFAULT_VERSION = dnsdb2.__version__

METHOD_LOOKUP = 'lookup'
METHOD_SUMMARIZE = 'summarize'
RRTYPE_ANY = 'ANY'

_STATUS_CODE_MAP = {
    http.HTTPStatus.UNAUTHORIZED: dnsdb2.AccessDenied,
    http.HTTPStatus.FORBIDDEN: dnsdb2.AccessDenied,
    http.HTTPStatus.REQUESTED_RANGE_NOT_SATISFIABLE: dnsdb2.OffsetError,
    http.HTTPStatus.TOO_MANY_REQUESTS: dnsdb2.QuotaExceeded,
    http.HTTPStatus.SERVICE_UNAVAILABLE: dnsdb2.ConcurrencyExceeded,
}

_DOC_IGNORE_LIMITED = '''\
    ignore_limited(bool): Suppress QueryLimited dnsdb2.
'''

_DOC_RRTYPE_ARG = '''\
    rrtype (str): a DNS RRtype mnemonic.
'''

_DOC_TIME_FENCE_ARGS = '''\
    time_first_before (int): provide results before the defined timestamp for
        when the DNS record was first observed. For example, the URL parameter
        “time_first_before=1420070400” will only provide matching DNS records
        that were first observed before (or older than) January 1, 2015.
        
    time_first_after (int): provide results after the defined timestamp for when
        the DNS record was first observed. For example, the URL parameter
        “time_first_after=-31536000” will only provide results that were first
        observed within the last year.
        
    time_last_before (int): provide results before the defined timestamp for
        when the DNS record was last observed. For example, the URL parameter
        “time_last_before=1356998400” will only provide results for DNS records
        that were last observed before 2013.
        
    time_last_after (int): provide results after the defined timestamp for when
        the DNS record was last observed. For example, the URL parameter
        “time_last_after=-2678400” will only provide results that were last
        observed after 31 days ago.    
'''

_DOC_COMMON_ARGS = '''\
    limit (int): Limit for the number of results returned via these lookup
        methods. There is a built-in limit to the number of results that are
        returned via these lookup methods. The default limit is set at 10,000.
        This limit can be raised or lowered by setting the “limit” query
        parameter.

        There is also a maximum number of results allowed; requesting a limit
        greater than the maximum will only return the maximum. See results_max
        below for information on that maximum. If “?limit=0” is used then DNSDB
        will return the maximum number of results allowed. Obviously, if there
        are less results for the query than the requested limit, only the actual
        amount can be returned.

    id (str): Client software specific identity of the user of the API client.
        Comprised of an alphanumeric string, a colon, and an alphanumeric
        string, limited to thirty characters. This may be logged by the DNSDB
        API server.
'''

_DOC_AGGR_ARGS = '''\
    aggr (bool): Aggregated results group identical RRsets across all time
        periods and is the classic behavior from querying the DNSDB. This means
        you could get the total number of times an rrset has been observed, but
        not when it was observed. Unaggregated results ungroup identical RRsets,
        allowing you to see how the domain name was resolved in the DNS across
        the full-time range covered in DNSDB (subject to time fencing). This can
        give a more accurate impression of record request volume across time
        because it will reveal the distinct timestamps of records whose values
        are repeated. You can answer questions like, “Was a domain parked for a
        long time, mostly unused, until it was repurposed for serving malware or
        relaying spam, but then was abandoned again?” It allows you to see if a
        record was observed heavily in the last week vs. having been observed
        constantly for years.
'''

_DOC_HUMANTIME_ARGS = '''\
    humantime (bool): A value that is True if time values (in time_first,
        time_last, zone_time_first, zone_time_last) should be returned in human
        readable (RFC3339 compliant) format or False if Unix-style time values
        in seconds since the epoch should be returned. False is the classic
        behavior from querying the DNSDB and is the default value for this
        option.
'''

_DOC_OFFSET_ARGS = '''\
    offset (int): How many rows to offset (e.g. skip) in the results.
        This implements an incremental result transfer feature, allowing you to
        view more of the available results for a single query. The rows are
        offset prior to the limit parameter being applied, therefore offset
        allows seeing additional results past a limit that matches the maximum
        number of results. Note that DNSDB recalculates the results for each
        query and the order of results might not be preserved. Therefore, this
        capability is not a valid way to walk all results over multiple queries
        – some results might be missing and some might be duplicated. The actual
        offset that can be used is limited or for certain API keys, offset is
        not allowed – see the offset_max rate_limit key below.
'''

_DOC_SUMMARIZE_ARGS = '''\
    max_count (int): max_count controls stopping when we reach that summary
        count. The resulting total count can exceed max_count as it will include
        the entire count from the last rrset examined.

        The default is to not constrain the count.
'''


def _docs_for_prefix(prefix: str) -> str:
    if prefix == 'lookup':
        return _DOC_OFFSET_ARGS
    elif prefix == 'summarize':
        return _DOC_SUMMARIZE_ARGS
    return ''


def _gen_rrset(prefix):
    def f(self, owner_name: str, rrtype: str = None, bailiwick: str = None, ignore_limited: bool = False, **params):
        owner_name = owner_name.encode('idna')
        path = f'{prefix}/rrset/name/{_quote(owner_name)}'
        if rrtype:
            path += f'/{rrtype}'
        if bailiwick:
            bailiwick = bailiwick.encode('idna')
            if not rrtype:
                path += f'/{RRTYPE_ANY}'
            path += f'/{_quote(bailiwick)}'
        return self._saf_query(path, ignore_limited=ignore_limited, **params)

    f.__doc__ = f'''\
Executes a {prefix} rrset query.

Args:
    owner_name (str): A DNS owner name in presentation format or wildcards.

        Wildcards are one of two forms: a left-hand (*.example.com) or
        right-hand (www.example.*) wildcard domain name. An owner name with a
        leading asterisk and label separator, (i.e., *.) will perform a
        wildcard search for any RRsets whose owner names end with the given
        domain name. An owner name with a trailing label separator and asterisk
        (i.e., .*) will perform a wildcard search for any RRsets whose owner
        names start with the given label(s). Note that left-hand wildcard
        queries are somewhat more expensive and slower than right-hand wildcard
        queries.
{_DOC_RRTYPE_ARG}
    bailiwick (str): A DNS bailiwick in presentation format or wildcards.
{_DOC_TIME_FENCE_ARGS}
{_DOC_COMMON_ARGS}
{_DOC_AGGR_ARGS}
{_DOC_HUMANTIME_ARGS}
{_DOC_IGNORE_LIMITED}
''' + _docs_for_prefix(prefix)

    return f


def _gen_rdata_name(prefix):
    def f(self, name: str, rrtype: str = None, ignore_limited: bool = False, **params):
        name = name.encode('idna')
        path = f'{prefix}/rdata/name/{_quote(name)}'
        if rrtype:
            path += f'/{rrtype}'
        return self._saf_query(path, ignore_limited=ignore_limited, **params)

    f.__doc__ = f'''\
Executes a {prefix} data name query.

Args:
    name (str): a DNS domain name in presentation format, or a left-hand
        (`.example.com`) or right-hand (`www.example.`) wildcard domain name.
        Note that left-hand wildcard queries are somewhat more expensive than
        right-hand wildcard queries.
{_DOC_RRTYPE_ARG}
{_DOC_TIME_FENCE_ARGS}
{_DOC_COMMON_ARGS}
{_DOC_AGGR_ARGS}
{_DOC_HUMANTIME_ARGS}
{_DOC_IGNORE_LIMITED}
''' + _docs_for_prefix(prefix)

    return f


def _gen_rdata_ip(prefix):
    def f(self, ip: str, ignore_limited: bool = False, **params):
        path = f'''{prefix}/rdata/ip/{ip.replace('/', ',')}'''
        return self._saf_query(path, ignore_limited=ignore_limited, **params)

    f.__doc__ = f'''\
Executes a {prefix} data ip query.

Args:
    ip (str): One of an IPv4 or IPv6 single address, with a prefix length, or
        with an address range.
{_DOC_TIME_FENCE_ARGS}
{_DOC_COMMON_ARGS}
{_DOC_AGGR_ARGS}
{_DOC_HUMANTIME_ARGS}
{_DOC_IGNORE_LIMITED}
''' + _docs_for_prefix(prefix)

    return f


def _gen_rdata_raw(prefix):
    def f(self, raw_rdata: str, rrtype: str = None, ignore_limited: bool = False, **params):
        path = f'{prefix}/rdata/raw/{raw_rdata}'
        if rrtype:
            path += f'/{rrtype}'
        return self._saf_query(path, ignore_limited=ignore_limited, **params)

    f.__doc__ = f'''\
Executes a {prefix} data raw query.

Args:
    raw_rdata (str): An even number of hexadecimal digits specifying a raw
        octet string.
{_DOC_RRTYPE_ARG}
{_DOC_TIME_FENCE_ARGS}
{_DOC_COMMON_ARGS}
{_DOC_AGGR_ARGS}
{_DOC_HUMANTIME_ARGS}
{_DOC_IGNORE_LIMITED}
''' + _docs_for_prefix(prefix)

    return f


def _gen_flex(method, key):
    def f(self, value: str, rrtype: str = None, ignore_limited: bool = False, **params):
        path = f'{method}/{key}/{_quote(value)}'

        if rrtype:
            path += f'/{rrtype}'

        return self._saf_query(path, ignore_limited=ignore_limited, **params)

    f.__doc__ = f'''\
Executes a {method} {key} flex search query.

Args:
    value (str): A {method} to match against {key}.
{_DOC_RRTYPE_ARG}
    verbose (bool): Set to false to disable `count`, `time_first`, and
        `time_last` fields in output.
{_DOC_TIME_FENCE_ARGS}
    exclude (str): Exclude (i.e. filter-out) results that match the {method}.
{_DOC_COMMON_ARGS}
{_DOC_OFFSET_ARGS}
{_DOC_IGNORE_LIMITED}
'''

    return f


class Client(object):
    """
    A client for DNSDB protocol version 2 with Flex Search.

    Example:
        c = dnsdb2.Client(apikey, swclient="yourappname", version="v0.0")
        try:
            for result in c.flex_rrnames_regex(r'\\._dkim\\.', limit=1):
                # do something with result
        except dnsdb2.QueryLimited:
            # log that the query was limited, or re-issue with the next offset
    """
    def __init__(self, apikey: str, server: str = DEFAULT_DNSDB_SERVER,
                 swclient: str = DEFAULT_SWCLIENT, version: str = DEFAULT_VERSION,
                 proxies: Dict[str, str] = None, insecure: bool = False):
        """
        Args:
            apikey (str): A DNSDB API key
            server (str): The DNSDB API server endpoint
            swclient (str): The name of the client software reported to DNSDB.
            version (str): The version of the software reported to DNSDB.
            proxies (Dict[str, str]): HTTP proxies to use. Mapping of protocol to URL.
            insecure (bool): Skip https validation.
        """
        self.apikey = apikey
        self.server = server
        self.swclient = swclient
        self.version = version
        self.proxies = proxies
        self.insecure = insecure
        self._session = requests.Session()

    def close(self) -> None:
        """
        Releases resources allocated by the Client.
        """
        self._session.close()

    lookup_rrset = _gen_rrset('lookup')
    summarize_rrset = _gen_rrset('summarize')
    lookup_rdata_name = _gen_rdata_name('lookup')
    summarize_rdata_name = _gen_rdata_name('summarize')
    lookup_rdata_ip = _gen_rdata_ip('lookup')
    summarize_rdata_ip = _gen_rdata_ip('summarize')
    lookup_rdata_raw = _gen_rdata_raw('lookup')
    summarize_rdata_raw = _gen_rdata_raw('summarize')
    flex_rrnames_regex = _gen_flex('regex', 'rrnames')
    flex_rrnames_glob = _gen_flex('glob', 'rrnames')
    flex_rdata_regex = _gen_flex('regex', 'rdata')
    flex_rdata_glob = _gen_flex('glob', 'rdata')

    def ping(self) -> bool:
        """
        Tests end to end connectivity tests to the DNSDB API endpoint, letting
        you know that there are no firewall blockages.
        """
        path = 'ping'
        return self._json_query(path).get('ping') == 'ok'

    def rate_limit(self) -> dict:
        """
        Retrieves quota information as described in the DNSDB API v2 documentation.
        """
        path = 'rate_limit'
        return self._json_query(path)

    def _base_params(self) -> dict:
        return {
            'swclient': self.swclient,
            'version': self.version,
        }

    def _headers(self) -> dict:
        return {
            'Accept': ACCEPT_CONTENT_TYPE,
            'X-Api-Key': self.apikey,
        }

    def _json_query(self, path: str, **params):
        url = f'{self.server}/{API_PREFIX}/{path}'

        query_params = self._base_params()
        query_params.update(params)

        try:
            with self._session.get(url,
                                   params=query_params,
                                   headers=self._headers(),
                                   proxies=self.proxies,
                                   verify=not self.insecure,
                                   ) as res:
                _raise_error(res)
                return res.json()
        except requests.RequestException as e:
            raise dnsdb2.QueryError from e

    def _saf_query(self, path: str, ignore_limited: bool = False, **params):
        url = f'{self.server}/{API_PREFIX}/{path}'

        query_params = self._base_params()
        query_params.update(params)

        try:
            res = self._session.get(
                url,
                headers=self._headers(),
                params=query_params,
                proxies=self.proxies,
                verify=not self.insecure,
                stream=True,
            )

            _raise_error(res)
        except requests.RequestException as e:
            raise dnsdb2.QueryError from e

        return dnsdb2.saf.handle_saf(res, ignore_limited=ignore_limited)


def _quote(path):
    return urllib.parse.quote(path, safe='')


def _raise_error(res: requests.Response) -> None:
    e = _STATUS_CODE_MAP.get(res.status_code)
    if e:
        raise e(res.text)
    res.raise_for_status()
