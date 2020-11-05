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

import requests

import dnsdb2


COND_BEGIN = 'begin'
COND_ONGOING = 'ongoing'
COND_SUCCEEDED = 'succeeded'
COND_LIMITED = 'limited'
COND_FAILED = 'failed'


def handle_saf(res: requests.Response, ignore_limited: bool = False):
    try:
        for line in res.iter_lines(decode_unicode=True):
            if not line:
                continue

            try:
                saf_msg = json.loads(line)
            except json.JSONDecodeError as e:
                raise dnsdb2.ProtocolError(f'could not decode json: {line}') from e

            cond = saf_msg.get('cond')
            obj = saf_msg.get('obj')
            msg = saf_msg.get('msg')

            if cond == COND_BEGIN:
                continue
            elif cond == COND_SUCCEEDED:
                return

            if obj:
                yield obj

            if cond == COND_ONGOING or not cond:
                continue
            elif cond == COND_LIMITED:
                if ignore_limited:
                    return
                raise dnsdb2.QueryLimited(msg)
            elif cond == COND_FAILED:
                raise dnsdb2.QueryFailed(msg)
            else:
                raise dnsdb2.ProtocolError(f'invalid cond: {cond}')

        raise dnsdb2.QueryTruncated()
    finally:
        res.close()
