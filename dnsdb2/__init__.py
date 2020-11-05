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
#     c = dnsdb2.Client(apikey)
#     try:
#        for result in c.flex_rrnames_regex(r'\._dkim\.', limit=1):
#            # do something with result
#        except dnsdb2.QueryLimited:
#            # log that the query was limited, or re-issue with the next
#            # offset

try:
    from importlib.metadata import version, PackageNotFoundError
except ImportError:
    from importlib_metadata import version, PackageNotFoundError

try:
    __version__ = version(__name__)
except PackageNotFoundError:
    # package is not installed
    __version__ = "unknown"

from .exceptions import *
from .client import Client, DEFAULT_DNSDB_SERVER
