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


class DnsdbException(Exception):
    """
    Common base class for all DNSDB exceptions.
    """


class AccessDenied(DnsdbException):
    """
    Exception raised if the API key is not authorized (usually indicates the
    block quota is expired), or the provided API key is not valid, or the
    Client IP address not authorized for this API key.
    """


class OffsetError(DnsdbException):
    """
    Exception raised if the offset value is greater than the maximum allowed
    or if an offset value was provided when not permitted.
    """


class QuotaExceeded(DnsdbException):
    """
    Exception raised if you have exceeded your quota and no new requests will
    be accepted at this time.

    For time-based quotas : The API key's daily quota limit is exceeded. The
    quota will automatically replenish, usually at the start of the next day.

    For block-based quotas : The block quota is exhausted. You may need to
    purchase a larger quota.

    For burst rate secondary quotas : There were too many queries within the
    burst window. The window will automatically reopen at its end.
    """


class ConcurrencyExceeded(DnsdbException):
    """
    Exception raised if the limit of number of concurrent connections is exceeded.
    """


class QueryError(DnsdbException):
    """
    Exception raised if a communication error occurs while executing a query, or
    the server reports an error due to invalid arguments.
    """


class QueryFailed(DnsdbException):
    """
    Exception raised if an error is reported by the server while a query is running.
    """


class QueryLimited(DnsdbException):
    """
    Exception raised if the result limit is reached.
    """


class QueryTruncated(DnsdbException):
    """
    Exception raised if query results are incomplete due to a server error.
    """


class ProtocolError(DnsdbException):
    """
    Exception raised if invalid data is received via the Streaming
    Application Framework.
    """
