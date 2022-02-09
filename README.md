# Farsight DNSDB Version 2 with Flexible Search SDK for Python

[Farsight Security DNSDB®](https://www.farsightsecurity.com/solutions/dnsdb/) is the world’s largest DNS intelligence database that provides a unique, fact-based, multifaceted view of the configuration of the global Internet infrastructure. DNSDB leverages the richness of Farsight’s Security Information Exchange (SIE) data-sharing platform and is engineered and operated by leading DNS experts. Farsight collects Passive DNS data from its global sensor array. It then filters and verifies the DNS transactions before inserting them into the DNSDB, along with ICANN-sponsored zone file access download data. The end result is the highest-quality and most comprehensive DNS intelligence data service of its kind - with more than 100 billion DNS records since 2010.

This software development kit for Python 3 implements all features of the [DNSDB Version 2](https://docs.dnsdb.info/dnsdb-apiv2/) with Flexible Search API. 

## Requirements

- Python 3.6 or greater.
- [Python requests](http://python-requests.org).
- [Requests mock](https://pypi.org/project/requests-mock/) for running the test suite.
- A [DNSDB API key](https://www.farsightsecurity.com/solutions/dnsdb/).

To purchase DNSDB, please complete the [application form](https://www.farsightsecurity.com/order-form/). Our due diligence process requires that you provide answers for all required fields in the application. We must be able to positively establish your identity and projected use case, so your cooperation in completing this information will be greatly appreciated and expedite the approval process. Once your application is completed, Farsight Security will review and respond to your request within two business days.

DNSDB Free 30-day Trial Key: Farsight’s [API Key portability program](https://www.farsightsecurity.com/trial-api/) lets you unlock the power of DNS intelligence across dozens of SIEM, Orchestration, Automation and Threat Intelligence Platforms that already support Farsight's DNSDB RESTful API. 

## Examples

Import the dnsdb2 library and configure a client.

```python
import dnsdb2
client = dnsdb2.Client(apikey, swclient="yourappname", version="v0.0")
```

Perform a flex regex search for `farsight`. This manually suppresses `QueryLimited` exceptions raised by the server if the query results exceed the row limited.

```python
results = list(client.flex_rdata_regex('farsight', ignore_limited=True))
```

Lookup rrsets for `*.dnsdb.info` with rrtype `A`. 

```python
results = list(client.lookup_rrset("*.dnsdb.info", rrtype='A', ignore_limited=True))
```

Summarize rdata records for `104.244.14.0/24` seen within the past 90 days.

```python
results = next(client.summarize_rdata_ip("104.244.14.0/24", time_last_after=-60*60*24*90, ignore_limited=True))
```

Iterate through a large result set by re-issuing queries with increasing offsets after `QueryLimited` is raised.

```python
limit = 1000
offset = 0
results = list()
while True:
    try:
        for res in client.lookup_rrset("farsightsecurity.com", limit=limit, offset=offset):
            results.append(res)
    except dnsdb2.QueryLimited:
        offset += limit
    else:
        break
```

## API Documentation

https://docs.dnsdb.info/dnsdb-apiv2/

https://docs.dnsdb.info/dnsdb-flex/

### Table of Contents

* [Client](#dnsdb2.Client)
  * [ping](#dnsdb2.Client.ping)
  * [rate\_limit](#dnsdb2.Client.rate_limit)
  * [lookup\_rrset](#dnsdb2.Client.lookup_rrset)
  * [summarize\_rrset](#dnsdb2.Client.summarize_rrset)
  * [lookup\_rdata\_name](#dnsdb2.Client.lookup_rdata_name)
  * [summarize\_rdata\_name](#dnsdb2.Client.summarize_rdata_name)
  * [lookup\_rdata\_ip](#dnsdb2.Client.lookup_rdata_ip)
  * [summarize\_rdata\_ip](#dnsdb2.Client.summarize_rdata_ip)
  * [lookup\_rdata\_raw](#dnsdb2.Client.lookup_rdata_raw)
  * [summarize\_rdata\_raw](#dnsdb2.Client.summarize_rdata_raw)
  * [flex\_rrnames\_regex](#dnsdb2.Client.flex_rrnames_regex)
  * [flex\_rrnames\_glob](#dnsdb2.Client.flex_rrnames_glob)
  * [flex\_rdata\_regex](#dnsdb2.Client.flex_rdata_regex)
  * [flex\_rdata\_glob](#dnsdb2.Client.flex_rdata_glob)
* [DnsdbException](#dnsdb2.DnsdbException)
* [AccessDenied](#dnsdb2.AccessDenied)
* [OffsetError](#dnsdb2.OffsetError)
* [QuotaExceeded](#dnsdb2.QuotaExceeded)
* [ConcurrencyExceeded](#dnsdb2.ConcurrencyExceeded)
* [QueryError](#dnsdb2.QueryError)
* [QueryFailed](#dnsdb2.QueryFailed)
* [QueryLimited](#dnsdb2.QueryLimited)
* [QueryTruncated](#dnsdb2.QueryTruncated)
* [ProtocolError](#dnsdb2.ProtocolError)

<a name="dnsdb2.Client"></a>
### Client Objects

```
 | dnsdb2.Client(apikey: str, server: str = 'https://api.dnsdb.info',
 |               swclient: str = 'dnsdb2-py', version: str = '0.0',
 |               proxies: Dict[str, str] = None, insecure: bool = False)
 |      A client for DNSDB protocol version 2 with Flex Search.
 |
 |      Args:
 |          apikey (str): A DNSDB API key
 |          server (str): The DNSDB API server endpoint
 |          swclient (str): The name of the client software reported to DNSDB.
 |          version (str): The version of the software reported to DNSDB.
 |          proxies (Dict[str, str]): HTTP proxies to use. Mapping of protocol to URL.
 |          insecure (bool): Skip https validation.
```

<a name="dnsdb2.Client.ping"></a>
#### ping

```
 |  ping(self) -> bool
 |      Tests end to end connectivity tests to the DNSDB API endpoint, letting
 |      you know that there are no firewall blockages.
```

<a name="dnsdb2.Client.rate_limit"></a>
#### rate\_limit

```
 |  rate_limit(self) -> dict
 |      Retrieves quota information as described in the DNSDB API v2 documentation.
```

<a name="dnsdb2.Client.lookup_rrset"></a>
#### lookup\_rrset

```
 |  lookup_rrset = f(self, owner_name: str, rrtype: str = None, bailiwick: str = None, ignore_limited: bool = False, **params)
 |      Executes a lookup rrset query.
 |      
 |      Args:
 |          owner_name (str): A DNS owner name in presentation format or wildcards.
 |      
 |              Wildcards are one of two forms: a left-hand (*.example.com) or
 |              right-hand (www.example.*) wildcard domain name. An owner name with a
 |              leading asterisk and label separator, (i.e., *.) will perform a
 |              wildcard search for any RRsets whose owner names end with the given
 |              domain name. An owner name with a trailing label separator and asterisk
 |              (i.e., .*) will perform a wildcard search for any RRsets whose owner
 |              names start with the given label(s). Note that left-hand wildcard
 |              queries are somewhat more expensive and slower than right-hand wildcard
 |              queries.
 |          rrtype (str): a DNS RRtype mnemonic.
 |      
 |          bailiwick (str): A DNS bailiwick in presentation format or wildcards.
 |          time_first_before (int): provide results before the defined timestamp for
 |              when the DNS record was first observed. For example, the URL parameter
 |              “time_first_before=1420070400” will only provide matching DNS records
 |              that were first observed before (or older than) January 1, 2015.
 |              
 |          time_first_after (int): provide results after the defined timestamp for when
 |              the DNS record was first observed. For example, the URL parameter
 |              “time_first_after=-31536000” will only provide results that were first
 |              observed within the last year.
 |              
 |          time_last_before (int): provide results before the defined timestamp for
 |              when the DNS record was last observed. For example, the URL parameter
 |              “time_last_before=1356998400” will only provide results for DNS records
 |              that were last observed before 2013.
 |              
 |          time_last_after (int): provide results after the defined timestamp for when
 |              the DNS record was last observed. For example, the URL parameter
 |              “time_last_after=-2678400” will only provide results that were last
 |              observed after 31 days ago.    
 |      
 |          limit (int): Limit for the number of results returned via these lookup
 |              methods. There is a built-in limit to the number of results that are
 |              returned via these lookup methods. The default limit is set at 10,000.
 |              This limit can be raised or lowered by setting the “limit” query
 |              parameter.
 |      
 |              There is also a maximum number of results allowed; requesting a limit
 |              greater than the maximum will only return the maximum. See results_max
 |              below for information on that maximum. If “?limit=0” is used then DNSDB
 |              will return the maximum number of results allowed. Obviously, if there
 |              are less results for the query than the requested limit, only the actual
 |              amount can be returned.
 |      
 |          id (str): Client software specific identity of the user of the API client.
 |              Comprised of an alphanumeric string, a colon, and an alphanumeric
 |              string, limited to thirty characters. This may be logged by the DNSDB
 |              API server.
 |      
 |          aggr (bool): Aggregated results group identical rrsets across all time
 |              periods and is the classic behavior from querying the DNSDB. This means
 |              you could get the total number of times an rrset has been observed, but
 |              not when it was observed. Unaggregated results ungroup identical rrsets,
 |              allowing you to see how the domain name was resolved in the DNS across
 |              the full-time range covered in DNSDB (subject to time fencing). This can
 |              give a more accurate impression of record request volume across time
 |              because it will reveal the distinct timestamps of records whose values
 |              are repeated. You can answer questions like, “Was a domain parked for a
 |              long time, mostly unused, until it was repurposed for serving malware or
 |              relaying spam, but then was abandoned again?” It allows you to see if a
 |              record was observed heavily in the last week vs. having been observed
 |              constantly for years.
 |      
 |          humantime (bool): A value that is True if time values (in time_first,
 |              time_last, zone_time_first, zone_time_last) should be returned in human
 |              readable (RFC3339 compliant) format or False if Unix-style time values
 |              in seconds since the epoch should be returned. False is the classic
 |              behavior from querying the DNSDB and is the default value for this
 |              option.
 |      
 |          ignore_limited(bool): Suppress QueryLimited exceptions.
 |      
 |          offset (int): How many rows to offset (e.g. skip) in the results.
 |              This implements an incremental result transfer feature, allowing you to
 |              view more of the available results for a single query. The rows are
 |              offset prior to the limit parameter being applied, therefore offset
 |              allows seeing additional results past a limit that matches the maximum
 |              number of results. Note that DNSDB recalculates the results for each
 |              query and the order of results might not be preserved. Therefore, this
 |              capability is not a valid way to walk all results over multiple queries
 |              – some results might be missing and some might be duplicated. The actual
 |              offset that can be used is limited or for certain API keys, offset is
 |              not allowed – see the offset_max rate_limit key below.
```

<a name="dnsdb2.Client.summarize_rrset"></a>
#### summarize\_rrset

```
 |  summarize_rrset = f(self, owner_name: str, rrtype: str = None, bailiwick: str = None, ignore_limited: bool = False, **params)
 |      Executes a summarize rrset query.
 |      
 |      Args:
 |          owner_name (str): A DNS owner name in presentation format or wildcards.
 |      
 |              Wildcards are one of two forms: a left-hand (*.example.com) or
 |              right-hand (www.example.*) wildcard domain name. An owner name with a
 |              leading asterisk and label separator, (i.e., *.) will perform a
 |              wildcard search for any RRsets whose owner names end with the given
 |              domain name. An owner name with a trailing label separator and asterisk
 |              (i.e., .*) will perform a wildcard search for any RRsets whose owner
 |              names start with the given label(s). Note that left-hand wildcard
 |              queries are somewhat more expensive and slower than right-hand wildcard
 |              queries.
 |          rrtype (str): a DNS RRtype mnemonic.
 |      
 |          bailiwick (str): A DNS bailiwick in presentation format or wildcards.
 |          time_first_before (int): provide results before the defined timestamp for
 |              when the DNS record was first observed. For example, the URL parameter
 |              “time_first_before=1420070400” will only provide matching DNS records
 |              that were first observed before (or older than) January 1, 2015.
 |              
 |          time_first_after (int): provide results after the defined timestamp for when
 |              the DNS record was first observed. For example, the URL parameter
 |              “time_first_after=-31536000” will only provide results that were first
 |              observed within the last year.
 |              
 |          time_last_before (int): provide results before the defined timestamp for
 |              when the DNS record was last observed. For example, the URL parameter
 |              “time_last_before=1356998400” will only provide results for DNS records
 |              that were last observed before 2013.
 |              
 |          time_last_after (int): provide results after the defined timestamp for when
 |              the DNS record was last observed. For example, the URL parameter
 |              “time_last_after=-2678400” will only provide results that were last
 |              observed after 31 days ago.    
 |      
 |          limit (int): Limit for the number of results returned via these lookup
 |              methods. There is a built-in limit to the number of results that are
 |              returned via these lookup methods. The default limit is set at 10,000.
 |              This limit can be raised or lowered by setting the “limit” query
 |              parameter.
 |      
 |              There is also a maximum number of results allowed; requesting a limit
 |              greater than the maximum will only return the maximum. See results_max
 |              below for information on that maximum. If “?limit=0” is used then DNSDB
 |              will return the maximum number of results allowed. Obviously, if there
 |              are less results for the query than the requested limit, only the actual
 |              amount can be returned.
 |      
 |          id (str): Client software specific identity of the user of the API client.
 |              Comprised of an alphanumeric string, a colon, and an alphanumeric
 |              string, limited to thirty characters. This may be logged by the DNSDB
 |              API server.
 |      
 |          aggr (bool): Aggregated results group identical rrsets across all time
 |              periods and is the classic behavior from querying the DNSDB. This means
 |              you could get the total number of times an rrset has been observed, but
 |              not when it was observed. Unaggregated results ungroup identical rrsets,
 |              allowing you to see how the domain name was resolved in the DNS across
 |              the full-time range covered in DNSDB (subject to time fencing). This can
 |              give a more accurate impression of record request volume across time
 |              because it will reveal the distinct timestamps of records whose values
 |              are repeated. You can answer questions like, “Was a domain parked for a
 |              long time, mostly unused, until it was repurposed for serving malware or
 |              relaying spam, but then was abandoned again?” It allows you to see if a
 |              record was observed heavily in the last week vs. having been observed
 |              constantly for years.
 |      
 |          humantime (bool): A value that is True if time values (in time_first,
 |              time_last, zone_time_first, zone_time_last) should be returned in human
 |              readable (RFC3339 compliant) format or False if Unix-style time values
 |              in seconds since the epoch should be returned. False is the classic
 |              behavior from querying the DNSDB and is the default value for this
 |              option.
 |      
 |          ignore_limited(bool): Suppress QueryLimited exceptions.
 |      
 |          max_count (int): max_count controls stopping when we reach that summary
 |              count. The resulting total count can exceed max_count as it will include
 |              the entire count from the last rrset examined.
 |      
 |              The default is to not constrain the count.
```

<a name="dnsdb2.Client.lookup_rdata_name"></a>
#### lookup\_rdata\_name

```
 |  lookup_rdata_name = f(self, name: str, rrtype: str = None, ignore_limited: bool = False, **params)
 |      Executes a lookup data name query.
 |      
 |      Args:
 |          name (str): a DNS domain name in presentation format, or a left-hand
 |              (`.example.com`) or right-hand (`www.example.`) wildcard domain name.
 |              Note that left-hand wildcard queries are somewhat more expensive than
 |              right-hand wildcard queries.
 |          rrtype (str): a DNS RRtype mnemonic.
 |      
 |          time_first_before (int): provide results before the defined timestamp for
 |              when the DNS record was first observed. For example, the URL parameter
 |              “time_first_before=1420070400” will only provide matching DNS records
 |              that were first observed before (or older than) January 1, 2015.
 |              
 |          time_first_after (int): provide results after the defined timestamp for when
 |              the DNS record was first observed. For example, the URL parameter
 |              “time_first_after=-31536000” will only provide results that were first
 |              observed within the last year.
 |              
 |          time_last_before (int): provide results before the defined timestamp for
 |              when the DNS record was last observed. For example, the URL parameter
 |              “time_last_before=1356998400” will only provide results for DNS records
 |              that were last observed before 2013.
 |              
 |          time_last_after (int): provide results after the defined timestamp for when
 |              the DNS record was last observed. For example, the URL parameter
 |              “time_last_after=-2678400” will only provide results that were last
 |              observed after 31 days ago.    
 |      
 |          limit (int): Limit for the number of results returned via these lookup
 |              methods. There is a built-in limit to the number of results that are
 |              returned via these lookup methods. The default limit is set at 10,000.
 |              This limit can be raised or lowered by setting the “limit” query
 |              parameter.
 |      
 |              There is also a maximum number of results allowed; requesting a limit
 |              greater than the maximum will only return the maximum. See results_max
 |              below for information on that maximum. If “?limit=0” is used then DNSDB
 |              will return the maximum number of results allowed. Obviously, if there
 |              are less results for the query than the requested limit, only the actual
 |              amount can be returned.
 |      
 |          id (str): Client software specific identity of the user of the API client.
 |              Comprised of an alphanumeric string, a colon, and an alphanumeric
 |              string, limited to thirty characters. This may be logged by the DNSDB
 |              API server.
 |      
 |          aggr (bool): Aggregated results group identical rrsets across all time
 |              periods and is the classic behavior from querying the DNSDB. This means
 |              you could get the total number of times an rrset has been observed, but
 |              not when it was observed. Unaggregated results ungroup identical rrsets,
 |              allowing you to see how the domain name was resolved in the DNS across
 |              the full-time range covered in DNSDB (subject to time fencing). This can
 |              give a more accurate impression of record request volume across time
 |              because it will reveal the distinct timestamps of records whose values
 |              are repeated. You can answer questions like, “Was a domain parked for a
 |              long time, mostly unused, until it was repurposed for serving malware or
 |              relaying spam, but then was abandoned again?” It allows you to see if a
 |              record was observed heavily in the last week vs. having been observed
 |              constantly for years.
 |      
 |          humantime (bool): A value that is True if time values (in time_first,
 |              time_last, zone_time_first, zone_time_last) should be returned in human
 |              readable (RFC3339 compliant) format or False if Unix-style time values
 |              in seconds since the epoch should be returned. False is the classic
 |              behavior from querying the DNSDB and is the default value for this
 |              option.
 |      
 |          ignore_limited(bool): Suppress QueryLimited exceptions.
 |      
 |          offset (int): How many rows to offset (e.g. skip) in the results.
 |              This implements an incremental result transfer feature, allowing you to
 |              view more of the available results for a single query. The rows are
 |              offset prior to the limit parameter being applied, therefore offset
 |              allows seeing additional results past a limit that matches the maximum
 |              number of results. Note that DNSDB recalculates the results for each
 |              query and the order of results might not be preserved. Therefore, this
 |              capability is not a valid way to walk all results over multiple queries
 |              – some results might be missing and some might be duplicated. The actual
 |              offset that can be used is limited or for certain API keys, offset is
 |              not allowed – see the offset_max rate_limit key below.
```

<a name="dnsdb2.Client.summarize_rdata_name"></a>
#### summarize\_rdata\_name

```
 |  summarize_rdata_name = f(self, name: str, rrtype: str = None, ignore_limited: bool = False, **params)
 |      Executes a summarize data name query.
 |      
 |      Args:
 |          name (str): a DNS domain name in presentation format, or a left-hand
 |              (`.example.com`) or right-hand (`www.example.`) wildcard domain name.
 |              Note that left-hand wildcard queries are somewhat more expensive than
 |              right-hand wildcard queries.
 |          rrtype (str): a DNS RRtype mnemonic.
 |      
 |          time_first_before (int): provide results before the defined timestamp for
 |              when the DNS record was first observed. For example, the URL parameter
 |              “time_first_before=1420070400” will only provide matching DNS records
 |              that were first observed before (or older than) January 1, 2015.
 |              
 |          time_first_after (int): provide results after the defined timestamp for when
 |              the DNS record was first observed. For example, the URL parameter
 |              “time_first_after=-31536000” will only provide results that were first
 |              observed within the last year.
 |              
 |          time_last_before (int): provide results before the defined timestamp for
 |              when the DNS record was last observed. For example, the URL parameter
 |              “time_last_before=1356998400” will only provide results for DNS records
 |              that were last observed before 2013.
 |              
 |          time_last_after (int): provide results after the defined timestamp for when
 |              the DNS record was last observed. For example, the URL parameter
 |              “time_last_after=-2678400” will only provide results that were last
 |              observed after 31 days ago.    
 |      
 |          limit (int): Limit for the number of results returned via these lookup
 |              methods. There is a built-in limit to the number of results that are
 |              returned via these lookup methods. The default limit is set at 10,000.
 |              This limit can be raised or lowered by setting the “limit” query
 |              parameter.
 |      
 |              There is also a maximum number of results allowed; requesting a limit
 |              greater than the maximum will only return the maximum. See results_max
 |              below for information on that maximum. If “?limit=0” is used then DNSDB
 |              will return the maximum number of results allowed. Obviously, if there
 |              are less results for the query than the requested limit, only the actual
 |              amount can be returned.
 |      
 |          id (str): Client software specific identity of the user of the API client.
 |              Comprised of an alphanumeric string, a colon, and an alphanumeric
 |              string, limited to thirty characters. This may be logged by the DNSDB
 |              API server.
 |      
 |          aggr (bool): Aggregated results group identical rrsets across all time
 |              periods and is the classic behavior from querying the DNSDB. This means
 |              you could get the total number of times an rrset has been observed, but
 |              not when it was observed. Unaggregated results ungroup identical rrsets,
 |              allowing you to see how the domain name was resolved in the DNS across
 |              the full-time range covered in DNSDB (subject to time fencing). This can
 |              give a more accurate impression of record request volume across time
 |              because it will reveal the distinct timestamps of records whose values
 |              are repeated. You can answer questions like, “Was a domain parked for a
 |              long time, mostly unused, until it was repurposed for serving malware or
 |              relaying spam, but then was abandoned again?” It allows you to see if a
 |              record was observed heavily in the last week vs. having been observed
 |              constantly for years.
 |      
 |          humantime (bool): A value that is True if time values (in time_first,
 |              time_last, zone_time_first, zone_time_last) should be returned in human
 |              readable (RFC3339 compliant) format or False if Unix-style time values
 |              in seconds since the epoch should be returned. False is the classic
 |              behavior from querying the DNSDB and is the default value for this
 |              option.
 |      
 |          ignore_limited(bool): Suppress QueryLimited exceptions.
 |      
 |          max_count (int): max_count controls stopping when we reach that summary
 |              count. The resulting total count can exceed max_count as it will include
 |              the entire count from the last rrset examined.
 |      
 |              The default is to not constrain the count.
```

<a name="dnsdb2.Client.lookup_rdata_ip"></a>
#### lookup\_rdata\_ip

```
 |  lookup_rdata_ip = f(self, ip: str, ignore_limited: bool = False, **params)
 |      Executes a lookup data ip query.
 |      
 |      Args:
 |          ip (str): One of an IPv4 or IPv6 single address, with a prefix length, or
 |              with an address range.
 |          time_first_before (int): provide results before the defined timestamp for
 |              when the DNS record was first observed. For example, the URL parameter
 |              “time_first_before=1420070400” will only provide matching DNS records
 |              that were first observed before (or older than) January 1, 2015.
 |              
 |          time_first_after (int): provide results after the defined timestamp for when
 |              the DNS record was first observed. For example, the URL parameter
 |              “time_first_after=-31536000” will only provide results that were first
 |              observed within the last year.
 |              
 |          time_last_before (int): provide results before the defined timestamp for
 |              when the DNS record was last observed. For example, the URL parameter
 |              “time_last_before=1356998400” will only provide results for DNS records
 |              that were last observed before 2013.
 |              
 |          time_last_after (int): provide results after the defined timestamp for when
 |              the DNS record was last observed. For example, the URL parameter
 |              “time_last_after=-2678400” will only provide results that were last
 |              observed after 31 days ago.    
 |      
 |          limit (int): Limit for the number of results returned via these lookup
 |              methods. There is a built-in limit to the number of results that are
 |              returned via these lookup methods. The default limit is set at 10,000.
 |              This limit can be raised or lowered by setting the “limit” query
 |              parameter.
 |      
 |              There is also a maximum number of results allowed; requesting a limit
 |              greater than the maximum will only return the maximum. See results_max
 |              below for information on that maximum. If “?limit=0” is used then DNSDB
 |              will return the maximum number of results allowed. Obviously, if there
 |              are less results for the query than the requested limit, only the actual
 |              amount can be returned.
 |      
 |          id (str): Client software specific identity of the user of the API client.
 |              Comprised of an alphanumeric string, a colon, and an alphanumeric
 |              string, limited to thirty characters. This may be logged by the DNSDB
 |              API server.
 |      
 |          aggr (bool): Aggregated results group identical rrsets across all time
 |              periods and is the classic behavior from querying the DNSDB. This means
 |              you could get the total number of times an rrset has been observed, but
 |              not when it was observed. Unaggregated results ungroup identical rrsets,
 |              allowing you to see how the domain name was resolved in the DNS across
 |              the full-time range covered in DNSDB (subject to time fencing). This can
 |              give a more accurate impression of record request volume across time
 |              because it will reveal the distinct timestamps of records whose values
 |              are repeated. You can answer questions like, “Was a domain parked for a
 |              long time, mostly unused, until it was repurposed for serving malware or
 |              relaying spam, but then was abandoned again?” It allows you to see if a
 |              record was observed heavily in the last week vs. having been observed
 |              constantly for years.
 |      
 |          humantime (bool): A value that is True if time values (in time_first,
 |              time_last, zone_time_first, zone_time_last) should be returned in human
 |              readable (RFC3339 compliant) format or False if Unix-style time values
 |              in seconds since the epoch should be returned. False is the classic
 |              behavior from querying the DNSDB and is the default value for this
 |              option.
 |      
 |          ignore_limited(bool): Suppress QueryLimited exceptions.
 |      
 |          offset (int): How many rows to offset (e.g. skip) in the results.
 |              This implements an incremental result transfer feature, allowing you to
 |              view more of the available results for a single query. The rows are
 |              offset prior to the limit parameter being applied, therefore offset
 |              allows seeing additional results past a limit that matches the maximum
 |              number of results. Note that DNSDB recalculates the results for each
 |              query and the order of results might not be preserved. Therefore, this
 |              capability is not a valid way to walk all results over multiple queries
 |              – some results might be missing and some might be duplicated. The actual
 |              offset that can be used is limited or for certain API keys, offset is
 |              not allowed – see the offset_max rate_limit key below.
```

<a name="dnsdb2.Client.summarize_rdata_ip"></a>
#### summarize\_rdata\_ip

```
 |  summarize_rdata_ip = f(self, ip: str, ignore_limited: bool = False, **params)
 |      Executes a summarize data ip query.
 |      
 |      Args:
 |          ip (str): One of an IPv4 or IPv6 single address, with a prefix length, or
 |              with an address range.
 |          time_first_before (int): provide results before the defined timestamp for
 |              when the DNS record was first observed. For example, the URL parameter
 |              “time_first_before=1420070400” will only provide matching DNS records
 |              that were first observed before (or older than) January 1, 2015.
 |              
 |          time_first_after (int): provide results after the defined timestamp for when
 |              the DNS record was first observed. For example, the URL parameter
 |              “time_first_after=-31536000” will only provide results that were first
 |              observed within the last year.
 |              
 |          time_last_before (int): provide results before the defined timestamp for
 |              when the DNS record was last observed. For example, the URL parameter
 |              “time_last_before=1356998400” will only provide results for DNS records
 |              that were last observed before 2013.
 |              
 |          time_last_after (int): provide results after the defined timestamp for when
 |              the DNS record was last observed. For example, the URL parameter
 |              “time_last_after=-2678400” will only provide results that were last
 |              observed after 31 days ago.    
 |      
 |          limit (int): Limit for the number of results returned via these lookup
 |              methods. There is a built-in limit to the number of results that are
 |              returned via these lookup methods. The default limit is set at 10,000.
 |              This limit can be raised or lowered by setting the “limit” query
 |              parameter.
 |      
 |              There is also a maximum number of results allowed; requesting a limit
 |              greater than the maximum will only return the maximum. See results_max
 |              below for information on that maximum. If “?limit=0” is used then DNSDB
 |              will return the maximum number of results allowed. Obviously, if there
 |              are less results for the query than the requested limit, only the actual
 |              amount can be returned.
 |      
 |          id (str): Client software specific identity of the user of the API client.
 |              Comprised of an alphanumeric string, a colon, and an alphanumeric
 |              string, limited to thirty characters. This may be logged by the DNSDB
 |              API server.
 |      
 |          aggr (bool): Aggregated results group identical rrsets across all time
 |              periods and is the classic behavior from querying the DNSDB. This means
 |              you could get the total number of times an rrset has been observed, but
 |              not when it was observed. Unaggregated results ungroup identical rrsets,
 |              allowing you to see how the domain name was resolved in the DNS across
 |              the full-time range covered in DNSDB (subject to time fencing). This can
 |              give a more accurate impression of record request volume across time
 |              because it will reveal the distinct timestamps of records whose values
 |              are repeated. You can answer questions like, “Was a domain parked for a
 |              long time, mostly unused, until it was repurposed for serving malware or
 |              relaying spam, but then was abandoned again?” It allows you to see if a
 |              record was observed heavily in the last week vs. having been observed
 |              constantly for years.
 |      
 |          humantime (bool): A value that is True if time values (in time_first,
 |              time_last, zone_time_first, zone_time_last) should be returned in human
 |              readable (RFC3339 compliant) format or False if Unix-style time values
 |              in seconds since the epoch should be returned. False is the classic
 |              behavior from querying the DNSDB and is the default value for this
 |              option.
 |      
 |          ignore_limited(bool): Suppress QueryLimited exceptions.
 |      
 |          max_count (int): max_count controls stopping when we reach that summary
 |              count. The resulting total count can exceed max_count as it will include
 |              the entire count from the last rrset examined.
 |      
 |              The default is to not constrain the count.
```

<a name="dnsdb2.Client.lookup_rdata_raw"></a>
#### lookup\_rdata\_raw

```
 |  lookup_rdata_raw = f(self, raw_rdata: str, rrtype: str = None, ignore_limited: bool = False, **params)
 |      Executes a lookup data raw query.
 |      
 |      Args:
 |          raw_rdata (str): An even number of hexadecimal digits specifying a raw
 |              octet string.
 |          rrtype (str): a DNS RRtype mnemonic.
 |      
 |          time_first_before (int): provide results before the defined timestamp for
 |              when the DNS record was first observed. For example, the URL parameter
 |              “time_first_before=1420070400” will only provide matching DNS records
 |              that were first observed before (or older than) January 1, 2015.
 |              
 |          time_first_after (int): provide results after the defined timestamp for when
 |              the DNS record was first observed. For example, the URL parameter
 |              “time_first_after=-31536000” will only provide results that were first
 |              observed within the last year.
 |              
 |          time_last_before (int): provide results before the defined timestamp for
 |              when the DNS record was last observed. For example, the URL parameter
 |              “time_last_before=1356998400” will only provide results for DNS records
 |              that were last observed before 2013.
 |              
 |          time_last_after (int): provide results after the defined timestamp for when
 |              the DNS record was last observed. For example, the URL parameter
 |              “time_last_after=-2678400” will only provide results that were last
 |              observed after 31 days ago.    
 |      
 |          limit (int): Limit for the number of results returned via these lookup
 |              methods. There is a built-in limit to the number of results that are
 |              returned via these lookup methods. The default limit is set at 10,000.
 |              This limit can be raised or lowered by setting the “limit” query
 |              parameter.
 |      
 |              There is also a maximum number of results allowed; requesting a limit
 |              greater than the maximum will only return the maximum. See results_max
 |              below for information on that maximum. If “?limit=0” is used then DNSDB
 |              will return the maximum number of results allowed. Obviously, if there
 |              are less results for the query than the requested limit, only the actual
 |              amount can be returned.
 |      
 |          id (str): Client software specific identity of the user of the API client.
 |              Comprised of an alphanumeric string, a colon, and an alphanumeric
 |              string, limited to thirty characters. This may be logged by the DNSDB
 |              API server.
 |      
 |          aggr (bool): Aggregated results group identical rrsets across all time
 |              periods and is the classic behavior from querying the DNSDB. This means
 |              you could get the total number of times an rrset has been observed, but
 |              not when it was observed. Unaggregated results ungroup identical rrsets,
 |              allowing you to see how the domain name was resolved in the DNS across
 |              the full-time range covered in DNSDB (subject to time fencing). This can
 |              give a more accurate impression of record request volume across time
 |              because it will reveal the distinct timestamps of records whose values
 |              are repeated. You can answer questions like, “Was a domain parked for a
 |              long time, mostly unused, until it was repurposed for serving malware or
 |              relaying spam, but then was abandoned again?” It allows you to see if a
 |              record was observed heavily in the last week vs. having been observed
 |              constantly for years.
 |      
 |          humantime (bool): A value that is True if time values (in time_first,
 |              time_last, zone_time_first, zone_time_last) should be returned in human
 |              readable (RFC3339 compliant) format or False if Unix-style time values
 |              in seconds since the epoch should be returned. False is the classic
 |              behavior from querying the DNSDB and is the default value for this
 |              option.
 |      
 |          ignore_limited(bool): Suppress QueryLimited exceptions.
 |      
 |          offset (int): How many rows to offset (e.g. skip) in the results.
 |              This implements an incremental result transfer feature, allowing you to
 |              view more of the available results for a single query. The rows are
 |              offset prior to the limit parameter being applied, therefore offset
 |              allows seeing additional results past a limit that matches the maximum
 |              number of results. Note that DNSDB recalculates the results for each
 |              query and the order of results might not be preserved. Therefore, this
 |              capability is not a valid way to walk all results over multiple queries
 |              – some results might be missing and some might be duplicated. The actual
 |              offset that can be used is limited or for certain API keys, offset is
 |              not allowed – see the offset_max rate_limit key below.
```

<a name="dnsdb2.Client.summarize_rdata_raw"></a>
#### summarize\_rdata\_raw

```
 |  summarize_rdata_raw = f(self, raw_rdata: str, rrtype: str = None, ignore_limited: bool = False, **params)
 |      Executes a summarize data raw query.
 |      
 |      Args:
 |          raw_rdata (str): An even number of hexadecimal digits specifying a raw
 |              octet string.
 |          rrtype (str): a DNS RRtype mnemonic.
 |      
 |          time_first_before (int): provide results before the defined timestamp for
 |              when the DNS record was first observed. For example, the URL parameter
 |              “time_first_before=1420070400” will only provide matching DNS records
 |              that were first observed before (or older than) January 1, 2015.
 |              
 |          time_first_after (int): provide results after the defined timestamp for when
 |              the DNS record was first observed. For example, the URL parameter
 |              “time_first_after=-31536000” will only provide results that were first
 |              observed within the last year.
 |              
 |          time_last_before (int): provide results before the defined timestamp for
 |              when the DNS record was last observed. For example, the URL parameter
 |              “time_last_before=1356998400” will only provide results for DNS records
 |              that were last observed before 2013.
 |              
 |          time_last_after (int): provide results after the defined timestamp for when
 |              the DNS record was last observed. For example, the URL parameter
 |              “time_last_after=-2678400” will only provide results that were last
 |              observed after 31 days ago.    
 |      
 |          limit (int): Limit for the number of results returned via these lookup
 |              methods. There is a built-in limit to the number of results that are
 |              returned via these lookup methods. The default limit is set at 10,000.
 |              This limit can be raised or lowered by setting the “limit” query
 |              parameter.
 |      
 |              There is also a maximum number of results allowed; requesting a limit
 |              greater than the maximum will only return the maximum. See results_max
 |              below for information on that maximum. If “?limit=0” is used then DNSDB
 |              will return the maximum number of results allowed. Obviously, if there
 |              are less results for the query than the requested limit, only the actual
 |              amount can be returned.
 |      
 |          id (str): Client software specific identity of the user of the API client.
 |              Comprised of an alphanumeric string, a colon, and an alphanumeric
 |              string, limited to thirty characters. This may be logged by the DNSDB
 |              API server.
 |      
 |          aggr (bool): Aggregated results group identical rrsets across all time
 |              periods and is the classic behavior from querying the DNSDB. This means
 |              you could get the total number of times an rrset has been observed, but
 |              not when it was observed. Unaggregated results ungroup identical rrsets,
 |              allowing you to see how the domain name was resolved in the DNS across
 |              the full-time range covered in DNSDB (subject to time fencing). This can
 |              give a more accurate impression of record request volume across time
 |              because it will reveal the distinct timestamps of records whose values
 |              are repeated. You can answer questions like, “Was a domain parked for a
 |              long time, mostly unused, until it was repurposed for serving malware or
 |              relaying spam, but then was abandoned again?” It allows you to see if a
 |              record was observed heavily in the last week vs. having been observed
 |              constantly for years.
 |      
 |          humantime (bool): A value that is True if time values (in time_first,
 |              time_last, zone_time_first, zone_time_last) should be returned in human
 |              readable (RFC3339 compliant) format or False if Unix-style time values
 |              in seconds since the epoch should be returned. False is the classic
 |              behavior from querying the DNSDB and is the default value for this
 |              option.
 |      
 |          ignore_limited(bool): Suppress QueryLimited exceptions.
 |      
 |          max_count (int): max_count controls stopping when we reach that summary
 |              count. The resulting total count can exceed max_count as it will include
 |              the entire count from the last rrset examined.
 |      
 |              The default is to not constrain the count.
```

<a name="dnsdb2.Client.flex_rrnames_regex"></a>
#### flex\_rrnames\_regex

```
 |  flex_rrnames_regex = f(self, value: str, rrtype: str = None, verbose: bool = True, ignore_limited: bool = False, **params)
 |      Executes a regex rrnames flex search query.
 |      
 |      Args:
 |          value (str): A regex to match against rrnames.
 |          rrtype (str): a DNS RRtype mnemonic.
 |      
 |          verbose (bool): Set to false to disable `count`, `time_first`, and
 |              `time_last` fields in output.
 |          time_first_before (int): provide results before the defined timestamp for
 |              when the DNS record was first observed. For example, the URL parameter
 |              “time_first_before=1420070400” will only provide matching DNS records
 |              that were first observed before (or older than) January 1, 2015.
 |              
 |          time_first_after (int): provide results after the defined timestamp for when
 |              the DNS record was first observed. For example, the URL parameter
 |              “time_first_after=-31536000” will only provide results that were first
 |              observed within the last year.
 |              
 |          time_last_before (int): provide results before the defined timestamp for
 |              when the DNS record was last observed. For example, the URL parameter
 |              “time_last_before=1356998400” will only provide results for DNS records
 |              that were last observed before 2013.
 |              
 |          time_last_after (int): provide results after the defined timestamp for when
 |              the DNS record was last observed. For example, the URL parameter
 |              “time_last_after=-2678400” will only provide results that were last
 |              observed after 31 days ago.    
 |      
 |          exclude (str): Exclude (i.e. filter-out) results that match the regex.
 |          limit (int): Limit for the number of results returned via these lookup
 |              methods. There is a built-in limit to the number of results that are
 |              returned via these lookup methods. The default limit is set at 10,000.
 |              This limit can be raised or lowered by setting the “limit” query
 |              parameter.
 |      
 |              There is also a maximum number of results allowed; requesting a limit
 |              greater than the maximum will only return the maximum. See results_max
 |              below for information on that maximum. If “?limit=0” is used then DNSDB
 |              will return the maximum number of results allowed. Obviously, if there
 |              are less results for the query than the requested limit, only the actual
 |              amount can be returned.
 |      
 |          id (str): Client software specific identity of the user of the API client.
 |              Comprised of an alphanumeric string, a colon, and an alphanumeric
 |              string, limited to thirty characters. This may be logged by the DNSDB
 |              API server.
 |      
 |          offset (int): How many rows to offset (e.g. skip) in the results.
 |              This implements an incremental result transfer feature, allowing you to
 |              view more of the available results for a single query. The rows are
 |              offset prior to the limit parameter being applied, therefore offset
 |              allows seeing additional results past a limit that matches the maximum
 |              number of results. Note that DNSDB recalculates the results for each
 |              query and the order of results might not be preserved. Therefore, this
 |              capability is not a valid way to walk all results over multiple queries
 |              – some results might be missing and some might be duplicated. The actual
 |              offset that can be used is limited or for certain API keys, offset is
 |              not allowed – see the offset_max rate_limit key below.
 |      
 |          ignore_limited(bool): Suppress QueryLimited exceptions.
```

<a name="dnsdb2.Client.flex_rrnames_glob"></a>
#### flex\_rrnames\_glob

```
 |  flex_rrnames_glob = f(self, value: str, rrtype: str = None, verbose: bool = True, ignore_limited: bool = False, **params)
 |      Executes a glob rrnames flex search query.
 |      
 |      Args:
 |          value (str): A glob to match against rrnames.
 |          rrtype (str): a DNS RRtype mnemonic.
 |      
 |          verbose (bool): Set to false to disable `count`, `time_first`, and
 |              `time_last` fields in output.
 |          time_first_before (int): provide results before the defined timestamp for
 |              when the DNS record was first observed. For example, the URL parameter
 |              “time_first_before=1420070400” will only provide matching DNS records
 |              that were first observed before (or older than) January 1, 2015.
 |              
 |          time_first_after (int): provide results after the defined timestamp for when
 |              the DNS record was first observed. For example, the URL parameter
 |              “time_first_after=-31536000” will only provide results that were first
 |              observed within the last year.
 |              
 |          time_last_before (int): provide results before the defined timestamp for
 |              when the DNS record was last observed. For example, the URL parameter
 |              “time_last_before=1356998400” will only provide results for DNS records
 |              that were last observed before 2013.
 |              
 |          time_last_after (int): provide results after the defined timestamp for when
 |              the DNS record was last observed. For example, the URL parameter
 |              “time_last_after=-2678400” will only provide results that were last
 |              observed after 31 days ago.    
 |      
 |          exclude (str): Exclude (i.e. filter-out) results that match the glob.
 |          limit (int): Limit for the number of results returned via these lookup
 |              methods. There is a built-in limit to the number of results that are
 |              returned via these lookup methods. The default limit is set at 10,000.
 |              This limit can be raised or lowered by setting the “limit” query
 |              parameter.
 |      
 |              There is also a maximum number of results allowed; requesting a limit
 |              greater than the maximum will only return the maximum. See results_max
 |              below for information on that maximum. If “?limit=0” is used then DNSDB
 |              will return the maximum number of results allowed. Obviously, if there
 |              are less results for the query than the requested limit, only the actual
 |              amount can be returned.
 |      
 |          id (str): Client software specific identity of the user of the API client.
 |              Comprised of an alphanumeric string, a colon, and an alphanumeric
 |              string, limited to thirty characters. This may be logged by the DNSDB
 |              API server.
 |      
 |          offset (int): How many rows to offset (e.g. skip) in the results.
 |              This implements an incremental result transfer feature, allowing you to
 |              view more of the available results for a single query. The rows are
 |              offset prior to the limit parameter being applied, therefore offset
 |              allows seeing additional results past a limit that matches the maximum
 |              number of results. Note that DNSDB recalculates the results for each
 |              query and the order of results might not be preserved. Therefore, this
 |              capability is not a valid way to walk all results over multiple queries
 |              – some results might be missing and some might be duplicated. The actual
 |              offset that can be used is limited or for certain API keys, offset is
 |              not allowed – see the offset_max rate_limit key below.
 |      
 |          ignore_limited(bool): Suppress QueryLimited exceptions.
```

<a name="dnsdb2.Client.flex_rdata_regex"></a>
#### flex\_rdata\_regex

```
 |  flex_rdata_regex = f(self, value: str, rrtype: str = None, verbose: bool = True, ignore_limited: bool = False, **params)
 |      Executes a regex rdata flex search query.
 |      
 |      Args:
 |          value (str): A regex to match against rdata.
 |          rrtype (str): a DNS RRtype mnemonic.
 |      
 |          verbose (bool): Set to false to disable `count`, `time_first`, and
 |              `time_last` fields in output.
 |          time_first_before (int): provide results before the defined timestamp for
 |              when the DNS record was first observed. For example, the URL parameter
 |              “time_first_before=1420070400” will only provide matching DNS records
 |              that were first observed before (or older than) January 1, 2015.
 |              
 |          time_first_after (int): provide results after the defined timestamp for when
 |              the DNS record was first observed. For example, the URL parameter
 |              “time_first_after=-31536000” will only provide results that were first
 |              observed within the last year.
 |              
 |          time_last_before (int): provide results before the defined timestamp for
 |              when the DNS record was last observed. For example, the URL parameter
 |              “time_last_before=1356998400” will only provide results for DNS records
 |              that were last observed before 2013.
 |              
 |          time_last_after (int): provide results after the defined timestamp for when
 |              the DNS record was last observed. For example, the URL parameter
 |              “time_last_after=-2678400” will only provide results that were last
 |              observed after 31 days ago.    
 |      
 |          exclude (str): Exclude (i.e. filter-out) results that match the regex.
 |          limit (int): Limit for the number of results returned via these lookup
 |              methods. There is a built-in limit to the number of results that are
 |              returned via these lookup methods. The default limit is set at 10,000.
 |              This limit can be raised or lowered by setting the “limit” query
 |              parameter.
 |      
 |              There is also a maximum number of results allowed; requesting a limit
 |              greater than the maximum will only return the maximum. See results_max
 |              below for information on that maximum. If “?limit=0” is used then DNSDB
 |              will return the maximum number of results allowed. Obviously, if there
 |              are less results for the query than the requested limit, only the actual
 |              amount can be returned.
 |      
 |          id (str): Client software specific identity of the user of the API client.
 |              Comprised of an alphanumeric string, a colon, and an alphanumeric
 |              string, limited to thirty characters. This may be logged by the DNSDB
 |              API server.
 |      
 |          offset (int): How many rows to offset (e.g. skip) in the results.
 |              This implements an incremental result transfer feature, allowing you to
 |              view more of the available results for a single query. The rows are
 |              offset prior to the limit parameter being applied, therefore offset
 |              allows seeing additional results past a limit that matches the maximum
 |              number of results. Note that DNSDB recalculates the results for each
 |              query and the order of results might not be preserved. Therefore, this
 |              capability is not a valid way to walk all results over multiple queries
 |              – some results might be missing and some might be duplicated. The actual
 |              offset that can be used is limited or for certain API keys, offset is
 |              not allowed – see the offset_max rate_limit key below.
 |      
 |          ignore_limited(bool): Suppress QueryLimited exceptions.
```

<a name="dnsdb2.Client.flex_rdata_glob"></a>
#### flex\_rdata\_glob

```
flex_rdata_glob = f(self, value: str, rrtype: str = None, verbose: bool = True, ignore_limited: bool = False, **params)
 |      Executes a glob rdata flex search query.
 |      
 |      Args:
 |          value (str): A glob to match against rdata.
 |          rrtype (str): a DNS RRtype mnemonic.
 |      
 |          verbose (bool): Set to false to disable `count`, `time_first`, and
 |              `time_last` fields in output.
 |          time_first_before (int): provide results before the defined timestamp for
 |              when the DNS record was first observed. For example, the URL parameter
 |              “time_first_before=1420070400” will only provide matching DNS records
 |              that were first observed before (or older than) January 1, 2015.
 |              
 |          time_first_after (int): provide results after the defined timestamp for when
 |              the DNS record was first observed. For example, the URL parameter
 |              “time_first_after=-31536000” will only provide results that were first
 |              observed within the last year.
 |              
 |          time_last_before (int): provide results before the defined timestamp for
 |              when the DNS record was last observed. For example, the URL parameter
 |              “time_last_before=1356998400” will only provide results for DNS records
 |              that were last observed before 2013.
 |              
 |          time_last_after (int): provide results after the defined timestamp for when
 |              the DNS record was last observed. For example, the URL parameter
 |              “time_last_after=-2678400” will only provide results that were last
 |              observed after 31 days ago.    
 |      
 |          exclude (str): Exclude (i.e. filter-out) results that match the glob.
 |          limit (int): Limit for the number of results returned via these lookup
 |              methods. There is a built-in limit to the number of results that are
 |              returned via these lookup methods. The default limit is set at 10,000.
 |              This limit can be raised or lowered by setting the “limit” query
 |              parameter.
 |      
 |              There is also a maximum number of results allowed; requesting a limit
 |              greater than the maximum will only return the maximum. See results_max
 |              below for information on that maximum. If “?limit=0” is used then DNSDB
 |              will return the maximum number of results allowed. Obviously, if there
 |              are less results for the query than the requested limit, only the actual
 |              amount can be returned.
 |      
 |          id (str): Client software specific identity of the user of the API client.
 |              Comprised of an alphanumeric string, a colon, and an alphanumeric
 |              string, limited to thirty characters. This may be logged by the DNSDB
 |              API server.
 |      
 |          offset (int): How many rows to offset (e.g. skip) in the results.
 |              This implements an incremental result transfer feature, allowing you to
 |              view more of the available results for a single query. The rows are
 |              offset prior to the limit parameter being applied, therefore offset
 |              allows seeing additional results past a limit that matches the maximum
 |              number of results. Note that DNSDB recalculates the results for each
 |              query and the order of results might not be preserved. Therefore, this
 |              capability is not a valid way to walk all results over multiple queries
 |              – some results might be missing and some might be duplicated. The actual
 |              offset that can be used is limited or for certain API keys, offset is
 |              not allowed – see the offset_max rate_limit key below.
 |      
 |          ignore_limited(bool): Suppress QueryLimited exceptions.
```

<a name="dnsdb2.DnsdbException"></a>
### DnsdbException Objects

```python
class DnsdbException(Exception)
```

Common base class for all DNSDB exceptions.

<a name="dnsdb2.AccessDenied"></a>
### AccessDenied Objects

```python
class AccessDenied(DnsdbException)
```

Exception raised if the API key is not authorized (usually indicates the
block quota is expired), or the provided API key is not valid, or the
Client IP address not authorized for this API key.

<a name="dnsdb2.OffsetError"></a>
### OffsetError Objects

```python
class OffsetError(DnsdbException)
```

Exception raised if the offset value is greater than the maximum allowed
or if an offset value was provided when not permitted.

<a name="dnsdb2.QuotaExceeded"></a>
### QuotaExceeded Objects

```python
class QuotaExceeded(DnsdbException)
```

Exception raised if you have exceeded your quota and no new requests will
be accepted at this time.

For time-based quotas : The API key’s daily quota limit is exceeded. The
quota will automatically replenish, usually at the start of the next day.

For block-based quotas : The block quota is exhausted. You may need to
purchase a larger quota.

For burst rate secondary quotas : There were too many queries within the
burst window. The window will automatically reopen at its end.

<a name="dnsdb2.ConcurrencyExceeded"></a>
### ConcurrencyExceeded Objects

```python
class ConcurrencyExceeded(DnsdbException)
```

Exception raised if the limit of number of concurrent connections is exceeded.

<a name="dnsdb2.QueryError"></a>
### QueryError Objects

```python
class QueryError(DnsdbException)
```

Exception raised if a communication error occurs while executing a query, or
the server reports an error due to invalid arguments.

<a name="dnsdb2.QueryFailed"></a>
### QueryFailed Objects

```python
class QueryFailed(DnsdbException)
```

Exception raised if an error is reported by the server while a query is running.

<a name="dnsdb2.QueryLimited"></a>
### QueryLimited Objects

```python
class QueryLimited(DnsdbException)
```

Exception raised if the result limit is reached.

<a name="dnsdb2.QueryTruncated"></a>
### QueryTruncated Objects

```python
class QueryTruncated(DnsdbException)
```

Exception raised if query results are incomplete due to a server error.

<a name="dnsdb2.ProtocolError"></a>
### ProtocolError Objects

```python
class ProtocolError(DnsdbException)
```

Exception raised if invalid data is received via the Streaming
Application Framework.


