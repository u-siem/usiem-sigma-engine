# uSIEM Sigma Rule Engine
uSIEM Sigma Rule Engine

Native Rule engine based on https://github.com/SigmaHQ/sigma

### How it works

All SIGMA rules that don't depend on a time interval are checked against each log if the log category/service matches the rules.
The following SIGMA rule is checked against every log marked as webserver (uSIEM Log Event of type WebServer).
If the rule has a time interval, then it uses a partially matched check. If parts of the rule not dependant on time matches, then its updated a shared counter stored in REDIS that uses the aggregattion over time. With it goes a condition that if the counter is bigger than the threshold of the rule, then the alert is fired.


```yml
title: Citrix Netscaler Attack CVE-2019-19781
id: ac5a6409-8c89-44c2-8d64-668c29a2d756
status: experimental
description: Detects CVE-2019-19781 exploitation attempt against Citrix Netscaler, Application Delivery Controller and Citrix Gateway Attack
author: Arnim Rupp, Florian Roth
date: 2020/01/02
modified: 2020/09/03
references:
    - https://support.citrix.com/article/CTX267679
    - https://support.citrix.com/article/CTX267027
    - https://isc.sans.edu/diary/25686
    - https://twitter.com/mpgn_x64/status/1216787131210829826
    - https://github.com/x1sec/x1sec.github.io/blob/master/CVE-2019-19781-DFIR.md
logsource:
    category: webserver
    definition: 'Make sure that your Netscaler appliance logs all kinds of attacks (test with http://your-citrix-gw.net/robots.txt). The directory traversal with ../ might not be needed on certain cloud instances or for authenticated users, so we also check for direct paths. All scripts in portal/scripts are exploitable except logout.pl.'
detection:
    selection:
        c-uri: 
            - '*/../vpns/*'
            - '*/vpns/cfg/smb.conf'
            - '*/vpns/portal/scripts/*.pl*'
    condition: selection
fields:
    - client_ip
    - vhost
    - url
    - response
falsepositives:
    - Unknown
level: critical
tags:
    - attack.initial_access
    - attack.t1190
```

### Aggregations

The aggregations uses a shared memmory in REDIS to do the MAGIC:
* count: If no field name is passed, counts the number of logs that matched the query. The alert is fired whith the contents of all the logs, using another query against the DDBB.
* min: Uses a local cache and a remote cache in REDIS.
* max: Uses a local cache and a remote cache in REDIS.
* avg: Always updates periodically the value of the REDIS cache.
* sum: Always updates periodically the value of the REDIS cache.


### Falsepositives

A list of known false positives that may occur. The engine supports using other SIGMA rule as a checker before creating an alert, using its ID. This separates the false positives from the rule.

```yml
falsepositives:
    - ac5a6409-8c89-44c2-8d64-668c29a2d757
level: critical
tags:
    - attack.initial_access
    - attack.t1190
```

### Tenant exceptions

A list of known false positives that may occur only for that particular Tenant. Use only when really needed.

```yml
falsepositives:
    - ac5a6409-8c89-44c2-8d64-668c29a2d757
tenant_exceptions:
    tenant_client_xxx: ac5a6409-8c89-44c2-8d64-668c29a2d757
    tenant_client_yyy: ac5a6409-8c89-44c2-8d64-668c29a2d758
level: critical
tags:
    - attack.initial_access
    - attack.t1190
```

### Parameters
We can use a new field called "parameters" to convert our normal SIGMA rule into a Lambda SIGMA rule that can accept log fields as parameters to build. This can be used to build a pipeline with multiple steps. This LambdaSigmas are executed against the Log DDBB. Can't be used in a Falsepositive field, only as a next phase (next_stage field).

```yml
next_stage: ac5a6409-8c89-44c2-8d64-668c29a2d758
level: critical
tags:
    - attack.initial_access
    - attack.t1190
```

And parameters:
```yml
parameters:
    source_ip: source.ip
    cat: category
    url: url.full
```