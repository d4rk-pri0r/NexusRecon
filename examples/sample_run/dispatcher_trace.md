# Dispatcher Trace — GitLab NexusRecon Demo

Campaign: `nr-20260520-185135-f7a176fb`

This trace is the operational backbone of the campaign: which tools
the framework chose to run, in what order, against what targets, and
with what results. Generated from the hash-chained audit log
(`audit_excerpt.jsonl`) which is tamper-evident — every entry's
`entry_hash` references the previous entry's hash, so a single
modified line breaks the chain.

Format:
```
<HH:MM:SS>  seq=N  EVENT          tool        target    result
```

---


## 18:51
`18:51:36`  seq=  2  **START**          `crtsh               ` (T0)  target=`gitlab.com`
`18:51:36`  seq=  3  **START**          `subfinder           ` (T0)  target=`gitlab.com`

## 18:52
`18:52:07`  seq=  4  **OK**              `subfinder           `            result_count=332 runtime=31045ms
`18:52:07`  seq=  5  **START**          `amass               ` (T0)  target=`gitlab.com`

## 18:53
`18:53:09`  seq=  6  **OK**              `amass               `            result_count=0   runtime=62177ms
`18:53:10`  seq=  7  **ERROR**           `crtsh               `            crt.sh returned 502
`18:53:10`  seq=  8  **START**          `dns                 ` (T1)  target=`gitlab.com`
`18:53:10`  seq=  9  **START**          `whois               ` (T0)  target=`gitlab.com`
`18:53:10`  seq= 10  **OK**              `whois               `            result_count=1   runtime=519ms
`18:53:10`  seq= 11  **START**          `asn_bgp             ` (T0)  target=`gitlab.com`
`18:53:10`  seq= 12  **ERROR**           `asn_bgp             `            [Errno 8] nodename nor servname provided, or not known
`18:53:11`  seq= 13  **OK**              `dns                 `            result_count=57  runtime=721ms

## 18:54
`18:54:37`  seq= 14  **START**          `ransomwatch         ` (T0)  target=`gitlab.com`
`18:54:37`  seq= 15  **START**          `ahmia               ` (T0)  target=`gitlab.com`
`18:54:37`  seq= 16  **START**          `pastebin_scan       ` (T0)  target=`gitlab.com`
`18:54:37`  seq= 17  **START**          `certstream_recent   ` (T0)  target=`gitlab.com`
`18:54:37`  seq= 18  **OK**              `ransomwatch         `            result_count=15  runtime=149ms
`18:54:37`  seq= 19  **OK**              `pastebin_scan       `            result_count=0   runtime=155ms
`18:54:38`  seq= 20  **OK**              `ahmia               `            result_count=0   runtime=571ms
`18:54:59`  seq= 21  **OK**              `certstream_recent   `            result_count=0   runtime=21945ms

## 18:55
`18:55:04`  seq= 22  **START**          `theharvester        ` (T0)  target=`gitlab.com`
`18:55:04`  seq= 23  **ERROR**           `theharvester        `            theHarvester binary not found in PATH (tried 'theHarvester' 
`18:55:04`  seq= 24  **START**          `hunter              ` (T0)  target=`gitlab.com`
`18:55:04`  seq= 25  **START**          `shodan              ` (T0)  target=`gitlab.com`
`18:55:04`  seq= 26  **START**          `github_recon        ` (T0)  target=`gitlab.com`
`18:55:04`  seq= 27  **START**          `hudsonrock          ` (T0)  target=`gitlab.com`
`18:55:05`  seq= 28  **OK**              `hudsonrock          `            result_count=0   runtime=455ms
`18:55:05`  seq= 29  **OK**              `hunter              `            result_count=10  runtime=799ms
`18:55:06`  seq= 30  **OK**              `shodan              `            result_count=88  runtime=1337ms
`18:55:27`  seq= 31  **OK**              `github_recon        `            result_count=0   runtime=22453ms
`18:55:27`  seq= 32  **START**          `azure_m365_recon    ` (T0)  target=`gitlab.com`
`18:55:50`  seq= 33  **OK**              `azure_m365_recon    `            result_count=9   runtime=23568ms
`18:55:50`  seq= 34  **START**          `aws_recon           ` (T0)  target=`gitlab.com`

## 18:59
`18:59:57`  seq= 35  **OK**              `aws_recon           `            result_count=22  runtime=246715ms
`18:59:57`  seq= 36  **START**          `gcp_recon           ` (T0)  target=`gitlab.com`

## 19:00
`19:00:00`  seq= 37  **OK**              `gcp_recon           `            result_count=9   runtime=3008ms
`19:00:00`  seq= 38  **START**          `theharvester        ` (T0)  target=`gitlab.com`
`19:00:00`  seq= 39  **ERROR**           `theharvester        `            theHarvester binary not found in PATH (tried 'theHarvester' 
`19:00:00`  seq= 40  **OK**              `hunter              `            result_count=0   runtime=0ms
`19:00:00`  seq= 41  **START**          `email_format        ` (T0)  target=`gitlab.com`
`19:00:00`  seq= 42  **OK**              `email_format        `            result_count=10  runtime=0ms
`19:00:00`  seq= 43  **START**          `playstore           ` (T0)  target=`gitlab.com`
`19:00:00`  seq= 44  **OK**              `playstore           `            result_count=7   runtime=318ms
`19:00:00`  seq= 45  **START**          `holehe              ` (T0)  target=`marin@gitlab.com`
`19:00:00`  seq= 46  **START**          `holehe              ` (T0)  target=`jcoghlan@gitlab.com`
`19:00:00`  seq= 47  **START**          `holehe              ` (T0)  target=`rpack@gitlab.com`
`19:00:00`  seq= 48  **START**          `holehe              ` (T0)  target=`eliran@gitlab.com`
`19:00:00`  seq= 49  **START**          `holehe              ` (T0)  target=`john@gitlab.com`
`19:00:18`  seq= 50  **OK**              `holehe              `            result_count=4   runtime=17447ms
`19:00:18`  seq= 51  **START**          `holehe              ` (T0)  target=`tzallmann@gitlab.com`
`19:00:18`  seq= 52  **OK**              `holehe              `            result_count=3   runtime=18021ms
`19:00:18`  seq= 53  **START**          `holehe              ` (T0)  target=`mmacfarlane@gitlab.com`
`19:00:20`  seq= 54  **OK**              `holehe              `            result_count=1   runtime=19328ms
`19:00:20`  seq= 55  **START**          `holehe              ` (T0)  target=`ashen@gitlab.com`
`19:00:21`  seq= 56  **OK**              `holehe              `            result_count=3   runtime=20963ms
`19:00:21`  seq= 57  **START**          `holehe              ` (T0)  target=`lcharles@gitlab.com`
`19:00:22`  seq= 58  **OK**              `holehe              `            result_count=4   runtime=21145ms
`19:00:22`  seq= 59  **START**          `holehe              ` (T0)  target=`karmstrong@gitlab.com`
`19:00:38`  seq= 60  **OK**              `holehe              `            result_count=3   runtime=20511ms
`19:00:39`  seq= 61  **OK**              `holehe              `            result_count=5   runtime=20590ms
`19:00:41`  seq= 62  **OK**              `holehe              `            result_count=1   runtime=21392ms
`19:00:42`  seq= 63  **OK**              `holehe              `            result_count=3   runtime=20418ms
`19:00:42`  seq= 64  **OK**              `holehe              `            result_count=4   runtime=20588ms

## 19:01
`19:01:44`  seq= 65  **START**          `crtsh               ` (T0)  target=`gitlab.com`
`19:01:44`  seq= 66  **OK**              `subfinder           `            result_count=0   runtime=0ms
`19:01:44`  seq= 67  **START**          `virustotal          ` (T0)  target=`gitlab.com`
`19:01:44`  seq= 68  **START**          `urlscan             ` (T0)  target=`gitlab.com`
`19:01:44`  seq= 69  **START**          `subdomain_takeover  ` (T1)  target=`gitlab.com`
`19:01:44`  seq= 70  **OK**              `subdomain_takeover  `            result_count=0   runtime=29ms
`19:01:45`  seq= 71  **OK**              `urlscan             `            result_count=20  runtime=1107ms
`19:01:46`  seq= 72  **OK**              `virustotal          `            result_count=20  runtime=1910ms
`19:01:59`  seq= 73  **ERROR**           `crtsh               `            (no error message provided by tool)
`19:01:59`  seq= 74  **OK**              `github_recon        `            result_count=0   runtime=0ms
`19:01:59`  seq= 75  **START**          `gitleaks            ` (T0)  target=`gitlab.com`

## 19:02
`19:02:00`  seq= 76  **OK**              `gitleaks            `            result_count=0   runtime=242ms
`19:02:00`  seq= 77  **START**          `trufflehog          ` (T0)  target=`gitlab.com`
`19:02:02`  seq= 78  **OK**              `trufflehog          `            result_count=0   runtime=2579ms
`19:02:02`  seq= 79  **START**          `gitdorker           ` (T0)  target=`gitlab.com`
`19:02:02`  seq= 80  **START**          `postman             ` (T0)  target=`gitlab.com`
`19:02:02`  seq= 81  **START**          `dockerhub           ` (T0)  target=`gitlab.com`
`19:02:02`  seq= 82  **OK**              `dockerhub           `            result_count=24  runtime=81ms
`19:02:02`  seq= 83  **OK**              `postman             `            result_count=0   runtime=316ms
`19:02:25`  seq= 84  **OK**              `gitdorker           `            result_count=0   runtime=23330ms

## 19:03
`19:03:44`  seq= 85  **START**          `httpx               ` (T2)  target=`auth.aws.gitlab.com`
`19:03:44`  seq= 86  **OK**              `httpx               `            result_count=0   runtime=412ms
`19:03:44`  seq= 87  **START**          `httpx               ` (T2)  target=`ai-gateway-eks.cloud.gitlab.com`
`19:03:45`  seq= 88  **OK**              `httpx               `            result_count=0   runtime=106ms
`19:03:45`  seq= 89  **START**          `httpx               ` (T2)  target=`privacy.gitlab.com`
`19:03:45`  seq= 90  **OK**              `httpx               `            result_count=0   runtime=106ms
`19:03:45`  seq= 91  **START**          `httpx               ` (T2)  target=`deps.staging.sec.gitlab.com`
`19:03:45`  seq= 92  **OK**              `httpx               `            result_count=0   runtime=105ms
`19:03:45`  seq= 93  **START**          `httpx               ` (T2)  target=`enable.gitlab.com`
`19:03:45`  seq= 94  **OK**              `httpx               `            result_count=0   runtime=105ms
`19:03:45`  seq= 95  **START**          `httpx               ` (T2)  target=`kas1.pre.gitlab.com`
`19:03:45`  seq= 96  **OK**              `httpx               `            result_count=0   runtime=105ms
`19:03:45`  seq= 97  **START**          `httpx               ` (T2)  target=`registry.geo.staging-ref.gitlab.com`
`19:03:45`  seq= 98  **OK**              `httpx               `            result_count=0   runtime=106ms
`19:03:45`  seq= 99  **START**          `httpx               ` (T2)  target=`www.registry.gitlab.com`
`19:03:45`  seq=100  **OK**              `httpx               `            result_count=0   runtime=105ms
`19:03:45`  seq=101  **START**          `httpx               ` (T2)  target=`auth.token.gitlab.com`
`19:03:45`  seq=102  **OK**              `httpx               `            result_count=0   runtime=103ms
`19:03:45`  seq=103  **START**          `httpx               ` (T2)  target=`cx-plan.gitlab.com`
`19:03:45`  seq=104  **OK**              `httpx               `            result_count=0   runtime=100ms
`19:03:45`  seq=105  **START**          `httpx               ` (T2)  target=`manager-staging.community.gitlab.com`
`19:03:45`  seq=106  **OK**              `httpx               `            result_count=0   runtime=99ms
`19:03:45`  seq=107  **START**          `httpx               ` (T2)  target=`prometheus-2.gitlab.com`
`19:03:46`  seq=108  **OK**              `httpx               `            result_count=0   runtime=100ms
`19:03:46`  seq=109  **START**          `httpx               ` (T2)  target=`www.chef.gitlab.com`
`19:03:46`  seq=110  **OK**              `httpx               `            result_count=0   runtime=104ms
`19:03:46`  seq=111  **START**          `httpx               ` (T2)  target=`4456656-review-jeldergl-m-i8pqtg.desig`
`19:03:46`  seq=112  **OK**              `httpx               `            result_count=0   runtime=100ms
`19:03:46`  seq=113  **START**          `httpx               ` (T2)  target=`auth.staging.gitlab.com`
`19:03:46`  seq=114  **OK**              `httpx               `            result_count=0   runtime=98ms
`19:03:46`  seq=115  **START**          `httpx               ` (T2)  target=`grafana.cell-c01j2gdw0zfdafxr6.cells.g`
`19:03:46`  seq=116  **OK**              `httpx               `            result_count=0   runtime=98ms
`19:03:46`  seq=117  **START**          `httpx               ` (T2)  target=`media.docs.gitlab.com`
`19:03:46`  seq=118  **OK**              `httpx               `            result_count=0   runtime=98ms
`19:03:46`  seq=119  **START**          `httpx               ` (T2)  target=`next.gitlab.com`
`19:03:46`  seq=120  **OK**              `httpx               `            result_count=0   runtime=98ms
`19:03:46`  seq=121  **START**          `httpx               ` (T2)  target=`prometheus-app.db-integration.gitlab.c`
`19:03:46`  seq=122  **OK**              `httpx               `            result_count=0   runtime=99ms
`19:03:46`  seq=123  **START**          `httpx               ` (T2)  target=`www.dr.gitlab.com`
`19:03:46`  seq=124  **OK**              `httpx               `            result_count=0   runtime=98ms
`19:03:46`  seq=125  **START**          `httpx               ` (T2)  target=`opensearch.us-east-1.cell-c01k35wpsh58`
`19:03:46`  seq=126  **OK**              `httpx               `            result_count=0   runtime=99ms
`19:03:46`  seq=127  **START**          `httpx               ` (T2)  target=`4456656-review-nadia-sotn-e9wgrt.desig`
`19:03:47`  seq=128  **OK**              `httpx               `            result_count=0   runtime=98ms
`19:03:47`  seq=129  **START**          `httpx               ` (T2)  target=`campaign-manager.gitlab.com`
`19:03:47`  seq=130  **OK**              `httpx               `            result_count=0   runtime=98ms
`19:03:47`  seq=131  **START**          `httpx               ` (T2)  target=`private.analytics.gitlab.com`
`19:03:47`  seq=132  **OK**              `httpx               `            result_count=0   runtime=98ms
`19:03:47`  seq=133  **START**          `httpx               ` (T2)  target=`registry.gitlab.com`
`19:03:47`  seq=134  **OK**              `httpx               `            result_count=0   runtime=98ms
`19:03:47`  seq=135  **START**          `httpx               ` (T2)  target=`arewefastyet.gitlab.com`
`19:03:47`  seq=136  **OK**              `httpx               `            result_count=0   runtime=99ms
`19:03:47`  seq=137  **START**          `httpx               ` (T2)  target=`opensearch.cell-c01j2gdw0zfdafxr6.cell`
`19:03:47`  seq=138  **OK**              `httpx               `            result_count=0   runtime=100ms
`19:03:47`  seq=139  **START**          `httpx               ` (T2)  target=`www.sync.geo.gitlab.com`
`19:03:47`  seq=140  **OK**              `httpx               `            result_count=0   runtime=107ms
`19:03:47`  seq=141  **START**          `httpx               ` (T2)  target=`tiar.gitlab.com`
`19:03:47`  seq=142  **OK**              `httpx               `            result_count=0   runtime=106ms
`19:03:47`  seq=143  **START**          `httpx               ` (T2)  target=`next.staging.gitlab.com`
`19:03:47`  seq=144  **OK**              `httpx               `            result_count=0   runtime=106ms
`19:03:47`  seq=145  **START**          `httpx               ` (T2)  target=`4456656-review-feat-add-n-atvmbp.desig`
`19:03:48`  seq=146  **OK**              `httpx               `            result_count=0   runtime=105ms
`19:03:48`  seq=147  **START**          `httpx               ` (T2)  target=`4456656-review-1325-vpat-wdbu9w.design`
`19:03:48`  seq=148  **OK**              `httpx               `            result_count=0   runtime=105ms
`19:03:48`  seq=149  **START**          `httpx               ` (T2)  target=`alerts.gitlab.com`
`19:03:48`  seq=150  **OK**              `httpx               `            result_count=0   runtime=105ms
`19:03:48`  seq=151  **START**          `httpx               ` (T2)  target=`auth.gcp.gitlab.com`
`19:03:48`  seq=152  **OK**              `httpx               `            result_count=0   runtime=105ms
`19:03:48`  seq=153  **START**          `httpx               ` (T2)  target=`geo2.gitlab.com`
`19:03:48`  seq=154  **OK**              `httpx               `            result_count=0   runtime=105ms
`19:03:48`  seq=155  **START**          `httpx               ` (T2)  target=`internal.gitlab.com`
`19:03:48`  seq=156  **OK**              `httpx               `            result_count=0   runtime=106ms
`19:03:48`  seq=157  **START**          `httpx               ` (T2)  target=`ir.gitlab.com`
`19:03:48`  seq=158  **OK**              `httpx               `            result_count=0   runtime=105ms
`19:03:48`  seq=159  **START**          `httpx               ` (T2)  target=`prometheus-db.db-integration.gitlab.co`
`19:03:48`  seq=160  **OK**              `httpx               `            result_count=0   runtime=137ms
`19:03:48`  seq=161  **START**          `httpx               ` (T2)  target=`prometheus.staging-ref.gitlab.com`
`19:03:48`  seq=162  **OK**              `httpx               `            result_count=0   runtime=108ms
`19:03:48`  seq=163  **START**          `httpx               ` (T2)  target=`go.gitlab.com`
`19:03:49`  seq=164  **OK**              `httpx               `            result_count=0   runtime=114ms
`19:03:49`  seq=165  **START**          `httpx               ` (T2)  target=`cell-c01j2gdw0zfdafxr6.cells.gitlab.co`
`19:03:49`  seq=166  **OK**              `httpx               `            result_count=0   runtime=117ms
`19:03:49`  seq=167  **START**          `httpx               ` (T2)  target=`customers.staging.gitlab.com`
`19:03:49`  seq=168  **OK**              `httpx               `            result_count=0   runtime=117ms
`19:03:49`  seq=169  **START**          `httpx               ` (T2)  target=`cxr.gitlab.com`
`19:03:49`  seq=170  **OK**              `httpx               `            result_count=0   runtime=162ms
`19:03:49`  seq=171  **START**          `httpx               ` (T2)  target=`hub.gitlab.com`
`19:03:49`  seq=172  **OK**              `httpx               `            result_count=0   runtime=122ms
`19:03:49`  seq=173  **START**          `httpx               ` (T2)  target=`live.docs.gitlab.com`
`19:03:49`  seq=174  **OK**              `httpx               `            result_count=0   runtime=125ms
`19:03:49`  seq=175  **START**          `httpx               ` (T2)  target=`runners-cache-3.gitlab.com`
`19:03:49`  seq=176  **OK**              `httpx               `            result_count=0   runtime=123ms
`19:03:49`  seq=177  **START**          `httpx               ` (T2)  target=`www.prometheus-2.gitlab.com`
`19:03:49`  seq=178  **OK**              `httpx               `            result_count=0   runtime=121ms
`19:03:49`  seq=179  **START**          `httpx               ` (T2)  target=`4456656-review-better-err-r52kcp.desig`
`19:03:50`  seq=180  **OK**              `httpx               `            result_count=0   runtime=120ms
`19:03:50`  seq=181  **START**          `httpx               ` (T2)  target=`pre.gitlab.com`
`19:03:50`  seq=182  **OK**              `httpx               `            result_count=0   runtime=126ms
`19:03:50`  seq=183  **START**          `httpx               ` (T2)  target=`v2.about.gitlab.com`
`19:03:50`  seq=184  **OK**              `httpx               `            result_count=0   runtime=121ms
`19:03:50`  seq=185  **START**          `httpx               ` (T2)  target=`us-east1.cell-c01j2gdw0zfdafxr6.cells.`
`19:03:50`  seq=186  **OK**              `httpx               `            result_count=0   runtime=122ms
`19:03:50`  seq=187  **START**          `httpx               ` (T2)  target=`www.canary.staging.gitlab.com`
`19:03:50`  seq=188  **OK**              `httpx               `            result_count=0   runtime=126ms
`19:03:50`  seq=189  **START**          `httpx               ` (T2)  target=`ci.forum.gitlab.com`
`19:03:50`  seq=190  **OK**              `httpx               `            result_count=0   runtime=125ms
`19:03:50`  seq=191  **START**          `httpx               ` (T2)  target=`developer.gitlab.com`
`19:03:50`  seq=192  **OK**              `httpx               `            result_count=0   runtime=122ms
`19:03:50`  seq=193  **START**          `httpx               ` (T2)  target=`doc.gitlab.com`
`19:03:50`  seq=194  **OK**              `httpx               `            result_count=0   runtime=121ms
`19:03:50`  seq=195  **START**          `httpx               ` (T2)  target=`metrics.gitlab.com`
`19:03:51`  seq=196  **OK**              `httpx               `            result_count=0   runtime=196ms
`19:03:51`  seq=197  **START**          `httpx               ` (T2)  target=`www.gstg.gitlab.com`
`19:03:51`  seq=198  **OK**              `httpx               `            result_count=0   runtime=259ms
`19:03:51`  seq=199  **START**          `httpx               ` (T2)  target=`snippets.gitlab.com`
`19:03:51`  seq=200  **OK**              `httpx               `            result_count=0   runtime=169ms
`19:03:51`  seq=201  **START**          `httpx               ` (T2)  target=`gitlab.com_gitlab-org_gitlab-services_`
`19:03:51`  seq=202  **OK**              `httpx               `            result_count=0   runtime=127ms
`19:03:51`  seq=203  **START**          `httpx               ` (T2)  target=`blog.about.gitlab.com`
`19:03:51`  seq=204  **OK**              `httpx               `            result_count=0   runtime=118ms
`19:03:51`  seq=205  **START**          `httpx               ` (T2)  target=`canary.gitlab.com`
`19:03:51`  seq=206  **OK**              `httpx               `            result_count=0   runtime=115ms
`19:03:51`  seq=207  **START**          `httpx               ` (T2)  target=`cert-test.staging.gitlab.com`
`19:03:52`  seq=208  **OK**              `httpx               `            result_count=0   runtime=125ms
`19:03:52`  seq=209  **START**          `httpx               ` (T2)  target=`donew.gitlab.com`
`19:03:52`  seq=210  **OK**              `httpx               `            result_count=0   runtime=145ms
`19:03:52`  seq=211  **START**          `httpx               ` (T2)  target=`do158-143.mg.gitlab.com`
`19:03:52`  seq=212  **OK**              `httpx               `            result_count=0   runtime=143ms
`19:03:52`  seq=213  **START**          `httpx               ` (T2)  target=`feedback.gitlab.com`
`19:03:52`  seq=214  **OK**              `httpx               `            result_count=0   runtime=116ms
`19:03:52`  seq=215  **START**          `httpx               ` (T2)  target=`prometheus.db-integration.gitlab.com`
`19:03:52`  seq=216  **OK**              `httpx               `            result_count=0   runtime=117ms
`19:03:52`  seq=217  **START**          `httpx               ` (T2)  target=`registry.cell-c01k35wpsh58x0j74g.cells`
`19:03:52`  seq=218  **OK**              `httpx               `            result_count=0   runtime=119ms
`19:03:52`  seq=219  **START**          `httpx               ` (T2)  target=`4456656-review-sselhorn-m-ulzly1.desig`
`19:03:52`  seq=220  **OK**              `httpx               `            result_count=0   runtime=116ms
`19:03:52`  seq=221  **START**          `httpx               ` (T2)  target=`private-runners-manager-3.gitlab.com`
`19:03:52`  seq=222  **OK**              `httpx               `            result_count=0   runtime=116ms
`19:03:52`  seq=223  **START**          `httpx               ` (T2)  target=`www.canary.gitlab.com`
`19:03:53`  seq=224  **OK**              `httpx               `            result_count=0   runtime=117ms
`19:03:53`  seq=225  **START**          `httpx               ` (T2)  target=`single.gitlab.com`
`19:03:53`  seq=226  **OK**              `httpx               `            result_count=0   runtime=114ms
`19:03:53`  seq=227  **START**          `httpx               ` (T2)  target=`www.get.gitlab.com`
`19:03:53`  seq=228  **OK**              `httpx               `            result_count=0   runtime=113ms
`19:03:53`  seq=229  **START**          `httpx               ` (T2)  target=`events.gitlab.com`
`19:03:53`  seq=230  **OK**              `httpx               `            result_count=0   runtime=120ms
`19:03:53`  seq=231  **START**          `httpx               ` (T2)  target=`www.prod.geo.gitlab.com`
`19:03:53`  seq=232  **OK**              `httpx               `            result_count=0   runtime=114ms
`19:03:53`  seq=233  **START**          `httpx               ` (T2)  target=`secrets.gitlab.com`
`19:03:53`  seq=234  **OK**              `httpx               `            result_count=0   runtime=120ms
`19:03:53`  seq=235  **START**          `httpx               ` (T2)  target=`api.community.gitlab.com`
`19:03:53`  seq=236  **OK**              `httpx               `            result_count=0   runtime=113ms
`19:03:53`  seq=237  **START**          `httpx               ` (T2)  target=`kas.us-east1.cell-c01j2gdw0zfdafxr6.ce`
`19:03:53`  seq=238  **OK**              `httpx               `            result_count=0   runtime=115ms
`19:03:53`  seq=239  **START**          `httpx               ` (T2)  target=`4456656-review-1748-glbad-aytmh6.desig`
`19:03:54`  seq=240  **OK**              `httpx               `            result_count=0   runtime=117ms
`19:03:54`  seq=241  **START**          `httpx               ` (T2)  target=`www.learn.gitlab.com`
`19:03:54`  seq=242  **OK**              `httpx               `            result_count=0   runtime=114ms
`19:03:54`  seq=243  **START**          `httpx               ` (T2)  target=`docs.runway.gitlab.com`
`19:03:54`  seq=244  **OK**              `httpx               `            result_count=0   runtime=113ms
`19:03:54`  seq=245  **START**          `httpx               ` (T2)  target=`dast-4456656-dast-default.design-stagi`
`19:03:54`  seq=246  **OK**              `httpx               `            result_count=0   runtime=111ms
`19:03:54`  seq=247  **START**          `httpx               ` (T2)  target=`runners-cache-5.gitlab.com`
`19:03:54`  seq=248  **OK**              `httpx               `            result_count=0   runtime=119ms
`19:03:54`  seq=249  **START**          `httpx               ` (T2)  target=`status.gitlab.com`
`19:03:54`  seq=250  **OK**              `httpx               `            result_count=0   runtime=114ms
`19:03:54`  seq=251  **START**          `httpx               ` (T2)  target=`4456656-review-spacing-ex-nrw7ke.desig`
`19:03:54`  seq=252  **OK**              `httpx               `            result_count=0   runtime=119ms
`19:03:54`  seq=253  **START**          `httpx               ` (T2)  target=`cell-c01k35wpsh58x0j74g.cells.gitlab.c`
`19:03:54`  seq=254  **OK**              `httpx               `            result_count=0   runtime=113ms
`19:03:54`  seq=255  **START**          `httpx               ` (T2)  target=`stats.gitlab.com`
`19:03:54`  seq=256  **OK**              `httpx               `            result_count=0   runtime=113ms
`19:03:54`  seq=257  **START**          `httpx               ` (T2)  target=`triage-ops.gitlab.com`
`19:03:55`  seq=258  **OK**              `httpx               `            result_count=0   runtime=116ms
`19:03:55`  seq=259  **START**          `httpx               ` (T2)  target=`trust.gitlab.com`
`19:03:55`  seq=260  **OK**              `httpx               `            result_count=0   runtime=114ms
`19:03:55`  seq=261  **START**          `httpx               ` (T2)  target=`usagestats.gitlab.com`
`19:03:55`  seq=262  **OK**              `httpx               `            result_count=0   runtime=116ms
`19:03:55`  seq=263  **START**          `httpx               ` (T2)  target=`www.forum.gitlab.com`
`19:03:55`  seq=264  **OK**              `httpx               `            result_count=0   runtime=120ms
`19:03:55`  seq=265  **START**          `httpx               ` (T2)  target=`www.geo2.gitlab.com`
`19:03:55`  seq=266  **OK**              `httpx               `            result_count=0   runtime=117ms
`19:03:55`  seq=267  **START**          `httpx               ` (T2)  target=`auth.gitlab.com`
`19:03:55`  seq=268  **OK**              `httpx               `            result_count=0   runtime=117ms
`19:03:55`  seq=269  **START**          `httpx               ` (T2)  target=`dr.gitlab.com`
`19:03:55`  seq=270  **OK**              `httpx               `            result_count=0   runtime=115ms
`19:03:55`  seq=271  **START**          `httpx               ` (T2)  target=`jobs.gitlab.com`
`19:03:55`  seq=272  **OK**              `httpx               `            result_count=0   runtime=119ms
`19:03:55`  seq=273  **START**          `httpx               ` (T2)  target=`staging-ref.gitlab.com`
`19:03:56`  seq=274  **OK**              `httpx               `            result_count=0   runtime=122ms
`19:03:56`  seq=275  **START**          `httpx               ` (T2)  target=`www.shop.gitlab.com`
`19:03:56`  seq=276  **OK**              `httpx               `            result_count=0   runtime=117ms
`19:03:56`  seq=277  **START**          `httpx               ` (T2)  target=`4456656-review-1292-rende-mv55i4.desig`
`19:03:56`  seq=278  **OK**              `httpx               `            result_count=0   runtime=117ms
`19:03:56`  seq=279  **START**          `httpx               ` (T2)  target=`4456656-review-aregnery-a-q3q5lo.desig`
`19:03:56`  seq=280  **OK**              `httpx               `            result_count=0   runtime=116ms
`19:03:56`  seq=281  **START**          `httpx               ` (T2)  target=`imap.docs.gitlab.com`
`19:03:56`  seq=282  **OK**              `httpx               `            result_count=0   runtime=115ms
`19:03:56`  seq=283  **START**          `httpx               ` (T2)  target=`mr-sidebar.prototype.gitlab.com`
`19:03:56`  seq=284  **OK**              `httpx               `            result_count=0   runtime=120ms
`19:03:56`  seq=285  **OK**              `shodan              `            result_count=0   runtime=0ms
`19:03:56`  seq=286  **OK**              `virustotal          `            result_count=0   runtime=0ms

## 19:04
`19:04:42`  seq=287  **OK**              `subdomain_takeover  `            result_count=0   runtime=0ms
`19:04:42`  seq=288  **START**          `wafw00f             ` (T1)  target=`gitlab.com`
`19:04:42`  seq=289  **OK**              `wafw00f             `            result_count=1   runtime=748ms
`19:04:42`  seq=290  **START**          `sslyze              ` (T1)  target=`gitlab.com`
`19:04:45`  seq=291  **OK**              `sslyze              `            result_count=0   runtime=2289ms
`19:04:46`  seq=293  **START**          `nuclei              ` (T2)  target=`gitlab.com`

## 19:06
`19:06:00`  seq=294  **OK**              `nuclei              `            result_count=0   runtime=73301ms
`19:06:42`  seq=295  **OK**              `pastebin_scan       `            result_count=0   runtime=0ms
`19:06:42`  seq=296  **OK**              `certstream_recent   `            result_count=0   runtime=0ms
`19:06:42`  seq=297  **OK**              `playstore           `            result_count=0   runtime=0ms

---

## Tool fire tally

| Tool | Fires | OK results | Errors | Items surfaced |
|---|---:|---:|---:|---:|
| `subfinder` | 1 | 2 | 0 | 332 |
| `shodan` | 1 | 2 | 0 | 88 |
| `dns` | 1 | 1 | 0 | 57 |
| `holehe` | 10 | 10 | 0 | 31 |
| `dockerhub` | 1 | 1 | 0 | 24 |
| `aws_recon` | 1 | 1 | 0 | 22 |
| `virustotal` | 1 | 2 | 0 | 20 |
| `urlscan` | 1 | 1 | 0 | 20 |
| `ransomwatch` | 1 | 1 | 0 | 15 |
| `hunter` | 1 | 2 | 0 | 10 |
| `email_format` | 1 | 1 | 0 | 10 |
| `azure_m365_recon` | 1 | 1 | 0 | 9 |
| `gcp_recon` | 1 | 1 | 0 | 9 |
| `playstore` | 1 | 2 | 0 | 7 |
| `wafw00f` | 1 | 1 | 0 | 1 |
| `whois` | 1 | 1 | 0 | 1 |
| `httpx` | 100 | 100 | 0 | 0 |
| `certstream_recent` | 1 | 2 | 0 | 0 |
| `github_recon` | 1 | 2 | 0 | 0 |
| `pastebin_scan` | 1 | 2 | 0 | 0 |
| `subdomain_takeover` | 1 | 2 | 0 | 0 |
| `ahmia` | 1 | 1 | 0 | 0 |
| `amass` | 1 | 1 | 0 | 0 |
| `gitdorker` | 1 | 1 | 0 | 0 |
| `gitleaks` | 1 | 1 | 0 | 0 |
| `hudsonrock` | 1 | 1 | 0 | 0 |
| `nuclei` | 1 | 1 | 0 | 0 |
| `postman` | 1 | 1 | 0 | 0 |
| `sslyze` | 1 | 1 | 0 | 0 |
| `trufflehog` | 1 | 1 | 0 | 0 |
| `asn_bgp` | 1 | 0 | 1 | 0 |
| `crtsh` | 2 | 0 | 2 | 0 |
| `theharvester` | 2 | 0 | 2 | 0 |

**Totals:** 143 fires · 147 OK · 5 errors · 656 items surfaced across 33 distinct tools.
