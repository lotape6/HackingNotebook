Let's take one SIEM alert to analyze it:


```
⭐ CVE-2024-24919 is a zero-day arbitrary file read in Check Point Security Gateways.
EventID :
263
Event Time :
Jun, 06, 2024, 03:12 PM
Rule :
SOC287 - Arbitrary File Read on Checkpoint Security Gateway CVE-2024-24919
Level :
Security Analyst
Hostname :
CP-Spark-Gateway-01
Destination IP Address :
172.16.20.146
Source IP Address :
203.160.68.12
HTTP Request Method :
POST
Requested URL :
172.16.20.146/clients/MyCRL
Request :
aCSHELL/../../../../../../../../../../etc/passwd
User-Agent :
Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:126.0) Gecko/20100101 Firefox/126.0
Alert Trigger Reason :
Characteristics exploit pattern Detected on Request, indicative exploitation of the CVE-2024-24919.
Device Action :
Allowed
Show Hint
```

Let's search for the source IP in the EDR so we can find out all affected machines:

203.160.68.12
There are several connection to the same subnet which looks strange:
```
Jun 6 2024 15:15:45
203.160.68.10
Jun 6 2024 15:17:25
203.160.68.11
Jun 6 2024 15:12:43
203.160.68.12
Jun 6 2024 15:12:45
203.160.68.12
Jun 6 2024 15:14:30
203.160.68.12
Jun 6 2024 15:12:48
203.160.68.13
Jun 6 2024 15:14:00
203.160.68.13
Jun 6 2024 15:16:20
203.160.68.15
Jun 6 2024 15:18:00
203.160.68.16
Jun 6 2024 15:19:45
203.160.68.17
Jun 6 2024 15:19:10
203.160.68.20
```

After a virustotal search we find out that it's a malicious server from china. People has also reported the same vulnerability exploitation for this IP, so definitely a threat.