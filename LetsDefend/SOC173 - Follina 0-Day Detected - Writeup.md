Notes for a write-up I was asked for ([this post](https://medium.com/@lotape6/soc173-follina-0-day-detected-writeup-cc4910bab9d0))
In this writeup we are going to take a close look to the "SOC173 - Follina 0-Day Detected" alert form [letsdefend.io](https://app.letsdefend.io/monitoring?channel=investigation).

# Hands on the analysis

First things first, let's take a close look to the alert and completely understand what kind of threat we are facing. 

![[Selection_011.png]]

As we can observe, we know that there is a suspicious `.doc` file found on JonasPRD (172.16.17.39) machine that has triggered the execution of msdt.exe after opening the Office document. Quite smelly so far since a `.doc` is not intended to run any executable. After a quick google search, we can find out that the executable mentioned in the alarm is related to a [troubleshooting pack](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/msdt).

## Is the alert a True Positive? 
Let's now take a look to the suspicious file itself. As a starting point we can go yo [VirusTotal](https://www.virustotal.com/gui/home/search) and check if given hash is already known to be malicious. You can either download the file and upload ti for a complete AV check or directly search for the hash and check the results.  

![[Pasted image 20241203224326.png]]

After searching for the hash, we can find out that the alarm completely looks like a true positive. Indeed we can observe that the file is related to [CVE-2022-30190](https://www.cve.org/CVERecord?id=CVE-2022-30190):

> [!Vulnerability description]
> A remote code execution vulnerability exists when MSDT is called using the URL protocol from a calling application such as Word. An attacker who successfully exploits this vulnerability can run arbitrary code with the privileges of the calling application.

Further checks :
1. **The last analysis performed date** is recent enough to take into account the results.
2. **Community reports**. If we click on community, we can take a look to the artifacts reported by other users. This could give us further hints on our research.
3. Check other malware databases as [filescan.io](https://www.filescan.io/uploads/674f7da4e5f10467692940a8) or [polyswarm](https://polyswarm.network/scan/results/file/90a1a94f5f9efce66697129bd4267b5e5102eec7446d51b769882360ae035b19) for example.  

They all agree that the file is malicious, so let's gather some further information.
In the [VT search community tab](https://www.virustotal.com/gui/file/4a24048f81afbe9fb62e7a6a49adbd1faf41f266b5f9feecdceb567aec096784/community) we can gather some IOC (Indicator Of Compromise) to further check the status of our system machines:

![[Pasted image 20241203210102.png]]

Interesting IOCs: 
- xmlformats.com
- xmlformats.com
- 199.115.115.119
- 185.107.56.58
- 199.59.243.225
- 162.210.196.171


## How did the `.doc` arrive? 

Let's take a look to emails, logs and EDR to check how did this malicious file arrived to the affected machine. Searching by the `.doc` name in the e-mails, we can observe that this was the delivery method for our target malware. We can now take the relevant data: 
![[Pasted image 20241203225615.png]]

```
From: radiosputnik@ria.ru
To: jonas@letsdefend.io
Subject: invitation for an interview
Date: Jun, 02, 2022, 01:51 PM
```
We can directly proceed deleting the mail since we have all the relevant  information and we do not want anyone to download this file ever again.

artifatct: radiosputnik@ria.ru

## What is the malware going to try? (Roughly)
Take advantage of DMA tool as any.run or joesandbox if you have access to them. Since I do not have (at least at the time of writing) any corporate mail, I cannot access them, so I'll be taking a look to VirusTotal behavior report. Taking a look to related MITRE ATT&CK information, we can easily observe that this malware is going to perform multiple tactics, techniques and subtechniques in order to evade the defense on the machine, escalate privileges and establish persistence (among others):
![[Pasted image 20241203232621.png]]

I really encourage you to go to [VirusTotal behavior's tab](https://www.virustotal.com/gui/file/4a24048f81afbe9fb62e7a6a49adbd1faf41f266b5f9feecdceb567aec096784/behavior) , expand each tactic and take a close look to each technique to have a better understanding of the operations performed.
Also we should take a look to the Network Communication triggered by the malware, to later determine if the exploitation was successful.
![[Pasted image 20241203232847.png]]

## Was the file malware executed?
As we could observe in the alarm itself, the malware was executed and allowed:
```
AV Action : Allowed
Alert Trigger Reason :  msdt.exe executed after Office document
```
But let's ensure that the harmful actions took place after executing the document. Let's take a look to the Log management tab and search for any of the domains and web pages involved in the exploit. I will go for a quick and dirty search for the domains reported on VT to check if there is any kind of connection to any of the domains.
![[Pasted image 20241203212449.png]]
As we can see, the host reported on the alarm has accessed the harmful domain.
https://www.xmlformats.com
https://www.xmlformats.com/office/word/2022/wordprocessingDrawing/
https://www.xmlformats.com/office/word/2022/wordprocessingDrawing/RDF842l.html

We now must take a look to the "Terminal History" tab inside JonasPRD host to check for malicious activity, and two commands are logged:

- 02.06.2022 15:20:45 -> C:/windows/system32/cmd.exe /c taskkill /f /im msdt.exe
- 02.06.2022 15:20:56 -> C:/windows/system32/cmd.exe /c cd C:/users/public/&&for /r %temp% %i in (05-2022-0438.rar) do copy %i 1.rar /y&&findstr TVNDRgAAAA 1.rar>1.t&&certutil -decode 1.t 1.c &&expand 1.c -F:* .&&rgb.exe

As we can observe, the timestamp is pretty close to the alarm event time, and we can observe something interesting, the `msdt.exe` file, being executed after the `.doc` is opened, is being killed and some nasty cmd is executed aftewards. Taking a close look to the next cmd we observe that multiple things are being addressed on the same cmd: 
- Going to `C:/users/public/` folder
- Iterates recursively through the folders searching for the 05-2022-0438.rar  and copies it into 1.rar
- Searches for `TVNDRgAAAA` inside the 1.rar file and stores the matching result into 1.t
- Decodes the 1.t file (likely encoded in Base64) and stores it into 1.c (likely a compressed file binary)
- Extracts all the content of 1.c
- Executes rgb.exe

We continue to confirm that the malware was successfully executed since we have identified that:
- The malicious file was delivered through an email.
- The content of the file is tagged as malicious for many AVs and many users have reported that threat along with some domains.
- The target host has executed the file since we have observed the reported network communication from the infected machine to the malicious domain.
- Along with the attackers' domain access, we have found some nasty commands that gets unrolled and executed.
Without further ado, we can directly go to the EDR's tab ("Endpoint Security") and set the containment for the affected machine, as we noticed that the `.doc` file was executed. 


## Further steps
We have already ensured that we have a true positive, but now it's time to check what happened after the exploitation took place, to ensure no further machines are being affected.
Taking a look to the processes running on JonasPRD host, we no longer observe the `rgb.exe` malware. Let's now take a look to the Network Action from the execution date onwards (02.06.2022 15:20:56). Let's first check the communication right after the incident:
![[Selection_021.png]]
It looks like there is only one Network Action which happens hours after the execution of the "self unfolding nasty command", but the searching for the IP in the Intel Threat tab as well as VT and other platforms, the IP does not look malicious at all. Taking a wider look, we check some other IPs:
![[Pasted image 20241203220450.png]]

Taking a look to further network actions, we observe some IPs that may worry us:
- [1.1.1.1](https://www.virustotal.com/gui/ip-address/1.1.1.1) (1 security vendor flagged it as malicious in VT)
- [151.101.1.140](https://www.ipqualityscore.com/ip-reputation-check/lookup/151.101.1.140) although it does not report anything in VirusTotal
- [52.85.96.126](https://www.ipqualityscore.com/ip-reputation-check/lookup/52.85.96.126)
But nothing really interesting is found from the IPs. Also, checking the suspicious IPs a [Tor's exit nodes](https://exonerator.torproject.org/) is also a good idea, but nothing found.

Let's also take a look to the Browser History right after the incident. The most strange URL is the one observed below, but after some Browserling and VirusTotal search, nothing harmful is found. 
+ https://z-p3-cdn.fbsbx.com/v/t59.2708-21/28059757_1618752734912252_3413650903192829952_n.txt/c-for-triangular.txt?_nc_eui2=v1%3AAeEg3xRqt6pGKy23pUBrz575y73BuCZmQ_CMAYBCQhCAq1mGxAe9lg-lPWPlyYXiNOTmVlHUmrQsj7KyJ-n-Uc5HKEmQTWeRFejnJEUquOwYgQ&oh=90013b86b700c11d6eaa80b34ac2ccd9&oe=5A9ADA01&dl=1
  
# The playbook
Then we can finally fill in our case's playbook. The first question is related to the Tread Indicator type. As we have been investigating an strange file, and the alert came from a suspicious execution after opening a `.doc` file, he thread indicator that fits the most would be "other"

![[Pasted image 20241204000327.png]]

The next question is if the malware was quarantined. Although I cannot connect directly to the machine to check for the presence of the malware or any Registry modification, as we have observe that the malware is going to establish persistence and that was successfully run, we must assume that the malware is still present.

![[Selection_030.png]]
Then easy question:
![[Selection_031.png]]
As we observed, the target C2 domains were accessed from the infected machine so:
![[Selection_032.png]]