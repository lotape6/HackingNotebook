Check #ldap 

# Active Directory Inspection
## SharpHound (enumeration)
#sharphound
https://github.com/BloodHoundAD/SharpHound and download the sharphound latest release OR you can go to bloodhound click on the gear and go to Download Collections
```
./shar.exe -c All -d htb.local --zipfilename loot.zip
```
## BloodHound (visualization)
#bloodhound
```
# Download and turn it up (Docker dependency required)
curl -L https://ghst.ly/getbhce -o docker-comose.yaml
docker compose pull && docker compose up
```

Check the logs to grab the `admin` password. Then you can enter in http://localhost:8080/ui/login and change the password.


## DCSync
https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/dcsync