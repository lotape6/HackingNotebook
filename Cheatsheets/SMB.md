#port-139 #port-445
## Listing
#nmap #nmap-smb
```
# Print extra information about SMB shares
nmap --script smb-enum-shares.nse $(cat ip)
```
#smbclient #smb 
```
# List public shares
smbclient -N -L $(cat ip) 
```
## Connect to shares
```
# Try No Login
smbclient //$(cat ip)/SHARE-NAME -N

# Try anonymous login 
smbclient //$(cat ip)/SHARE-NAME -U%

# Login with an username 
smbclient //$(cat ip)/Users -U "active.htb\SVC_TGS"


# Recursive copy (once connected to smb and you are in the desired folder)
recurse ON
prompt OFF
mget *

```

> [!NOTE] Do not forget
> To try writing on different shares to check further Local File Inclusions Remote Code Execution (lfi2rce)  
