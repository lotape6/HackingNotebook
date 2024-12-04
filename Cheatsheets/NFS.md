#nfs #port-2049
```
# Enumeration
showmount -e $(cat ip)

# Mounting
sudo mount -t nfs [-o vers=2] <ip>:<remote_folder> <local_folder> -o nolock

# Mounting with user permissions
sudo mount -t nfs [-o vers=2] <ip>:<remote_folder> <local_folder> -o nolock -o umask=filePermissions,gid=<ownerGroupID>,uid=<ownerID>

# Check uid and gid with 
id -u user


```
# Permissions

If you mount a folder which contains **files or folders only accesible by some user** (by **UID**). You can **create** **locally** a user with that **UID** and using that **user** you will be able to **access** the file/folder.

Interesting tool -> nfsshell: https://www.pentestpartners.com/security-blog/using-nfsshell-to-compromise-older-environments/ 