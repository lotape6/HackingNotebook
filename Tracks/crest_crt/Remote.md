
After a quick enumeration we found multiple ports:

* ftp with anon login (no files)
* nfs 
* http
* 

We have to install nfs stuff and rpcbind:
`sudo apt-get install rpcbind nfs-kernel-server

THen you can check rpcinfo:
`rpcinfo -p remote.htb
`rpcinfo -n <port> -t <url> <program>
`rpcinfo -n 2049 -t remote.htb 100003


