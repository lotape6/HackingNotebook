- Mail record lookup: https://mxtoolbox.com/
- IP/URL/Domain/fileHash reputation check: https://talosintelligence.com/
- IP/URL/Domain/fileHash AV check: https://virustotal.com (*note searches could be cached and you may want to re run it*)
- Online cross-browser testing: https://www.browserling.com/
- Common sandboxes:
	- VMRay
	- Cuckoo Sandbox 
	- JoeSandbox
	- AnyRun
	- Hybrid Analysis(Falcon Sandbox)
- Automated Web-Vuln scanner: https://www.zaproxy.org/ (OWASP)

# Regex
## Log search:
Redirects:
```
/^.*"GET.*\?.*=(https%3a%2f%2f[a-z0-9-]+%2e[a-z]{2,}).+?.*HTTP\/.*".*$/gm
```
Encoded Directory traversal:
```
/^.*"GET.*\?.*=(%2e%2e%2f).+?.*HTTP\/.*".*$/gm
# More specific regex
/^.*"GET.*\?.*=(.+?(?=%2e%2e%2fetc%2f)).+?.*HTTP\/.*".*$/gm
```


## Sensitive files:
**Linux**
- /etc/issue
- /etc/passwd
- /etc/shadow
- /etc/group
- /etc/hosts  

**Windows**
- c:/boot.ini
- c:/inetpub/logs/logfiles
- c:/inetpub/wwwroot/global.asa
- c:/inetpub/wwwroot/index.asp
- c:/inetpub/wwwroot/web.config
- c:/sysprep.inf
