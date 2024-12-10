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
Find repeated filed login example:
```
/^(\S+) \S+ \S+ \[.*?\] "(POST|GET) \/login\.php.*?" (401|403) \d+ ".*?" ".*?"/gm
```
Find bare XXE attemps:
```
^(\S+) - (\S+) \[(.*?)\] "(\S+) (.*?)\?(?=.*?\b21DOCTYPE\|ELEMENT\|ENTITY\b).*? HTTP\/\d\.\d" (\d+) (\d+) "(.*?)" "(.*?)"
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

## Malware analysis webs
- [Anlyz](https://sandbox.anlyz.io/)
- [Any.run](https://app.any.run/)
- [Comodo Valkyrie](https://valkyrie.comodo.com/)
- [Cuckoo](https://sandbox.pikker.ee/)
- [Hybrid Analysis](http://www.hybrid-analysis.com/)
- [Intezer Analyze](https://www.intezer.com/)
- [SecondWrite Malware Deepview](https://www.secondwrite.com/)
- [Jevereg](http://jevereg.amnpardaz.com/)
- [IObit Cloud](http://cloud.iobit.com/)
- [BinaryGuard](http://www.binaryguard.com/)
- [BitBlaze](http://bitblaze.cs.berkeley.edu/)
- [SandDroid](http://sanddroid.xjtu.edu.cn/)
- [Joe Sandbox](https://www.joesandbox.com/#windows)
- [AMAaaS](https://amaaas.com/)
- [IRIS-H](https://iris-h.services/pages/dashboard#/pages/dashboard)
- [Gatewatcher Intelligence](https://intelligence.gatewatcher.com/)
- [Hatching Triage](https://tria.ge/) 
- [InQuest Labs](https://labs.inquest.net/dfi)
- [Manalyzer](https://manalyzer.org/)
- [SandBlast Analysis](https://threatpoint.checkpoint.com/ThreatPortal/emulation)
- [SNDBOX](https://app.sndbox.com/)
- [firmware](http://firmware.re/)
- [opswat](https://metadefender.opswat.com/?lang=en)
- [virusade](http://virusade.com/)
- [virustotal](https://www.virustotal.com/gui/)
- [malware config](https://malwareconfig.com/)
- [malware hunter team](https://id-ransomware.malwarehunterteam.com/)
- [virscan](http://www.virscan.org/) 
- [jotti](https://virusscan.jotti.org/it)
