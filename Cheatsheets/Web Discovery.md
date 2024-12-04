#web-discovery 
Interesting resources:
* https://github.com/danielmiessler/SecLists
* https://github.com/OJ/gobuster.git
* https://github.com/ffuf/ffuf.git
* https://github.com/aboul3la/Sublist3r

# Web content discovery
#gobuster #feroxbuster
```
feroxbuster -u https://intra.redcross.htb/documentation -w $SECLIST/Discovery/Web-Content/directory-list-2.3-small.txt -x pdf -T 2 -k -C 400 414 -o search_doc.txt


gobuster dir  -u http://10.10.10.123:80/ -w /path/to/SecLists/Discovery/Web-Content/common.txt

# If you have some error webpage with a constant lenght
gobuster dir  -u http://10.10.10.123:80/ -w /path/to/SecLists/Discovery/Web-Content/common.txt
--exclude-length <length-of-error-page>

```

> [!NOTE] Nothing found?
> Try to also find for some specific file extensions.
> Gobuster -> `-x pdf,zip`
> fffuf ->` -e pdf,zip`

> [!NOTE] HTTPS issues
>  Try `-k`

## Web subdomain finder
#sublist3r 
```
python sublist3r.py -d <domain> # e.g. friendzone.red
```
## Web dns discovery
#gobuster #ffuf #dns #subdomain #discovery  
```
gobuster fuzz --url http://FUZZ.friendzone.red --wordlist /home/lotape6/resources/hack/SecLists/Discovery/DNS/subdomains-top1million-5000.txt 


ffuf -u http://FUZZ.friendzone.red:80/ -w /home/lotape6/resources/hack/SecLists/Discovery/DNS/subdomains-top1million-110000.txt

# If you get some response like "too many request" or any other failure message, you can filter the number of lines returned by the petition:
ffuf -u http://FUZZ.friendzone.red:80/ -w /home/lotape6/resources/hack/SecLists/Discovery/DNS/subdomains-top1million-110000.txt -fl 3-1000000000
```


## Dns 
### DNS Server Discovery
#dns-discovery #dig #nslookup
```
# Using dig  
dig NS <target-domain>  
  
# Using nslookup  
nslookup -type=NS <target-domain>

dig axfr <target-domain> @<DNS>
```