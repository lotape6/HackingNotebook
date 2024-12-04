#ldap 
* Openldap
* windapsearch
* https://www.baeldung.com/linux/ldap-command-line-authentication
* https://book.hacktricks.xyz/network-services-pentesting/pentesting-ldap
```
ldapsearch -h $(cat ip) -p 389 -x -b "dc=htb,dc=local"


ldapsearch -x -LLL -H ldap://<IP> -b dc=example,dc=com dn

ldapsearch -x -H ldap://$(cat ip) -D '' -w '' -b "DC=local,DC=htb"

# Bypass TLS SNI check
ldapsearch -H ldaps://company.com:636/ -x -s base -b '' "(objectClass=*)" "*" +


nmap -n -sV --script "ldap* and not brute"
```

## Enumeration
#nmap-ldap #windapsearch
```
nmap -n -sV --script "ldap* and not brute" <IP> #Using anonymous credentials

# Users enumeration
./windapsearch.py --dc-ip 10.10.10.161:389 -U
./windapsearch.py --dc-ip 10.10.10.161:389 -U --full

# Enumerate users with service principal name (4 Kerberoasting)
./windapsearch.py --dc-ip 10.10.10.161:389 --user-spns


# Enumerate existing objects 
./windapsearch.py --dc-ip 10.10.10.161:389 --custom "objectClass=*"

```