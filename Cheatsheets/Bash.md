#bash
# Encoding #encodings
## Base64 #base64

`b64=$(echo -ne $payload | base64)`

* Special attention to echo's -ne for XML encoding
## URL #url

`url=$(echo -n $payload | jq -Rr '@uri')

# HTTP 

## Post

`curl -d "data=2jb1u27ca9105b17" -d "key=!1234567890" http://some-site.dom/endpoint

# Port discovery
## Remote ports
#nmap 
```
# Quick enumeration
sudo nmap -sS --min-rate 5000 -vvv -n -Pn -p- $(cat ip) -oN  out.nmap


# Advanced enumeration (akes longer)
ports=$(nmap -p- --min-rate=1000 -T4 $1 | grep ^[0-9] | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//)
nmap -p$ports -sC -sV $1

```
## Local ports
#list-ports #port #netstat #lsof
```
netstat -tulpn | grep LISTEN

sudo lsof -i -P -n | grep LISTEN
```
### Local network remote Hosts
```
# Only Bash. Scanninf from 0 to 1000 in IP 192.168.0.1 
for PORT in {0..1000}; do timeout 1 bash -c "

</dev/tcp/192.168.0.1/$PORT &>/dev/null" 2>/dev/null && echo "port $PORT is open"; done
```
# Port Forwarding
#port-forwarding 
```
# local port forwarding
# the target host 192.168.0.100 is running a service on port 8888
# and you want that service available on the localhost port 7777

ssh -L 7777:localhost:8888 user@192.168.0.100

# remote port forwarding
# you are running a service on localhost port 9999 
# and you want that service available on the target host 192.168.0.100 port 12340

ssh -R 12340:localhost:9999 user@192.168.0.100

# Avoiding the initial prompt
ssh -o StrictHostKeyChecking=no -R 1025:localhost:1025 lotape6@10.10.16.6

```

# Set UID and GID
```
# If you can acces (e.g. through docker) to change the ownership and permissions of bash you can then try:
#Privileged machine
chown root:root bash
chmod 4755 bash

# Unprivileged machine
./bash -p
```

# Xargs examples
```
cat /home/lotape6/resources/hack/SecLists/Passwords/Default-Credentials/tomcat-betterdefaultpasslist.txt | xargs -I % sh -c "echo % | cut -d: -f1 >> users"

```