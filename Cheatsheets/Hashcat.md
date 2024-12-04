#hashcat #hash 
Interesting webpage: https://hashes.com/en/tools/hash_identifier

Search for hash mode:
```
hashcat -h | grep -i -e md5
```

## Dictionary attack
Atack md5 hash:

```
hashcat -m 0 -a 0 hash /home/lotape6/resources/hack/rockyou.txt
```


## Brute force attack 
```
hashcat -m 13100 -O -a3 -i ntlm_hashes.txt
```
