We fin doubt by searching for `http` some interesting file `logins.json`. Definitely there are some credentials stored in there. After some failed tries to decode them, we go to google and search for `mozilla login.json` we find out that there is another interesting file along the `login.json` which is the `key4.db`. After a quick search we find a tool to decrypt both files:   https://github.com/lclevy/firepwd.git

And after running it,  we directly get the flag:
```
python3 firepwd.py -d /home/lotape6/resources/hack/htb/tracks/intro_to_blue_team/Insider/Mozilla/Firefox/Profiles/2542z9mo.default-release

...

clearText b'c8e53851c7fed9a1260720791abf1526aeceae89ef079bb60808080808080808'
decrypting login/password pairs
   http://acc01:8080:b'admin',b'HTB{ur_8...
```