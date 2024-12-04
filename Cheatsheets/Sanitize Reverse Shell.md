#revshell #reverse-shell #sanitize 
Once you've got a revshell:
```
# on host machine

# With python
python -c 'import pty; pty.spawn("/bin/bash")'

# with script and bash
/usr/bin/script -qc /bin/bash /dev/null

ctrl + z 
==========
# on local machine

stty raw -echo

fg
===========
# on host machine

reset
```
