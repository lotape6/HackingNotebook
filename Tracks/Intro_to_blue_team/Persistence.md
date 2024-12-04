After checking the file type:
```
file query

query: MS Windows registry file, NT/2000 or above
```

We find a tool for managing this information:
https://github.com/p0dalirius/hivetools

```
./hive-to-json.py --hive ~/resources/hack/htb/tracks/intro_to_blue_team/Persistence/query -o ~/resources/hack/htb/tracks/intro_to_blue_team/Persistence/query.json
```

After opening the json and searching for the classic persistence registries:
```
- HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run 
    
- HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce 
    
- HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run 
    
- HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce 
    

Similarly, the registry keys that are used to launch programs or set folder items for persistence are: 

- HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders 
    
- HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders 
    
- HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders 
    
- HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders
```

We find out somethinginteresting:
```
"Run": "C:\\Windows\\System32\\SFRCezFfQzRuX2t3M3J5XzRMUjE5aDd9.exe",
HTB{1_C4n_...
```