# Base64
```
# Encode file to base64 and store file
certutil -encode file C:\out\path\file

# Decode
certutil -decode file outputfile
```
# Retrieve some file over http
#windows-http-file-download
```
# CMD
certutil -urlcache -split -f <URL> <OUTPUT>

$client = new-object System.Net.WebClient
$client.DownloadFile("http://www.xyz.net/file.txt","C:\tmp\file.txt")

# PowerShell
Invoke-WebRequest -OutFile index.html -Uri https://superuser.com

```

# Find file
```
gci -recurse -filter "hosts" -File

# Avoid printing errors
gci -recurse -filter "hosts" -File -ErrorAction SilentlyContinue
```

# List hidden files
```
dir /a:h
```
# Check stored credentials
https://github.com/nickvourd/Windows-Local-Privilege-Escalation-Cookbook/blob/master/Notes/StoredCredentialsRunas.md
```
cmdkey /list
```

# Running an executable
```
# PowerShell
./executable.exe

# cmd
cmd /K "C:\SomeFolder\MyApp.exe"
```

# Check architecture
```
# Privileged cmd
wmic os get osarchitecture
```