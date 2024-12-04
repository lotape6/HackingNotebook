# Uploading files
```
sudo python3 -m http.server 80
```
# Retrieving files
```
python3 -m pip install --user uploadserver
python3 -m uploadserver

curl -X POST http://127.0.0.1:8000/upload -F 'files=@multiple-example-1.txt' -F 'files=@multiple-example-2.txt'
```
