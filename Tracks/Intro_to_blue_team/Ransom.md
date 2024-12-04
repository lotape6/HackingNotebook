An interesting malicious exe and an encrypted file where given. It's now time to dig into radare2:
```
radare2 windows_update.exe

# In there we can do

aaa # analyze everything
v   # enter visual mode
# Right click and select functions
# Click on sym.enctyp (as it looks quite smelly)
# And there you can find the key being printed (looks like SUPERSECURE69 or SUPERSECURE 69 )
```
Now it's time to find a tool to decrypt the file:
```
https://pypi.org/project/msoffcrypto-tool/
```
0x2e8ba2e8ba2e8ba3
And let's go:
That was not the tool: as the function call was named sym.encrypt, lets assume the encryption si Symetrical encryption
Not the case. Let's do a full reverse engineering method to decode the file:

Let's open Ghidra and decompile the encrypt method so we can reverse the ecncryption:

```

void encryptFile(char *param_1)

{
  bool bVar1;
  undefined7 extraout_var;
  
  bVar1 = readfile(param_1);
  if ((int)CONCAT71(extraout_var,bVar1) != 1) {
    encrypt((longlong)file,DAT_00409978);
    writefile(param_1,file,DAT_00409978);
    free(file);
  }
  return;
}

void encrypt(longlong param_1,ulonglong param_2)

{
  undefined8 local_17;
  undefined2 local_f;
  undefined local_d;
  int local_c;
  
  local_17 = 0x4345535245505553;
  local_f = 0x5255;
  local_d = 0x45;
  for (local_c = 0; (ulonglong)(longlong)local_c < param_2; local_c = local_c + 1) {
    *(char *)(param_1 + local_c) =
         *(char *)((longlong)&local_17 + (ulonglong)(longlong)local_c % 0xb) +
         *(char *)(param_1 + local_c);
  }
  return;
}

```


`Decrypt.cpp`
```
#include <fstream>
#include <iostream>
#include <vector>

void *file;
size_t fileSize;

bool readfile(const char *filePath)

{
  long lVar1;
  FILE *_File;

  _File = fopen(filePath, "rb");

  std::cout << "Fopen returned " << _File << std::endl;
  if (_File != (FILE *)0x0) {
    fseek(_File, 0, SEEK_END);
    lVar1 = ftell(_File);
    fileSize = (size_t)lVar1;
    rewind(_File);
    file = malloc(fileSize + 1);
    fread(file, 1, fileSize, _File);
    fclose(_File);
    std::cout << "file addres " << file << std::endl;
  } else {
    fclose((FILE *)0x0);
  }

  return _File;
}

void writefile(const char *param_1, void *param_2, size_t param_3)

{
  FILE *_File;
  _File = fopen(param_1, "wb");
  if (_File != (FILE *)0x0) {
    std::cout << "Writting file" << std::endl;
    fwrite(param_2, 1, param_3, _File);
  }
  return;
}

void decrypt(long long inFile, unsigned long long inFileSize) {
  //   unsigned long long local_17;
  const char *key = "SUPERSECURE";
  for (unsigned long long local_c = 0; local_c < inFileSize; ++local_c) {
    *(char *)(inFile + local_c) -= *(char *)(key + (local_c % 11));
    // *(char *)(inFile + local_c) &= 0xFF;
  }
  return;
}

void decryptFile(const char *filePath)

{
  bool isFileOpened;
  std::string outputPath = "test-decrypted.xlsx";
  isFileOpened = readfile(filePath);
  if (isFileOpened) {
    std::cout << "Decrypting" << std::endl;
    decrypt((long long)file, fileSize);
    writefile(outputPath.c_str(), file, fileSize);
    free(file);
  }
  return;
}

int main() {
  const std::string filePath = "test.xlsx";

  decryptFile(filePath.c_str());

  return 0;
}
```