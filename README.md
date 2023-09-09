thread injection
===
Implementation of Remote Thread Injection using DInvoke.

Usage
---
First, create a 16 or 32-byte key for the XOR operation.
```
$ dd if=/dev/urandom bs=1 count=32 of=key.dat
```
Afterward, you can use the projects (https://github.com/hiatus/binops) and (https://github.com/hiatus/dotenv) by [https://github.com/hiatus] to perform the XOR operation and then perform the hex array dump of the shellcode and the key to replace in the code of this project.
```
xor -f key.dat shellcode.sc | .dump.hex.array
```
Compile and execute by passing the target process by name or PID
```
C:\Users\User> ThreadInjection.exe notepad
```
