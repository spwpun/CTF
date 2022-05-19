from matplotlib import interactive
from pwn import *

r = remote("157.245.46.136", 30608)

r.sendafter(b"\n>> ", b"1" )
r.sendafter(b"Input: ", b"DRAEGER15th30n34nd0nly4dm1n15tr4t0R0fth15sp4c3cr4ft\x00\n" )

r.interactive()