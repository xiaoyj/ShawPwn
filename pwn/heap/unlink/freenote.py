from pwn import *
context(
	log_level='debug',
	binary='./stkof'
)
e=context.binary
libc=e.libc
io=process()
# io=process('books',env={"LD_PRELOAD":"libc.so.6"})

#=========================================
#Function

def dbg(script=''):
	gdb.attach(io,gdbscript=script)

def menu(func):
	io.sendlineafter('choice: ' , str(func))

def list(size):
	menu(1)

def new(size,content):
	menu(2)
	io.sendlineafter('Length of new note: ' , str(size))
	io.sendlineafter('Enter your note: ' , str(content))

def edit(number,size,content):
	menu(3)
	io.sendlineafter('Note number: ' , str(number))
	io.sendlineafter('Length of new note: ' , str(size))
	io.sendlineafter('Enter your note: ' , str(content))


def free(num):
	menu(4)
	io.sendlineafter('Note number: ' , str(num))
	io.sendline(str(num))


#=========================================
#VAR

#=========================================



dbg()
io.interactive()
