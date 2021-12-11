#!/usr/bin/env python
#-*-coding:utf-8-*-

__auther__='guijianchou'

'hash.py'

import hashlib,os

def md5(filename):
    hash_md5=hashlib.md5()
    with open(filename,'rb') as f:
        for chunk in iter(lambda:f.read(4096),b''):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()
def sha1(filename):
    hash_sha1=hashlib.sha1()
    with open(filename,'rb') as f:
        for chunk in iter(lambda:f.read(4096),b''):
            hash_sha1.update(chunk)
    return hash_sha1.hexdigest()



#f_local=input("Please type file location: \n")
f_local="c/Users/Zen/Downloads"
f_real_loc=("/mnt/"+f_local)

for x in os.listdir(f_real_loc):
    m=os.path.join(f_real_loc,x)
    print (x+'  md5:'+md5(m))
   # print (x+"  sha1:"+sha1(m))
    
