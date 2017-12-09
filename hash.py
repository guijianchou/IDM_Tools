#!/usr/bin/env python
#-*-coding:utf-8-*-

__auther__='guijianchou'

'hash.py'

import os
import hashlib
import sys



filelist="/mnt/f/Download"
hashname="/mnt/f/Download/hash.txt"
md5=hashlib.md5()
sha1=hashlib.sha1()
def __hashdownload():
    for x in filelist:
        print x
        md5_x=md5(x)
        sha1_x=sha1(x)

        m=md5_x.hexdigest(x)
        n=sha1_x.hexdigest(x)
        
        with open(hashname,'w') as t:
            t.write(x,'\n','md5:',m,'\n','sha1:',n,'\n\n')
            t.close()
        print x,' md5:',m
def hashfile():
    __hashdownload()
    print "already add new file hash into hash.txt"

if __name__=='__main__':
    hashfile()
    