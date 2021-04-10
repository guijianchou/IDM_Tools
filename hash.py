#!/usr/bin/env python
#-*-coding:utf-8-*-

__auther__='guijianchou'

'hash.py'

import os
import hashlib
import sys



filelist=os.listdir("/mnt/e/Downloads")
#hashname=os.path("/mnt/e/Downloads/hash.txt")
md5=hashlib.md5()
sha1=hashlib.sha1()
def __hashdownload():
    for x in filelist:
        print(os.fspath(x))
        m=md5.update(x.encode('utf-8'))
        print(m)
    #    n=sha1.update(x.encode('utf-8')).hexdigest()
        
#        with open(hashname,'w') as t:
 #           t.write(x,'\n','md5:',m,'\n','sha1:',n,'\n\n')
 #           t.close()
 #       print (x,' md5:',m)
def hashfile():
    __hashdownload()
    print ("already add new file hash into hash.txt")

if __name__=='__main__':
    hashfile()
    