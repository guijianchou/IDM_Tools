#!/usr/bin/env python
#-*-coding:utf-8-*-

__auther__='guijianchou'

'copyfile.py'

import os
import shutil
filelist=[]
rootdir="/mnt/c/Users/falsemeet/Downloads/"
fileDst="/mnt/f/Downloads"
filelist=os.listdir(rootdir)
def __copy_file1():
    for x in filelist:
        print x
        m=os.path.join(rootdir,x)
        print m
        shutil.copy2(m,fileDst)
        os.remove(m)
def copy_file2():
    __copy_file1()
    print "copy and remove finished !\n"

if __name__=='__main__':
    copy_file2()