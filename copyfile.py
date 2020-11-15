#! /usr/bin/env python3
#-*-coding:utf-8-*-

__auther__='guijianchou'

'copyfile.py'

import os
import shutil
filelist=[]
rootdir="/mnt/c/Users/Zen/Downloads/"
fileDst="/mnt/e/Downloads"
filelist=os.listdir(rootdir)
def copy_file1():
    for x in filelist:
        print (x)
        m=os.path.join(rootdir,x)
        print (m)
        shutil.copy2(m,fileDst)
        os.remove(m)

if __name__=='__main__':
    copy_file1()
    print ("copy and remove finished !")
