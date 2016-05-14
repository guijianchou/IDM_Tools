#/usr/bin/env python
#-*-coding:utf-8-*-

__auther__='guijianchou'

'copyfile.py'

import os
import shutil
filelist=[]
rootdir="D:\\IDM DOWNLOADS\\"
fileDst="E:\\DOWNLOADS\\"
filelist=os.listdir(rootdir)
for x in filelist:
    print x
    m=os.path.join('D:\\IDM DOWNLOADS\\',x)
    print m
    shutil.copy2(m,fileDst)
    os.remove(m)

if __name__=='__main__':
    print "copy  and remove finished !"