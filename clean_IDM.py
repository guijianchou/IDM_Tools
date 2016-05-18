#/usr/bin/env python
#-*-coding;utf-8-*-

__auther__='guijianchou'

'clean_IDM.py'

import os
import shutil
filelist=[]
filepath="D:\\IDM TEMPS\\DwnlData\\Anonymous\\" #if you use the defult or self folder, Please Change the correct Path. for some reason, win cannot get os.uname(),some codes hard to change
filelist=os.listdir(filepath)
for x in filelist:
    print x
    m=os.path.join(filepath,x)
    print m
    try:
        shutil.rmtree(m)
    except TypeError,e:
        print 'Exception:',e
    finally:
        pass
    

if __name__=='__main__':  
    print 'already clean the \'IDM TEMPS\' !'