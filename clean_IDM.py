#/usr/bin/env python
#-*-coding;utf-8-*-

__auther__='falsemeet'

'clean_IDM.py'

import os
import shutil
filelist=[]
filepath="D:\\IDM TEMPS\\DwnlData\\falsemeet\\"
filelist=os.listdir(filepath)
for x in filelist:
    print x
    print os.path.abspath(x)
    

if __name__=='__main__':
    try:
        shutil.rmtree(filepath)
    except TypeError,e:
        print 'Exception:',e
    finally:
        pass
    print 'already clean the \'IDM TEMPS\' !'