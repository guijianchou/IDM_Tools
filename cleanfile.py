#!/usr/bin/env python
#-*-coding;utf-8-*-

__auther__='guijianchou'

'clean_IDM.py'

import os
import shutil
filelist=[]
print("If your have different TEMP path, Please change your TEMP path : \n")
#filepath=input()
filepath="/mnt/e/Applications/Idm/Temps/DwnlData" #if you use the defult or self folder, Please Change the correct Path. for some reason, win cannot get os.uname(),some codes hard to change
filelist=os.listdir(filepath)
def __clean_file1():
    for x in filelist:
        print (x)
        m=os.path.join(filepath,x)
        print (m)
        try:
            shutil.rmtree(m)
        except TypeError,e: # This comma is Python 2 syntax for exception handling
            print ('Exception:',e)
        finally:
            pass
    
def clean_file2():
    __clean_file1()  
    print ('already clean the \'IDM TEMPS\' !\n')

if __name__=='__main__':
    clean_file2()