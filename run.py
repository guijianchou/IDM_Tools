#!/usr/bin/env python3
#-*- coding: UTF-8 -*-

__auther__='guijianchou'

'run.py'

import cleanfile 
import copyfile
import copy_file2


def __run_func1():
    try:
        cleanfile.clean_file2()
    except TypeError,e:
        print 'Exception:',e
    finally:
        pass

def __run_func2():
    try:
        copyfile.copy_file2()
    except TypeError,e:
        print 'Exception:',e
    finally:
        pass
def __run_func3():
    try:
        copyfile.copy_file3()
    except TypeError,e:
        print 'Exception:',e
    finally:
        pass

if __name__=='__main__':
    __run_func3()
    __run_func2()
    __run_func1()
    print"All Job DONE !"
