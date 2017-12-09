#!/usr/bin/env python
#-*-coding:utf-8-*-

__auther__='guijianchou'

'hashs.py'

import os
import sys
import hashlib

sha1=hashlib.sha1()
md5=hashlib.md5()

BUFF_SIZE=102400

with open(sys.argv[1],'rb') as f:
    while True:
        m=f.read(BUFF_SIZE)
        if not f:
            break
        md5.update(m)
        sha1.update(m)

print("md5: {0}",format(md5.hexdigest()))
print("sha1: {0}",format(sha.hexdigest()))