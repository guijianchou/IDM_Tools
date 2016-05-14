#IDM TOOLS python 版本0.2#
#IDM TOOLS python Ver 0.2#
#CHS
修复问题2，补充代码2
存在问题
下阶段代码补充
1、修复问题0.1版本中的1

2、模块化，整合代码
#EN
fix bug2 and issue2 in version 0.1
issues
next version
1.fix issues1 in version 0.1

2.make the part into one model





# IDM_clean Python 版本 0.1#
#CHS#
本文利用python来清除IDM下载后的残余空目录

具体路径修改：“filepath”
#存在问题#
1、因为循环的缘故会把整个文件夹清空，因此必须是所有下载完成以后方可delete

2、当删除以后，下次下载会重建user目录。暂且未考虑其所带来的性能损耗和磁盘读写
#下阶段代码补充#
1、利用os.rmdir来确定文件夹是否非空

2、新增下载后的文件移动到特定的目录（因为本人三块磁盘，IDM的下载和缓存盘是一块容量仅为24GB的SSD，需要每段时间把下载目录的东西移动到机械盘）
    
    
#EN#
Those code aims to clean IDM DOWNLOAD temps with Python

The specific file dictionary modified: "filepath"
#issues#
1.delete temp will clean those not download complete as well

2.after delete, user file dictionary recreat maybe effect something
#next version#
1.use some function bypass files not downloads completed (os.rmdir)

2.cut downloads file to some special own dolder
