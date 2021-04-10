IDM known as "Internet Download Manager", which creat several useless folders and make simple download into one complex job when fresh install. So, I write some code make it easier after IDM finish download.

IDM下载器总是在安装时创建一些无用繁琐的文件夹，以及杂乱的下载路径。因个人时常用得到，故写几行代码简化下载完后的流程

run.py 包含如下几个模块：
<1> 文件复制移动到其他硬盘；
<2> 文件的hash值存储到复制的目录，包含md5和sha1;
<3> 重复文件的重命名，添加日期之类备注;
<4> 同名文件的差分更新;
<5> IDM临时文件夹定期移除;


Todo：
<1> 文件移动的同时，调用自带windows defender基础病毒查杀
<2> 文件复制时，如果存在文件夹造成的异常抛出和功能实现
<3> 文件移动后，根据文件扩展名的分类。以及ef2结尾文件的移除

