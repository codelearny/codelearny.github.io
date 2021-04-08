---
title: Java error check
date: 2021-03-08 20:17:42
tags: [jstack,jmap]
---
Java线上进程问题排查常用方法
===
* CPU
> ps命令查看进程pid  
 使用 top -H -p pid 查看cpu使用率高的线程  
 使用 printf '%x\n' pid 得到 nid  
 使用 jstack pid|grep nid -C10 -color  
* gc
> jstat -gc pid 1000（采样间隔ms）
* 线程
> pstree -p pid | wc -l 线程数统计  
 ls -l /proc/pid/task | wc -l 线程数统计  
* 上下文切换
> vmstat 1（采样间隔） 10（采样次数）  
* 内存
> free 内存整体使用情况  
 jmap -dump:format=b,file={filename} {pid} 导出dump文件，可视化工具分析  
 pmap -x pid | sort -rn -k3 | head -30  内存段前三十,隔一段时间再跑一次对比  
 如果有可疑内存段需要分析  
 gdb --batch --pid {pid} -ex "dump memory {filename}.dump {内存起始地址} {内存起始地址}+{内存块大小}"   
 NMT是Java7U40引入的HotSpot新特性，配合jcmd命令我们就可以看到具体内存组成了。需要在启动参数中加入 -XX:NativeMemoryTracking=summary 或者 -XX:NativeMemoryTracking=detail，会有略微性能损耗。  
 一般对于堆外内存缓慢增长直到爆炸的情况来说，可以先设一个基线  
 jcmd {pid} VM.native_memory baseline  
 然后等放一段时间后再去看看内存增长的情况，通过  
 jcmd {pid} VM.native_memory summary.diff  
 jcmd {pid} VM.native_memory detail.diff  
 做一下summary或者detail级别的diff。  
 系统层面，我们还可以使用strace命令来监控内存分配  
 strace -f -e "brk,mmap,munmap" -p {pid}
* 磁盘
> df -hl
* 设备io负载
> iostat -d -x -k 1 10  
* 查看io源
> iotop -o
* lsof 
> lsof -c {file} 查看指定的命令正在使用的文件和网络连接  
 lsof -p {pid} 查看指定进程ID已打开的内容  
 lsof -i 显示所有连接  
 lsof -i:{port} 来显示与指定端口相关的网络信息  
