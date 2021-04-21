---
title: Java线上进程问题排查常用方法
date: 2021-03-08 20:17:42
tags: [jstack,jmap]
---
>
### CPU
查看进程pid
```bash
$ ps -ef|grep xxxService
```
查看cpu使用率高的线程
```bash
$ top -H -p pid 
```
得到 nid  
```bash
$ printf '%x\n' pid 
```
查看堆栈信息
```bash
$ jstack pid|grep nid -C10 -color  
```
### GC
查看进程gc信息（采样间隔1000ms）
```bash
$ jstat -gc pid 1000
```
### 线程
线程数统计  
```bash
$ pstree -p pid | wc -l
$ ls -l /proc/pid/task | wc -l
```
### 上下文切换
操作系统上下文切换，采样间隔1s，采样次数10次
```bash
$ vmstat 1 10
```
### 内存
内存整体使用情况  
```bash
$ free 
```
导出dump文件，可视化工具分析
```bash
$ jmap -dump:format=b,file={filename} {pid}
```
内存段前三十,隔一段时间再跑一次对比  
```bash
$ pmap -x pid | sort -rn -k3 | head -30
```
如果有可疑内存段需要分析  
```bash
$ gdb --batch --pid {pid} -ex "dump memory {filename}.dump {内存起始地址} {内存起始地址}+{内存块大小}"   
```
NMT是Java7U40引入的HotSpot新特性，配合jcmd命令我们就可以看到具体内存组成了。
>需要在启动参数中加入 -XX:NativeMemoryTracking=summary 或者 -XX:NativeMemoryTracking=detail，会有略微性能损耗。  

一般对于堆外内存缓慢增长直到爆炸的情况来说，可以先设一个基线  
```bash
$ jcmd {pid} VM.native_memory baseline  
```
 然后等放一段时间后再去看看内存增长的情况，通过  
```bash
$ jcmd {pid} VM.native_memory summary.diff  
$ jcmd {pid} VM.native_memory detail.diff  
```
 做一下summary或者detail级别的diff。  
 系统层面，我们还可以使用strace命令来监控内存分配  
```bash
$ strace -f -e "brk,mmap,munmap" -p {pid}
```
### 磁盘
查看磁盘空间占用情况
>-h 方便阅读显示，-l 只显示本地文件系统
```bash
$ df -hl
```
### IO
监控系统设备的IO负载情况
>-d 显示设备（磁盘）使用状态；-k 某些使用block为单位的列强制使用Kilobytes为单位；1表示数据显示每隔1秒刷新一次。10表示刷新10次
```bash
$ iostat -d -x -k 1 10  
```
查看io源
```bash
$ iotop -o
```
查看指定的命令正在使用的文件和网络连接  
```bash
$ lsof -c {file} 
```
查看指定进程ID已打开的内容  
```bash
$ lsof -p {pid}
```
显示所有连接  
```bash
$ lsof -i
```
显示与指定端口相关的网络信息  
```bash
$ lsof -i:{port}
```
