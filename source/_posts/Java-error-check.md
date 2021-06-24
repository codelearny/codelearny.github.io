---
title: 线上进程问题排查常用方法
date: 2021-03-08 20:17:42
tags: [jstack,jmap,ps]
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
得到线程id nid  
```bash
$ printf '%x\n' pid 
```
查看java线程堆栈信息
```bash
$ jstack pid|grep nid -C10 -color  
```
### 内核调用
跟踪进程系统调用
```bash
$ strace -cp pid
```
跟踪进程用户态运行时栈
```bash
$ pstack pid
```
ps命令查看进程的运行状态，S列，阻塞函数，WCHAN列，man ps 可查询状态的详细说明
```bash
$ ps -lfp pid
F S UID        PID  PPID  C PRI  NI ADDR SZ WCHAN  STIME TTY          TIME CMD
4 S root         9     0  0  80   0 -  1027 do_wai 02:38 pts/1    00:00:00 /bin/bash
```
显示当进程sleep时，kernel当前运行的函数
```bash
$ cat /proc/<pid>/wchan
do_wait
```
当前进程正在进行的系统调用，第一个数字代表系统调用号，参考内核源码，如include/asm/unistd.h，后面跟着系统调用的参数值（位于寄存器中），最后两个值是堆栈指针和指令计数器，如果当前进程的阻塞不是系统调用产生，则系统调用号的值为-1。如果进程没有阻塞，则文件只有一个`running`的字符串
```bash
$ cat /proc/<pic>/syscall
61 0xffffffff 0x7ffd255ae8a0 0xa 0x0 0x0 0x7 0x7ffd255ae888 0x7f6d6c283dba
```
当前进程的内核调用栈信息
```bash
$ cat /proc/<pid>/stack
[<ffffffff80168375>] poll_schedule_timeout+0x45/0x60
[<ffffffff8016994d>] do_sys_poll+0x49d/0x550
[<ffffffff80169abd>] SyS_poll+0x5d/0xf0
[<ffffffff804c16e7>] system_call_fastpath+0x16/0x1b
[<00007f4a41ff2c1d>] 0x7f4a41ff2c1d
[<ffffffffffffffff>] 0xffffffffffffffff
```
当前进程打开的文件，目录中的每一项都是一个符号链接，指向打开的文件，数字则代表文件描述符。
```bash
$ ls -lt /proc/<pid>/fd
total 0
lrwx------ 1 root root 64 May 29 03:23 255 -> /dev/pts/1
lrwx------ 1 root root 64 May 29 02:38 0 -> /dev/pts/1
lrwx------ 1 root root 64 May 29 02:38 1 -> /dev/pts/1
lrwx------ 1 root root 64 May 29 02:38 2 -> /dev/pts/1
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
查看进程使用端口相关的网络信息  
```bash
$ netstat -nltp
```
