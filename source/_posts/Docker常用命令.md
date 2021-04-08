---
title: Docker常用命令
date: 2021-03-17 14:08:20
tags: [Docker]
categories:
    - [容器,Docker]
---
+ 容器
  * docker info
  * docker version
  * docker run -i -t <image_name/continar_id> /bin/bash  
  创建容器，并打开bash交互  -i 开启stdin， -t 分配一个伪tty终端，-d 指定后台运行， --name 指定容器名称， -p <主机端口>:<容器端口> 指定端口，-v <主机目录>:<容器目录> 挂载卷 ， --link <目标容器名>:<别名> 连接容器 ，--privileged 特权模式 
  * docker attach <id/container_name>  
  附着到正在运行的容器
  * docker exec -t -i <id/container_name>  /bin/bash  
  在容器内部启动新进程，-it 交互式进程 -d 后台进程（docker exec -d <af7as3df> touch /etc/myconf）
  * docker logs <id/container_name>  
  查看容器日志，-f 监控 (类似 tail -f) ，-t 显示时间戳
  * docker ps  
  列出当前所有正在运行的容器， -a  列出所有容器， -l 最后一次运行的容器
  * docker top <id/container_name>  
  显示一个运行的容器里面的进程信息
  * docker inspect <id/container_name>  
  查看容器内部详情细节，查看容器ip： docker inspect -f '{{ .NetworkSettings.IPAddress }}' <id/container_name>
  * docker cp <id/container_name>:/container_path to_path  
  从容器里面拷贝文件/目录到本地一个路径
  * docker start/stop/restart/kill/rm <id/container_name>  
  启动、停止(SIGTERM信号)、重启、杀掉(SIGKILL信号)、删除单个容器

+ 镜像
  * docker images  
  列出所有镜像，可指定镜像名称
  * docker search <image_name>  
  从dockerHub检索镜像
  * docker pull <image_name>  
  拉取镜像
  * docker rmi <image_name>  
  删除镜像
  * docker history <image_name>  
  显示镜像历史，可以看到镜像的每一层以及创建这些层的指令
  * docker push <new_image_name>  
  发布镜像到仓库，私有仓库需要加上域名端口（docker push dockerhub.yourdomain.com:443/hello.demo.kdemo:v1.0）
  * docker build -t '<repo>/<image_name>:<tag>' .
  根据Dockerfile构建镜像，-t 指定仓库/镜像名:标签， . 代表当前目录的Dockerfile，也可以指定git仓库地址

