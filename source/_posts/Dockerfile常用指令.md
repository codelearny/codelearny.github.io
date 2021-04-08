---
title: Dockerfile常用指令
date: 2021-03-18 11:51:42
tags: [Docker]
categories:
    - [容器,Docker]
---
从来都没有最佳的行动时机，敢于行动，比找到时机更重要
+ CMD
  指定一个容器启动时要运行的命令，可以指定参数，最好将命令放在一个数组结构中 CMD ["/bin/bash","true"]
+ ENTRYPOINT
  与CMD类似，但是CMD会被run命令覆盖，而run命令的参数会被当作参数再次传递给ENTRYPOINT
+ WORKDIR
  设置工作目录，可多次设置
+ ENV
  设置环境变量，可在其他指令中使用$ENV引用，也可以在run命令中使用-e参数传递环境变量，这些变量只在运行时有效
+ USER
  指定运行容器的用户，uid或组及其组合，不指定默认为root
+ VOLUME
  添加卷，也可以通过-v参数指定挂载卷 -v 本地目录：容器目录
+ ADD
  用于添加环境中的文件或目录到容器中，ADD src dest/path,src可以是url或文件或目录
+ COPY
  类似ADD,但是只是复制而不会提取和解压
+ ONBUILD
  为镜像添加触发器，当一个镜像被用作其他镜像的基础镜像时，该触发器会执行，注意只能被继承一次