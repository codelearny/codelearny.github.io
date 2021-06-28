---
title: Kafka简单使用
date: 2021-06-28 19:53:05
tags: [Kafka]
---
## Kafka官网介绍
> `Apache Kafka` 是一个开源分布式事件流平台，被数千家公司用于高性能数据管道，流分析，数据集成和任务关键型应用

## 简介
### Broker
`Kafka`作为一个集群，运行在一台或者多台服务器上。集群中的每个实例称为`Broker`。
### topic
`Kafka`通过`topic`对存储的流数据进行分类。每一个`topic`由一个或多个分区日志`partition`组成，多个`partition`均衡的分布在集群的`Broker`上。
### partition
每个`partition`都是有序且顺序不可变的记录集，并且不断地追加到结构化的`commit.log`文件。`partition`使得`Kafka`具有横向扩展能力，分区日志可以分布在任意`Broker`上，为了使消息数据具有容错性和高可用性，每个`partition`都可以`replica`复制，在不同的`Broker`上进行备份，其中一个作为`leader`，其它的`replica`作为`follwer`，`leader`处理一切对`partition`的读写请求，而`follwer`只需被动的同步`leader`上的数据。当`leader`宕机了，从`follower`中选举一个成为新的`leader`。`leader`均衡的分布在集群的`Broker`上使得系统具有高可用性。
### offset
`partition`中的每一个记录都会分配一个id号来表示顺序，我们称之为`offset`，`offset`用来唯一的标识分区中每一条记录。
### Producer
`Producer`是向`Kafka`写入数据的客户端应用，`Producer`需要指定写入的`topic`，也可以指定`partition`写入。
### Consumer
`Consumer`是从`Kafka`读数据的客户端应用，在每一个消费者中唯一保存的元数据是`offset`。`offset`由消费者所控制:通常在读取记录后，消费者会以线性的方式增加`offset`，但是实际上，由于这个位置由消费者控制，所以消费者可以采用任何顺序来消费记录。例如，一个消费者可以重置到一个旧的`offset`，从而重新处理过去的数据；也可以跳过最近的记录，从"现在"开始消费。
### group
`Consumer`使用`group id`来标识所属的消费组，通过消费组来订阅感兴趣的`topic`，`Kafka`会将消息广播到所有的消费组，对于同一个消息组的`Consumer`，消息记录会负载平衡分发。通过指定`group id`可以很方便的实现队列模式和发布订阅模式。

## 快速开始
kafka目录bin下，有许多便捷脚本，可以快速执行一些任务，如果需要了解脚本如何使用，不带参数直接运行。
### 启动ZooKeeper
```bash
$ ./bin/zookeeper-server-start.sh config/zookeeper.properties
```
### 启动Kafka broker
```bash
$ ./bin/kafka-server-start.sh config/server.properties
```
### 创建topic
```bash
$ ./bin/kafka-topics.sh --create --topic aztopic --bootstrap-server localhost:9990
```
### 查看topic
```bash
$ ./bin/kafka-topics.sh --describe --topic aztopic --bootstrap-server localhost:9990
```
### 发布消息
```bash
$ ./bin/kafka-console-producer.sh --topic aztopic --bootstrap-server localhost:9990
```
### 订阅消息
```bash
$ ./bin/kafka-console-consumer.sh --topic aztopic --bootstrap-server localhost:9990 --from-beginning
```
### 查看group
```bash
$ ./bin/kafka-consumer-groups.sh --bootstrap-server localhost:9990 --all-groups --list
```
### 导出日志文件内容
```bash
$ ./bin/kafka-dump-log.sh --files /was/kafka/data/kafka/TOPIC_DISPATCH_PRO_OSS2-0/00000000000000576560.log --print-data-log 
```
### 查看topic的offset
```bash
$ ./bin/kafka-run-class.sh kafka.tools.GetOffsetShell --broker-list localhost:9990 --topic aztopic --time -1
```

## 部分属性说明
config/server.properties Broker配置
```properties
zookeeper.connect=hostname1:port1,hostname2:port2,hostname3:port3/chroot/path	Zookeeper主机地址
num.partitions=1	每个topic的默认日志分区数
default.replication.factor=1	自动创建topic时的默认副本个数
log.dir=/tmp/kafka-logs	保存日志数据的目录（对log.dirs属性的补充）
broker.id=-1  用于服务的broker id。如果没设置，将生存一个唯一broker id。为了避免ZooKeeper生成的id和用户配置的broker id相冲突，生成的id将在reserved.broker.max.id的值基础上加1。
log.flush.interval.messages=9223372036854775807	在将消息刷新到磁盘之前，在日志分区上累积的消息数量。
log.flush.interval.ms	在刷新到磁盘之前，任何topic中的消息保留在内存中的最长时间（以毫秒为单位）。如果未设置，则使用log.flush.scheduler.interval.ms中的值。
log.retention.bytes=-1	日志删除的大小阈值
log.retention.hours=168	日志删除的时间阈值（小时为单位）
log.roll.hours=168	新日志段轮转时间间隔（小时为单位），次要配置为log.roll.ms
log.segment.bytes=1073741824	单个日志段文件最大大小
```