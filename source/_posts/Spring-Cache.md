---
title: Spring Cache
date: 2021-03-08 09:11:50
tags: [Spring,Cache]
categories:
    - [Java,Spring,Spring Cache]
---
Spring Cache 设计原理
===
location:spring-context/org.springframework.cache
* 两大接口
    >org.springframework.cache.CacheManager 缓存管理核心SPI，允许检索命名缓存区域
    >org.springframework.cache.Cache 定义通用缓存操作的接口
* org.springframework.cache.annotation包  
  使用@EnableCaching 可以开启注解支持，该注解导入了一个CachingConfigurationSelector
  根据注解的mode属性，导入相应的配置类，默认导入：
  > AutoProxyRegistrar  
   >> 自动代理创建器注册器，用于在容器中注册一个AbstractAutoProxyCreator，通常是AnnotationAwareAspectJAutoProxyCreator，它是一个SmartInstantiationAwareBeanPostProcessor，在bean实例化之后返回代理后的实例

  > ProxyCachingConfiguration
  1. 注入CachingConfigurer
     可实现该接口自定义缓存相关的CacheManager，CacheResolver，KeyGenerator，CacheErrorHandler，也可以继承CachingConfigurerSupport，选择实现部分功能
  2. 声明AnnotationCacheOperationSource
     实现接口CacheOperationSource，给CacheInterceptor拦截器提供缓存操作所需的属性，该实现类从Spring缓存相关注解中读取元数据，
     默认内置SpringCacheAnnotationParser从方法或类上解析注解的元数据并缓存
  3. 声明CacheInterceptor
     实现接口AOP联盟MethodInterceptor，用于使用通用Spring缓存基础结构的声明式缓存管理。
     继承CacheAspectSupport，该类包含与Spring底层缓存API的集成，使用策略设计模式。CacheOperationSource用于确定缓存操作，KeyGenerator将构建缓存密钥，CacheResolver将解析要使用的实际缓存。
  4. 声明BeanFactoryCacheOperationSourceAdvisor
     


* Spring Boot 自动配置
    >org.springframework.boot.autoconfigure.cache.CacheAutoConfiguration  
